// SPDX-License-Identifier: Apache-2.0
// InstallShield cabinet handling is derived from MIT-licensed Unshield.
// Source: https://github.com/twogood/unshield

namespace Dumplings.InstallShield
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Compression;
    using System.Security.Cryptography;
    using System.Text;

    public static class InstallShieldCabinetExtractor
    {
        private const uint Signature = 0x28635349;
        private const int CommonHeaderSize = 20;
        private const int ModernFileDescriptorSize = 0x57;
        private const long MaximumHeaderBytes = 256L * 1024L * 1024L;
        private const int MaximumDirectoryCount = 65536;
        private const int MaximumFileCount = 100000;
        private const int MaximumRegistrySetCount = 4096;
        private const int MaximumRegistryComponentCount = 16384;
        private const int MaximumRegistryKeyCount = 65535;
        private const int MaximumRegistryValueCount = 65535;
        private const int MaximumTopologyRecordCount = 4096;
        private const int MaximumSetupTypeLocaleCount = 256;
        private const int MaximumSetupTypeCount = 4096;
        private const int MaximumSetupTypeFeatureCount = 65535;
        private const int MaximumEncodedRegistryBytes = 1024 * 1024;
        private const int MaximumMediaDirectoryCount = 64;
        private const int MaximumShellFolderCount = 4096;
        private const int MaximumShortcutCount = 10000;
        private const int MaximumSpannedVolumeCount = 1024;
        private const int DeflateChunkOutputLimit = 65536;

        /// <summary>Enumerate catalog entries without opening payload volumes.</summary>
        public static List<InstallShieldCabinetEntry> List(string headerPath)
        {
            return ReadCatalog(headerPath).Entries;
        }

        /// <summary>
        /// Decode the ordinary cabinet catalog and InstallScript media tables
        /// from one validated, bounded header read.
        /// </summary>
        public static InstallShieldCabinetInspection Inspect(string headerPath)
        {
            var catalog = ReadCatalog(headerPath);
            return new InstallShieldCabinetInspection(catalog.Entries, ReadMediaMetadata(catalog));
        }

        /// <summary>
        /// Extract selected catalog ordinals to validated absolute paths.
        /// Linked records resolve to their source descriptor. Split records are
        /// exposed as one forward-only stream over validated numbered-volume
        /// ranges. Output is streamed and hashed incrementally so a large
        /// selected payload does not require a same-sized managed byte array.
        /// </summary>
        public static List<string> Extract(string headerPath, IDictionary<int, string> targets, long maximumExpandedBytes)
        {
            if (targets == null) throw new ArgumentNullException("targets");
            if (maximumExpandedBytes <= 0) throw new ArgumentOutOfRangeException("maximumExpandedBytes");

            var catalog = ReadCatalog(headerPath);
            var results = new List<string>();
            long expandedTotal = 0;
            foreach (var pair in targets)
            {
                if (pair.Key < 0 || pair.Key >= catalog.Entries.Count)
                    throw new InvalidDataException("An InstallShield cabinet target index is outside the catalog.");
                var requestedEntry = catalog.Entries[pair.Key];
                if (!requestedEntry.IsValid) throw new InvalidDataException("The selected InstallShield cabinet entry is invalid.");

                // InstallShield link records are aliases. Unshield follows
                // LinkPrevious until it reaches the descriptor that owns the
                // stored bytes; LinkNext only records the forward relationship.
                var entry = ResolveLinkedEntry(catalog, requestedEntry);
                if (!entry.IsValid) throw new InvalidDataException("A linked InstallShield cabinet source entry is invalid.");
                if (entry.ExpandedSize > maximumExpandedBytes - expandedTotal)
                    throw new InvalidDataException("Selected InstallShield cabinet output exceeds the configured expansion limit.");
                expandedTotal += entry.ExpandedSize;

                var destination = Path.GetFullPath(pair.Value);
                if (!Path.IsPathRooted(destination))
                    throw new InvalidDataException("An InstallShield cabinet destination is not absolute.");
                var parent = Path.GetDirectoryName(destination);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

                WriteEntry(catalog, entry, destination, maximumExpandedBytes);
                results.Add(destination);
            }
            return results;
        }

        private static InstallShieldCabinetEntry ResolveLinkedEntry(Catalog catalog, InstallShieldCabinetEntry entry)
        {
            var visited = new HashSet<int>();
            var current = entry;
            while (true)
            {
                if ((current.LinkFlags & ~3) != 0)
                    throw new InvalidDataException("An InstallShield cabinet entry uses unknown link flags.");
                if (!visited.Add(current.Index))
                    throw new InvalidDataException("An InstallShield cabinet link chain contains a cycle.");
                if ((current.LinkFlags & 1) == 0) return current;
                if (current.LinkPrevious >= catalog.Entries.Count)
                    throw new InvalidDataException("An InstallShield cabinet link references an invalid previous entry.");
                current = catalog.Entries[checked((int)current.LinkPrevious)];
            }
        }

        private static Catalog ReadCatalog(string headerPath)
        {
            if (string.IsNullOrWhiteSpace(headerPath)) throw new ArgumentException("A cabinet header path is required.", "headerPath");
            headerPath = Path.GetFullPath(headerPath);
            if (!File.Exists(headerPath)) throw new FileNotFoundException("The InstallShield cabinet header does not exist.", headerPath);

            // Early media stores the catalog at the beginning of data1.cab,
            // followed by an arbitrarily large payload. Read only the common
            // header and descriptor prefix first, derive the complete catalog
            // range, then materialize that bounded prefix for random access.
            byte[] header;
            CommonHeader common;
            uint fileTableOffset;
            uint fileTableSize;
            uint fileTableSize2;
            uint directoryCount;
            uint fileCount;
            uint fileTableOffset2;
            using (var source = new FileStream(headerPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                if (source.Length < CommonHeaderSize)
                    throw new InvalidDataException("The InstallShield cabinet header is truncated.");
                common = ReadCommonHeader(ReadExactly(source, CommonHeaderSize), 0);
                if (common.DescriptorSize < 0x30)
                    throw new InvalidDataException("The InstallShield cabinet descriptor is too small for its required fields.");

                var descriptorBaseCandidate = (long)common.DescriptorOffset;
                var descriptorEnd = checked(descriptorBaseCandidate + common.DescriptorSize);
                if (descriptorBaseCandidate < CommonHeaderSize || descriptorEnd > source.Length)
                    throw new InvalidDataException("The InstallShield cabinet descriptor is outside the source file.");
                source.Position = descriptorBaseCandidate;
                var descriptorHeader = ReadExactly(source, 0x30);
                var descriptorCursor = 0x0C;
                fileTableOffset = ReadUInt32(descriptorHeader, descriptorCursor); descriptorCursor += 8;
                fileTableSize = ReadUInt32(descriptorHeader, descriptorCursor); descriptorCursor += 4;
                fileTableSize2 = ReadUInt32(descriptorHeader, descriptorCursor); descriptorCursor += 4;
                directoryCount = ReadUInt32(descriptorHeader, descriptorCursor); descriptorCursor += 12;
                fileCount = ReadUInt32(descriptorHeader, descriptorCursor); descriptorCursor += 4;
                fileTableOffset2 = ReadUInt32(descriptorHeader, descriptorCursor);

                var catalogTableEnd = checked(descriptorBaseCandidate + fileTableOffset + fileTableSize);
                var requiredBytes = Math.Max(descriptorEnd, catalogTableEnd);
                if (requiredBytes > source.Length)
                    throw new InvalidDataException("The InstallShield cabinet catalog is truncated.");
                if (requiredBytes > MaximumHeaderBytes || requiredBytes > int.MaxValue)
                    throw new InvalidDataException("The InstallShield cabinet catalog exceeds the 256 MiB limit.");
                source.Position = 0;
                header = ReadExactly(source, checked((int)requiredBytes));
            }
            var major = GetMajorVersion(common.Version);
            // Early InstallShield 5 media uses family-1 version 0. Unshield
            // treats that profile separately from the later version-5
            // descriptor because the earlier record has no trailing MD5.
            if (major != 0 && major < 5)
                throw new NotSupportedException("The focused InstallShield cabinet reader supports the legacy version-0 profile and version 5 or later.");

            var descriptorBase = CheckedRange(header, common.DescriptorOffset, common.DescriptorSize, "cabinet descriptor");
            if (fileTableSize != fileTableSize2) throw new InvalidDataException("InstallShield cabinet file-table sizes do not match.");
            if (directoryCount > MaximumDirectoryCount || fileCount > MaximumFileCount)
                throw new InvalidDataException("InstallShield cabinet catalog counts exceed parser limits.");

            var tableBase = CheckedAdd(descriptorBase, fileTableOffset, header.Length, "file table");
            CheckedRange(header, tableBase, fileTableSize, "file table");
            var tableEnd = checked(tableBase + fileTableSize);
            var offsetCount = checked((int)(directoryCount + fileCount));
            CheckedSubrange(tableBase, checked((long)offsetCount * 4), tableBase, tableEnd, "file offset table");
            var offsets = new uint[offsetCount];
            for (var index = 0; index < offsetCount; index++) offsets[index] = ReadUInt32(header, tableBase + index * 4L);

            var directories = new string[directoryCount];
            for (var index = 0; index < directories.Length; index++)
                directories[index] = ReadCatalogString(header, CheckedAdd(tableBase, offsets[index], tableEnd, "directory name"), tableEnd, major);

            var entries = new List<InstallShieldCabinetEntry>((int)fileCount);
            for (var index = 0; index < (int)fileCount; index++)
            {
                long record;
                ushort flags;
                long expandedSize;
                long compressedSize;
                long dataOffset;
                byte[] md5;
                uint nameOffset;
                ushort directoryIndex;
                uint linkPrevious = 0;
                uint linkNext = 0;
                byte linkFlags = 0;
                ushort volume = 1;

                if (major == 0 || major == 5)
                {
                    // InstallShield 5 stores each descriptor at the file's own
                    // offset-table entry rather than in the v6+ contiguous
                    // descriptor array. Version 0 ends at 0x2A; version 5 adds
                    // a 16-byte MD5 and therefore occupies 0x3A bytes.
                    record = CheckedAdd(tableBase, offsets[checked((int)directoryCount + index)], tableEnd, "legacy file descriptor");
                    CheckedSubrange(record, major == 5 ? 0x3A : 0x2A, tableBase, tableEnd, "legacy file descriptor");
                    nameOffset = ReadUInt32(header, record);
                    directoryIndex = ReadUInt16(header, record + 4);
                    flags = ReadUInt16(header, record + 8);
                    expandedSize = ReadUInt32(header, record + 10);
                    compressedSize = ReadUInt32(header, record + 14);
                    dataOffset = ReadUInt32(header, record + 38);
                    md5 = major == 5 ? new byte[16] : Array.Empty<byte>();
                    if (major == 5)
                        Buffer.BlockCopy(header, checked((int)(record + 42)), md5, 0, md5.Length);
                }
                else
                {
                    var descriptorTable = CheckedAdd(tableBase, fileTableOffset2, tableEnd, "file descriptor table");
                    CheckedSubrange(descriptorTable, checked((long)fileCount * ModernFileDescriptorSize), tableBase, tableEnd, "file descriptor table");
                    record = descriptorTable + index * (long)ModernFileDescriptorSize;
                    flags = ReadUInt16(header, record);
                    expandedSize = ToInt64(ReadUInt64(header, record + 2), "expanded size");
                    compressedSize = ToInt64(ReadUInt64(header, record + 10), "compressed size");
                    dataOffset = ToInt64(ReadUInt64(header, record + 18), "data offset");
                    md5 = new byte[16];
                    Buffer.BlockCopy(header, checked((int)(record + 26)), md5, 0, md5.Length);
                    nameOffset = ReadUInt32(header, record + 58);
                    directoryIndex = ReadUInt16(header, record + 62);
                    linkPrevious = ReadUInt32(header, record + 76);
                    linkNext = ReadUInt32(header, record + 80);
                    linkFlags = header[checked((int)(record + 84))];
                    volume = ReadUInt16(header, record + 85);
                }
                // Legacy catalogs retain unused descriptor slots whose fields
                // are deliberately nonsensical and whose invalid bit is set.
                // Match the runtime/Unshield ordering: validate and resolve
                // strings only for entries that can own payload data.
                var isValid = (flags & 8) == 0 && dataOffset > 0 && nameOffset > 0;
                if (isValid && directoryIndex >= directories.Length)
                    throw new InvalidDataException("An InstallShield cabinet file references an invalid directory.");
                var name = isValid
                    ? ReadCatalogString(header, CheckedAdd(tableBase, nameOffset, tableEnd, "file name"), tableEnd, major)
                    : string.Empty;
                var directory = isValid ? directories[directoryIndex] : string.Empty;
                entries.Add(new InstallShieldCabinetEntry(index, name, directory, flags, expandedSize, compressedSize, dataOffset, md5, volume, linkPrevious, linkNext, linkFlags));
            }

            return new Catalog(headerPath, common.Version, major, header, descriptorBase, common.DescriptorSize, entries);
        }

        private static InstallShieldMediaMetadata ReadMediaMetadata(Catalog catalog)
        {
            var profile = catalog.MajorVersion == 0
                ? "LegacyDescriptorWithoutDigest"
                : catalog.MajorVersion == 5 ? "LegacyDescriptor"
                : catalog.MajorVersion >= 17 ? "UnicodeCatalog" : "AnsiCatalog";
            var metadata = new InstallShieldMediaMetadata(catalog.HeaderPath, catalog.RawVersion, catalog.MajorVersion, profile);

            // The hash-table offsets interpreted below belong to the v6+
            // descriptor family. InstallShield 5 uses the legacy descriptor
            // and volume records but does not expose these v6+ metadata graphs.
            if (catalog.MajorVersion == 0 || catalog.MajorVersion == 5) return metadata;

            // Parse file-transfer topology before registry and shell records so
            // component-associated effects can report their eligible features
            // and setup types without claiming that a feature was selected.
            try { ReadTransferTopology(catalog, metadata); }
            catch (Exception exception) when (exception is InvalidDataException || exception is OverflowException)
            {
                metadata.Warnings.Add("InstallShield media transfer topology is malformed or unsupported: " + exception.Message);
            }
            try { ReadSetupTypes(catalog, metadata); }
            catch (Exception exception) when (exception is InvalidDataException || exception is OverflowException)
            {
                metadata.Warnings.Add("InstallShield media setup-type records are malformed or unsupported: " + exception.Message);
            }

            // Unicode media can carry the same registry and shell graphs, as
            // proven by major-22 and major-30/32 fixtures. Older generations
            // may reuse these descriptor offsets for another purpose. Parse
            // each graph transactionally: failed probes publish no partial
            // records, and only fully grounded modern profiles report damage.
            if (catalog.MajorVersion >= 17)
            {
                var reportOptionalGraphFailure = catalog.MajorVersion >= 30;
                TryReadRegistryMetadata(catalog, metadata, reportOptionalGraphFailure);
                TryReadShellMetadata(catalog, metadata, reportOptionalGraphFailure);
            }
            return metadata;
        }

        private static void TryReadRegistryMetadata(Catalog catalog, InstallShieldMediaMetadata metadata, bool reportFailure)
        {
            // The decoder resolves selections through topology already stored
            // on metadata, so retain the shared object and roll back only the
            // collections owned by this optional graph when validation fails.
            var setCount = metadata.RegistrySets.Count;
            var writeCount = metadata.RegistryWrites.Count;
            var warningCount = metadata.Warnings.Count;
            try { ReadRegistryMetadata(catalog, metadata); }
            catch (Exception exception) when (exception is InvalidDataException || exception is OverflowException)
            {
                RemoveTail(metadata.RegistrySets, setCount);
                RemoveTail(metadata.RegistryWrites, writeCount);
                RemoveTail(metadata.Warnings, warningCount);
                if (reportFailure)
                    metadata.Warnings.Add("InstallShield media registry records are malformed or unsupported: " + exception.Message);
            }
        }

        private static void TryReadShellMetadata(Catalog catalog, InstallShieldMediaMetadata metadata, bool reportFailure)
        {
            var folderCount = metadata.ShellFolders.Count;
            var shortcutCount = metadata.Shortcuts.Count;
            var warningCount = metadata.Warnings.Count;
            try { ReadShellMetadata(catalog, metadata); }
            catch (Exception exception) when (exception is InvalidDataException || exception is OverflowException)
            {
                RemoveTail(metadata.ShellFolders, folderCount);
                RemoveTail(metadata.Shortcuts, shortcutCount);
                RemoveTail(metadata.Warnings, warningCount);
                if (reportFailure)
                    metadata.Warnings.Add("InstallShield media shell-object records are malformed or unsupported: " + exception.Message);
            }
        }

        private static void RemoveTail<T>(List<T> items, int retainedCount)
        {
            if (items.Count > retainedCount)
                items.RemoveRange(retainedCount, items.Count - retainedCount);
        }

        private static void ReadTransferTopology(Catalog catalog, InstallShieldMediaMetadata metadata)
        {
            // Unshield documents the two 71-bucket hash tables at descriptor
            // offsets 0x3E and 0x15A. Each bucket is a bounded singly linked
            // list of 12-byte OffsetList records.
            if (catalog.DescriptorSize < 0x276) return;
            foreach (var descriptorRelative in ReadOffsetListDescriptors(catalog, 0x3E, "file-group"))
            {
                var record = GetDescriptorAddress(catalog, descriptorRelative, 30, "file-group descriptor");
                var name = ReadMediaString(catalog, ReadUInt32(catalog.Header, record), "file-group name");
                var firstFile = ReadInt32(catalog.Header, record + 0x16);
                var lastFile = ReadInt32(catalog.Header, record + 0x1A);
                if (firstFile < -1 || lastFile < -1 || firstFile >= catalog.Entries.Count || lastFile >= catalog.Entries.Count)
                    throw new InvalidDataException("A file-group range references a file outside the cabinet catalog.");
                if ((firstFile == -1) != (lastFile == -1) || (firstFile >= 0 && firstFile > lastFile))
                    throw new InvalidDataException("A file-group range is inconsistent.");
                metadata.FileGroups.Add(new InstallShieldCabinetFileGroup(name, firstFile, lastFile));
            }

            foreach (var descriptorRelative in ReadOffsetListDescriptors(catalog, 0x15A, "component"))
            {
                // Version 6 and later use an unaligned file-group count at
                // descriptor+0x6F and a uint32 table pointer at +0x71.
                var record = GetDescriptorAddress(catalog, descriptorRelative, 0x75, "component descriptor");
                var name = ReadMediaString(catalog, ReadUInt32(catalog.Header, record), "component name");
                var groupCount = ReadUInt16(catalog.Header, record + 0x6F);
                if (groupCount > 71)
                    throw new InvalidDataException("A component file-group count exceeds the format limit.");
                var groups = new List<string>(groupCount);
                if (groupCount > 0)
                {
                    var table = GetDescriptorAddress(
                        catalog,
                        ReadUInt32(catalog.Header, record + 0x71),
                        checked((long)groupCount * 4),
                        "component file-group table");
                    for (var index = 0; index < groupCount; index++)
                    {
                        var group = ReadMediaString(
                            catalog,
                            ReadUInt32(catalog.Header, table + index * 4L),
                            "component file-group name");
                        if (!string.IsNullOrWhiteSpace(group)) groups.Add(group);
                    }
                }
                metadata.Components.Add(new InstallShieldCabinetComponent(name, groups));
            }
        }

        private static List<uint> ReadOffsetListDescriptors(Catalog catalog, long bucketOffset, string name)
        {
            const int bucketCount = 71;
            var bucketTable = catalog.DescriptorBase + bucketOffset;
            CheckedSubrange(bucketTable, bucketCount * 4L, catalog.DescriptorBase, catalog.DescriptorBase + catalog.DescriptorSize, name + " bucket table");
            var descriptors = new List<uint>();
            var visited = new HashSet<uint>();
            for (var bucket = 0; bucket < bucketCount; bucket++)
            {
                var next = ReadUInt32(catalog.Header, bucketTable + bucket * 4L);
                while (next != 0)
                {
                    if (!visited.Add(next))
                        throw new InvalidDataException("The " + name + " offset list contains a cycle or duplicate record.");
                    if (visited.Count > MaximumTopologyRecordCount)
                        throw new InvalidDataException("The " + name + " offset-list count exceeds the parser limit.");
                    var node = GetDescriptorAddress(catalog, next, 12, name + " offset-list record");
                    // The list's name pointer is redundant with the descriptor,
                    // but validating it catches malformed nodes before traversal.
                    ReadMediaString(catalog, ReadUInt32(catalog.Header, node), name + " offset-list name");
                    descriptors.Add(ReadUInt32(catalog.Header, node + 4));
                    next = ReadUInt32(catalog.Header, node + 8);
                }
            }
            return descriptors;
        }

        private static void ReadSetupTypes(Catalog catalog, InstallShieldMediaMetadata metadata)
        {
            // The setup-type directory is packed immediately before the
            // file-group buckets. It contains one contiguous LCID array followed
            // by one shared setup-type table; the table is not repeated for each
            // language. A single-language directory happens to look like the
            // older assumed 12-byte locale record, which hid this distinction
            // until multi-language version-31 media was observed.
            if (catalog.DescriptorSize < 0x36) return;
            var localeCount = ReadUInt16(catalog.Header, catalog.DescriptorBase + 0x30);
            if (localeCount > MaximumSetupTypeLocaleCount)
                throw new InvalidDataException("The setup-type locale count exceeds the parser limit.");
            if (localeCount == 0) return;
            var directory = GetDescriptorAddress(
                catalog,
                ReadUInt32(catalog.Header, catalog.DescriptorBase + 0x32),
                checked((long)localeCount * 4 + 8),
                "setup-type directory");
            var languages = new List<uint>(localeCount);
            for (var localeIndex = 0; localeIndex < localeCount; localeIndex++)
                languages.Add(ReadUInt32(catalog.Header, directory + localeIndex * 4L));

            var setupTypeDirectory = directory + localeCount * 4L;
            var setupTypeCount = ReadUInt32(catalog.Header, setupTypeDirectory);
            if (setupTypeCount > MaximumSetupTypeCount)
                throw new InvalidDataException("The setup-type count exceeds the parser limit.");
            if (setupTypeCount == 0) return;
            var setupTypeTable = GetDescriptorAddress(
                catalog,
                ReadUInt32(catalog.Header, setupTypeDirectory + 4),
                checked((long)setupTypeCount * 4),
                "setup-type offset table");
            for (var setupTypeIndex = 0; setupTypeIndex < setupTypeCount; setupTypeIndex++)
            {
                var setupType = GetDescriptorAddress(
                    catalog,
                    ReadUInt32(catalog.Header, setupTypeTable + setupTypeIndex * 4L),
                    20,
                    "setup-type record");
                var featureCount = ReadUInt32(catalog.Header, setupType + 12);
                if (featureCount > MaximumSetupTypeFeatureCount)
                    throw new InvalidDataException("A setup-type feature count exceeds the parser limit.");
                var features = new List<string>((int)featureCount);
                if (featureCount > 0)
                {
                    var featureTable = GetDescriptorAddress(
                        catalog,
                        ReadUInt32(catalog.Header, setupType + 16),
                        checked((long)featureCount * 4),
                        "setup-type feature table");
                    for (var featureIndex = 0; featureIndex < featureCount; featureIndex++)
                    {
                        var feature = ReadMediaString(
                            catalog,
                            ReadUInt32(catalog.Header, featureTable + featureIndex * 4L),
                            "setup-type feature path");
                        if (!string.IsNullOrWhiteSpace(feature)) features.Add(feature);
                    }
                }

                var name = ReadMediaString(catalog, ReadUInt32(catalog.Header, setupType), "setup-type name");
                var description = ReadMediaString(catalog, ReadUInt32(catalog.Header, setupType + 4), "setup-type description");
                var displayName = ReadMediaString(catalog, ReadUInt32(catalog.Header, setupType + 8), "setup-type display name");
                foreach (var language in languages)
                {
                    metadata.SetupTypes.Add(new InstallShieldMediaSetupType(
                        language,
                        checked((int)setupTypeIndex),
                        name,
                        description,
                        displayName,
                        features));
                }
            }
        }

        private static void ReadRegistryMetadata(Catalog catalog, InstallShieldMediaMetadata metadata)
        {
            // Validated Unicode major-22, major-30, and major-32 media store
            // the registry-directory pointer at descriptor-relative 0x282.
            if (catalog.DescriptorSize < 0x286) return;
            var directoryRelative = ReadUInt32(catalog.Header, catalog.DescriptorBase + 0x282);
            if (directoryRelative == 0) return;
            var directory = GetDescriptorAddress(catalog, directoryRelative, 6, "registry directory");
            var setCount = ReadUInt16(catalog.Header, directory);
            if (setCount > MaximumRegistrySetCount)
                throw new InvalidDataException("The registry-set count exceeds the parser limit.");
            if (setCount == 0) return;
            var setTable = GetDescriptorAddress(
                catalog,
                ReadUInt32(catalog.Header, directory + 2),
                checked((long)setCount * 4),
                "registry-set offset table");

            for (var setIndex = 0; setIndex < setCount; setIndex++)
            {
                var setRecord = GetDescriptorAddress(
                    catalog,
                    ReadUInt32(catalog.Header, setTable + setIndex * 4L),
                    40,
                    "registry-set record");
                var qualifiedName = ReadMediaString(catalog, ReadUInt32(catalog.Header, setRecord), "registry-set name");
                var name = GetUnqualifiedRegistrySetName(qualifiedName);
                var isDefault = name.Equals("<Default>", StringComparison.OrdinalIgnoreCase);
                var componentCount = ReadUInt16(catalog.Header, setRecord + 4);
                if (componentCount > MaximumRegistryComponentCount)
                    throw new InvalidDataException("A registry-set component count exceeds the parser limit.");
                var components = new List<string>(componentCount);
                if (componentCount > 0)
                {
                    var componentTable = GetDescriptorAddress(
                        catalog,
                        ReadUInt32(catalog.Header, setRecord + 6),
                        checked((long)componentCount * 4),
                        "registry-set component offset table");
                    for (var componentIndex = 0; componentIndex < componentCount; componentIndex++)
                    {
                        var component = ReadMediaString(
                            catalog,
                            ReadUInt32(catalog.Header, componentTable + componentIndex * 4L),
                            "registry-set component name");
                        if (!string.IsNullOrWhiteSpace(component)) components.Add(component);
                    }
                }

                metadata.RegistrySets.Add(new InstallShieldMediaRegistrySet(qualifiedName, name, isDefault, components));
                var roots = new[] { "HKCR", "HKCU", "HKLM", "HKU", "SHCTX" };
                for (var rootIndex = 0; rootIndex < roots.Length; rootIndex++)
                {
                    var rootSlot = setRecord + 10 + rootIndex * 6L;
                    var keyCount = ReadUInt16(catalog.Header, rootSlot);
                    if (keyCount > MaximumRegistryKeyCount)
                        throw new InvalidDataException("A registry-set key count exceeds the parser limit.");
                    if (keyCount == 0) continue;
                    var keyTable = GetDescriptorAddress(
                        catalog,
                        ReadUInt32(catalog.Header, rootSlot + 2),
                        checked((long)keyCount * 4),
                        "registry-key offset table");
                    for (var keyIndex = 0; keyIndex < keyCount; keyIndex++)
                    {
                        var keyRecord = GetDescriptorAddress(
                            catalog,
                            ReadUInt32(catalog.Header, keyTable + keyIndex * 4L),
                            14,
                            "registry-key record");
                        var key = ReadMediaString(catalog, ReadUInt32(catalog.Header, keyRecord), "registry key");
                        // The high bit is a key-control flag in generated media,
                        // not part of the value count. Empty flagged keys occur
                        // in ordinary projects and must not turn into a 32768-item
                        // table read. The lower 15 bits remain the bounded count.
                        var valueCount = ReadUInt16(catalog.Header, keyRecord + 8) & 0x7FFF;
                        if (valueCount > MaximumRegistryValueCount)
                            throw new InvalidDataException("A registry-key value count exceeds the parser limit.");
                        if (valueCount == 0) continue;
                        var valueTable = GetDescriptorAddress(
                            catalog,
                            ReadUInt32(catalog.Header, keyRecord + 10),
                            checked((long)valueCount * 4),
                            "registry-value offset table");
                        for (var valueIndex = 0; valueIndex < valueCount; valueIndex++)
                        {
                            var valueRecord = GetDescriptorAddress(
                                catalog,
                                ReadUInt32(catalog.Header, valueTable + valueIndex * 4L),
                                10,
                                "registry-value record");
                            var valueName = ReadMediaString(catalog, ReadUInt32(catalog.Header, valueRecord), "registry value name");
                            var typeCode = ReadUInt16(catalog.Header, valueRecord + 4);
                            var dataRelative = ReadUInt32(catalog.Header, valueRecord + 6);
                            object data;
                            string type;
                            var complete = TryReadRegistryData(catalog, typeCode, dataRelative, out type, out data);
                            if (!complete)
                            {
                                metadata.Warnings.Add(
                                    "InstallShield registry value '" + valueName + "' in set '" + name +
                                    "' uses unsupported REGDB type " + typeCode + "; its data is left unresolved.");
                            }
                            var selection = ResolveMediaSelection(metadata, components);
                            metadata.RegistryWrites.Add(new InstallShieldMediaRegistryWrite(
                                roots[rootIndex], key, valueName, type, typeCode, data,
                                name, qualifiedName, isDefault, components,
                                selection.Features, selection.SetupTypes, complete));
                        }
                    }
                }
            }
        }

        private static bool TryReadRegistryData(
            Catalog catalog,
            ushort typeCode,
            uint dataRelative,
            out string type,
            out object data)
        {
            // ISRTDefs.h defines REGDB_STRING=1, REGDB_STRING_EXPAND=2,
            // REGDB_BINARY=3, REGDB_NUMBER=4, and REGDB_STRING_MULTI=7.
            // Official-builder differential media proves that the latter
            // three store bounded textual encodings: hexadecimal bytes,
            // invariant decimal text, and a hexadecimal MULTI_SZ payload.
            switch (typeCode)
            {
                case 1:
                    type = "REG_SZ";
                    data = ReadMediaString(catalog, dataRelative, "registry string data");
                    return true;
                case 2:
                    type = "REG_EXPAND_SZ";
                    data = ReadMediaString(catalog, dataRelative, "registry expandable-string data");
                    return true;
                case 4:
                    type = "REG_DWORD";
                    var numberText = ReadMediaString(catalog, dataRelative, "registry DWORD data");
                    uint unsignedNumber;
                    int signedNumber;
                    if (uint.TryParse(numberText, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out unsignedNumber))
                    {
                        data = unsignedNumber;
                        return true;
                    }
                    if (int.TryParse(numberText, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out signedNumber))
                    {
                        data = unchecked((uint)signedNumber);
                        return true;
                    }
                    data = null;
                    return false;
                case 7:
                    type = "REG_MULTI_SZ";
                    byte[] multiBytes;
                    if (!TryDecodeRegistryHex(catalog, dataRelative, out multiBytes))
                    {
                        data = null;
                        return false;
                    }
                    data = DecodeRegistryMultiString(catalog, multiBytes);
                    return true;
                case 3:
                    type = "REG_BINARY";
                    byte[] binaryBytes;
                    if (!TryDecodeRegistryHex(catalog, dataRelative, out binaryBytes))
                    {
                        data = null;
                        return false;
                    }
                    data = binaryBytes;
                    return true;
                default:
                    type = "REGDB_" + typeCode;
                    data = null;
                    return false;
            }
        }

        private static void ReadShellMetadata(Catalog catalog, InstallShieldMediaMetadata metadata)
        {
            if (catalog.DescriptorSize < 0x282) return;
            var mediaDirectoryRelative = ReadUInt32(catalog.Header, catalog.DescriptorBase + 0x27E);
            if (mediaDirectoryRelative == 0) return;
            var mediaDirectory = GetDescriptorAddress(catalog, mediaDirectoryRelative, 12, "media-table directory");
            if (mediaDirectory < catalog.DescriptorBase + 2)
                throw new InvalidDataException("The media-table directory has no count field.");
            var mediaDirectoryCount = ReadUInt16(catalog.Header, mediaDirectory - 2);
            if (mediaDirectoryCount > MaximumMediaDirectoryCount)
                throw new InvalidDataException("The media-table directory count exceeds the parser limit.");
            if (mediaDirectoryCount <= 2) return;
            var shellGroupRelative = ReadUInt32(catalog.Header, mediaDirectory + 8);
            if (shellGroupRelative == 0) return;
            var shellGroup = GetDescriptorAddress(catalog, shellGroupRelative, 14, "shell-folder group");
            var folderCount = ReadUInt16(catalog.Header, shellGroup + 8);
            if (folderCount > MaximumShellFolderCount)
                throw new InvalidDataException("The shell-folder count exceeds the parser limit.");
            if (folderCount == 0) return;
            var folderTable = GetDescriptorAddress(
                catalog,
                ReadUInt32(catalog.Header, shellGroup + 10),
                checked((long)folderCount * 4),
                "shell-folder offset table");

            for (var folderIndex = 0; folderIndex < folderCount; folderIndex++)
            {
                var folderRecord = GetDescriptorAddress(
                    catalog,
                    ReadUInt32(catalog.Header, folderTable + folderIndex * 4L),
                    20,
                    "shell-folder record");
                var installShieldName = ReadMediaString(catalog, ReadUInt32(catalog.Header, folderRecord), "shell-folder InstallShield name");
                var directoryName = ReadMediaString(catalog, ReadUInt32(catalog.Header, folderRecord + 4), "shell-folder directory name");
                var shortcutCount = ReadUInt16(catalog.Header, folderRecord + 14);
                if (shortcutCount > MaximumShortcutCount)
                    throw new InvalidDataException("A shell-folder shortcut count exceeds the parser limit.");
                var shortcuts = new List<InstallShieldMediaShortcut>(shortcutCount);
                if (shortcutCount > 0)
                {
                    var shortcutTable = GetDescriptorAddress(
                        catalog,
                        ReadUInt32(catalog.Header, folderRecord + 16),
                        checked((long)shortcutCount * 4),
                        "shortcut offset table");
                    for (var shortcutIndex = 0; shortcutIndex < shortcutCount; shortcutIndex++)
                    {
                        var shortcutRecord = GetDescriptorAddress(
                            catalog,
                            ReadUInt32(catalog.Header, shortcutTable + shortcutIndex * 4L),
                            54,
                            "shortcut record");
                        var component = ReadMediaString(catalog, ReadUInt32(catalog.Header, shortcutRecord + 50), "shortcut component");
                        var encodedProperties = ReadMediaString(catalog, ReadUInt32(catalog.Header, shortcutRecord + 23), "shortcut generated properties");
                        var selection = ResolveMediaSelection(metadata, new List<string> { component });
                        var shortcut = new InstallShieldMediaShortcut(
                            ReadMediaString(catalog, ReadUInt32(catalog.Header, shortcutRecord + 4), "shortcut name"),
                            ReadMediaString(catalog, ReadUInt32(catalog.Header, shortcutRecord), "shortcut InstallShield name"),
                            ReadMediaString(catalog, ReadUInt32(catalog.Header, shortcutRecord + 10), "shortcut target"),
                            ReadMediaString(catalog, ReadUInt32(catalog.Header, shortcutRecord + 15), "shortcut arguments"),
                            ReadMediaString(catalog, ReadUInt32(catalog.Header, shortcutRecord + 19), "shortcut working directory"),
                            component,
                            installShieldName,
                            encodedProperties,
                            ParseShortcutHotKey(encodedProperties),
                            ReadUInt32(catalog.Header, shortcutRecord + 27),
                            selection.Features,
                            selection.SetupTypes);
                        shortcuts.Add(shortcut);
                        metadata.Shortcuts.Add(shortcut);
                    }
                }
                metadata.ShellFolders.Add(new InstallShieldMediaShellFolder(installShieldName, directoryName, shortcuts));
            }
        }

        private static string GetUnqualifiedRegistrySetName(string qualifiedName)
        {
            if (string.IsNullOrEmpty(qualifiedName)) return string.Empty;
            var separator = qualifiedName.IndexOf(':');
            if (separator <= 0) return qualifiedName;
            Guid ignored;
            return Guid.TryParse(qualifiedName.Substring(0, separator).Trim('{', '}'), out ignored)
                ? qualifiedName.Substring(separator + 1)
                : qualifiedName;
        }

        private static SelectionEvidence ResolveMediaSelection(InstallShieldMediaMetadata metadata, List<string> fileGroups)
        {
            var features = new List<string>();
            var setupTypes = new List<string>();
            foreach (var fileGroup in fileGroups)
            {
                if (string.IsNullOrWhiteSpace(fileGroup)) continue;
                foreach (var component in metadata.Components)
                {
                    if (!ContainsOrdinalIgnoreCase(component.FileGroups, fileGroup) || ContainsOrdinalIgnoreCase(features, component.Name)) continue;
                    features.Add(component.Name);
                }
            }
            foreach (var setupType in metadata.SetupTypes)
            {
                foreach (var feature in features)
                {
                    if (!ContainsOrdinalIgnoreCase(setupType.Features, feature)) continue;
                    if (!ContainsOrdinalIgnoreCase(setupTypes, setupType.Name)) setupTypes.Add(setupType.Name);
                    break;
                }
            }
            return new SelectionEvidence(features, setupTypes);
        }

        private static bool ContainsOrdinalIgnoreCase(List<string> values, string candidate)
        {
            foreach (var value in values)
                if (string.Equals(value, candidate, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static int? ParseShortcutHotKey(string properties)
        {
            const string prefix = "HotKeyCode=";
            if (string.IsNullOrWhiteSpace(properties) || !properties.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;
            int value;
            return int.TryParse(properties.Substring(prefix.Length), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out value)
                ? (int?)value
                : null;
        }

        private static string ReadMediaString(Catalog catalog, uint relativeOffset, string name)
        {
            if (relativeOffset == 0) return string.Empty;
            var offset = GetDescriptorAddress(catalog, relativeOffset, catalog.MajorVersion >= 17 ? 2 : 1, name);
            var descriptorEnd = checked(catalog.DescriptorBase + catalog.DescriptorSize);
            var maximumEnd = Math.Min(descriptorEnd, offset + 65536);
            if (catalog.MajorVersion >= 17)
            {
                var end = offset;
                while (end + 1 < maximumEnd && (catalog.Header[(int)end] != 0 || catalog.Header[(int)end + 1] != 0)) end += 2;
                if (end + 1 >= maximumEnd) throw new InvalidDataException("The InstallShield " + name + " is unterminated or exceeds 64 KiB.");
                return Encoding.Unicode.GetString(catalog.Header, (int)offset, (int)(end - offset));
            }
            else
            {
                var end = offset;
                while (end < maximumEnd && catalog.Header[(int)end] != 0) end++;
                if (end >= maximumEnd) throw new InvalidDataException("The InstallShield " + name + " is unterminated or exceeds 64 KiB.");
                return Encoding.Latin1.GetString(catalog.Header, (int)offset, (int)(end - offset));
            }
        }

        private static bool TryDecodeRegistryHex(Catalog catalog, uint relativeOffset, out byte[] bytes)
        {
            var text = ReadMediaString(catalog, relativeOffset, "registry hexadecimal data");
            if ((text.Length & 1) != 0 || text.Length / 2 > MaximumEncodedRegistryBytes)
            {
                bytes = null;
                return false;
            }
            bytes = new byte[text.Length / 2];
            for (var index = 0; index < bytes.Length; index++)
            {
                var high = HexValue(text[index * 2]);
                var low = HexValue(text[index * 2 + 1]);
                if (high < 0 || low < 0)
                {
                    bytes = null;
                    return false;
                }
                bytes[index] = (byte)(high << 4 | low);
            }
            return true;
        }

        private static int HexValue(char value)
        {
            if (value >= '0' && value <= '9') return value - '0';
            if (value >= 'A' && value <= 'F') return value - 'A' + 10;
            if (value >= 'a' && value <= 'f') return value - 'a' + 10;
            return -1;
        }

        private static string[] DecodeRegistryMultiString(Catalog catalog, byte[] bytes)
        {
            if (bytes.Length > MaximumEncodedRegistryBytes)
                throw new InvalidDataException("An InstallShield registry multi-string exceeds the parser limit.");
            if (catalog.MajorVersion >= 17 && (bytes.Length & 1) != 0)
                throw new InvalidDataException("An InstallShield Unicode registry multi-string has an odd byte length.");
            var text = catalog.MajorVersion >= 17
                ? Encoding.BigEndianUnicode.GetString(bytes)
                : Encoding.Latin1.GetString(bytes);
            var result = new List<string>();
            foreach (var value in text.Split('\0'))
                if (value.Length != 0) result.Add(value);
            return result.ToArray();
        }

        private static long GetDescriptorAddress(Catalog catalog, uint relativeOffset, long length, string name)
        {
            var descriptorEnd = checked(catalog.DescriptorBase + catalog.DescriptorSize);
            var offset = checked(catalog.DescriptorBase + relativeOffset);
            return CheckedSubrange(offset, length, catalog.DescriptorBase, descriptorEnd, name);
        }

        private static void WriteEntry(Catalog catalog, InstallShieldCabinetEntry entry, string destination, long maximumExpandedBytes)
        {
            var storedSize = entry.IsCompressed ? entry.CompressedSize : entry.ExpandedSize;
            using (var stream = OpenEntryStream(catalog, entry, storedSize))
            {
                if (entry.ExpandedSize > maximumExpandedBytes)
                    throw new InvalidDataException("An InstallShield cabinet output exceeds the configured limit.");

                try
                {
                    using (var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None))
                    using (var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5))
                    {
                        var written = entry.IsCompressed
                            ? (catalog.MajorVersion <= 5
                                ? InflateLegacyChunks(stream, storedSize, output, md5, entry.IsObfuscated, entry.ExpandedSize)
                                : InflateChunks(stream, storedSize, output, md5, entry.IsObfuscated, entry.ExpandedSize))
                            : CopyStoredRange(stream, storedSize, output, md5, entry.IsObfuscated, entry.ExpandedSize);
                        if (written != entry.ExpandedSize)
                            throw new InvalidDataException("InstallShield cabinet expanded size does not match its descriptor.");
                        var actual = md5.GetHashAndReset();
                        if (entry.Md5.Length == 16 && !FixedTimeEquals(actual, entry.Md5))
                            throw new InvalidDataException("InstallShield cabinet MD5 verification failed.");
                    }
                }
                catch
                {
                    // A failed range, decompression, or digest check must not
                    // leave a plausible-looking partial payload behind.
                    try { File.Delete(destination); } catch { }
                    throw;
                }
            }
        }

        private static Stream OpenEntryStream(Catalog catalog, InstallShieldCabinetEntry entry, long storedSize)
        {
            if (storedSize < 0) throw new InvalidDataException("An InstallShield cabinet stored size is negative.");
            if (entry.IsSplit || catalog.MajorVersion <= 5 && IsLegacyEntrySplit(catalog, entry, storedSize))
                return new InstallShieldSpannedStream(GetSpannedSegments(catalog, entry, storedSize));

            var volumePath = GetVolumePath(catalog.HeaderPath, entry.Volume);
            var stream = new FileStream(volumePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            try
            {
                ValidateVolume(stream, catalog.MajorVersion);
                var minimumDataOffset = CommonHeaderSize + (catalog.MajorVersion <= 5 ? 40 : 64);
                if (entry.DataOffset < minimumDataOffset || entry.DataOffset > stream.Length)
                    throw new InvalidDataException("An InstallShield cabinet file offset is outside its volume.");
                if (storedSize > stream.Length - entry.DataOffset)
                    throw new InvalidDataException("An InstallShield cabinet file range is truncated.");
                stream.Position = entry.DataOffset;
                return stream;
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }

        private static List<VolumeSegment> GetSpannedSegments(Catalog catalog, InstallShieldCabinetEntry entry, long storedSize)
        {
            var segments = new List<VolumeSegment>();
            var remaining = storedSize;
            var volume = (int)entry.Volume;
            while (remaining > 0)
            {
                if (segments.Count >= MaximumSpannedVolumeCount)
                    throw new InvalidDataException("An InstallShield cabinet entry spans too many volumes.");
                if (volume < 0 || volume > ushort.MaxValue)
                    throw new InvalidDataException("An InstallShield cabinet volume number is outside the supported range.");

                var volumePath = GetVolumePath(catalog.HeaderPath, checked((ushort)volume));
                using (var stream = new FileStream(volumePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var header = ValidateVolume(stream, catalog.MajorVersion);
                    var firstFileIndex = ReadUInt32(header, CommonHeaderSize + 8);
                    var lastFileIndex = ReadUInt32(header, CommonHeaderSize + 12);
                    long dataOffset;
                    long segmentStoredSize;

                    // Match InstallShield/Unshield ordering: when a descriptor
                    // is both the first and last file in a volume, the trailing
                    // segment fields are authoritative.
                    var legacyLastOffset = catalog.MajorVersion <= 5 ? ReadUInt32(header, CommonHeaderSize + 28) : 1U;
                    if ((uint)entry.Index == lastFileIndex && legacyLastOffset != 0)
                    {
                        if (catalog.MajorVersion <= 5)
                        {
                            dataOffset = ReadUInt32(header, CommonHeaderSize + 28);
                            segmentStoredSize = ReadUInt32(header, CommonHeaderSize + (entry.IsCompressed ? 36 : 32));
                        }
                        else
                        {
                            dataOffset = ToInt64(ReadUInt64(header, CommonHeaderSize + 40), "split last-file offset");
                            segmentStoredSize = ToInt64(ReadUInt64(
                                header,
                                CommonHeaderSize + (entry.IsCompressed ? 56 : 48)),
                                "split last-file size");
                        }
                    }
                    else if ((uint)entry.Index == firstFileIndex)
                    {
                        if (catalog.MajorVersion <= 5)
                        {
                            dataOffset = ReadUInt32(header, CommonHeaderSize + 16);
                            segmentStoredSize = ReadUInt32(header, CommonHeaderSize + (entry.IsCompressed ? 24 : 20));
                        }
                        else
                        {
                            dataOffset = ToInt64(ReadUInt64(header, CommonHeaderSize + 16), "split first-file offset");
                            segmentStoredSize = ToInt64(ReadUInt64(
                                header,
                                CommonHeaderSize + (entry.IsCompressed ? 32 : 24)),
                                "split first-file size");
                        }
                    }
                    else
                    {
                        throw new InvalidDataException("A split InstallShield cabinet volume does not reference the selected entry.");
                    }

                    var minimumDataOffset = CommonHeaderSize + (catalog.MajorVersion <= 5 ? 40 : 64);
                    if (dataOffset < minimumDataOffset || segmentStoredSize <= 0)
                        throw new InvalidDataException("A split InstallShield cabinet segment has an invalid range.");
                    if (segmentStoredSize > remaining)
                        throw new InvalidDataException("Split InstallShield cabinet segment sizes exceed the file descriptor.");
                    if (dataOffset > stream.Length || segmentStoredSize > stream.Length - dataOffset)
                        throw new InvalidDataException("A split InstallShield cabinet segment is truncated.");

                    segments.Add(new VolumeSegment(volumePath, dataOffset, segmentStoredSize));
                    remaining -= segmentStoredSize;
                }
                volume++;
            }
            return segments;
        }

        private static byte[] ValidateVolume(Stream stream, int expectedMajorVersion)
        {
            stream.Position = 0;
            var header = ReadExactly(stream, CommonHeaderSize + (expectedMajorVersion <= 5 ? 40 : 64));
            var common = ReadCommonHeader(header, 0);
            if (GetMajorVersion(common.Version) != expectedMajorVersion)
                throw new InvalidDataException("An InstallShield cabinet volume version does not match its catalog.");
            return header;
        }

        private static bool IsLegacyEntrySplit(Catalog catalog, InstallShieldCabinetEntry entry, long storedSize)
        {
            var volumePath = GetVolumePath(catalog.HeaderPath, entry.Volume);
            using (var stream = new FileStream(volumePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                var header = ValidateVolume(stream, catalog.MajorVersion);
                var firstFileIndex = ReadUInt32(header, CommonHeaderSize + 8);
                var lastFileIndex = ReadUInt32(header, CommonHeaderSize + 12);
                var firstStored = ReadUInt32(header, CommonHeaderSize + (entry.IsCompressed ? 24 : 20));
                var lastStored = ReadUInt32(header, CommonHeaderSize + (entry.IsCompressed ? 36 : 32));
                return (uint)entry.Index == firstFileIndex && firstStored != storedSize ||
                    (uint)entry.Index == lastFileIndex && lastStored != storedSize;
            }
        }

        private static long CopyStoredRange(
            Stream input,
            long storedSize,
            Stream output,
            IncrementalHash hash,
            bool obfuscated,
            long expectedSize)
        {
            var buffer = new byte[65536];
            long consumed = 0;
            long written = 0;
            while (consumed < storedSize)
            {
                var count = (int)Math.Min(buffer.Length, storedSize - consumed);
                ReadStoredExactly(input, buffer, 0, count, obfuscated, ref consumed);
                if (written + count > expectedSize)
                    throw new InvalidDataException("InstallShield cabinet output exceeds its descriptor.");
                output.Write(buffer, 0, count);
                hash.AppendData(buffer, 0, count);
                written += count;
            }
            return written;
        }

        private static long InflateChunks(
            Stream input,
            long storedSize,
            Stream output,
            IncrementalHash hash,
            bool obfuscated,
            long expectedSize)
        {
            long consumed = 0;
            long written = 0;
            var lengthBytes = new byte[2];
            var outputBuffer = new byte[8192];
            while (consumed < storedSize)
            {
                if (storedSize - consumed < 2)
                    throw new InvalidDataException("An InstallShield Deflate chunk length is truncated.");
                ReadStoredExactly(input, lengthBytes, 0, lengthBytes.Length, obfuscated, ref consumed);
                var compressedLength = lengthBytes[0] | lengthBytes[1] << 8;
                if (compressedLength <= 0 || compressedLength > storedSize - consumed)
                    throw new InvalidDataException("An InstallShield Deflate chunk range is invalid.");

                // Unshield appends one zero byte because some small blocks omit
                // the conventional empty stored-block terminator. A cabinet
                // chunk is at most UInt16.MaxValue bytes, so this allocation is
                // independent of the complete payload size.
                var chunk = new byte[compressedLength + 1];
                ReadStoredExactly(input, chunk, 0, compressedLength, obfuscated, ref consumed);
                using (var chunkInput = new MemoryStream(chunk, false))
                using (var inflater = new DeflateStream(chunkInput, CompressionMode.Decompress, false))
                {
                    var chunkWritten = 0;
                    int read;
                    while ((read = inflater.Read(outputBuffer, 0, outputBuffer.Length)) > 0)
                    {
                        chunkWritten += read;
                        if (chunkWritten > DeflateChunkOutputLimit || written + read > expectedSize)
                            throw new InvalidDataException("An InstallShield Deflate chunk exceeds its output bound.");
                        output.Write(outputBuffer, 0, read);
                        hash.AppendData(outputBuffer, 0, read);
                        written += read;
                    }
                }
            }
            return written;
        }

        private static long InflateLegacyChunks(
            Stream input,
            long storedSize,
            Stream output,
            IncrementalHash hash,
            bool obfuscated,
            long expectedSize)
        {
            // InstallShield 5 concatenates raw-Deflate streams separated by
            // 00 00 FF FF. A set marker followed by a byte whose low bit is one
            // can occur inside Deflate data, matching Unshield's source-backed
            // disambiguation rule.
            var reader = new LegacyStoredByteReader(input, storedSize, obfuscated);
            var outputBuffer = new byte[8192];
            long written = 0;
            while (reader.Remaining > 0)
            {
                var chunk = reader.ReadChunk();
                if (chunk.Length == 0) continue;
                using (var chunkInput = new MemoryStream(chunk, false))
                using (var inflater = new DeflateStream(chunkInput, CompressionMode.Decompress, false))
                {
                    int read;
                    while ((read = inflater.Read(outputBuffer, 0, outputBuffer.Length)) > 0)
                    {
                        if (written + read > expectedSize)
                            throw new InvalidDataException("An InstallShield 5 Deflate chunk exceeds its output descriptor.");
                        output.Write(outputBuffer, 0, read);
                        hash.AppendData(outputBuffer, 0, read);
                        written += read;
                    }
                }
            }
            return written;
        }

        private sealed class LegacyStoredByteReader
        {
            private const int MaximumChunkBytes = 64 * 1024 * 1024;
            private readonly Stream stream;
            private readonly bool obfuscated;
            private long ordinal;
            private int pending = -1;

            internal LegacyStoredByteReader(Stream stream, long length, bool obfuscated)
            {
                this.stream = stream;
                Remaining = length;
                this.obfuscated = obfuscated;
            }

            internal long Remaining { get; private set; }

            internal byte[] ReadChunk()
            {
                var bytes = new List<byte>();
                while (Remaining > 0 || pending >= 0)
                {
                    var value = ReadByte();
                    if (value < 0) break;
                    bytes.Add((byte)value);
                    if (bytes.Count > MaximumChunkBytes)
                        throw new InvalidDataException("An InstallShield 5 Deflate chunk exceeds the 64 MiB compressed limit.");
                    if (bytes.Count < 4 || bytes[bytes.Count - 4] != 0 || bytes[bytes.Count - 3] != 0 ||
                        bytes[bytes.Count - 2] != 0xFF || bytes[bytes.Count - 1] != 0xFF) continue;

                    var next = ReadByte();
                    if (next >= 0 && (next & 1) != 0)
                    {
                        bytes.Add((byte)next);
                        continue;
                    }
                    if (next >= 0) pending = next;
                    bytes.RemoveRange(bytes.Count - 4, 4);
                    break;
                }
                // DeflateStream tolerates the raw stream, but one zero byte
                // preserves Unshield's behavior for abbreviated terminal blocks.
                bytes.Add(0);
                return bytes.ToArray();
            }

            private int ReadByte()
            {
                if (pending >= 0)
                {
                    var result = pending;
                    pending = -1;
                    return result;
                }
                if (Remaining <= 0) return -1;
                var value = stream.ReadByte();
                if (value < 0) throw new EndOfStreamException("An InstallShield 5 cabinet range is truncated.");
                Remaining--;
                if (obfuscated)
                {
                    var decoded = (byte)(value ^ 0xD5);
                    decoded = (byte)((decoded >> 2) | (decoded << 6));
                    value = unchecked((byte)(decoded - ordinal % 0x47));
                }
                ordinal++;
                return value;
            }
        }

        private static void ReadStoredExactly(
            Stream stream,
            byte[] buffer,
            int offset,
            int count,
            bool obfuscated,
            ref long storedOrdinal)
        {
            var completed = 0;
            while (completed < count)
            {
                var read = stream.Read(buffer, offset + completed, count - completed);
                if (read <= 0) throw new EndOfStreamException("An InstallShield cabinet range is truncated.");
                if (obfuscated)
                {
                    for (var index = 0; index < read; index++)
                    {
                        var ordinal = storedOrdinal + index;
                        var value = (byte)(buffer[offset + completed + index] ^ 0xD5);
                        var rotated = (byte)((value >> 2) | (value << 6));
                        buffer[offset + completed + index] = unchecked((byte)(rotated - ordinal % 0x47));
                    }
                }
                completed += read;
                storedOrdinal += read;
            }
        }

        private static string GetVolumePath(string headerPath, ushort volume)
        {
            var directory = Path.GetDirectoryName(headerPath);
            var stem = Path.GetFileNameWithoutExtension(headerPath);
            var end = stem.Length;
            while (end > 0 && char.IsDigit(stem[end - 1])) end--;
            if (end == stem.Length) throw new InvalidDataException("The InstallShield cabinet header name does not end in a volume number.");
            var path = Path.Combine(directory ?? string.Empty, stem.Substring(0, end) + volume + ".cab");
            if (!File.Exists(path)) throw new FileNotFoundException("A required InstallShield cabinet volume is missing.", path);
            return path;
        }

        private static CommonHeader ReadCommonHeader(byte[] bytes, long offset)
        {
            CheckedRange(bytes, offset, CommonHeaderSize, "common header");
            var signature = ReadUInt32(bytes, offset);
            if (signature != Signature) throw new InvalidDataException("The file does not contain an InstallShield ISc( cabinet header.");
            return new CommonHeader(signature, ReadUInt32(bytes, offset + 4), ReadUInt32(bytes, offset + 12), ReadUInt32(bytes, offset + 16));
        }

        private static int GetMajorVersion(uint version)
        {
            var family = version >> 24;
            if (family == 1) return (int)((version >> 12) & 0x0F);
            if (family == 2 || family == 4)
            {
                var value = (int)(version & 0xFFFF);
                return value == 0 ? 0 : value / 100;
            }
            return 0;
        }

        private static string ReadCatalogString(byte[] bytes, long offset, long limit, int major)
        {
            if (limit < 0 || limit > bytes.LongLength || offset < 0 || offset >= limit)
                throw new InvalidDataException("An InstallShield catalog string starts outside the declared file table.");
            if (major >= 17)
            {
                var end = offset;
                while (end + 1 < limit && (bytes[(int)end] != 0 || bytes[(int)end + 1] != 0)) end += 2;
                if (end + 1 >= limit) throw new InvalidDataException("An InstallShield UTF-16 catalog string is unterminated inside the declared file table.");
                return Encoding.Unicode.GetString(bytes, (int)offset, (int)(end - offset));
            }
            else
            {
                var end = offset;
                while (end < limit && bytes[(int)end] != 0) end++;
                if (end >= limit) throw new InvalidDataException("An InstallShield catalog string is unterminated inside the declared file table.");
                return Encoding.Latin1.GetString(bytes, (int)offset, (int)(end - offset));
            }
        }

        private static byte[] ReadExactly(Stream stream, int count)
        {
            var bytes = new byte[count];
            var offset = 0;
            while (offset < count)
            {
                var read = stream.Read(bytes, offset, count - offset);
                if (read <= 0) throw new EndOfStreamException("An InstallShield cabinet range is truncated.");
                offset += read;
            }
            return bytes;
        }

        private static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            var difference = 0;
            for (var index = 0; index < left.Length; index++) difference |= left[index] ^ right[index];
            return difference == 0;
        }

        private static long CheckedRange(byte[] bytes, long offset, long length, string name)
        {
            if (offset < 0 || length < 0 || offset > bytes.LongLength || length > bytes.LongLength - offset)
                throw new InvalidDataException("The InstallShield " + name + " is outside the header file.");
            return offset;
        }

        private static long CheckedSubrange(long offset, long length, long rangeStart, long rangeEnd, string name)
        {
            if (rangeStart < 0 || rangeEnd < rangeStart || offset < rangeStart || length < 0 || offset > rangeEnd || length > rangeEnd - offset)
                throw new InvalidDataException("The InstallShield " + name + " is outside the declared file table.");
            return offset;
        }

        private static long CheckedAdd(long baseOffset, long relativeOffset, long limit, string name)
        {
            if (baseOffset < 0 || relativeOffset < 0 || baseOffset > limit || relativeOffset > limit - baseOffset)
                throw new InvalidDataException("The InstallShield " + name + " offset is outside the header file.");
            return baseOffset + relativeOffset;
        }

        private static ushort ReadUInt16(byte[] bytes, long offset)
        {
            CheckedRange(bytes, offset, 2, "uint16 field");
            return (ushort)(bytes[(int)offset] | bytes[(int)offset + 1] << 8);
        }

        private static uint ReadUInt32(byte[] bytes, long offset)
        {
            CheckedRange(bytes, offset, 4, "uint32 field");
            return (uint)(bytes[(int)offset] | bytes[(int)offset + 1] << 8 | bytes[(int)offset + 2] << 16 | bytes[(int)offset + 3] << 24);
        }

        private static int ReadInt32(byte[] bytes, long offset)
        {
            return unchecked((int)ReadUInt32(bytes, offset));
        }

        private static ulong ReadUInt64(byte[] bytes, long offset)
        {
            return ReadUInt32(bytes, offset) | (ulong)ReadUInt32(bytes, offset + 4) << 32;
        }

        private static long ToInt64(ulong value, string name)
        {
            if (value > long.MaxValue) throw new InvalidDataException("The InstallShield " + name + " exceeds supported stream limits.");
            return (long)value;
        }

        private sealed class VolumeSegment
        {
            internal VolumeSegment(string path, long offset, long length)
            {
                Path = path;
                Offset = offset;
                Length = length;
            }

            internal string Path { get; private set; }
            internal long Offset { get; private set; }
            internal long Length { get; private set; }
        }

        /// <summary>
        /// Present validated ranges from consecutive dataN.cab files as one
        /// logical stored stream. InstallShield compression framing is applied
        /// after this layer, so even a two-byte chunk length may cross volumes.
        /// </summary>
        private sealed class InstallShieldSpannedStream : Stream
        {
            private readonly List<VolumeSegment> segments;
            private readonly long length;
            private FileStream currentStream;
            private int segmentIndex;
            private long segmentRemaining;
            private long position;

            internal InstallShieldSpannedStream(List<VolumeSegment> segments)
            {
                if (segments == null) throw new ArgumentNullException("segments");
                if (segments.Count == 0) throw new InvalidDataException("A split InstallShield cabinet entry has no volume segments.");
                this.segments = segments;
                foreach (var segment in segments) length = checked(length + segment.Length);
                segmentIndex = -1;
            }

            public override bool CanRead { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return false; } }
            public override long Length { get { return length; } }
            public override long Position
            {
                get { return position; }
                set { throw new NotSupportedException(); }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (buffer == null) throw new ArgumentNullException("buffer");
                if (offset < 0 || count < 0 || offset > buffer.Length - count)
                    throw new ArgumentOutOfRangeException("offset");
                if (count == 0 || position >= length) return 0;

                var totalRead = 0;
                while (count > 0 && position < length)
                {
                    if (currentStream == null || segmentRemaining == 0) OpenNextSegment();
                    var requested = (int)Math.Min(count, segmentRemaining);
                    var read = currentStream.Read(buffer, offset, requested);
                    if (read <= 0) throw new EndOfStreamException("A split InstallShield cabinet segment is truncated.");
                    offset += read;
                    count -= read;
                    totalRead += read;
                    position += read;
                    segmentRemaining -= read;
                }
                return totalRead;
            }

            private void OpenNextSegment()
            {
                if (currentStream != null)
                {
                    currentStream.Dispose();
                    currentStream = null;
                }
                segmentIndex++;
                if (segmentIndex >= segments.Count)
                    throw new EndOfStreamException("A split InstallShield cabinet stream ended before its descriptor size.");
                var segment = segments[segmentIndex];
                currentStream = new FileStream(segment.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                currentStream.Position = segment.Offset;
                segmentRemaining = segment.Length;
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing && currentStream != null)
                {
                    currentStream.Dispose();
                    currentStream = null;
                }
                base.Dispose(disposing);
            }

            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        }

        private sealed class Catalog
        {
            internal Catalog(
                string headerPath,
                uint rawVersion,
                int majorVersion,
                byte[] header,
                long descriptorBase,
                long descriptorSize,
                List<InstallShieldCabinetEntry> entries)
            {
                HeaderPath = headerPath;
                RawVersion = rawVersion;
                MajorVersion = majorVersion;
                Header = header;
                DescriptorBase = descriptorBase;
                DescriptorSize = descriptorSize;
                Entries = entries;
            }

            internal string HeaderPath { get; private set; }
            internal uint RawVersion { get; private set; }
            internal int MajorVersion { get; private set; }
            internal byte[] Header { get; private set; }
            internal long DescriptorBase { get; private set; }
            internal long DescriptorSize { get; private set; }
            internal List<InstallShieldCabinetEntry> Entries { get; private set; }
        }

        private sealed class SelectionEvidence
        {
            internal SelectionEvidence(List<string> features, List<string> setupTypes)
            {
                Features = features;
                SetupTypes = setupTypes;
            }

            internal List<string> Features { get; private set; }
            internal List<string> SetupTypes { get; private set; }
        }

        private struct CommonHeader
        {
            internal CommonHeader(uint signature, uint version, uint descriptorOffset, uint descriptorSize)
            {
                Signature = signature;
                Version = version;
                DescriptorOffset = descriptorOffset;
                DescriptorSize = descriptorSize;
            }

            internal uint Signature;
            internal uint Version;
            internal uint DescriptorOffset;
            internal uint DescriptorSize;
        }
    }
}
