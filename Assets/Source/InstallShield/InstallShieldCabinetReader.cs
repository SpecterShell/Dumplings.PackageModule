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
        /// Split, linked, or external records are rejected conservatively.
        /// Output is streamed and hashed incrementally so a large selected
        /// payload does not require a same-sized managed byte array.
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
                var entry = catalog.Entries[pair.Key];
                if (!entry.IsValid) throw new InvalidDataException("The selected InstallShield cabinet entry is invalid.");
                if (entry.IsSplit) throw new NotSupportedException("Split InstallShield cabinet entries are not supported by the focused support-file reader.");
                if (entry.LinkFlags != 0) throw new NotSupportedException("Linked InstallShield cabinet entries are not supported by the focused support-file reader.");
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

        private static Catalog ReadCatalog(string headerPath)
        {
            if (string.IsNullOrWhiteSpace(headerPath)) throw new ArgumentException("A cabinet header path is required.", "headerPath");
            headerPath = Path.GetFullPath(headerPath);
            if (!File.Exists(headerPath)) throw new FileNotFoundException("The InstallShield cabinet header does not exist.", headerPath);

            // The parser needs random access to the descriptor/string tables,
            // but a catalog should never justify an unbounded ReadAllBytes.
            // Bound the source before allocation and cap object fan-out below.
            var headerLength = new FileInfo(headerPath).Length;
            if (headerLength > MaximumHeaderBytes)
                throw new InvalidDataException("The InstallShield cabinet header exceeds the 256 MiB catalog limit.");
            var header = File.ReadAllBytes(headerPath);
            if (header.Length < CommonHeaderSize) throw new InvalidDataException("The InstallShield cabinet header is truncated.");
            var common = ReadCommonHeader(header, 0);
            var major = GetMajorVersion(common.Version);
            if (major < 6) throw new NotSupportedException("The focused InstallShield cabinet reader supports version 6 and later.");

            var descriptorBase = CheckedRange(header, common.DescriptorOffset, common.DescriptorSize, "cabinet descriptor");
            if (common.DescriptorSize < 0x30)
                throw new InvalidDataException("The InstallShield cabinet descriptor is too small for its required fields.");
            var cursor = CheckedAdd(descriptorBase, 0x0C, header.Length, "cabinet descriptor fields");
            var fileTableOffset = ReadUInt32(header, cursor); cursor += 8;
            var fileTableSize = ReadUInt32(header, cursor); cursor += 4;
            var fileTableSize2 = ReadUInt32(header, cursor); cursor += 4;
            var directoryCount = ReadUInt32(header, cursor); cursor += 12;
            var fileCount = ReadUInt32(header, cursor); cursor += 4;
            var fileTableOffset2 = ReadUInt32(header, cursor);
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

            var descriptorTable = CheckedAdd(tableBase, fileTableOffset2, tableEnd, "file descriptor table");
            CheckedSubrange(descriptorTable, checked((long)fileCount * ModernFileDescriptorSize), tableBase, tableEnd, "file descriptor table");
            var entries = new List<InstallShieldCabinetEntry>((int)fileCount);
            for (var index = 0; index < (int)fileCount; index++)
            {
                var record = descriptorTable + index * (long)ModernFileDescriptorSize;
                var flags = ReadUInt16(header, record);
                var expandedSize = ToInt64(ReadUInt64(header, record + 2), "expanded size");
                var compressedSize = ToInt64(ReadUInt64(header, record + 10), "compressed size");
                var dataOffset = ToInt64(ReadUInt64(header, record + 18), "data offset");
                var md5 = new byte[16];
                Buffer.BlockCopy(header, checked((int)(record + 26)), md5, 0, md5.Length);
                var nameOffset = ReadUInt32(header, record + 58);
                var directoryIndex = ReadUInt16(header, record + 62);
                if (directoryIndex >= directories.Length) throw new InvalidDataException("An InstallShield cabinet file references an invalid directory.");
                var name = ReadCatalogString(header, CheckedAdd(tableBase, nameOffset, tableEnd, "file name"), tableEnd, major);
                var linkPrevious = ReadUInt32(header, record + 76);
                var linkNext = ReadUInt32(header, record + 80);
                var linkFlags = header[checked((int)(record + 84))];
                var volume = ReadUInt16(header, record + 85);
                entries.Add(new InstallShieldCabinetEntry(index, name, directories[directoryIndex], flags, expandedSize, compressedSize, dataOffset, md5, volume, linkPrevious, linkNext, linkFlags));
            }

            return new Catalog(headerPath, major, header, descriptorBase, common.DescriptorSize, entries);
        }

        private static InstallShieldMediaMetadata ReadMediaMetadata(Catalog catalog)
        {
            var metadata = new InstallShieldMediaMetadata(catalog.HeaderPath, catalog.MajorVersion);

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

            // Registry and shell records are independent extension graphs. A
            // malformed proprietary graph should not hide the ordinary file
            // catalog or prevent the other graphs from being inspected.
            try { ReadRegistryMetadata(catalog, metadata); }
            catch (Exception exception) when (exception is InvalidDataException || exception is OverflowException)
            {
                metadata.Warnings.Add("InstallShield media registry records are malformed or unsupported: " + exception.Message);
            }
            try { ReadShellMetadata(catalog, metadata); }
            catch (Exception exception) when (exception is InvalidDataException || exception is OverflowException)
            {
                metadata.Warnings.Add("InstallShield media shell-object records are malformed or unsupported: " + exception.Message);
            }
            return metadata;
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
            // The setup-type locale directory is packed immediately before the
            // file-group buckets. Its records were verified by changing only
            // ISSetupType and ISSetupTypeFeatures in official-builder media.
            if (catalog.DescriptorSize < 0x36) return;
            var localeCount = ReadUInt16(catalog.Header, catalog.DescriptorBase + 0x30);
            if (localeCount > MaximumSetupTypeLocaleCount)
                throw new InvalidDataException("The setup-type locale count exceeds the parser limit.");
            if (localeCount == 0) return;
            var localeTable = GetDescriptorAddress(
                catalog,
                ReadUInt32(catalog.Header, catalog.DescriptorBase + 0x32),
                checked((long)localeCount * 12),
                "setup-type locale table");
            for (var localeIndex = 0; localeIndex < localeCount; localeIndex++)
            {
                var locale = localeTable + localeIndex * 12L;
                var language = ReadUInt32(catalog.Header, locale);
                var setupTypeCount = ReadUInt16(catalog.Header, locale + 4);
                if (setupTypeCount > MaximumSetupTypeCount)
                    throw new InvalidDataException("A setup-type count exceeds the parser limit.");
                var setupTypeTable = GetDescriptorAddress(
                    catalog,
                    ReadUInt32(catalog.Header, locale + 8),
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
                    metadata.SetupTypes.Add(new InstallShieldMediaSetupType(
                        language,
                        setupTypeIndex,
                        ReadMediaString(catalog, ReadUInt32(catalog.Header, setupType), "setup-type name"),
                        ReadMediaString(catalog, ReadUInt32(catalog.Header, setupType + 4), "setup-type description"),
                        ReadMediaString(catalog, ReadUInt32(catalog.Header, setupType + 8), "setup-type display name"),
                        features));
                }
            }
        }

        private static void ReadRegistryMetadata(Catalog catalog, InstallShieldMediaMetadata metadata)
        {
            // InstallShield 2026 and observed version-30 media store the
            // registry-directory pointer at descriptor-relative 0x282.
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
                        var valueCount = ReadUInt16(catalog.Header, keyRecord + 8);
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
            var volumePath = GetVolumePath(catalog.HeaderPath, entry.Volume);
            using (var stream = new FileStream(volumePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                var commonBytes = ReadExactly(stream, CommonHeaderSize);
                var common = ReadCommonHeader(commonBytes, 0);
                if (common.Signature != Signature) throw new InvalidDataException("An InstallShield cabinet volume has an invalid signature.");
                if (entry.DataOffset < CommonHeaderSize + 64 || entry.DataOffset > stream.Length)
                    throw new InvalidDataException("An InstallShield cabinet file offset is outside its volume.");
                var storedSize = entry.IsCompressed ? entry.CompressedSize : entry.ExpandedSize;
                if (storedSize < 0 || storedSize > stream.Length - entry.DataOffset)
                    throw new InvalidDataException("An InstallShield cabinet file range is truncated.");
                if (entry.ExpandedSize > maximumExpandedBytes)
                    throw new InvalidDataException("An InstallShield cabinet output exceeds the configured limit.");

                stream.Position = entry.DataOffset;
                try
                {
                    using (var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None))
                    using (var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5))
                    {
                        var written = entry.IsCompressed
                            ? InflateChunks(stream, storedSize, output, md5, entry.IsObfuscated, entry.ExpandedSize)
                            : CopyStoredRange(stream, storedSize, output, md5, entry.IsObfuscated, entry.ExpandedSize);
                        if (written != entry.ExpandedSize)
                            throw new InvalidDataException("InstallShield cabinet expanded size does not match its descriptor.");
                        var actual = md5.GetHashAndReset();
                        if (!FixedTimeEquals(actual, entry.Md5))
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

        private sealed class Catalog
        {
            internal Catalog(
                string headerPath,
                int majorVersion,
                byte[] header,
                long descriptorBase,
                long descriptorSize,
                List<InstallShieldCabinetEntry> entries)
            {
                HeaderPath = headerPath;
                MajorVersion = majorVersion;
                Header = header;
                DescriptorBase = descriptorBase;
                DescriptorSize = descriptorSize;
                Entries = entries;
            }

            internal string HeaderPath { get; private set; }
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
