// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;

namespace Dumplings.InstallerInfrastructure
{
    public sealed class PeSectionData
    {
        public string Name { get; set; }
        public uint VirtualAddress { get; set; }
        public uint VirtualSize { get; set; }
        public uint RawOffset { get; set; }
        public uint RawSize { get; set; }
    }

    public sealed class PeDirectoryData
    {
        public int Index { get; set; }
        public string Name { get; set; }
        public uint Rva { get; set; }
        public uint Size { get; set; }
        public long Offset { get; set; }
    }

    public sealed class PeLayoutData
    {
        public int PeOffset { get; set; }
        public ushort Machine { get; set; }
        public ushort Characteristics { get; set; }
        public ushort OptionalHeaderMagic { get; set; }
        public string OptionalHeaderFormat { get; set; }
        public int OptionalHeaderSize { get; set; }
        public ushort Subsystem { get; set; }
        public ulong ImageBase { get; set; }
        public uint SizeOfHeaders { get; set; }
        public Dictionary<string, PeDirectoryData> DataDirectories { get; } = new Dictionary<string, PeDirectoryData>(StringComparer.OrdinalIgnoreCase);
        public List<PeSectionData> Sections { get; } = new List<PeSectionData>();
        public uint ResourceRva { get; set; }
        public uint ResourceSize { get; set; }
        public long ResourceOffset { get; set; }
    }

    public sealed class PeResourceData
    {
        public string TypeName { get; set; }
        public uint? TypeId { get; set; }
        public string Name { get; set; }
        public uint? Id { get; set; }
        public uint? LanguageId { get; set; }
        public uint CodePage { get; set; }
        public long Offset { get; set; }
        public long Size { get; set; }
    }

    public sealed class PeImportData
    {
        public string Name { get; set; }
        public bool IsDelayLoad { get; set; }
    }

    public sealed class PeClrData
    {
        public uint HeaderSize { get; set; }
        public ushort MajorRuntimeVersion { get; set; }
        public ushort MinorRuntimeVersion { get; set; }
        public uint MetaDataRva { get; set; }
        public uint MetaDataSize { get; set; }
        public uint Flags { get; set; }
        public uint EntryPointToken { get; set; }
    }

    public sealed class PeFrameworkData
    {
        public string FrameworkName { get; set; }
        public string Version { get; set; }
        public string RawValue { get; set; }
    }

    public static class PEImageReader
    {
        private static readonly string[] DirectoryNames = {
            "Export", "Import", "Resource", "Exception", "Certificate", "BaseRelocation", "Debug", "Architecture",
            "GlobalPointer", "Tls", "LoadConfig", "BoundImport", "ImportAddressTable", "DelayImport", "ClrRuntimeHeader", "Reserved"
        };

        /// <summary>
        /// Returns the largest stream range that PEReader can address from the
        /// current position. PE files may carry overlays larger than 2 GiB, but
        /// PEReader accepts only a signed 32-bit image size. The PE headers and
        /// sections remain addressable while the format parser handles the
        /// trailing installer overlay through 64-bit stream offsets.
        /// </summary>
        public static int GetReaderSize(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("The PE stream must be readable and seekable.", nameof(stream));
            long remaining = stream.Length - stream.Position;
            if (remaining <= 0) throw new ArgumentException("The PE stream does not contain any data at its current position.", nameof(stream));
            return remaining > int.MaxValue ? int.MaxValue : checked((int)remaining);
        }

        public static PeLayoutData ReadLayout(Stream stream, bool restorePosition)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("The PE stream must be readable and seekable.", nameof(stream));
            long original = stream.Position;
            try
            {
                stream.Position = 0;
                // The explicit size prevents PEReader from treating a large
                // installer overlay as part of its signed 32-bit PE image.
                using PEReader reader = new PEReader(stream, PEStreamOptions.LeaveOpen, GetReaderSize(stream));
                PEHeaders headers = reader.PEHeaders;
                if (headers.PEHeader == null) return null;
                PEHeader pe = headers.PEHeader;
                PeLayoutData layout = new PeLayoutData
                {
                    PeOffset = headers.PEHeaderStartOffset - 24,
                    Machine = (ushort)headers.CoffHeader.Machine,
                    Characteristics = (ushort)headers.CoffHeader.Characteristics,
                    OptionalHeaderMagic = (ushort)pe.Magic,
                    OptionalHeaderFormat = pe.Magic == PEMagic.PE32Plus ? "PE32+" : "PE32",
                    OptionalHeaderSize = headers.CoffHeader.SizeOfOptionalHeader,
                    Subsystem = (ushort)pe.Subsystem,
                    ImageBase = (ulong)pe.ImageBase,
                    SizeOfHeaders = unchecked((uint)pe.SizeOfHeaders)
                };
                foreach (SectionHeader section in headers.SectionHeaders)
                {
                    layout.Sections.Add(new PeSectionData {
                        Name = section.Name, VirtualAddress = unchecked((uint)section.VirtualAddress), VirtualSize = unchecked((uint)section.VirtualSize),
                        RawOffset = unchecked((uint)section.PointerToRawData), RawSize = unchecked((uint)section.SizeOfRawData)
                    });
                }
                DirectoryEntry[] directories = {
                    pe.ExportTableDirectory, pe.ImportTableDirectory, pe.ResourceTableDirectory, pe.ExceptionTableDirectory,
                    pe.CertificateTableDirectory, pe.BaseRelocationTableDirectory, pe.DebugTableDirectory, default(DirectoryEntry),
                    pe.GlobalPointerTableDirectory, pe.ThreadLocalStorageTableDirectory, pe.LoadConfigTableDirectory, pe.BoundImportTableDirectory,
                    pe.ImportAddressTableDirectory, pe.DelayImportTableDirectory, pe.CorHeaderTableDirectory, new DirectoryEntry()
                };
                for (int i = 0; i < directories.Length; i++)
                {
                    DirectoryEntry item = directories[i];
                    uint address = unchecked((uint)item.RelativeVirtualAddress);
                    uint size = unchecked((uint)item.Size);
                    // The certificate directory uses a file offset; all other directories use RVAs.
                    long offset = address == 0 ? -1 : (i == 4 ? (long)address : RvaToOffset(address, layout.Sections));
                    layout.DataDirectories[DirectoryNames[i]] = new PeDirectoryData {
                        Index = i, Name = DirectoryNames[i], Rva = address, Size = size, Offset = offset
                    };
                }
                PeDirectoryData resource = layout.DataDirectories["Resource"];
                layout.ResourceRva = resource.Rva;
                layout.ResourceSize = resource.Size;
                layout.ResourceOffset = resource.Offset;
                return layout;
            }
            catch (BadImageFormatException) { return null; }
            finally { if (restorePosition) stream.Position = original; }
        }

        public static PeResourceData[] ReadResources(Stream stream, PeLayoutData layout, int maximumResources, bool restorePosition)
        {
            if (layout == null || layout.ResourceOffset < 0 || layout.ResourceSize <= 0) return Array.Empty<PeResourceData>();
            long original = stream.Position;
            List<PeResourceData> result = new List<PeResourceData>();
            try
            {
                foreach (ResourceNode type in ReadDirectory(stream, layout.ResourceOffset, 0))
                {
                    if (!type.IsDirectory) continue;
                    foreach (ResourceNode name in ReadDirectory(stream, layout.ResourceOffset, type.Offset))
                    {
                        if (!name.IsDirectory) continue;
                        foreach (ResourceNode language in ReadDirectory(stream, layout.ResourceOffset, name.Offset))
                        {
                            if (language.IsDirectory) continue;
                            if (result.Count >= maximumResources) throw new InvalidDataException($"The PE contains more than {maximumResources} leaf resources.");
                            byte[] entry = BinaryIO.ReadExactly(stream, layout.ResourceOffset + language.Offset, 16, true);
                            uint dataRva = BitConverter.ToUInt32(entry, 0);
                            uint size = BitConverter.ToUInt32(entry, 4);
                            uint codePage = BitConverter.ToUInt32(entry, 8);
                            long dataOffset = RvaToOffset(dataRva, layout.Sections);
                            if (dataOffset < 0 || size > stream.Length - dataOffset) throw new InvalidDataException("A PE resource points outside the file.");
                            result.Add(new PeResourceData {
                                TypeName = type.Name, TypeId = type.Id, Name = name.Name, Id = name.Id,
                                LanguageId = language.Id, CodePage = codePage, Offset = dataOffset, Size = size
                            });
                        }
                    }
                }
                return result.ToArray();
            }
            finally { if (restorePosition) stream.Position = original; }
        }

        public static PeImportData[] ReadImports(Stream stream, PeLayoutData layout, bool delay, bool restorePosition)
        {
            string directoryName = delay ? "DelayImport" : "Import";
            if (layout == null || !layout.DataDirectories.TryGetValue(directoryName, out PeDirectoryData directory) || directory.Offset < 0 || directory.Rva == 0) return Array.Empty<PeImportData>();
            long original = stream.Position;
            List<PeImportData> result = new List<PeImportData>();
            int descriptorSize = delay ? 32 : 20;
            try
            {
                for (int index = 0; index < 4096; index++)
                {
                    long offset = directory.Offset + (long)index * descriptorSize;
                    if (offset + descriptorSize > stream.Length) break;
                    byte[] descriptor = BinaryIO.ReadExactly(stream, offset, descriptorSize, true);
                    bool empty = true;
                    for (int i = 0; i < descriptor.Length; i++) if (descriptor[i] != 0) { empty = false; break; }
                    if (empty) break;
                    uint nameRva = BitConverter.ToUInt32(descriptor, delay ? 4 : 12);
                    if (nameRva == 0) continue;
                    if (delay && (BitConverter.ToUInt32(descriptor, 0) & 1) == 0)
                    {
                        if ((ulong)nameRva < layout.ImageBase) continue;
                        nameRva = checked((uint)((ulong)nameRva - layout.ImageBase));
                    }
                    long nameOffset = RvaToOffset(nameRva, layout.Sections);
                    string name = ReadAsciiZ(stream, nameOffset, 4096);
                    if (!string.IsNullOrWhiteSpace(name)) result.Add(new PeImportData { Name = name, IsDelayLoad = delay });
                }
                return result.ToArray();
            }
            finally { if (restorePosition) stream.Position = original; }
        }

        public static PeClrData ReadClrHeader(Stream stream, PeLayoutData layout, bool restorePosition)
        {
            if (layout == null || !layout.DataDirectories.TryGetValue("ClrRuntimeHeader", out PeDirectoryData directory) || directory.Offset < 0 || directory.Rva == 0) return null;
            long original = stream.Position;
            try
            {
                byte[] bytes = BinaryIO.ReadExactly(stream, directory.Offset, 24, true);
                return new PeClrData {
                    HeaderSize = BitConverter.ToUInt32(bytes, 0), MajorRuntimeVersion = BitConverter.ToUInt16(bytes, 4),
                    MinorRuntimeVersion = BitConverter.ToUInt16(bytes, 6), MetaDataRva = BitConverter.ToUInt32(bytes, 8),
                    MetaDataSize = BitConverter.ToUInt32(bytes, 12), Flags = BitConverter.ToUInt32(bytes, 16),
                    EntryPointToken = BitConverter.ToUInt32(bytes, 20)
                };
            }
            finally { if (restorePosition) stream.Position = original; }
        }

        public static PeFrameworkData ReadManagedTargetFramework(Stream stream, PeLayoutData layout, bool restorePosition)
        {
            PeClrData clr = ReadClrHeader(stream, layout, true);
            if (clr == null || clr.MetaDataSize == 0 || clr.MetaDataSize > 268435456) return null;
            long metadataOffset = RvaToOffset(clr.MetaDataRva, layout.Sections);
            if (metadataOffset < 0 || clr.MetaDataSize > stream.Length - metadataOffset) return null;
            long original = stream.Position;
            try
            {
                byte[] bytes = BinaryIO.ReadExactly(stream, metadataOffset, checked((int)clr.MetaDataSize), true);
                string text = Encoding.UTF8.GetString(bytes);
                Match match = Regex.Match(text, @"(?<Name>\.NETFramework|\.NETCoreApp|\.NETStandard),Version=v(?<Version>[0-9]+(?:\.[0-9]+){0,3})", RegexOptions.IgnoreCase);
                if (!match.Success) return null;
                return new PeFrameworkData { FrameworkName = match.Groups["Name"].Value, Version = match.Groups["Version"].Value, RawValue = match.Value };
            }
            finally { if (restorePosition) stream.Position = original; }
        }

        public static long RvaToOffset(uint rva, IList<PeSectionData> sections)
        {
            if (rva == 0) return -1;
            foreach (PeSectionData section in sections)
            {
                long start = section.VirtualAddress;
                long size = Math.Max((long)section.VirtualSize, section.RawSize);
                if (rva >= start && rva < start + size) return section.RawOffset + (rva - start);
            }
            return -1;
        }

        private sealed class ResourceNode
        {
            public string Name;
            public uint? Id;
            public bool IsDirectory;
            public uint Offset;
        }

        private static IEnumerable<ResourceNode> ReadDirectory(Stream stream, long resourceBase, uint directoryOffset)
        {
            byte[] header = BinaryIO.ReadExactly(stream, resourceBase + directoryOffset, 16, true);
            int count = BitConverter.ToUInt16(header, 12) + BitConverter.ToUInt16(header, 14);
            if (count > 65535) throw new InvalidDataException("The PE resource directory contains too many entries.");
            for (int index = 0; index < count; index++)
            {
                byte[] entry = BinaryIO.ReadExactly(stream, resourceBase + directoryOffset + 16 + index * 8L, 8, true);
                uint nameValue = BitConverter.ToUInt32(entry, 0);
                uint dataValue = BitConverter.ToUInt32(entry, 4);
                bool named = (nameValue & 0x80000000U) != 0;
                yield return new ResourceNode {
                    Name = named ? ReadResourceName(stream, resourceBase, nameValue & 0x7FFFFFFFU) : null,
                    Id = named ? null : (uint?)(nameValue & 0xFFFFU),
                    IsDirectory = (dataValue & 0x80000000U) != 0,
                    Offset = dataValue & 0x7FFFFFFFU
                };
            }
        }

        private static string ReadResourceName(Stream stream, long resourceBase, uint offset)
        {
            byte[] lengthBytes = BinaryIO.ReadExactly(stream, resourceBase + offset, 2, true);
            ushort length = BitConverter.ToUInt16(lengthBytes, 0);
            if (length > 32768) throw new InvalidDataException("The PE resource name is too long.");
            return Encoding.Unicode.GetString(BinaryIO.ReadExactly(stream, resourceBase + offset + 2, length * 2, true));
        }

        private static string ReadAsciiZ(Stream stream, long offset, int maximum)
        {
            if (offset < 0 || offset >= stream.Length) return null;
            long original = stream.Position;
            try
            {
                stream.Position = offset;
                List<byte> bytes = new List<byte>();
                while (bytes.Count < maximum)
                {
                    int value = stream.ReadByte();
                    if (value <= 0) break;
                    bytes.Add((byte)value);
                }
                return Encoding.ASCII.GetString(bytes.ToArray());
            }
            finally { stream.Position = original; }
        }
    }
}
