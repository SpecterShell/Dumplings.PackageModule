// SPDX-License-Identifier: MIT AND Zlib
// InstallShield 3 archive framing is derived from MIT-licensed setup30.
// Source: https://github.com/ostrich/setup30
// TTCOMP/PKWARE implode decoding is derived from Mark Adler's blast.c.
// Source: https://github.com/madler/zlib/tree/develop/contrib/blast

namespace Dumplings.InstallShield
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;

    public sealed class InstallShieldClassicEntry
    {
        internal InstallShieldClassicEntry(int index, string name, uint expandedSize, uint compressedSize,
            uint dataOffset, uint crcOrStamp, uint flagsA, uint flagsB, ushort directoryIndex)
        {
            Index = index;
            Name = name;
            ExpandedSize = expandedSize;
            CompressedSize = compressedSize;
            DataOffset = dataOffset;
            CrcOrStamp = crcOrStamp;
            FlagsA = flagsA;
            FlagsB = flagsB;
            DirectoryIndex = directoryIndex;
        }

        public int Index { get; private set; }
        public string Name { get; private set; }
        public uint ExpandedSize { get; private set; }
        public uint CompressedSize { get; private set; }
        public uint DataOffset { get; private set; }
        public uint CrcOrStamp { get; private set; }
        public uint FlagsA { get; private set; }
        public uint FlagsB { get; private set; }
        public ushort DirectoryIndex { get; private set; }
    }

    public sealed class InstallShieldClassicInspection
    {
        internal InstallShieldClassicInspection(string[] paths, List<InstallShieldClassicEntry> entries, bool multipart)
        {
            Paths = paths;
            Entries = entries;
            IsMultipart = multipart;
        }

        public string[] Paths { get; private set; }
        public List<InstallShieldClassicEntry> Entries { get; private set; }
        public bool IsMultipart { get; private set; }
        public string Profile { get { return "Setup30FooterTtComp"; } }
    }

    /// <summary>
    /// Reads InstallShield 3 Setup30 footer catalogs and TTCOMP members. The
    /// parser never executes setup.exe and accepts only bounded caller-selected
    /// output paths.
    /// </summary>
    public static class InstallShieldClassicExtractor
    {
        private const int FooterScanBytes = 2048;
        private const int EntryPrefixBytes = 27;
        private const int MaximumEntries = 4096;

        public static InstallShieldClassicInspection Inspect(string path, bool requireLocalData)
        {
            path = ResolvePath(path);
            var entries = ReadEntries(path, requireLocalData);
            if (entries.Count == 0)
                throw new InvalidDataException("The archive contains no validated Setup30 footer entries.");
            return new InstallShieldClassicInspection(new[] { path }, entries, false);
        }

        public static InstallShieldClassicInspection InspectMultipart(string[] paths)
        {
            var resolved = ResolveParts(paths);
            var entries = new List<InstallShieldClassicEntry>();
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var path in resolved)
            {
                foreach (var entry in ReadEntries(path, false))
                {
                    if (!names.Add(entry.Name)) continue;
                    entries.Add(new InstallShieldClassicEntry(entries.Count, entry.Name, entry.ExpandedSize,
                        entry.CompressedSize, entry.DataOffset, entry.CrcOrStamp, entry.FlagsA,
                        entry.FlagsB, entry.DirectoryIndex));
                }
            }
            entries.Sort((left, right) =>
            {
                var value = left.DataOffset.CompareTo(right.DataOffset);
                return value != 0 ? value : StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name);
            });
            if (entries.Count == 0) throw new InvalidDataException("The multipart media contains no validated Setup30 footer entries.");
            return new InstallShieldClassicInspection(resolved, entries, true);
        }

        public static List<string> Extract(string path, IDictionary<int, string> targets, long maximumExpandedBytes)
        {
            path = ResolvePath(path);
            var inspection = Inspect(path, true);
            return ExtractCore(inspection, targets, maximumExpandedBytes, index => ReadMember(path, inspection.Entries[index]));
        }

        public static List<string> ExtractMultipart(string[] paths, IDictionary<int, string> targets, long maximumExpandedBytes)
        {
            var inspection = InspectMultipart(paths);
            return ExtractCore(inspection, targets, maximumExpandedBytes,
                index => ReadMultipartMember(inspection.Paths, inspection.Entries[index]));
        }

        private static List<string> ExtractCore(InstallShieldClassicInspection inspection,
            IDictionary<int, string> targets, long maximumExpandedBytes, Func<int, byte[]> readMember)
        {
            if (targets == null) throw new ArgumentNullException("targets");
            if (maximumExpandedBytes <= 0 || maximumExpandedBytes > int.MaxValue)
                throw new ArgumentOutOfRangeException("maximumExpandedBytes", "Classic TTCOMP output is limited to Int32.MaxValue bytes per operation.");
            var results = new List<string>();
            long expandedTotal = 0;
            foreach (var pair in targets)
            {
                if (pair.Key < 0 || pair.Key >= inspection.Entries.Count)
                    throw new InvalidDataException("A selected Setup30 footer entry is outside the catalog.");
                var entry = inspection.Entries[pair.Key];
                if (entry.ExpandedSize > maximumExpandedBytes - expandedTotal)
                    throw new InvalidDataException("Selected Setup30 output exceeds the configured expansion limit.");
                expandedTotal += entry.ExpandedSize;
                var destination = Path.GetFullPath(pair.Value);
                if (!Path.IsPathRooted(destination)) throw new InvalidDataException("A Setup30 destination is not absolute.");
                var parent = Path.GetDirectoryName(destination);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                try
                {
                    var compressed = readMember(pair.Key);
                    var decoded = ClassicTtCompDecoder.Decode(compressed, checked((int)entry.ExpandedSize));
                    File.WriteAllBytes(destination, decoded);
                    results.Add(destination);
                }
                catch
                {
                    try { File.Delete(destination); } catch { }
                    throw;
                }
            }
            return results;
        }

        private static List<InstallShieldClassicEntry> ReadEntries(string path, bool requireLocalData)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                var tailLength = checked((int)Math.Min(FooterScanBytes, stream.Length));
                var tail = new byte[tailLength];
                stream.Position = stream.Length - tailLength;
                ReadExactly(stream, tail, 0, tail.Length);
                var entries = new List<InstallShieldClassicEntry>();
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (var start = 0; start < tail.Length; start++)
                {
                    if (!IsNameByte(tail[start])) continue;
                    var end = start;
                    while (end < tail.Length && IsNameByte(tail[end])) end++;
                    if (end >= tail.Length || tail[end] != 0 || end - start < 4) { start = end; continue; }
                    var name = Encoding.ASCII.GetString(tail, start, end - start);
                    start = end;
                    if (name.IndexOf('.') < 0 || !names.Add(name)) continue;
                    var nameOffset = stream.Length - tailLength + start - name.Length;
                    if (nameOffset < EntryPrefixBytes) continue;
                    var prefix = new byte[EntryPrefixBytes];
                    stream.Position = nameOffset - EntryPrefixBytes;
                    ReadExactly(stream, prefix, 0, prefix.Length);
                    if (prefix[26] != name.Length) continue;
                    var expanded = ReadUInt32(prefix, 0);
                    var compressed = ReadUInt32(prefix, 4);
                    var dataOffset = ReadUInt32(prefix, 8);
                    if (compressed == 0 || expanded == 0) continue;
                    if (requireLocalData && ((long)dataOffset > stream.Length || compressed > stream.Length - dataOffset)) continue;
                    entries.Add(new InstallShieldClassicEntry(entries.Count, name, expanded, compressed, dataOffset,
                        ReadUInt32(prefix, 12), ReadUInt32(prefix, 16), ReadUInt32(prefix, 20), ReadUInt16(prefix, 24)));
                    if (entries.Count > MaximumEntries)
                        throw new InvalidDataException("The Setup30 footer contains too many entries.");
                }
                entries.Sort((left, right) => left.DataOffset.CompareTo(right.DataOffset));
                return entries;
            }
        }

        private static byte[] ReadMember(string path, InstallShieldClassicEntry entry)
        {
            if (entry.CompressedSize > int.MaxValue) throw new InvalidDataException("A TTCOMP member exceeds the managed read limit.");
            var bytes = new byte[checked((int)entry.CompressedSize)];
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                if (entry.DataOffset > stream.Length || entry.CompressedSize > stream.Length - entry.DataOffset)
                    throw new InvalidDataException("A TTCOMP member range is truncated.");
                stream.Position = entry.DataOffset;
                ReadExactly(stream, bytes, 0, bytes.Length);
            }
            ValidateTtCompHeader(bytes);
            return bytes;
        }

        private static byte[] ReadMultipartMember(string[] paths, InstallShieldClassicEntry entry)
        {
            foreach (var startPath in paths)
            {
                using (var candidate = new FileStream(startPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (entry.DataOffset + 2 > candidate.Length) continue;
                    candidate.Position = entry.DataOffset;
                    var first = candidate.ReadByte();
                    var second = candidate.ReadByte();
                    if (first != 0 || second < 4 || second > 6) continue;
                }

                if (entry.CompressedSize > int.MaxValue) throw new InvalidDataException("A multipart TTCOMP member exceeds the managed read limit.");
                var result = new byte[checked((int)entry.CompressedSize)];
                var written = 0;
                var startIndex = Array.IndexOf(paths, startPath);
                var offset = (long)entry.DataOffset;
                for (var index = startIndex; index < paths.Length && written < result.Length; index++)
                {
                    using (var stream = new FileStream(paths[index], FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        if (offset >= stream.Length) break;
                        stream.Position = offset;
                        var count = checked((int)Math.Min(result.Length - written, stream.Length - offset));
                        ReadExactly(stream, result, written, count);
                        written += count;
                        offset = 0;
                    }
                }
                if (written != result.Length) continue;
                ValidateTtCompHeader(result);
                return result;
            }
            throw new InvalidDataException("No multipart volume contains the TTCOMP start for the selected entry.");
        }

        private static string ResolvePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A classic InstallShield archive path is required.", "path");
            path = Path.GetFullPath(path);
            if (!File.Exists(path)) throw new FileNotFoundException("The classic InstallShield archive does not exist.", path);
            return path;
        }

        private static string[] ResolveParts(string[] paths)
        {
            if (paths == null || paths.Length < 2) throw new ArgumentException("At least two multipart archive paths are required.", "paths");
            var result = new string[paths.Length];
            for (var index = 0; index < paths.Length; index++) result[index] = ResolvePath(paths[index]);
            return result;
        }

        private static bool IsNameByte(byte value)
        {
            return value >= (byte)'A' && value <= (byte)'Z' || value >= (byte)'a' && value <= (byte)'z' ||
                value >= (byte)'0' && value <= (byte)'9' || value == (byte)'_' || value == (byte)'.' ||
                value == (byte)'\\' || value == (byte)'-';
        }

        private static void ValidateTtCompHeader(byte[] bytes)
        {
            if (bytes.Length < 4 || bytes[0] > 1 || bytes[1] < 4 || bytes[1] > 6)
                throw new InvalidDataException("The selected Setup30 member does not contain a TTCOMP header.");
        }

        private static ushort ReadUInt16(byte[] bytes, int offset)
        {
            return (ushort)(bytes[offset] | bytes[offset + 1] << 8);
        }

        private static uint ReadUInt32(byte[] bytes, int offset)
        {
            return (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);
        }

        private static void ReadExactly(Stream stream, byte[] bytes, int offset, int count)
        {
            var completed = 0;
            while (completed < count)
            {
                var read = stream.Read(bytes, offset + completed, count - completed);
                if (read <= 0) throw new EndOfStreamException("A classic InstallShield range is truncated.");
                completed += read;
            }
        }
    }

    internal static class ClassicTtCompDecoder
    {
        private const int MaxBits = 13;
        private static readonly byte[] LitLengths = { 11,124,8,7,28,7,188,13,76,4,10,8,12,10,12,10,8,23,8,9,7,6,7,8,7,6,55,8,23,24,12,11,7,9,11,12,6,7,22,5,7,24,6,11,9,6,7,22,7,11,38,7,9,8,25,11,8,11,9,12,8,12,5,38,5,38,5,11,7,5,6,21,6,10,53,8,7,24,10,27,44,253,253,253,252,252,252,13,12,45,12,45,12,61,12,45,44,173 };
        private static readonly byte[] LenLengths = { 2,35,36,53,38,23 };
        private static readonly byte[] DistLengths = { 2,20,53,230,247,151,248 };
        private static readonly int[] LengthBase = { 3,2,4,5,6,7,8,9,10,12,16,24,40,72,136,264 };
        private static readonly int[] LengthExtra = { 0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8 };
        private static readonly Huffman LitTable = Construct(256, LitLengths);
        private static readonly Huffman LenTable = Construct(16, LenLengths);
        private static readonly Huffman DistTable = Construct(64, DistLengths);

        internal static byte[] Decode(byte[] input, int expectedSize)
        {
            if (input == null || input.Length < 3) throw new InvalidDataException("The TTCOMP stream is truncated.");
            if (input[0] > 1) throw new InvalidDataException("The TTCOMP literal mode is invalid.");
            if (input[1] < 4 || input[1] > 6) throw new InvalidDataException("The TTCOMP dictionary size is invalid.");
            var bits = new BitReader(input, 2);
            var output = new byte[expectedSize];
            var count = 0;
            while (true)
            {
                if (bits.ReadBits(1) != 0)
                {
                    var symbol = DecodeSymbol(bits, LenTable);
                    var length = LengthBase[symbol] + bits.ReadBits(LengthExtra[symbol]);
                    if (length == 519) break;
                    var lowBits = length == 2 ? 2 : input[1];
                    var distance = (DecodeSymbol(bits, DistTable) << lowBits) + bits.ReadBits(lowBits) + 1;
                    if (distance > count) throw new InvalidDataException("A TTCOMP back-reference exceeds the decoded window.");
                    if (length > output.Length - count) throw new InvalidDataException("TTCOMP output exceeds the catalog size.");
                    for (var index = 0; index < length; index++)
                    {
                        output[count] = output[count - distance];
                        count++;
                    }
                }
                else
                {
                    if (count >= output.Length) throw new InvalidDataException("TTCOMP output exceeds the catalog size.");
                    output[count++] = (byte)(input[0] != 0 ? DecodeSymbol(bits, LitTable) : bits.ReadBits(8));
                }
            }
            if (count != expectedSize) throw new InvalidDataException("TTCOMP output size does not match the catalog entry.");
            return output;
        }

        private static int DecodeSymbol(BitReader bits, Huffman table)
        {
            var code = 0; var first = 0; var index = 0;
            for (var length = 1; length <= MaxBits; length++)
            {
                code |= bits.ReadBits(1) ^ 1;
                var count = table.Count[length];
                if (code < first + count) return table.Symbol[index + code - first];
                index += count; first = (first + count) << 1; code <<= 1;
            }
            throw new InvalidDataException("The TTCOMP Huffman code is invalid.");
        }

        private static Huffman Construct(int capacity, byte[] representation)
        {
            var lengths = new byte[256]; var symbolCount = 0;
            foreach (var value in representation)
            {
                var repeat = (value >> 4) + 1; var bitLength = value & 15;
                if (symbolCount + repeat > lengths.Length) throw new InvalidDataException("The TTCOMP Huffman table is invalid.");
                for (var index = 0; index < repeat; index++) lengths[symbolCount++] = (byte)bitLength;
            }
            var table = new Huffman(capacity);
            for (var symbol = 0; symbol < symbolCount; symbol++) table.Count[lengths[symbol]]++;
            var offsets = new int[MaxBits + 1];
            for (var length = 1; length < MaxBits; length++) offsets[length + 1] = offsets[length] + table.Count[length];
            for (var symbol = 0; symbol < symbolCount; symbol++) if (lengths[symbol] != 0) table.Symbol[offsets[lengths[symbol]]++] = symbol;
            return table;
        }

        private sealed class Huffman
        {
            internal readonly int[] Count = new int[MaxBits + 1];
            internal readonly int[] Symbol;
            internal Huffman(int capacity) { Symbol = new int[capacity]; }
        }

        private sealed class BitReader
        {
            private readonly byte[] input; private int index; private int accumulator; private int available;
            internal BitReader(byte[] input, int offset) { this.input = input; index = offset; }
            internal int ReadBits(int count)
            {
                var value = 0;
                for (var bit = 0; bit < count; bit++)
                {
                    if (available == 0)
                    {
                        if (index >= input.Length) throw new InvalidDataException("The TTCOMP stream ended before its end marker.");
                        accumulator = input[index++]; available = 8;
                    }
                    value |= (accumulator & 1) << bit; accumulator >>= 1; available--;
                }
                return value;
            }
        }
    }
}
