// SPDX-License-Identifier: Apache-2.0
// OBL framing was independently implemented from the MIT-licensed
// https://github.com/jte/installscript-decompiler LibFile reader.

namespace Dumplings.InstallShield.InstallScript
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;

    /// <summary>One bounded member in an InstallScript OBL library.</summary>
    public sealed class InstallScriptLibraryMember
    {
        internal InstallScriptLibraryMember(string name, uint offset, uint length, string formatProfile)
        {
            Name = name;
            Offset = offset;
            Length = length;
            FormatProfile = formatProfile;
        }

        public string Name { get; private set; }
        public uint Offset { get; private set; }
        public uint Length { get; private set; }
        public string FormatProfile { get; private set; }
    }

    /// <summary>Validated OBL catalog evidence without eager member copies.</summary>
    public sealed class InstallScriptLibrary
    {
        internal InstallScriptLibrary(uint version)
        {
            Version = version;
            Members = new List<InstallScriptLibraryMember>();
            Warnings = new List<string>();
        }

        public uint Version { get; private set; }
        public long CatalogLength { get; internal set; }
        public List<InstallScriptLibraryMember> Members { get; private set; }
        public List<string> Warnings { get; private set; }
    }

    /// <summary>Parses the pOdA OBL catalog and bounded embedded programs.</summary>
    public static class InstallScriptLibraryReader
    {
        private const int MaximumMembers = 4096;
        private const int MaximumNameBytes = 32768;

        public static bool IsLibrary(byte[] bytes)
        {
            return bytes != null && bytes.Length >= 12 &&
                bytes[0] == (byte)'p' && bytes[1] == (byte)'O' &&
                bytes[2] == (byte)'d' && bytes[3] == (byte)'A';
        }

        public static InstallScriptLibrary Read(byte[] bytes)
        {
            if (!IsLibrary(bytes)) throw new InvalidDataException("The input does not contain an InstallScript OBL signature.");
            var reader = new Reader(bytes);
            reader.Skip(4);
            var version = reader.ReadUInt32();
            if (version != 1) throw new InvalidDataException("Unsupported InstallScript OBL catalog version " + version + ".");
            var memberCount = reader.ReadUInt32();
            if (memberCount > MaximumMembers) throw new InvalidDataException("The InstallScript OBL member count exceeds the parser limit.");

            var result = new InstallScriptLibrary(version);
            var ranges = new List<Tuple<long, long>>();
            for (var index = 0; index < memberCount; index++)
            {
                var nameLength = reader.ReadUInt16();
                if (nameLength > MaximumNameBytes) throw new InvalidDataException("An InstallScript OBL member name exceeds the parser limit.");
                var name = reader.ReadAscii(nameLength).TrimEnd('\0');
                var offset = reader.ReadUInt32();
                var length = reader.ReadUInt32();
                ValidateRange(offset, length, bytes.LongLength, "member");

                var end = checked((long)offset + length);
                foreach (var range in ranges)
                {
                    if ((long)offset < range.Item2 && end > range.Item1)
                        throw new InvalidDataException("InstallScript OBL member ranges overlap.");
                }
                ranges.Add(Tuple.Create((long)offset, end));
                result.Members.Add(new InstallScriptLibraryMember(name, offset, length, IdentifyMember(bytes, offset, length)));
            }
            result.CatalogLength = reader.Position;
            foreach (var member in result.Members)
            {
                if (member.Offset < result.CatalogLength)
                    throw new InvalidDataException("An InstallScript OBL member overlaps the catalog.");
            }
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var member in result.Members)
            {
                if (!names.Add(member.Name)) result.Warnings.Add("The InstallScript OBL catalog contains duplicate member name '" + member.Name + "'.");
            }
            return result;
        }

        public static byte[] ReadMember(byte[] bytes, InstallScriptLibraryMember member, int maximumBytes)
        {
            if (bytes == null) throw new ArgumentNullException("bytes");
            if (member == null) throw new ArgumentNullException("member");
            if (maximumBytes <= 0) throw new ArgumentOutOfRangeException("maximumBytes");
            ValidateRange(member.Offset, member.Length, bytes.LongLength, "member");
            if (member.Length > maximumBytes) throw new InvalidDataException("The InstallScript OBL member exceeds the output limit.");
            var result = new byte[member.Length];
            Buffer.BlockCopy(bytes, checked((int)member.Offset), result, 0, checked((int)member.Length));
            return result;
        }

        public static InstallScriptProgram ReadProgram(byte[] bytes, string memberName, int maximumInstructions)
        {
            var program = InstallScriptBytecodeReader.Read(bytes, maximumInstructions);
            program.LibraryMemberName = memberName ?? string.Empty;
            return program;
        }

        private static string IdentifyMember(byte[] bytes, uint offset, uint length)
        {
            if (length < 4) return "Unknown";
            var start = checked((int)offset);
            if (bytes[start] == 0xB8 && bytes[start + 1] == 0xC9 && bytes[start + 2] == 0x0C && bytes[start + 3] == 0x00)
                return "INS-Old";
            if (bytes[start] == 0x48 && bytes[start + 1] == 0x4F && bytes[start + 2] == 0xF3 && bytes[start + 3] == 0xC9)
                return "OBS";
            if (bytes[start] == (byte)'a' && bytes[start + 1] == (byte)'L' && bytes[start + 2] == (byte)'u' && bytes[start + 3] == (byte)'Z')
                return "aLuZ";
            if (bytes[start] == (byte)'k' && bytes[start + 1] == (byte)'U' && bytes[start + 2] == (byte)'t' && bytes[start + 3] == (byte)'Z')
                return "kUtZ";
            return "Unknown";
        }

        private static void ValidateRange(long offset, long length, long total, string name)
        {
            if (offset < 0 || length < 0 || offset > total || length > total - offset)
                throw new InvalidDataException("The InstallScript OBL " + name + " range is outside the file.");
        }

        private sealed class Reader
        {
            private readonly byte[] bytes;
            private int position;
            internal Reader(byte[] bytes) { this.bytes = bytes; }
            internal int Position { get { return position; } }
            internal void Skip(int count) { Ensure(count); position += count; }
            internal ushort ReadUInt16() { Ensure(2); var value = (ushort)(bytes[position] | bytes[position + 1] << 8); position += 2; return value; }
            internal uint ReadUInt32() { Ensure(4); var value = (uint)(bytes[position] | bytes[position + 1] << 8 | bytes[position + 2] << 16 | bytes[position + 3] << 24); position += 4; return value; }
            internal string ReadAscii(int count) { Ensure(count); var value = Encoding.ASCII.GetString(bytes, position, count); position += count; return value; }
            private void Ensure(int count) { if (count < 0 || count > bytes.Length - position) throw new EndOfStreamException("The InstallScript OBL catalog is truncated."); }
        }
    }
}
