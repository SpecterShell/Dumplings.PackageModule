// SPDX-License-Identifier: Apache-2.0
// Independently implemented from PE/COFF documentation, Paquet Builder's shipped
// pbcore.h ABI, and controlled builder output. No vendor source is copied here.

using System;
using System.Collections.Generic;
using System.Text;

namespace Dumplings.PaquetBuilder
{
    public sealed class CompiledVariableAssignment
    {
        public CompiledVariableAssignment(string name, string value, uint callRva)
        {
            Name = name;
            Value = value;
            CallRva = callRva;
        }

        public string Name { get; }
        public string Value { get; }
        public uint CallRva { get; }
    }

    public sealed class PeScriptEvidence
    {
        public PeScriptEvidence(
            bool setVarImportFound,
            CompiledVariableAssignment[] assignments,
            string[] uninstallProductCodes)
        {
            SetVarImportFound = setVarImportFound;
            Assignments = assignments;
            UninstallProductCodes = uninstallProductCodes;
        }

        public bool SetVarImportFound { get; }
        public CompiledVariableAssignment[] Assignments { get; }
        public string[] UninstallProductCodes { get; }
    }

    public static class PaquetBuilderPeScanner
    {
        private const int MaxImports = 4096;
        private const int MaxAssignments = 4096;
        private const int MaxStringCharacters = 1024;

        public static PeScriptEvidence Scan(
            byte[] image,
            ulong imageBase,
            bool is64Bit,
            uint sizeOfHeaders,
            uint[] virtualAddresses,
            uint[] virtualSizes,
            uint[] rawOffsets,
            uint[] rawSizes,
            uint importRva,
            uint importSize,
            uint delayImportRva,
            uint delayImportSize,
            uint[] executableSectionIndexes)
        {
            if (image == null) throw new ArgumentNullException(nameof(image));
            ValidateSectionArrays(virtualAddresses, virtualSizes, rawOffsets, rawSizes);

            var iatRvas = new HashSet<uint>();
            // Import metadata is additive script evidence. Historical PE linkers
            // can leave directory ranges that contain valid loader data but no
            // fully file-backed name table. Keep scanning literal uninstall
            // paths even when either optional import route is unavailable.
            try { ReadNormalImports(image, imageBase, is64Bit, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes, importRva, importSize, iatRvas); }
            catch (InvalidOperationException) { }
            try { ReadDelayImports(image, imageBase, is64Bit, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes, delayImportRva, delayImportSize, iatRvas); }
            catch (InvalidOperationException) { }

            var assignments = new List<CompiledVariableAssignment>();
            if (iatRvas.Count > 0)
            {
                if (is64Bit)
                {
                    ScanX64(image, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes, executableSectionIndexes, iatRvas, assignments);
                }
                else
                {
                    ScanX86(image, imageBase, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes, executableSectionIndexes, iatRvas, assignments);
                }
            }

            return new PeScriptEvidence(
                iatRvas.Count > 0,
                DeduplicateAssignments(assignments).ToArray(),
                FindUninstallProductCodes(image).ToArray());
        }

        private static void ValidateSectionArrays(uint[] virtualAddresses, uint[] virtualSizes, uint[] rawOffsets, uint[] rawSizes)
        {
            if (virtualAddresses == null || virtualSizes == null || rawOffsets == null || rawSizes == null)
            {
                throw new ArgumentNullException("PE section arrays cannot be null.");
            }
            if (virtualAddresses.Length != virtualSizes.Length || virtualAddresses.Length != rawOffsets.Length || virtualAddresses.Length != rawSizes.Length)
            {
                throw new ArgumentException("PE section arrays must have identical lengths.");
            }
        }

        private static void ReadNormalImports(
            byte[] image,
            ulong imageBase,
            bool is64Bit,
            uint sizeOfHeaders,
            uint[] virtualAddresses,
            uint[] virtualSizes,
            uint[] rawOffsets,
            uint[] rawSizes,
            uint directoryRva,
            uint directorySize,
            HashSet<uint> setVarIatRvas)
        {
            if (directoryRva == 0 || directorySize < 20) return;
            int directoryOffset = MapRva(directoryRva, 20, image.Length, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes);
            int directoryEnd = CheckedEnd(directoryOffset, directorySize, image.Length);

            for (int descriptor = directoryOffset, count = 0; descriptor + 20 <= directoryEnd && count < MaxImports; descriptor += 20, count++)
            {
                uint nameTableRva = ReadUInt32(image, descriptor);
                uint dllNameRva = ReadUInt32(image, descriptor + 12);
                uint iatRva = ReadUInt32(image, descriptor + 16);
                if (nameTableRva == 0 && dllNameRva == 0 && iatRva == 0) break;
                if (nameTableRva == 0) nameTableRva = iatRva;

                try
                {
                    string dllName = ReadAsciiStringAtRva(image, dllNameRva, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes);
                    if (!IsPbCoreName(dllName)) continue;
                    ReadImportNames(image, imageBase, is64Bit, true, nameTableRva, iatRva, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes, setVarIatRvas);
                }
                catch (InvalidOperationException)
                {
                    // Bound or bound-import artifacts can leave individual
                    // descriptors without file-backed name data. They are not
                    // evidence for the PBCore ABI, so continue with later rows.
                }
            }
        }

        private static void ReadDelayImports(
            byte[] image,
            ulong imageBase,
            bool is64Bit,
            uint sizeOfHeaders,
            uint[] virtualAddresses,
            uint[] virtualSizes,
            uint[] rawOffsets,
            uint[] rawSizes,
            uint directoryRva,
            uint directorySize,
            HashSet<uint> setVarIatRvas)
        {
            if (directoryRva == 0 || directorySize < 32) return;
            int directoryOffset = MapRva(directoryRva, 32, image.Length, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes);
            int directoryEnd = CheckedEnd(directoryOffset, directorySize, image.Length);

            for (int descriptor = directoryOffset, count = 0; descriptor + 32 <= directoryEnd && count < MaxImports; descriptor += 32, count++)
            {
                uint attributes = ReadUInt32(image, descriptor);
                uint dllName = ReadUInt32(image, descriptor + 4);
                uint iat = ReadUInt32(image, descriptor + 12);
                uint nameTable = ReadUInt32(image, descriptor + 16);
                if (attributes == 0 && dllName == 0 && iat == 0 && nameTable == 0) break;
                bool valuesAreRvas = (attributes & 1) != 0;
                try
                {
                    uint dllNameRva = ToRva(dllName, imageBase, valuesAreRvas);
                    uint iatRva = ToRva(iat, imageBase, valuesAreRvas);
                    uint nameTableRva = ToRva(nameTable, imageBase, valuesAreRvas);
                    string dll = ReadAsciiStringAtRva(image, dllNameRva, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes);
                    if (!IsPbCoreName(dll)) continue;
                    ReadImportNames(image, imageBase, is64Bit, valuesAreRvas, nameTableRva, iatRva, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes, setVarIatRvas);
                }
                catch (InvalidOperationException)
                {
                    // Ignore a malformed optional delay descriptor without
                    // discarding independently valid normal-import evidence.
                }
            }
        }

        private static void ReadImportNames(
            byte[] image,
            ulong imageBase,
            bool is64Bit,
            bool valuesAreRvas,
            uint nameTableRva,
            uint iatRva,
            uint sizeOfHeaders,
            uint[] virtualAddresses,
            uint[] virtualSizes,
            uint[] rawOffsets,
            uint[] rawSizes,
            HashSet<uint> setVarIatRvas)
        {
            int pointerSize = is64Bit ? 8 : 4;
            int tableOffset = MapRva(nameTableRva, pointerSize, image.Length, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes);
            ulong ordinalMask = is64Bit ? 0x8000000000000000UL : 0x80000000UL;
            for (int index = 0; index < MaxImports; index++)
            {
                int entryOffset = checked(tableOffset + index * pointerSize);
                if (entryOffset < 0 || entryOffset + pointerSize > image.Length) throw new InvalidOperationException("Paquet Builder import-name table is truncated.");
                ulong value = is64Bit ? ReadUInt64(image, entryOffset) : ReadUInt32(image, entryOffset);
                if (value == 0) break;
                if ((value & ordinalMask) != 0) continue;
                try
                {
                    uint importNameRva = ToRva(value, imageBase, valuesAreRvas);
                    int importNameOffset = MapRva(importNameRva, 3, image.Length, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes);
                    string importName = ReadAsciiString(image, importNameOffset + 2);
                    if (string.Equals(importName, "SetVar", StringComparison.Ordinal))
                    {
                        setVarIatRvas.Add(checked(iatRva + (uint)(index * pointerSize)));
                    }
                }
                catch (InvalidOperationException) { continue; }
                catch (OverflowException) { continue; }
            }
        }

        private static void ScanX64(
            byte[] image,
            uint sizeOfHeaders,
            uint[] virtualAddresses,
            uint[] virtualSizes,
            uint[] rawOffsets,
            uint[] rawSizes,
            uint[] executableSectionIndexes,
            HashSet<uint> setVarIatRvas,
            List<CompiledVariableAssignment> assignments)
        {
            foreach (uint sectionIndexValue in executableSectionIndexes ?? Array.Empty<uint>())
            {
                int sectionIndex = checked((int)sectionIndexValue);
                if (sectionIndex < 0 || sectionIndex >= rawOffsets.Length) throw new InvalidOperationException("Executable PE section index is invalid.");
                int start = checked((int)rawOffsets[sectionIndex]);
                int end = Math.Min(image.Length, checked(start + (int)rawSizes[sectionIndex]));
                var values = new HashSet<string>[16];
                var functions = new uint?[16];
                for (int index = 0; index < values.Length; index++) values[index] = new HashSet<string>(StringComparer.Ordinal);

                for (int cursor = start; cursor + 2 < end && assignments.Count < MaxAssignments; cursor++)
                {
                    byte rex = image[cursor] >= 0x40 && image[cursor] <= 0x4F ? image[cursor] : (byte)0;
                    int opcodeOffset = cursor + (rex == 0 ? 0 : 1);
                    if (opcodeOffset + 1 >= end) continue;
                    byte opcode = image[opcodeOffset];
                    byte modRm = image[opcodeOffset + 1];
                    int mod = modRm >> 6;
                    int reg = ((modRm >> 3) & 7) + ((rex & 4) != 0 ? 8 : 0);
                    int rm = (modRm & 7) + ((rex & 1) != 0 ? 8 : 0);
                    int instructionLength = rex == 0 ? 6 : 7;

                    if (opcode == 0x8D && mod == 0 && (modRm & 7) == 5 && opcodeOffset + 5 < end)
                    {
                        uint instructionRva = checked(virtualAddresses[sectionIndex] + (uint)(cursor - start));
                        if (!TryAddDisplacement(instructionRva, instructionLength, ReadInt32(image, opcodeOffset + 2), out uint targetRva)) continue;
                        string value = TryReadWideStringAtRva(image, targetRva, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes);
                        values[reg].Clear();
                        if (value != null) values[reg].Add(value);
                        functions[reg] = null;
                        continue;
                    }

                    if (opcode == 0x8B && mod == 0 && (modRm & 7) == 5 && opcodeOffset + 5 < end)
                    {
                        uint instructionRva = checked(virtualAddresses[sectionIndex] + (uint)(cursor - start));
                        functions[reg] = TryAddDisplacement(instructionRva, instructionLength, ReadInt32(image, opcodeOffset + 2), out uint targetRva) ? targetRva : null;
                        values[reg].Clear();
                        continue;
                    }

                    if ((opcode == 0x8B || opcode == 0x89) && mod == 3)
                    {
                        int destination = opcode == 0x8B ? reg : rm;
                        int source = opcode == 0x8B ? rm : reg;
                        CopySet(values[source], values[destination]);
                        functions[destination] = functions[source];
                        continue;
                    }

                    if (opcode == 0x0F && opcodeOffset + 2 < end && image[opcodeOffset + 1] >= 0x40 && image[opcodeOffset + 1] <= 0x4F)
                    {
                        byte conditionalModRm = image[opcodeOffset + 2];
                        if ((conditionalModRm >> 6) == 3)
                        {
                            int destination = ((conditionalModRm >> 3) & 7) + ((rex & 4) != 0 ? 8 : 0);
                            int source = (conditionalModRm & 7) + ((rex & 1) != 0 ? 8 : 0);
                            values[destination].UnionWith(values[source]);
                        }
                        continue;
                    }

                    uint? targetIatRva = null;
                    if (opcode == 0xFF && ((modRm >> 3) & 7) == 2)
                    {
                        if (mod == 3)
                        {
                            targetIatRva = functions[rm];
                        }
                        else if (mod == 0 && (modRm & 7) == 5 && opcodeOffset + 5 < end)
                        {
                            uint instructionRva = checked(virtualAddresses[sectionIndex] + (uint)(cursor - start));
                            if (TryAddDisplacement(instructionRva, instructionLength, ReadInt32(image, opcodeOffset + 2), out uint targetRva)) targetIatRva = targetRva;
                        }
                    }

                    if (targetIatRva.HasValue)
                    {
                        if (setVarIatRvas.Contains(targetIatRva.Value))
                        {
                            uint callRva = checked(virtualAddresses[sectionIndex] + (uint)(cursor - start));
                            AddAssignments(values[1], values[2], callRva, assignments);
                        }
                        foreach (int volatileRegister in new[] { 0, 1, 2, 8, 9, 10, 11 })
                        {
                            values[volatileRegister].Clear();
                            functions[volatileRegister] = null;
                        }
                    }
                }
            }
        }

        private static void ScanX86(
            byte[] image,
            ulong imageBase,
            uint sizeOfHeaders,
            uint[] virtualAddresses,
            uint[] virtualSizes,
            uint[] rawOffsets,
            uint[] rawSizes,
            uint[] executableSectionIndexes,
            HashSet<uint> setVarIatRvas,
            List<CompiledVariableAssignment> assignments)
        {
            var setVarAddresses = new HashSet<uint>();
            foreach (uint iatRva in setVarIatRvas)
            {
                ulong address = imageBase + iatRva;
                if (address <= uint.MaxValue) setVarAddresses.Add((uint)address);
            }

            foreach (uint sectionIndexValue in executableSectionIndexes ?? Array.Empty<uint>())
            {
                int sectionIndex = checked((int)sectionIndexValue);
                int start = checked((int)rawOffsets[sectionIndex]);
                int end = Math.Min(image.Length, checked(start + (int)rawSizes[sectionIndex]));
                var pushedStrings = new List<string>();
                for (int cursor = start; cursor + 6 <= end && assignments.Count < MaxAssignments; cursor++)
                {
                    if (image[cursor] == 0x68)
                    {
                        uint address = ReadUInt32(image, cursor + 1);
                        if (address >= imageBase && address - imageBase <= uint.MaxValue)
                        {
                            string value = TryReadWideStringAtRva(image, (uint)(address - imageBase), sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes);
                            if (value != null) pushedStrings.Add(value);
                        }
                        continue;
                    }
                    if (image[cursor] == 0xFF && image[cursor + 1] == 0x15)
                    {
                        uint address = ReadUInt32(image, cursor + 2);
                        if (setVarAddresses.Contains(address) && pushedStrings.Count >= 2)
                        {
                            string name = pushedStrings[pushedStrings.Count - 1];
                            string value = pushedStrings[pushedStrings.Count - 2];
                            uint callRva = checked(virtualAddresses[sectionIndex] + (uint)(cursor - start));
                            AddAssignment(name, value, callRva, assignments);
                        }
                        pushedStrings.Clear();
                    }
                    else if (image[cursor] == 0xE8)
                    {
                        pushedStrings.Clear();
                    }
                }
            }
        }

        private static void AddAssignments(HashSet<string> names, HashSet<string> values, uint callRva, List<CompiledVariableAssignment> assignments)
        {
            if (names.Count > 8 || values.Count > 16) return;
            foreach (string name in names)
            {
                foreach (string value in values) AddAssignment(name, value, callRva, assignments);
            }
        }

        private static void AddAssignment(string name, string value, uint callRva, List<CompiledVariableAssignment> assignments)
        {
            if (!IsVariableName(name) || value == null || value.Length > MaxStringCharacters) return;
            assignments.Add(new CompiledVariableAssignment(name, value, callRva));
        }

        private static List<CompiledVariableAssignment> DeduplicateAssignments(List<CompiledVariableAssignment> assignments)
        {
            var result = new List<CompiledVariableAssignment>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (CompiledVariableAssignment assignment in assignments)
            {
                string identity = assignment.Name + "\0" + assignment.Value + "\0" + assignment.CallRva.ToString("X8");
                if (seen.Add(identity)) result.Add(assignment);
            }
            return result;
        }

        private static bool IsVariableName(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 128) return false;
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                if (!(character == '_' || char.IsLetterOrDigit(character))) return false;
            }
            return true;
        }

        private static List<string> FindUninstallProductCodes(byte[] image)
        {
            const string prefix = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
            byte[] pattern = Encoding.Unicode.GetBytes(prefix);
            var result = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int offset = 0; offset + pattern.Length + 2 <= image.Length; offset++)
            {
                if (!Matches(image, offset, pattern)) continue;
                int valueOffset = offset + pattern.Length;
                string productCode = ReadWideString(image, valueOffset);
                if (string.IsNullOrWhiteSpace(productCode) || productCode.IndexOf('%') >= 0 || productCode.IndexOf('\\') >= 0 || productCode.IndexOf('/') >= 0) continue;
                if (seen.Add(productCode)) result.Add(productCode);
            }
            return result;
        }

        private static string TryReadWideStringAtRva(byte[] image, uint rva, uint sizeOfHeaders, uint[] virtualAddresses, uint[] virtualSizes, uint[] rawOffsets, uint[] rawSizes)
        {
            int offset;
            try { offset = MapRva(rva, 2, image.Length, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes); }
            catch (InvalidOperationException) { return null; }
            string value = ReadWideString(image, offset);
            if (value == null) return null;
            foreach (char character in value)
            {
                if (char.IsControl(character)) return null;
            }
            return value;
        }

        private static string ReadWideString(byte[] image, int offset)
        {
            if (offset < 0 || offset + 1 >= image.Length) return null;
            int end = offset;
            int maximumEnd = Math.Min(image.Length - 1, offset + MaxStringCharacters * 2);
            while (end + 1 <= maximumEnd && (image[end] != 0 || image[end + 1] != 0)) end += 2;
            if (end + 1 > maximumEnd) return null;
            return Encoding.Unicode.GetString(image, offset, end - offset);
        }

        private static string ReadAsciiStringAtRva(byte[] image, uint rva, uint sizeOfHeaders, uint[] virtualAddresses, uint[] virtualSizes, uint[] rawOffsets, uint[] rawSizes)
        {
            int offset = MapRva(rva, 1, image.Length, sizeOfHeaders, virtualAddresses, virtualSizes, rawOffsets, rawSizes);
            return ReadAsciiString(image, offset);
        }

        private static string ReadAsciiString(byte[] image, int offset)
        {
            int end = offset;
            int maximumEnd = Math.Min(image.Length, offset + MaxStringCharacters);
            while (end < maximumEnd && image[end] != 0) end++;
            if (end == maximumEnd) throw new InvalidOperationException("Paquet Builder PE string is unterminated.");
            return Encoding.ASCII.GetString(image, offset, end - offset);
        }

        private static bool IsPbCoreName(string value)
        {
            return !string.IsNullOrEmpty(value) && value.StartsWith("pbcore", StringComparison.OrdinalIgnoreCase) && value.EndsWith(".dll", StringComparison.OrdinalIgnoreCase);
        }

        private static uint ToRva(ulong value, ulong imageBase, bool isRva)
        {
            if (isRva)
            {
                if (value > uint.MaxValue) throw new InvalidOperationException("Paquet Builder import RVA exceeds the PE address space.");
                return (uint)value;
            }
            if (value < imageBase || value - imageBase > uint.MaxValue) throw new InvalidOperationException("Paquet Builder import VA is outside the PE image.");
            return (uint)(value - imageBase);
        }

        private static int MapRva(uint rva, int requiredBytes, int imageLength, uint sizeOfHeaders, uint[] virtualAddresses, uint[] virtualSizes, uint[] rawOffsets, uint[] rawSizes)
        {
            if (rva < sizeOfHeaders)
            {
                if ((ulong)rva + (uint)requiredBytes > (ulong)imageLength) throw new InvalidOperationException("PE header RVA is outside the mapped image.");
                return checked((int)rva);
            }
            for (int index = 0; index < virtualAddresses.Length; index++)
            {
                uint span = Math.Max(virtualSizes[index], rawSizes[index]);
                if (rva < virtualAddresses[index] || (ulong)rva >= (ulong)virtualAddresses[index] + span) continue;
                uint relative = rva - virtualAddresses[index];
                if ((ulong)relative + (uint)requiredBytes > rawSizes[index]) throw new InvalidOperationException("PE RVA points into an unbacked virtual section range.");
                ulong offset = (ulong)rawOffsets[index] + relative;
                if (offset + (uint)requiredBytes > (ulong)imageLength) throw new InvalidOperationException("PE RVA points outside the mapped image.");
                return checked((int)offset);
            }
            throw new InvalidOperationException("PE RVA does not map to a section.");
        }

        private static int CheckedEnd(int offset, uint length, int imageLength)
        {
            ulong end = (ulong)(uint)offset + length;
            if (end > (ulong)imageLength) throw new InvalidOperationException("PE directory exceeds the mapped image.");
            return checked((int)end);
        }

        private static bool TryAddDisplacement(uint rva, int instructionLength, int displacement, out uint value)
        {
            long result = (long)rva + instructionLength + displacement;
            if (result < 0 || result > uint.MaxValue)
            {
                value = 0;
                return false;
            }
            value = (uint)result;
            return true;
        }

        private static void CopySet(HashSet<string> source, HashSet<string> destination)
        {
            destination.Clear();
            destination.UnionWith(source);
        }

        private static bool Matches(byte[] image, int offset, byte[] pattern)
        {
            for (int index = 0; index < pattern.Length; index++)
            {
                if (image[offset + index] != pattern[index]) return false;
            }
            return true;
        }

        private static ushort ReadUInt16(byte[] image, int offset)
        {
            if (offset < 0 || offset + 2 > image.Length) throw new InvalidOperationException("PE record is truncated.");
            return (ushort)(image[offset] | image[offset + 1] << 8);
        }

        private static uint ReadUInt32(byte[] image, int offset)
        {
            if (offset < 0 || offset + 4 > image.Length) throw new InvalidOperationException("PE record is truncated.");
            return (uint)(image[offset] | image[offset + 1] << 8 | image[offset + 2] << 16 | image[offset + 3] << 24);
        }

        private static int ReadInt32(byte[] image, int offset)
        {
            return unchecked((int)ReadUInt32(image, offset));
        }

        private static ulong ReadUInt64(byte[] image, int offset)
        {
            uint low = ReadUInt32(image, offset);
            uint high = ReadUInt32(image, offset + 4);
            return low | ((ulong)high << 32);
        }
    }
}
