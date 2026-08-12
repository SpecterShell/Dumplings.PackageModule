// SPDX-License-Identifier: Apache-2.0
// OBS framing is adapted from the MIT-licensed InstallScript Decompiler:
// https://github.com/jte/installscript-decompiler

namespace Dumplings.InstallShield.InstallScript
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;

    /// <summary>
    /// Reads an InstallScript OBS object module. OBS files are compiler/linker
    /// inputs and use a fixed 0x100-byte header whose table offsets differ from
    /// the linked aLuZ/kUtZ program header consumed by InstallScriptBytecodeReader.
    /// </summary>
    internal static class InstallScriptObjectBytecodeReader
    {
        private const uint Signature = 0xC9F34F48;
        private const int HeaderSize = 0x100;
        private const int MaximumBasicBlocks = 60000;
        private const int MaximumFunctions = 8192;
        private const int MaximumExternals = 32768;
        private const int MaximumAddressResolutions = 60000;
        private const int MaximumTypes = 4096;
        private const int MaximumTypeFields = 32768;
        private const int MaximumParameters = 1024;
        private const int MaximumStringBytes = 32768;

        internal static bool IsObjectModule(byte[] bytes)
        {
            return bytes != null && bytes.Length >= 4 &&
                ReadUInt32(bytes, 0) == Signature;
        }

        internal static InstallScriptProgram Read(byte[] bytes, int maximumInstructions)
        {
            if (!IsObjectModule(bytes))
                throw new InvalidDataException("The input is not an InstallScript OBS object module.");
            if (bytes.Length < HeaderSize)
                throw new InvalidDataException("The InstallScript OBS header is truncated.");
            if (maximumInstructions <= 0) maximumInstructions = 1000000;

            var program = new InstallScriptProgram();
            program.HeaderValue = Signature;
            program.FormatProfile = "OBS Object Module";
            program.CompilerVersion = ReadFixedAscii(bytes, 0x04, 12);
            program.InfoString = ReadFixedAscii(bytes, 0x10, 80);

            var basicBlockCount = ReadUInt16(bytes, 0x62);
            if (basicBlockCount > MaximumBasicBlocks)
                throw new InvalidDataException("The InstallScript OBS basic-block count exceeds the parser limit.");

            var stringTableOffset = ReadUInt32(bytes, 0x7C);
            var variantTableOffset = ReadUInt32(bytes, 0x80);
            var externTableOffset = ReadUInt32(bytes, 0x84);
            var prototypesTableOffset = ReadUInt32(bytes, 0x88);
            var typedefsTableOffset = ReadUInt32(bytes, 0x8C);
            var addressResolveTableOffset = ReadUInt32(bytes, 0x90);
            var basicBlocksTableOffset = ReadUInt32(bytes, 0xD8);

            ValidateTableOffset(prototypesTableOffset, bytes.LongLength, "prototype");
            ValidateTableOffset(typedefsTableOffset, bytes.LongLength, "type-definition");
            ValidateTableOffset(basicBlocksTableOffset, bytes.LongLength, "basic-block");
            ValidateOptionalTableOffset(stringTableOffset, bytes.LongLength, "string-variable");
            ValidateOptionalTableOffset(variantTableOffset, bytes.LongLength, "variant-variable");
            ValidateOptionalTableOffset(externTableOffset, bytes.LongLength, "external-symbol");
            ValidateOptionalTableOffset(addressResolveTableOffset, bytes.LongLength, "address-resolution");

            program.CatalogOffset = new long[]
            {
                prototypesTableOffset, typedefsTableOffset, basicBlocksTableOffset,
                stringTableOffset, variantTableOffset, externTableOffset, addressResolveTableOffset
            }.Where(value => value != 0).Min();
            program.EndCodeOffset = bytes.LongLength;

            ReadTypeCatalog(bytes, typedefsTableOffset, program);
            ReadPrototypeCatalog(bytes, prototypesTableOffset, program);
            ReadExternalSymbols(bytes, externTableOffset, program);
            ReadAddressResolutions(bytes, addressResolveTableOffset, program);
            ReadBasicBlocks(bytes, basicBlocksTableOffset, basicBlockCount, maximumInstructions, program);
            return program;
        }

        private static void ReadTypeCatalog(byte[] bytes, long tableOffset, InstallScriptProgram program)
        {
            var reader = CreateReader(bytes, tableOffset);
            var typeCount = reader.ReadUInt16();
            if (typeCount > MaximumTypes)
                throw new InvalidDataException("The InstallScript OBS type count exceeds the parser limit.");
            program.DataTypeCount = typeCount;

            var totalFields = 0;
            for (var typeIndex = 0; typeIndex < typeCount; typeIndex++)
            {
                ReadString(reader, "type name");
                var fieldCount = reader.ReadUInt16();
                totalFields = checked(totalFields + fieldCount);
                if (totalFields > MaximumTypeFields)
                    throw new InvalidDataException("The InstallScript OBS type-field count exceeds the parser limit.");
                for (var fieldIndex = 0; fieldIndex < fieldCount; fieldIndex++)
                {
                    reader.ReadByte();
                    reader.ReadUInt16();
                    ReadString(reader, "type-field name");
                }
            }
        }

        private static void ReadPrototypeCatalog(byte[] bytes, long tableOffset, InstallScriptProgram program)
        {
            var reader = CreateReader(bytes, tableOffset);
            var functionCount = reader.ReadUInt16();
            if (functionCount > MaximumFunctions)
                throw new InvalidDataException("The InstallScript OBS prototype count exceeds the parser limit.");

            for (var index = 0; index < functionCount; index++)
            {
                var function = new InstallScriptFunction(index);
                var flags = reader.ReadByte();
                function.Flags = flags;

                if ((flags & 0x04) != 0)
                {
                    function.FunctionType = 4;
                    function.Name = "predefined" + index;
                    program.Functions.Add(function);
                    continue;
                }

                if ((flags & 0x01) != 0)
                {
                    function.FunctionType = 1;
                    function.ReturnType = reader.ReadByte();
                    function.DllName = ReadString(reader, "DLL name");
                    var name = ReadString(reader, "DLL function name");
                    function.Name = string.IsNullOrEmpty(function.DllName) ? name : function.DllName + "." + name;
                    function.LabelIndex = reader.ReadUInt16();
                    ReadParameters(reader, function);
                }
                else if ((flags & 0x02) != 0)
                {
                    function.FunctionType = 2;
                    function.ReturnType = reader.ReadByte();
                    reader.ReadUInt16(); // Linker alignment/reserved value.
                    var name = ReadString(reader, "internal function name");
                    function.Name = string.IsNullOrEmpty(name) ? "function" + index : name;
                    function.LabelIndex = reader.ReadUInt16();
                    ReadParameters(reader, function);
                }
                else
                {
                    throw new InvalidDataException("The InstallScript OBS prototype uses unsupported flags 0x" + flags.ToString("X2") + ".");
                }
                program.Functions.Add(function);
            }
        }

        private static void ReadParameters(InstallScriptBytecodeReader.BoundedReader reader, InstallScriptFunction function)
        {
            var parameterCount = reader.ReadUInt16();
            if (parameterCount > MaximumParameters)
                throw new InvalidDataException("An InstallScript OBS prototype parameter count exceeds the parser limit.");
            for (var index = 0; index < parameterCount; index++)
            {
                function.Parameters.Add(reader.ReadByte());
                function.ParameterFlags.Add(reader.ReadByte());
            }
        }

        private static void ReadExternalSymbols(byte[] bytes, long tableOffset, InstallScriptProgram program)
        {
            if (tableOffset == 0) return;
            var reader = CreateReader(bytes, tableOffset);
            var count = reader.ReadUInt16();
            if (count > MaximumExternals)
                throw new InvalidDataException("The InstallScript OBS external-symbol count exceeds the parser limit.");
            for (var index = 0; index < count; index++)
            {
                var type = reader.ReadByte();
                var address = unchecked((short)reader.ReadUInt16());
                program.ExternalSymbols.Add(new InstallScriptExternalSymbol(type, address, ReadString(reader, "external-symbol name")));
            }
        }

        private static void ReadAddressResolutions(byte[] bytes, long tableOffset, InstallScriptProgram program)
        {
            if (tableOffset == 0) return;
            var reader = CreateReader(bytes, tableOffset);
            var count = reader.ReadUInt16();
            if (count > MaximumAddressResolutions)
                throw new InvalidDataException("The InstallScript OBS address-resolution count exceeds the parser limit.");
            for (var index = 0; index < count; index++)
            {
                var type = reader.ReadByte();
                var offset = reader.ReadUInt32();
                if (offset >= bytes.LongLength)
                    throw new InvalidDataException("An InstallScript OBS address-resolution record points outside the object module.");
                program.AddressResolutions.Add(new InstallScriptAddressResolution(type, offset));
            }
        }

        private static void ReadBasicBlocks(byte[] bytes, long tableOffset, int basicBlockCount, int maximumInstructions, InstallScriptProgram program)
        {
            var table = CreateReader(bytes, tableOffset);
            var blockOffsets = new long[basicBlockCount];
            for (var index = 0; index < basicBlockCount; index++)
            {
                blockOffsets[index] = table.ReadUInt32();
                ValidateTableOffset(blockOffsets[index], bytes.LongLength, "basic-block record");
                program.LabelOffsets.Add(blockOffsets[index]);
            }
            program.CodeOffset = blockOffsets.Length == 0 ? bytes.LongLength : blockOffsets.Min();

            var functionsByBlock = program.Functions
                .Where(function => function.LabelIndex >= 0 && function.LabelIndex != 0xFFFF)
                .GroupBy(function => function.LabelIndex)
                .ToDictionary(group => group.Key, group => group.First());
            var blockBoundaries = blockOffsets
                .Concat(new long[] { bytes.LongLength })
                .Distinct()
                .OrderBy(offset => offset)
                .ToArray();
            InstallScriptFunction currentFunction = null;
            var failedFunctions = new HashSet<int>();

            for (var blockIndex = 0; blockIndex < blockOffsets.Length; blockIndex++)
            {
                InstallScriptFunction entryFunction;
                if (functionsByBlock.TryGetValue(blockIndex, out entryFunction))
                {
                    currentFunction = entryFunction;
                    currentFunction.StartOffset = blockOffsets[blockIndex];
                }

                var blockStart = blockOffsets[blockIndex];
                var blockEnd = blockBoundaries.First(offset => offset > blockStart);
                var reader = new InstallScriptBytecodeReader.BoundedReader(bytes, blockStart, blockEnd - blockStart);
                var actionCount = reader.ReadUInt16();
                if (actionCount > maximumInstructions - program.InstructionCount)
                    throw new InvalidDataException("The InstallScript OBS instruction count exceeds the parser limit.");

                for (var actionIndex = 0; actionIndex < actionCount; actionIndex++)
                {
                    var instructionOffset = reader.Position;
                    InstallScriptInstruction instruction = null;
                    try
                    {
                        var sourceOpcode = reader.ReadUInt16();
                        var opcode = NormalizeOpcode(sourceOpcode);
                        instruction = new InstallScriptInstruction(instructionOffset, opcode, GetObjectOperationName(sourceOpcode, opcode));
                        instruction.SourceOpcode = sourceOpcode;
                        if (actionIndex == 0) instruction.LabelIndexes.Add(blockIndex);
                        if (currentFunction != null) currentFunction.Instructions.Add(instruction);
                        program.InstructionCount++;
                        DecodeObjectInstruction(reader, instruction);
                    }
                    catch (Exception exception) when (exception is InvalidDataException || exception is EndOfStreamException || exception is OverflowException)
                    {
                        if (instruction != null) instruction.IsOpaque = true;
                        if (currentFunction != null) failedFunctions.Add(currentFunction.Index);
                        program.Warnings.Add("OBS block " + blockIndex + " could not be decoded after offset 0x" + instructionOffset.ToString("X") + ": " + exception.Message);
                        break;
                    }
                }
            }

            foreach (var function in program.Functions.Where(function => function.Instructions.Count != 0))
                function.BodyDecoded = !failedFunctions.Contains(function.Index);
        }

        private static void DecodeObjectInstruction(InstallScriptBytecodeReader.BoundedReader reader, InstallScriptInstruction instruction)
        {
            if (instruction.Opcode == 0x0020 || instruction.Opcode == 0x0021)
            {
                instruction.CallTargetIndex = reader.ReadUInt16();
                var count = reader.ReadUInt16();
                ReadArguments(reader, instruction, count, false);
                return;
            }
            if (instruction.Opcode == 0x001C || instruction.Opcode == 0x0022 || instruction.Opcode == 0x0026)
            {
                InstallScriptBytecodeReader.DecodeInstruction(reader, instruction);
                return;
            }

            var argumentCount = reader.ReadUInt16();
            if (argumentCount > MaximumParameters)
                throw new InvalidDataException("An InstallScript OBS action argument count exceeds the parser limit.");
            ReadArguments(reader, instruction, argumentCount, HasDestination(instruction.Opcode));

            if ((instruction.Opcode == 0x0004 || instruction.Opcode == 0x0005) && instruction.Destination != null)
                instruction.BranchTarget = instruction.Destination.IntegerValue;
        }

        private static void ReadArguments(InstallScriptBytecodeReader.BoundedReader reader, InstallScriptInstruction instruction, int count, bool firstIsDestination)
        {
            if (count > MaximumParameters)
                throw new InvalidDataException("An InstallScript OBS action argument count exceeds the parser limit.");
            for (var index = 0; index < count; index++)
            {
                var argument = InstallScriptBytecodeReader.ReadOperand(reader);
                if (index == 0 && firstIsDestination) instruction.Destination = argument;
                else instruction.Operands.Add(argument);
            }
        }

        private static bool HasDestination(int opcode)
        {
            return opcode == 0x0004 || opcode == 0x0005 ||
                (opcode >= 0x0006 && opcode <= 0x001E) ||
                (opcode >= 0x0031 && opcode <= 0x0035) || opcode == 0x003B || opcode == 0x003C;
        }

        private static int NormalizeOpcode(int sourceOpcode)
        {
            // OBS compiler actions use a related, but not identical, opcode
            // vocabulary. Normalize only differences proven by the source-backed
            // action factory; linked aLuZ/kUtZ programs keep their own mapping.
            if (sourceOpcode == 0x0001) return 0x0027; // OBS NOP.
            if (sourceOpcode == 0x0018) return 0x0019; // OBS logical AND.
            if (sourceOpcode == 0x0019) return 0x0018; // OBS logical OR.
            return sourceOpcode;
        }

        private static string GetObjectOperationName(int sourceOpcode, int normalizedOpcode)
        {
            switch (sourceOpcode)
            {
                case 0x0001: return "Nop";
                case 0x0005: return "Goto";
                case 0x0018: return "LogicalAnd";
                case 0x0019: return "LogicalOr";
                case 0x001C: return "IndirectStruct";
                case 0x001D: return "SetByte";
                case 0x001E: return "GetByte";
                case 0x002E: return "Handler";
                case 0x002F: return "HandlerEx";
                case 0x0033: return "PropertyPut";
                case 0x0034: return "PropertyPutReference";
                case 0x0035: return "PropertyGet";
                case 0x0037: return "EndTry";
                case 0x003B: return "BindVariable";
                case 0x003C: return "AddressOfWide";
                default: return InstallScriptBytecodeReader.GetOperationName(normalizedOpcode);
            }
        }

        private static string ReadString(InstallScriptBytecodeReader.BoundedReader reader, string field)
        {
            var length = reader.ReadUInt16();
            if (length > MaximumStringBytes)
                throw new InvalidDataException("An InstallScript OBS " + field + " exceeds the parser limit.");
            return reader.ReadAscii(length);
        }

        private static InstallScriptBytecodeReader.BoundedReader CreateReader(byte[] bytes, long offset)
        {
            var reader = new InstallScriptBytecodeReader.BoundedReader(bytes);
            reader.Position = offset;
            return reader;
        }

        private static string ReadFixedAscii(byte[] bytes, int offset, int length)
        {
            ValidateRange(offset, length, bytes.LongLength, "fixed header string");
            return System.Text.Encoding.ASCII.GetString(bytes, offset, length).TrimEnd('\0');
        }

        private static ushort ReadUInt16(byte[] bytes, int offset)
        {
            ValidateRange(offset, 2, bytes.LongLength, "header field");
            return (ushort)(bytes[offset] | (bytes[offset + 1] << 8));
        }

        private static uint ReadUInt32(byte[] bytes, int offset)
        {
            ValidateRange(offset, 4, bytes.LongLength, "header field");
            return (uint)(bytes[offset] | (bytes[offset + 1] << 8) |
                (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24));
        }

        private static void ValidateTableOffset(long offset, long total, string name)
        {
            ValidateRange(offset, 2, total, name + " table");
        }

        private static void ValidateOptionalTableOffset(long offset, long total, string name)
        {
            if (offset != 0) ValidateTableOffset(offset, total, name);
        }

        private static void ValidateRange(long offset, long length, long total, string name)
        {
            if (offset < 0 || length < 0 || offset > total || length > total - offset)
                throw new InvalidDataException("The InstallScript OBS " + name + " range is outside the object module.");
        }
    }
}
