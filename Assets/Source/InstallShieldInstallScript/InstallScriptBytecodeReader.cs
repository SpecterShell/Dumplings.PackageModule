// SPDX-License-Identifier: Apache-2.0
// Independently implemented from binary observations and public InstallShield documentation.
// Historical IsDcc utilities were used only to compare observable decoder behavior.

namespace Dumplings.InstallShield.InstallScript
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;

    public static class InstallScriptBytecodeReader
    {
        private const int OffsetTablePosition = 104;
        private const int InfoStringLength = 74;
        private const int MaximumFunctions = 8192;
        private const int MaximumLabels = 60000;
        private const int MaximumTypes = 4096;
        private const int MaximumTypeFields = 32768;
        private const int MaximumParameters = 1024;
        private const int MaximumStringBytes = 32768;
        private const int DefaultMaximumInstructions = 1000000;

        private static readonly Dictionary<int, string> OperationNames = new Dictionary<int, string>
        {
            { 0x0000, "UnknownOperation" }, { 0x0001, "Goto" }, { 0x0002, "Abort" },
            { 0x0003, "Exit" }, { 0x0004, "IfFalse" }, { 0x0005, "GotoAbsolute" },
            { 0x0006, "Assign" }, { 0x0007, "Add" }, { 0x0008, "Modulo" },
            { 0x0009, "LessThan" }, { 0x000A, "GreaterThan" },
            { 0x000B, "LessThanOrEqual" }, { 0x000C, "GreaterThanOrEqual" },
            { 0x000D, "Equal" }, { 0x000E, "NotEqual" }, { 0x000F, "Subtract" },
            { 0x0010, "Multiply" }, { 0x0011, "Divide" }, { 0x0012, "BitAnd" },
            { 0x0013, "BitOr" }, { 0x0014, "ConcatOrXor" }, { 0x0015, "BitNot" },
            { 0x0016, "ShiftLeft" }, { 0x0017, "ShiftRight" },
            { 0x0018, "LogicalOr" }, { 0x0019, "LogicalAnd" },
            { 0x001A, "AddressOf" }, { 0x001B, "Indirect" }, { 0x001C, "Pointer" },
            { 0x001D, "StringWrite" }, { 0x001E, "StringRead" },
            { 0x0020, "CallDll" }, { 0x0021, "Call" }, { 0x0022, "FunctionStart" },
            { 0x0023, "Return" }, { 0x0024, "Return" }, { 0x0025, "Return" },
            { 0x0026, "FunctionEnd" }, { 0x0027, "FreeLocalVariable" },
            { 0x0028, "StringLength" }, { 0x0029, "StringSubstring" },
            { 0x002A, "StringFind" }, { 0x002B, "StringCompare" },
            { 0x002C, "StringToNumber" }, { 0x002D, "NumberToString" },
            { 0x002F, "Handler" }, { 0x0030, "ExecuteHandler" },
            { 0x0031, "Resize" }, { 0x0032, "SizeOf" }, { 0x0033, "MemberWrite" },
            { 0x0034, "AssignMember" }, { 0x0035, "MemberRead" }, { 0x0036, "Try" },
            { 0x0037, "Catch" }, { 0x0038, "EndCatch" }, { 0x0039, "UseDll" },
            { 0x003A, "UnuseDll" }, { 0x003B, "ObservedSpecial" },
            { 0x003C, "ObservedStringPointer" }, { 0x003D, "ObservedMemberReference" },
            { 0x0129, "EndCodeSegment" }
        };

        /// <summary>
        /// Parses decoded INX bytes. The caller owns the byte array; no imported function is invoked.
        /// </summary>
        public static InstallScriptProgram Read(byte[] bytes, int maximumInstructions)
        {
            if (bytes == null) throw new ArgumentNullException("bytes");
            if (bytes.Length < 128) throw new InvalidDataException("The decoded InstallScript header is truncated.");
            if (maximumInstructions <= 0) maximumInstructions = DefaultMaximumInstructions;

            var reader = new BoundedReader(bytes);
            var program = new InstallScriptProgram();
            program.HeaderValue = reader.ReadUInt32();
            reader.ReadUInt16();
            program.InfoString = reader.ReadAscii(InfoStringLength).TrimEnd('\0');

            reader.Position = OffsetTablePosition;
            var offsets = new uint[5];
            for (var index = 0; index < offsets.Length; index++) offsets[index] = reader.ReadUInt32();
            reader.ReadUInt16();

            program.CatalogOffset = offsets[2];
            program.EndCodeOffset = offsets[4] == 0 ? bytes.LongLength : offsets[4];
            ValidateRange(program.CatalogOffset, 2, bytes.LongLength, "catalog");
            ValidateRange(program.EndCodeOffset, 0, bytes.LongLength, "code segment end");
            if (program.EndCodeOffset <= program.CatalogOffset)
                throw new InvalidDataException("The InstallScript code segment ends before its catalog.");

            reader.Position = program.CatalogOffset;
            program.DataTypeCount = reader.ReadUInt16();
            if (program.DataTypeCount > MaximumTypes) throw new InvalidDataException("The InstallScript type count exceeds the parser limit.");
            SkipTypeCatalog(reader, program.DataTypeCount);

            var functionCount = reader.ReadUInt16();
            if (functionCount > MaximumFunctions) throw new InvalidDataException("The InstallScript function count exceeds the parser limit.");
            for (var index = 0; index < functionCount; index++) program.Functions.Add(ReadFunction(reader, index));

            var labelCount = reader.ReadUInt16();
            if (labelCount > MaximumLabels) throw new InvalidDataException("The InstallScript label count exceeds the parser limit.");
            for (var index = 0; index < labelCount; index++)
            {
                var offset = reader.ReadUInt32();
                if (offset >= bytes.LongLength) throw new InvalidDataException("An InstallScript label points outside the file.");
                program.LabelOffsets.Add(offset);
            }

            foreach (var function in program.Functions)
            {
                if (function.LabelIndex == 0xFFFF) continue;
                if (function.LabelIndex < 0 || function.LabelIndex >= program.LabelOffsets.Count)
                {
                    program.Warnings.Add("Function " + function.Name + " has an invalid entry label index.");
                    continue;
                }
                function.StartOffset = program.LabelOffsets[function.LabelIndex];
            }

            program.CodeOffset = reader.Position;
            DecodeBodies(reader, program, maximumInstructions);
            return program;
        }

        public static InstallScriptProgram Read(byte[] bytes)
        {
            return Read(bytes, DefaultMaximumInstructions);
        }

        private static void SkipTypeCatalog(BoundedReader reader, int typeCount)
        {
            var fieldTotal = 0;
            for (var typeIndex = 0; typeIndex < typeCount; typeIndex++)
            {
                var fields = reader.ReadUInt16();
                fieldTotal += fields;
                if (fieldTotal > MaximumTypeFields) throw new InvalidDataException("The InstallScript type-field count exceeds the parser limit.");
                for (var fieldIndex = 0; fieldIndex < fields; fieldIndex++)
                {
                    reader.ReadByte();
                    reader.ReadUInt16();
                    var nameLength = reader.ReadUInt16();
                    if (nameLength > MaximumStringBytes) throw new InvalidDataException("An InstallScript type name exceeds the parser limit.");
                    reader.Skip(nameLength);
                }
            }
        }

        private static InstallScriptFunction ReadFunction(BoundedReader reader, int index)
        {
            var function = new InstallScriptFunction(index);
            function.FunctionType = reader.ReadByte();
            function.ReturnType = reader.ReadByte();
            var dllLength = reader.ReadUInt16();
            if (dllLength > MaximumStringBytes) throw new InvalidDataException("An InstallScript DLL name exceeds the parser limit.");
            function.DllName = reader.ReadAscii(dllLength);
            var nameLength = reader.ReadUInt16();
            if (nameLength > MaximumStringBytes) throw new InvalidDataException("An InstallScript function name exceeds the parser limit.");
            var functionName = reader.ReadAscii(nameLength);
            function.Name = nameLength == 0 ? "function" + index :
                (dllLength == 0 ? functionName : function.DllName + "." + functionName);
            function.LabelIndex = reader.ReadUInt16();
            var parameterCount = reader.ReadUInt16();
            if (parameterCount > MaximumParameters) throw new InvalidDataException("An InstallScript function parameter count exceeds the parser limit.");
            for (var parameterIndex = 0; parameterIndex < parameterCount; parameterIndex++)
            {
                function.Parameters.Add(reader.ReadByte());
                function.ParameterFlags.Add(reader.ReadByte());
            }
            return function;
        }

        private static void DecodeBodies(BoundedReader reader, InstallScriptProgram program, int maximumInstructions)
        {
            var labelsByOffset = new Dictionary<long, List<int>>();
            for (var index = 0; index < program.LabelOffsets.Count; index++)
            {
                List<int> indexes;
                if (!labelsByOffset.TryGetValue(program.LabelOffsets[index], out indexes))
                {
                    indexes = new List<int>();
                    labelsByOffset.Add(program.LabelOffsets[index], indexes);
                }
                indexes.Add(index);
            }

            var functionsByOffset = program.Functions
                .Where(function => function.StartOffset >= 0)
                .GroupBy(function => function.StartOffset)
                .ToDictionary(group => group.Key, group => group.First());
            var bodyOffsets = functionsByOffset.Keys.OrderBy(value => value).ToArray();

            reader.Position = program.CodeOffset;
            var bodyIndex = 0;
            while (reader.Position < program.EndCodeOffset && bodyIndex < bodyOffsets.Length)
            {
                var expectedOffset = bodyOffsets[bodyIndex++];
                if (expectedOffset < reader.Position) continue;
                if (expectedOffset >= program.EndCodeOffset) break;
                reader.Position = expectedOffset;
                var function = functionsByOffset[expectedOffset];

                // Each observed modern body begins with a two-byte prefix before
                // the 0x0022 function-start opcode. Keep the value opaque.
                reader.ReadUInt16();
                var completed = false;
                while (reader.Position < program.EndCodeOffset)
                {
                    if (program.InstructionCount >= maximumInstructions)
                        throw new InvalidDataException("The InstallScript instruction count exceeds the parser limit.");

                    List<int> labelIndexes;
                    if (labelsByOffset.TryGetValue(reader.Position, out labelIndexes))
                    {
                        // The instruction stream stores a two-byte label marker at
                        // every catalogued label position.
                        reader.ReadUInt16();
                    }
                    else
                    {
                        labelIndexes = new List<int>();
                    }

                    var instructionOffset = reader.Position;
                    var opcode = reader.ReadUInt16();
                    var instruction = new InstallScriptInstruction(instructionOffset, opcode, GetOperationName(opcode));
                    instruction.LabelIndexes.AddRange(labelIndexes);
                    function.Instructions.Add(instruction);
                    program.InstructionCount++;

                    try
                    {
                        DecodeInstruction(reader, instruction);
                    }
                    catch (Exception exception) when (exception is InvalidDataException || exception is EndOfStreamException)
                    {
                        instruction.IsOpaque = true;
                        program.Warnings.Add("Function " + function.Name + " could not be decoded after offset 0x" + instructionOffset.ToString("X") + ": " + exception.Message);
                        break;
                    }

                    if (opcode == 0x0026)
                    {
                        completed = true;
                        break;
                    }
                    if (opcode == 0x0129) break;
                }
                function.BodyDecoded = completed;
            }
        }

        private static void DecodeInstruction(BoundedReader reader, InstallScriptInstruction instruction)
        {
            var opcode = instruction.Opcode;
            if (opcode == 0x0020 || opcode == 0x0021)
            {
                instruction.CallTargetIndex = reader.ReadUInt16();
                var count = reader.ReadUInt16();
                if (count > MaximumParameters) throw new InvalidDataException("A call argument count exceeds the parser limit.");
                for (var index = 0; index < count; index++) instruction.Operands.Add(ReadOperand(reader));
                return;
            }
            if (opcode == 0x0022)
            {
                reader.ReadUInt16();
                var marker = reader.ReadByte();
                if (marker != 0x07) throw new InvalidDataException("The function-start marker is invalid.");
                instruction.Operands.Add(new InstallScriptOperand(InstallScriptOperandKind.Integer, reader.ReadInt32(), null, marker));
                return;
            }
            if (opcode == 0x0026)
            {
                reader.ReadUInt16();
                reader.ReadUInt16();
                var firstCount = reader.ReadUInt16();
                if (firstCount > MaximumParameters) throw new InvalidDataException("A function-end table exceeds the parser limit.");
                reader.Skip((long)firstCount * 4);
                reader.ReadUInt16();
                var secondCount = reader.ReadUInt16();
                if (secondCount > MaximumParameters) throw new InvalidDataException("A function-end table exceeds the parser limit.");
                reader.Skip((long)secondCount * 4);
                return;
            }
            if (opcode == 0x0006)
            {
                var count = reader.ReadUInt16();
                if (count == 1)
                {
                    instruction.Destination = new InstallScriptOperand(InstallScriptOperandKind.SystemNumberVariable, reader.ReadUInt16(), null, 0x03);
                }
                else
                {
                    instruction.Destination = ReadOperand(reader);
                    instruction.Operands.Add(ReadOperand(reader));
                }
                return;
            }
            if (opcode == 0x0001 || opcode == 0x0005)
            {
                DecodeBranch(reader, instruction, opcode == 0x0005);
                return;
            }
            if (opcode == 0x0023 || opcode == 0x0024 || opcode == 0x0025 || opcode == 0x0027)
            {
                DecodeReturn(reader, instruction);
                return;
            }
            if (opcode == 0x0002)
            {
                var position = reader.Position;
                var count = reader.ReadUInt16();
                if (count != 0) reader.Position = position;
                return;
            }
            if (opcode == 0x0003)
            {
                var position = reader.Position;
                var count = reader.ReadUInt16();
                if (count > 1) reader.Position = position;
                else for (var index = 0; index < count; index++) reader.ReadUInt16();
                return;
            }
            if (opcode == 0x0129) return;
            // Modern decoder implementations and observed compiler output use
            // the same tagged destination/operand framing for reserved 0x001F,
            // 0x002E, and extension opcodes through 0x0062. Preserve their raw
            // operation identity and operands even when semantics are unknown;
            // the static analyzer reports them as EvidenceOnly rather than
            // assigning invented behavior.
            DecodeGeneric(reader, instruction);
        }

        private static void DecodeGeneric(BoundedReader reader, InstallScriptInstruction instruction)
        {
            var countPosition = reader.Position;
            var encodedCount = reader.ReadUInt16();
            var parameterCount = encodedCount - 1;

            if (instruction.Opcode == 0x001C)
            {
                reader.Position = countPosition;
                instruction.Operands.Add(new InstallScriptOperand(InstallScriptOperandKind.DataType, reader.ReadUInt16(), null, -1));
                instruction.Destination = ReadOperand(reader);
                return;
            }

            // Some expression opcodes are immediately followed by another
            // opcode rather than a count. Implausible arity is the observable
            // discriminator used by supported modern INX generations.
            if ((instruction.Opcode == 0x0004 && parameterCount > 1) ||
                (((instruction.Opcode >= 0x0007 && instruction.Opcode < 0x0020) || instruction.Opcode == 0x002A || instruction.Opcode == 0x002B) && parameterCount > 2))
            {
                reader.Position = countPosition;
                instruction.IsOpaque = true;
                return;
            }

            if (instruction.Opcode == 0x0004 && parameterCount == 1)
            {
                var argumentPosition = reader.Position;
                var value = reader.ReadUInt16();
                if (value == 0)
                {
                    instruction.BranchTarget = 0;
                    return;
                }
                reader.Position = argumentPosition;
            }

            if (parameterCount < 0)
            {
                // Catch/end-catch and several extension records use a zero
                // encoded count as an explicit no-operand form. The record is
                // structurally complete even though the emulator treats its
                // exception semantics as evidence-only.
                if (encodedCount != 0) instruction.IsOpaque = true;
                return;
            }
            if (parameterCount > MaximumParameters)
                throw new InvalidDataException("An instruction operand count exceeds the parser limit.");
            instruction.Destination = ReadOperand(reader);
            for (var index = 0; index < parameterCount; index++) instruction.Operands.Add(ReadOperand(reader));
            if (instruction.Opcode == 0x0004 && instruction.Destination != null)
                instruction.BranchTarget = instruction.Destination.IntegerValue;
        }

        private static void DecodeBranch(BoundedReader reader, InstallScriptInstruction instruction, bool absoluteForm)
        {
            if (absoluteForm)
            {
                var position = reader.Position;
                var count = reader.ReadUInt16();
                if (count == 1)
                {
                    instruction.BranchTarget = ReadTaggedBranchTarget(reader);
                    return;
                }
                reader.Position = position;
                instruction.IsOpaque = true;
                return;
            }

            var tag = reader.ReadByte();
            if (tag == 0)
            {
                reader.ReadByte();
                instruction.BranchTarget = 0;
                return;
            }
            reader.Position--;
            instruction.BranchTarget = ReadTaggedBranchTarget(reader);
        }

        private static int ReadTaggedBranchTarget(BoundedReader reader)
        {
            var tag = reader.ReadByte();
            if (tag == 0x00) return reader.ReadByte() << 8;
            if (tag == 0x70 || tag == 0x80) return reader.ReadUInt16();
            if (tag == 0x07) return reader.ReadInt32();
            throw new InvalidDataException("A branch uses an unknown target tag 0x" + tag.ToString("X2") + ".");
        }

        private static void DecodeReturn(BoundedReader reader, InstallScriptInstruction instruction)
        {
            if (instruction.Opcode == 0x0027)
            {
                reader.ReadUInt16();
                return;
            }
            if (instruction.Opcode == 0x0025) return;
            var position = reader.Position;
            var count = reader.ReadUInt16();
            if (count > 10)
            {
                reader.Position = position;
                instruction.IsOpaque = true;
                return;
            }
            for (var index = 0; index < count; index++) instruction.Operands.Add(ReadOperand(reader));
        }

        private static InstallScriptOperand ReadOperand(BoundedReader reader)
        {
            var tag = reader.ReadByte();
            switch (tag)
            {
                case 0x00:
                    return new InstallScriptOperand(InstallScriptOperandKind.Integer, reader.ReadByte(), null, tag);
                case 0x06:
                    var length = reader.ReadUInt16();
                    if (length > MaximumStringBytes) throw new InvalidDataException("An instruction string exceeds the parser limit.");
                    return new InstallScriptOperand(InstallScriptOperandKind.String, 0, reader.ReadAscii(length), tag);
                case 0x07:
                    return new InstallScriptOperand(InstallScriptOperandKind.Integer, reader.ReadInt32(), null, tag);
                case 0x02:
                    return new InstallScriptOperand(InstallScriptOperandKind.UserStringVariable, reader.ReadUInt16(), null, tag);
                case 0x03:
                    return new InstallScriptOperand(InstallScriptOperandKind.UserNumberVariable, reader.ReadUInt16(), null, tag);
                case 0x04:
                    return new InstallScriptOperand(InstallScriptOperandKind.LocalStringVariable, NormalizeLocalIndex(reader.ReadUInt16()), null, tag);
                case 0x05:
                    return new InstallScriptOperand(InstallScriptOperandKind.LocalNumberVariable, NormalizeLocalIndex(reader.ReadUInt16()), null, tag);
                case 0x08:
                    return new InstallScriptOperand(InstallScriptOperandKind.UserNumberVariable, NormalizeLocalIndex(reader.ReadUInt16()), null, tag);
                case 0x0A:
                    return new InstallScriptOperand(InstallScriptOperandKind.Label, reader.ReadUInt16(), null, tag);
                default:
                    throw new InvalidDataException("An instruction uses an unknown operand tag 0x" + tag.ToString("X2") + ".");
            }
        }

        private static int NormalizeLocalIndex(int encodedIndex)
        {
            var candidate = 0xFF9B - encodedIndex;
            return candidate >= 0 && candidate < 0x8000 ? candidate : encodedIndex;
        }

        private static string GetOperationName(int opcode)
        {
            string value;
            return OperationNames.TryGetValue(opcode, out value) ? value : "Opcode0x" + opcode.ToString("X4");
        }

        private static void ValidateRange(long offset, long length, long total, string name)
        {
            if (offset < 0 || length < 0 || offset > total || length > total - offset)
                throw new InvalidDataException("The InstallScript " + name + " range is outside the file.");
        }

        private sealed class BoundedReader
        {
            private readonly byte[] bytes;
            private long position;

            internal BoundedReader(byte[] bytes) { this.bytes = bytes; }

            internal long Position
            {
                get { return position; }
                set
                {
                    if (value < 0 || value > bytes.LongLength) throw new EndOfStreamException("An InstallScript offset is outside the file.");
                    position = value;
                }
            }

            internal byte ReadByte()
            {
                Ensure(1);
                return bytes[position++];
            }

            internal ushort ReadUInt16()
            {
                Ensure(2);
                var result = (ushort)(bytes[position] | (bytes[position + 1] << 8));
                position += 2;
                return result;
            }

            internal uint ReadUInt32()
            {
                Ensure(4);
                var result = (uint)(bytes[position] | (bytes[position + 1] << 8) |
                    (bytes[position + 2] << 16) | (bytes[position + 3] << 24));
                position += 4;
                return result;
            }

            internal int ReadInt32() { return unchecked((int)ReadUInt32()); }

            internal string ReadAscii(int length)
            {
                if (length < 0) throw new InvalidDataException("A string length is negative.");
                Ensure(length);
                var value = Encoding.ASCII.GetString(bytes, checked((int)position), length);
                position += length;
                return value;
            }

            internal void Skip(long length)
            {
                if (length < 0) throw new InvalidDataException("A record length is negative.");
                Ensure(length);
                position += length;
            }

            private void Ensure(long length)
            {
                if (length < 0 || position < 0 || position > bytes.LongLength || length > bytes.LongLength - position)
                    throw new EndOfStreamException("The InstallScript record is truncated.");
            }
        }
    }
}
