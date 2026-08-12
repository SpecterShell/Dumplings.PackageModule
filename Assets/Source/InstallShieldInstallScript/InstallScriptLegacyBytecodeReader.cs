// SPDX-License-Identifier: Apache-2.0
// The old INS table order and action framing were independently adapted from
// the MIT-licensed https://github.com/jte/installscript-decompiler old frontend.

namespace Dumplings.InstallShield.InstallScript
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;

    /// <summary>
    /// Reads the pre-OBS InstallScript INS stream used by InstallShield 3-era
    /// media. Actions are normalized to the existing bounded interpreter where
    /// their semantics are source-backed; all other framed actions remain
    /// opaque evidence and are never executed.
    /// </summary>
    public static class InstallScriptLegacyBytecodeReader
    {
        private const int MaximumEvents = 60000;
        private const int MaximumFunctions = 8192;
        private const int MaximumParameters = 1024;
        private const int MaximumRecords = 1000000;
        private const int MaximumStringBytes = 32768;

        // The low nibble is the number of tagged operands for ordinary old-INS
        // actions. High-nibble flags belong to the historical runtime. FF/F0
        // entries have no safe generic framing and therefore stop that event.
        private static readonly byte[] OperandCounts = Convert.FromBase64String(
            "/wEBAgMBAAACAgEBAUMCAoGDggICAQIBBAMC/4IBA4HAAgQCA4QEBCIDAgAB/wIBBAICYgICBQICAgECAwICAgQCAgEABAMBAQMDBAEBAwMCAgEBAwMEAQICAQEBBAUEAgMBAQIBAQIEAwMEhAICAQIBAgIEAgICAgUDAwQEAQICAgEBAgECAQECAghBAQECAwMDAgMDAgQCAwEBAQEBAQEDAgMCAgICAQICAgMDA////wEB8PDwAQABAQEFBQUF////////AQIBCAIDCAMBAQkBQQECggEEAgMCAgMDBQQDAwJDAwIEBQMCAwUCAYSFAwMDAQICAQIBBIMCAgICAQEDA/DwAwMFAQECAQIBAwMBAQMEAQICAwIDAwMDAwMDAwMDAwMDAwMEAAIBAQLwAAUFAAAAAABERUMIRAEBAsIBBAQJQgQEAgJEBAIDQwIBAgUFAUECAwNEAAIBAQUFAwQEBAcDAwIDAwADAQLwAgEEAQMFBQYEBQKDggUDAwEFBQUFBQUBBAIEAgICBAQCAQECAwIFAQQD");

        private static readonly Dictionary<int, Tuple<int, string>> NormalizedOperations =
            new Dictionary<int, Tuple<int, string>>
        {
            { 0x0013, Tuple.Create(0x0006, "Assign") },
            { 0x0021, Tuple.Create(0x0006, "Assign") },
            { 0x0022, Tuple.Create(0x0004, "IfFalse") },
            { 0x002B, Tuple.Create(0x0003, "Exit") },
            { 0x002C, Tuple.Create(0x0005, "GotoAbsolute") },
            { 0x00B4, Tuple.Create(0x0020, "CallDll") },
            { 0x00B5, Tuple.Create(0x0021, "Call") },
            { 0x00B7, Tuple.Create(0x0023, "Return") },
            { 0x00B8, Tuple.Create(0x0025, "Return") },
            { 0x0112, Tuple.Create(0x0006, "AssignStringConstant") },
            { 0x0119, Tuple.Create(0x0007, "Add") },
            { 0x011A, Tuple.Create(0x000F, "Subtract") },
            { 0x011B, Tuple.Create(0x0010, "Multiply") },
            { 0x011C, Tuple.Create(0x0011, "Divide") },
            { 0x011D, Tuple.Create(0x0012, "BitAnd") },
            { 0x011E, Tuple.Create(0x0013, "BitOr") },
            { 0x011F, Tuple.Create(0x0014, "BitXor") },
            { 0x0120, Tuple.Create(0x0015, "BitNot") },
            { 0x0121, Tuple.Create(0x0016, "ShiftLeft") },
            { 0x0122, Tuple.Create(0x0017, "ShiftRight") },
            { 0x0123, Tuple.Create(0x0008, "Modulo") },
            { 0x0126, Tuple.Create(0x0018, "LogicalOr") },
            { 0x0127, Tuple.Create(0x0019, "LogicalAnd") },
            { 0x0128, Tuple.Create(0x0000, "LegacyDefinedBinary") },
            { 0x012F, Tuple.Create(0x0000, "Nop") },
            { 0x0181, Tuple.Create(0x0035, "PropertyGet") },
            { 0x0183, Tuple.Create(0x0033, "PropertyPut") }
        };

        public static bool IsLegacyIns(byte[] bytes)
        {
            return bytes != null && bytes.Length >= 4 && bytes[0] == 0xB8 &&
                bytes[1] == 0xC9 && bytes[2] == 0x0C && bytes[3] == 0x00;
        }

        public static InstallScriptProgram Read(byte[] bytes, int maximumInstructions)
        {
            if (!IsLegacyIns(bytes)) throw new InvalidDataException("The input does not contain an old InstallScript INS header.");
            if (maximumInstructions <= 0) maximumInstructions = MaximumRecords;
            var reader = new Reader(bytes);
            var program = new InstallScriptProgram
            {
                HeaderValue = 0x000CC9B8,
                FormatProfile = "INS-Old",
                EndCodeOffset = bytes.LongLength
            };

            reader.Position = 0x0D;
            program.InfoString = reader.ReadString();
            var eventCount = reader.ReadUInt16();
            if (eventCount > MaximumEvents) throw new InvalidDataException("The old InstallScript event count exceeds the parser limit.");

            SkipGlobalCatalog(reader);
            ReadPrototypes(reader, program);
            program.CatalogOffset = reader.Position;
            program.CodeOffset = reader.Position;
            ReadEvents(reader, program, eventCount, maximumInstructions);
            return program;
        }

        private static void SkipGlobalCatalog(Reader reader)
        {
            var globalStrings = reader.ReadUInt16();
            reader.Skip(checked(globalStrings * 2));
            SkipNamedVariables(reader, "loadable string");
            reader.ReadUInt16();
            SkipNamedVariables(reader, "loadable number");

            var structureCount = reader.ReadUInt16();
            if (structureCount > MaximumFunctions) throw new InvalidDataException("The old InstallScript structure count exceeds the parser limit.");
            for (var structureIndex = 0; structureIndex < structureCount; structureIndex++)
            {
                reader.ReadUInt16();
                reader.ReadString();
                var fieldCount = reader.ReadUInt16();
                if (fieldCount > MaximumParameters) throw new InvalidDataException("An old InstallScript structure field count exceeds the parser limit.");
                for (var fieldIndex = 0; fieldIndex < fieldCount; fieldIndex++)
                {
                    reader.ReadUInt16();
                    reader.ReadUInt16();
                    reader.ReadString();
                }
            }
        }

        private static void SkipNamedVariables(Reader reader, string description)
        {
            var count = reader.ReadUInt16();
            if (count > MaximumFunctions) throw new InvalidDataException("The old InstallScript " + description + " count exceeds the parser limit.");
            for (var index = 0; index < count; index++)
            {
                reader.ReadUInt16();
                reader.ReadString();
            }
        }

        private static void ReadPrototypes(Reader reader, InstallScriptProgram program)
        {
            var count = reader.ReadUInt16();
            if (count == 0 || count > MaximumFunctions) throw new InvalidDataException("The old InstallScript prototype count is invalid.");
            for (var index = 0; index < count; index++)
            {
                var function = new InstallScriptFunction(index);
                function.FunctionType = reader.ReadByte();
                function.ReturnType = reader.ReadByte();
                if (function.FunctionType == 2)
                {
                    function.DllName = reader.ReadString();
                    var name = reader.ReadString();
                    function.Name = string.IsNullOrEmpty(name) ? "function" + index : name;
                    function.LabelIndex = reader.ReadUInt16();
                }
                else if (function.FunctionType == 1)
                {
                    reader.ReadUInt16();
                    function.DllName = reader.ReadString();
                    var name = reader.ReadString();
                    function.Name = string.IsNullOrEmpty(name) ? "function" + index :
                        (string.IsNullOrEmpty(function.DllName) ? name : function.DllName + "." + name);
                    function.LabelIndex = 0xFFFF;
                }
                else
                {
                    throw new InvalidDataException("Unsupported old InstallScript prototype type " + function.FunctionType + ".");
                }

                var parameterCount = reader.ReadUInt16();
                if (parameterCount > MaximumParameters) throw new InvalidDataException("An old InstallScript prototype parameter count exceeds the parser limit.");
                for (var parameterIndex = 0; parameterIndex < parameterCount; parameterIndex++)
                {
                    function.Parameters.Add(reader.ReadUInt16());
                    function.ParameterFlags.Add(reader.ReadUInt16());
                }
                program.Functions.Add(function);
            }
        }

        private static void ReadEvents(Reader reader, InstallScriptProgram program, int eventCount, int maximumInstructions)
        {
            var currentFunctionIndex = 0;
            for (var eventIndex = 0; eventIndex < eventCount; eventIndex++)
            {
                reader.ReadUInt16();
                var actionCount = reader.ReadUInt16();
                if (actionCount > maximumInstructions - program.InstructionCount)
                    throw new InvalidDataException("The old InstallScript instruction count exceeds the parser limit.");
                var function = program.Functions[currentFunctionIndex];
                var eventStart = reader.Position;
                var eventLabelPending = true;

                for (var actionIndex = 0; actionIndex < actionCount; actionIndex++)
                {
                    var sourceOpcode = reader.PeekUInt16();
                    if (sourceOpcode == 0x00B6)
                    {
                        ReadFunctionProlog(reader);
                        currentFunctionIndex++;
                        if (currentFunctionIndex >= program.Functions.Count)
                            throw new InvalidDataException("An old InstallScript function prolog exceeds the prototype table.");
                        function = program.Functions[currentFunctionIndex];
                        eventStart = reader.Position;
                        continue;
                    }

                    InstallScriptInstruction instruction;
                    try
                    {
                        instruction = ReadAction(reader, program, function);
                    }
                    catch (Exception exception) when (exception is InvalidDataException || exception is EndOfStreamException)
                    {
                        program.Warnings.Add("Old InstallScript event " + eventIndex + " stopped at action " + actionIndex + ": " + exception.Message);
                        function.BodyDecoded = false;
                        return;
                    }
                    if (eventLabelPending)
                    {
                        instruction.LabelIndexes.Add(eventIndex);
                        if (function.StartOffset < 0) function.StartOffset = eventStart;
                        if (function.LabelIndex < 0 || function.LabelIndex == 0xFFFF) function.LabelIndex = eventIndex;
                        eventLabelPending = false;
                    }
                    function.Instructions.Add(instruction);
                    program.InstructionCount++;
                }
                function.BodyDecoded = true;
            }
        }

        private static void ReadFunctionProlog(Reader reader)
        {
            if (reader.ReadUInt16() != 0x00B6) throw new InvalidDataException("The old InstallScript function prolog marker is invalid.");
            reader.ReadUInt16();
            var stringCount = reader.ReadUInt16();
            if (stringCount > MaximumParameters) throw new InvalidDataException("An old InstallScript local-string table exceeds the parser limit.");
            reader.Skip(checked(stringCount * 2));
            reader.ReadUInt16();
            reader.ReadUInt16();
            reader.ReadUInt16();
        }

        private static InstallScriptInstruction ReadAction(Reader reader, InstallScriptProgram program, InstallScriptFunction function)
        {
            var offset = reader.Position;
            var sourceOpcode = reader.ReadUInt16();
            Tuple<int, string> normalized;
            if (!NormalizedOperations.TryGetValue(sourceOpcode, out normalized))
                normalized = Tuple.Create(0x0000, "LegacyOpcode0x" + sourceOpcode.ToString("X4"));
            var instruction = new InstallScriptInstruction(offset, normalized.Item1, normalized.Item2) { SourceOpcode = sourceOpcode };

            if (sourceOpcode == 0x002C)
            {
                reader.ReadByte();
                instruction.BranchTarget = reader.ReadUInt16();
                return instruction;
            }
            if (sourceOpcode == 0x0022)
            {
                instruction.BranchTarget = reader.ReadByte();
                reader.ReadUInt16();
                reader.ReadByte();
                instruction.Operands.Add(ReadOperand(reader));
                reader.Skip(5);
                return instruction;
            }
            if (sourceOpcode == 0x00B5)
            {
                reader.ReadByte();
                instruction.CallTargetIndex = reader.ReadUInt16();
                reader.ReadByte();
                reader.ReadUInt16();
                ReadCallArguments(reader, program, instruction);
                return instruction;
            }
            if (sourceOpcode == 0x00B4)
            {
                reader.ReadByte();
                instruction.CallTargetIndex = reader.ReadUInt16();
                ReadCallArguments(reader, program, instruction);
                return instruction;
            }
            if (sourceOpcode == 0x0103 || sourceOpcode == 0x0104)
            {
                reader.ReadByte();
                var count = reader.ReadUInt16();
                if (count > MaximumParameters) throw new InvalidDataException("An old InstallScript variable-argument action exceeds the parser limit.");
                for (var index = 0; index < count; index++) instruction.Operands.Add(ReadOperand(reader));
                instruction.IsOpaque = true;
                return instruction;
            }

            var operandCount = GetOperandCount(sourceOpcode);
            for (var index = 0; index < operandCount; index++) instruction.Operands.Add(ReadOperand(reader));
            ProjectOperands(instruction);
            if (!NormalizedOperations.ContainsKey(sourceOpcode) || sourceOpcode == 0x0128 ||
                sourceOpcode == 0x012F || sourceOpcode == 0x0181 || sourceOpcode == 0x0183)
                instruction.IsOpaque = true;
            return instruction;
        }

        private static void ReadCallArguments(Reader reader, InstallScriptProgram program, InstallScriptInstruction instruction)
        {
            if (instruction.CallTargetIndex < 0 || instruction.CallTargetIndex >= program.Functions.Count)
                throw new InvalidDataException("An old InstallScript call target is outside the prototype table.");
            var count = program.Functions[instruction.CallTargetIndex].Parameters.Count;
            for (var index = 0; index < count; index++) instruction.Operands.Add(ReadOperand(reader));
        }

        private static int GetOperandCount(int sourceOpcode)
        {
            if (sourceOpcode < 0 || sourceOpcode >= OperandCounts.Length)
                throw new InvalidDataException("Old InstallScript opcode 0x" + sourceOpcode.ToString("X4") + " has no known framing.");
            var encoded = OperandCounts[sourceOpcode];
            if (encoded == 0xFF || encoded == 0xF0)
                throw new InvalidDataException("Old InstallScript opcode 0x" + sourceOpcode.ToString("X4") + " has generation-dependent framing.");
            return encoded & 0x0F;
        }

        private static void ProjectOperands(InstallScriptInstruction instruction)
        {
            if ((instruction.Opcode == 0x0006 || instruction.Opcode == 0x0007 ||
                (instruction.Opcode >= 0x000F && instruction.Opcode <= 0x0019) ||
                instruction.Opcode == 0x0033 || instruction.Opcode == 0x0035) && instruction.Operands.Count != 0)
            {
                var destinationIndex = instruction.SourceOpcode == 0x0112 && instruction.Operands.Count >= 3 ? 2 : 0;
                instruction.Destination = instruction.Operands[destinationIndex];
                instruction.Operands.RemoveAt(destinationIndex);
            }
        }

        private static InstallScriptOperand ReadOperand(Reader reader)
        {
            var tag = reader.ReadByte();
            var kind = tag & 0xF0;
            var flags = tag & 0x0F;
            if (kind == 0x10)
            {
                return new InstallScriptOperand(InstallScriptOperandKind.Unknown, reader.ReadByte(), null, tag);
            }
            if (kind == 0x30 || kind == 0x40)
            {
                if (kind == 0x40 && (flags & 1) != 0)
                    return new InstallScriptOperand(InstallScriptOperandKind.Integer, reader.ReadInt32(), null, tag);
                var address = reader.ReadInt16();
                return new InstallScriptOperand(address < 0 ? InstallScriptOperandKind.LocalNumberVariable : InstallScriptOperandKind.UserNumberVariable, address, null, tag);
            }
            if (kind == 0x50 || kind == 0x60)
            {
                if (kind == 0x60 && (flags & 1) != 0)
                    return new InstallScriptOperand(InstallScriptOperandKind.String, 0, reader.ReadString(), tag);
                var address = reader.ReadInt16();
                return new InstallScriptOperand(address < 0 ? InstallScriptOperandKind.LocalStringVariable : InstallScriptOperandKind.UserStringVariable, address, null, tag);
            }
            throw new InvalidDataException("Old InstallScript operand tag 0x" + tag.ToString("X2") + " is unsupported.");
        }

        private sealed class Reader
        {
            private readonly byte[] bytes;
            private int position;
            internal Reader(byte[] bytes) { this.bytes = bytes; }
            internal long Position { get { return position; } set { if (value < 0 || value > bytes.LongLength) throw new EndOfStreamException("An old InstallScript offset is outside the file."); position = checked((int)value); } }
            internal byte ReadByte() { Ensure(1); return bytes[position++]; }
            internal ushort PeekUInt16() { Ensure(2); return (ushort)(bytes[position] | bytes[position + 1] << 8); }
            internal ushort ReadUInt16() { var value = PeekUInt16(); position += 2; return value; }
            internal short ReadInt16() { return unchecked((short)ReadUInt16()); }
            internal uint ReadUInt32() { Ensure(4); var value = (uint)(bytes[position] | bytes[position + 1] << 8 | bytes[position + 2] << 16 | bytes[position + 3] << 24); position += 4; return value; }
            internal int ReadInt32() { return unchecked((int)ReadUInt32()); }
            internal string ReadString() { var length = ReadUInt16(); if (length > MaximumStringBytes) throw new InvalidDataException("An old InstallScript string exceeds the parser limit."); Ensure(length); var value = Encoding.ASCII.GetString(bytes, position, length); position += length; return value; }
            internal void Skip(int count) { Ensure(count); position += count; }
            private void Ensure(int count) { if (count < 0 || count > bytes.Length - position) throw new EndOfStreamException("The old InstallScript record is truncated."); }
        }
    }
}
