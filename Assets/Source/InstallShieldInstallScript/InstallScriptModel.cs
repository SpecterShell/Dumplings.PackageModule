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

    public enum InstallScriptOperandKind
    {
        Unknown,
        Integer,
        String,
        SystemStringVariable,
        UserStringVariable,
        LocalStringVariable,
        SystemNumberVariable,
        UserNumberVariable,
        LocalNumberVariable,
        Label,
        DataType
    }

    /// <summary>Represents one typed operand from an instruction record.</summary>
    public sealed class InstallScriptOperand
    {
        internal InstallScriptOperand(InstallScriptOperandKind kind, int integerValue, string stringValue, int encodedTag)
        {
            Kind = kind;
            IntegerValue = integerValue;
            StringValue = stringValue;
            EncodedTag = encodedTag;
        }

        public InstallScriptOperandKind Kind { get; private set; }
        public int IntegerValue { get; private set; }
        public string StringValue { get; private set; }
        public int EncodedTag { get; private set; }

        public override string ToString()
        {
            if (Kind == InstallScriptOperandKind.String) return "\"" + StringValue + "\"";
            if (Kind == InstallScriptOperandKind.Integer) return IntegerValue.ToString();
            return Kind + "[" + IntegerValue + "]";
        }
    }

    /// <summary>Represents one bounded instruction record in a function body.</summary>
    public sealed class InstallScriptInstruction
    {
        internal InstallScriptInstruction(long offset, int opcode, string operation)
        {
            Offset = offset;
            Opcode = opcode;
            SourceOpcode = opcode;
            Operation = operation;
            Operands = new List<InstallScriptOperand>();
            LabelIndexes = new List<int>();
            CallTargetIndex = -1;
            BranchTarget = -1;
        }

        public long Offset { get; private set; }
        public int Opcode { get; private set; }
        /// <summary>
        /// Opcode encoded by the source generation. Legacy INS actions are
        /// normalized to the modern interpreter vocabulary in <see cref="Opcode"/>
        /// while retaining their original action identifier here.
        /// </summary>
        public int SourceOpcode { get; internal set; }
        public string Operation { get; internal set; }
        public InstallScriptOperand Destination { get; internal set; }
        public List<InstallScriptOperand> Operands { get; private set; }
        public List<int> LabelIndexes { get; private set; }
        public int CallTargetIndex { get; internal set; }
        public int BranchTarget { get; internal set; }
        public bool IsOpaque { get; internal set; }
    }

    /// <summary>Describes a function prototype and its decoded body.</summary>
    public sealed class InstallScriptFunction
    {
        internal InstallScriptFunction(int index)
        {
            Index = index;
            Name = "function" + index;
            DllName = string.Empty;
            Parameters = new List<int>();
            ParameterFlags = new List<int>();
            Instructions = new List<InstallScriptInstruction>();
            StartOffset = -1;
            LabelIndex = -1;
        }

        public int Index { get; private set; }
        public string Name { get; internal set; }
        public string DllName { get; internal set; }
        public int FunctionType { get; internal set; }
        /// <summary>Compiler flags that classify DLL, internal, predefined, exported, and property prototypes.</summary>
        public int Flags { get; internal set; }
        /// <summary>Whether the object module exports this prototype to the InstallScript linker.</summary>
        public bool IsExported { get { return (Flags & 0x08) != 0; } }
        public int ReturnType { get; internal set; }
        public int LabelIndex { get; internal set; }
        public long StartOffset { get; internal set; }
        public List<int> Parameters { get; private set; }
        public List<int> ParameterFlags { get; private set; }
        public List<InstallScriptInstruction> Instructions { get; private set; }
        public bool BodyDecoded { get; internal set; }
    }

    /// <summary>One named global imported by an OBS object module.</summary>
    public sealed class InstallScriptExternalSymbol
    {
        internal InstallScriptExternalSymbol(int type, int address, string name)
        {
            Type = type;
            Address = address;
            Name = name ?? string.Empty;
        }

        public int Type { get; private set; }
        public int Address { get; private set; }
        public string Name { get; private set; }
    }

    /// <summary>One OBS linker address-resolution record retained as structural evidence.</summary>
    public sealed class InstallScriptAddressResolution
    {
        internal InstallScriptAddressResolution(int type, long offset)
        {
            Type = type;
            Offset = offset;
        }

        public int Type { get; private set; }
        public long Offset { get; private set; }
    }

    /// <summary>Contains the immutable structural evidence returned by the INX reader.</summary>
    public sealed class InstallScriptProgram
    {
        internal InstallScriptProgram()
        {
            Functions = new List<InstallScriptFunction>();
            LabelOffsets = new List<long>();
            Warnings = new List<string>();
            ExternalSymbols = new List<InstallScriptExternalSymbol>();
            AddressResolutions = new List<InstallScriptAddressResolution>();
            InfoString = string.Empty;
            CompilerVersion = string.Empty;
            FormatProfile = string.Empty;
            LibraryMemberName = string.Empty;
        }

        public uint HeaderValue { get; internal set; }
        /// <summary>Structural bytecode profile used by the reader.</summary>
        public string FormatProfile { get; internal set; }
        /// <summary>OBL member name when this program came from a script library.</summary>
        public string LibraryMemberName { get; internal set; }
        public string InfoString { get; internal set; }
        /// <summary>Compiler-version text carried by an OBS object-module header.</summary>
        public string CompilerVersion { get; internal set; }
        public long CatalogOffset { get; internal set; }
        public long CodeOffset { get; internal set; }
        public long EndCodeOffset { get; internal set; }
        public int DataTypeCount { get; internal set; }
        public List<InstallScriptFunction> Functions { get; private set; }
        public List<InstallScriptExternalSymbol> ExternalSymbols { get; private set; }
        public List<InstallScriptAddressResolution> AddressResolutions { get; private set; }
        public List<long> LabelOffsets { get; private set; }
        public List<string> Warnings { get; private set; }
        public int InstructionCount { get; internal set; }
    }

    /// <summary>One callsite-backed dialog step in a symbolic scenario trace.</summary>
    public sealed class InstallScriptDialogStep
    {
        internal InstallScriptDialogStep()
        {
            EntryPoint = string.Empty;
            Function = string.Empty;
            Alternatives = new List<string>();
        }

        public string EntryPoint { get; internal set; }
        public long Offset { get; internal set; }
        public string Function { get; internal set; }
        public string Dialog { get; internal set; }
        public List<string> Alternatives { get; private set; }
        public bool Complete { get; internal set; }
    }

    /// <summary>Ordered dialog evidence for a fresh-install, maintenance, or explicit entry point.</summary>
    public sealed class InstallScriptDialogTrace
    {
        internal InstallScriptDialogTrace()
        {
            EntryPoints = new List<string>();
            Steps = new List<InstallScriptDialogStep>();
            Dialogs = new List<string>();
            Warnings = new List<string>();
            Scenario = string.Empty;
            Source = string.Empty;
        }

        public string EntryPoint { get { return EntryPoints.Count == 0 ? null : EntryPoints[0]; } }
        public List<string> EntryPoints { get; private set; }
        public string Scenario { get; internal set; }
        /// <summary>Identifies direct bytecode tracing or framework-callback reconstruction.</summary>
        public string Source { get; internal set; }
        public List<InstallScriptDialogStep> Steps { get; private set; }
        public List<string> Dialogs { get; private set; }
        public bool IsComplete { get; internal set; }
        public List<string> Warnings { get; private set; }
    }

    /// <summary>One imported or user-function call observed by bounded emulation.</summary>
    public sealed class InstallScriptCallEvidence
    {
        internal InstallScriptCallEvidence()
        {
            Arguments = new List<string>();
            EntryPoint = string.Empty;
            Function = string.Empty;
            Target = string.Empty;
        }

        public string EntryPoint { get; internal set; }
        public string Function { get; internal set; }
        public long Offset { get; internal set; }
        public string Target { get; internal set; }
        public List<string> Arguments { get; private set; }
        public bool Complete { get; internal set; }
    }

    /// <summary>One explicit registry value write reconstructed from documented runtime calls.</summary>
    public sealed class InstallScriptRegistryWrite
    {
        internal InstallScriptRegistryWrite()
        {
            RootCandidates = new List<string>();
            EntryPoint = string.Empty;
            Function = string.Empty;
            Root = string.Empty;
            Key = string.Empty;
            Name = string.Empty;
            Type = string.Empty;
            Data = string.Empty;
            Source = string.Empty;
            Confidence = string.Empty;
        }

        public string EntryPoint { get; internal set; }
        public string Function { get; internal set; }
        public long Offset { get; internal set; }
        public string Root { get; internal set; }
        public List<string> RootCandidates { get; private set; }
        public string Key { get; internal set; }
        public string Name { get; internal set; }
        public string Type { get; internal set; }
        public string Data { get; internal set; }
        public string Source { get; internal set; }
        public string Confidence { get; internal set; }
        public bool Complete { get; internal set; }
    }

    /// <summary>
    /// One RegDBSetItem assignment to InstallShield's built-in registration
    /// model. The runtime consumes these values later during MaintenanceStart.
    /// </summary>
    public sealed class InstallScriptRegistryItemEvidence
    {
        internal InstallScriptRegistryItemEvidence()
        {
            EntryPoint = string.Empty;
            Function = string.Empty;
            Name = string.Empty;
            Data = string.Empty;
            Source = string.Empty;
        }

        public string EntryPoint { get; internal set; }
        public string Function { get; internal set; }
        public long Offset { get; internal set; }
        public long Item { get; internal set; }
        public string Name { get; internal set; }
        public string Data { get; internal set; }
        public string Source { get; internal set; }
        public bool Complete { get; internal set; }
    }

    /// <summary>One statically observed child-process launch request.</summary>
    public sealed class InstallScriptExecutedPayload
    {
        internal InstallScriptExecutedPayload()
        {
            Arguments = new List<string>();
            EntryPoint = string.Empty;
            Function = string.Empty;
            Operation = string.Empty;
            Program = string.Empty;
            CommandLine = string.Empty;
        }

        public string EntryPoint { get; internal set; }
        public string Function { get; internal set; }
        public long Offset { get; internal set; }
        public string Operation { get; internal set; }
        public string Program { get; internal set; }
        public string CommandLine { get; internal set; }
        public List<string> Arguments { get; private set; }
        public bool Complete { get; internal set; }
    }

    /// <summary>One statically observed file-system operation.</summary>
    public sealed class InstallScriptFileOperation
    {
        internal InstallScriptFileOperation()
        {
            Arguments = new List<string>();
            EntryPoint = string.Empty;
            Function = string.Empty;
            Operation = string.Empty;
            Source = string.Empty;
            Destination = string.Empty;
        }

        public string EntryPoint { get; internal set; }
        public string Function { get; internal set; }
        public long Offset { get; internal set; }
        public string Operation { get; internal set; }
        public string Source { get; internal set; }
        public string Destination { get; internal set; }
        public List<string> Arguments { get; private set; }
        public bool Complete { get; internal set; }
    }

    /// <summary>
    /// One explicit InstallScript UseDLL or UnUseDLL instruction. The analyzer
    /// records the requested module path but never loads or invokes the module.
    /// </summary>
    public sealed class InstallScriptDllOperation
    {
        internal InstallScriptDllOperation()
        {
            EntryPoint = string.Empty;
            Function = string.Empty;
            Operation = string.Empty;
            Path = string.Empty;
        }

        public string EntryPoint { get; internal set; }
        public string Function { get; internal set; }
        public long Offset { get; internal set; }
        public string Operation { get; internal set; }
        public string Path { get; internal set; }
        public bool Complete { get; internal set; }
    }

    /// <summary>One shortcut request reconstructed from a documented InstallScript API.</summary>
    public sealed class InstallScriptShortcutEvidence
    {
        internal InstallScriptShortcutEvidence()
        {
            Arguments = new List<string>();
            EntryPoint = string.Empty;
            Function = string.Empty;
            Operation = string.Empty;
            Folder = string.Empty;
            Name = string.Empty;
            CommandLine = string.Empty;
            WorkingDirectory = string.Empty;
            IconPath = string.Empty;
        }

        public string EntryPoint { get; internal set; }
        public string Function { get; internal set; }
        public long Offset { get; internal set; }
        public string Operation { get; internal set; }
        public string Folder { get; internal set; }
        public string Name { get; internal set; }
        public string CommandLine { get; internal set; }
        public string WorkingDirectory { get; internal set; }
        public string IconPath { get; internal set; }
        public List<string> Arguments { get; private set; }
        public bool Complete { get; internal set; }
    }

    /// <summary>Coverage for one opcode present in the decoded program.</summary>
    public sealed class InstallScriptOpcodeEvidence
    {
        internal InstallScriptOpcodeEvidence(int opcode, string operation)
        {
            Opcode = opcode;
            Operation = operation;
            Emulation = "EvidenceOnly";
        }

        public int Opcode { get; private set; }
        public string Operation { get; private set; }
        public int Count { get; internal set; }
        public int OpaqueCount { get; internal set; }
        public string Emulation { get; internal set; }
    }

    /// <summary>
    /// One compiler-generated property proxy registered by opcode 0x003B.
    /// InstallShield assigns the returned opaque handle to a numeric slot and
    /// later routes reads and writes through the paired getter/setter functions.
    /// The analyzer exposes this structure but does not invoke either handler.
    /// </summary>
    public sealed class InstallScriptPropertyHandlerEvidence
    {
        internal InstallScriptPropertyHandlerEvidence()
        {
            Function = string.Empty;
            VariableKind = string.Empty;
            GetterFunction = string.Empty;
            SetterFunction = string.Empty;
            HandleSlotKind = string.Empty;
        }

        public string Function { get; internal set; }
        public long Offset { get; internal set; }
        public string VariableKind { get; internal set; }
        public int VariableIndex { get; internal set; }
        public int GetterFunctionIndex { get; internal set; }
        public string GetterFunction { get; internal set; }
        public int SetterFunctionIndex { get; internal set; }
        public string SetterFunction { get; internal set; }
        public string HandleSlotKind { get; internal set; }
        public int? HandleSlotIndex { get; internal set; }
        public bool Complete { get; internal set; }
    }

    /// <summary>Bounded static-emulation evidence for a decoded InstallScript program.</summary>
    public sealed class InstallScriptStaticAnalysis
    {
        internal InstallScriptStaticAnalysis()
        {
            EntryPoints = new List<string>();
            Calls = new List<InstallScriptCallEvidence>();
            RegistryWrites = new List<InstallScriptRegistryWrite>();
            RegistryItems = new List<InstallScriptRegistryItemEvidence>();
            ExecutedPayloads = new List<InstallScriptExecutedPayload>();
            FileOperations = new List<InstallScriptFileOperation>();
            DllOperations = new List<InstallScriptDllOperation>();
            Shortcuts = new List<InstallScriptShortcutEvidence>();
            PropertyHandlers = new List<InstallScriptPropertyHandlerEvidence>();
            OpcodeCoverage = new List<InstallScriptOpcodeEvidence>();
            UnsupportedOpcodes = new List<string>();
            Notices = new List<string>();
            Warnings = new List<string>();
        }

        public List<string> EntryPoints { get; private set; }
        public List<InstallScriptCallEvidence> Calls { get; private set; }
        public List<InstallScriptRegistryWrite> RegistryWrites { get; private set; }
        public List<InstallScriptRegistryItemEvidence> RegistryItems { get; private set; }
        public List<InstallScriptExecutedPayload> ExecutedPayloads { get; private set; }
        public List<InstallScriptFileOperation> FileOperations { get; private set; }
        public List<InstallScriptDllOperation> DllOperations { get; private set; }
        public List<InstallScriptShortcutEvidence> Shortcuts { get; private set; }
        public List<InstallScriptPropertyHandlerEvidence> PropertyHandlers { get; private set; }
        public List<InstallScriptOpcodeEvidence> OpcodeCoverage { get; private set; }
        public List<string> UnsupportedOpcodes { get; private set; }
        public List<string> Notices { get; private set; }
        public List<string> Warnings { get; private set; }
        public int ExploredInstructionCount { get; internal set; }
        public bool Truncated { get; internal set; }
    }

    /// <summary>
    /// Performs bounded abstract interpretation over modern INX instructions.
    /// It evaluates language operations and generated user-function wrappers,
    /// but imported functions are never invoked. Only documented registry,
    /// process, and file APIs are projected as side-effect evidence.
    /// </summary>
}
