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

    public static class InstallScriptStaticAnalyzer
    {
        private const int MaximumValueAlternatives = 32;
        private const int MaximumPathsPerCall = 4;
        private const int MaximumNestedOutcomes = 2;

        private sealed class Value
        {
            internal Value()
            {
                Strings = new List<string>();
                Complete = false;
            }

            internal List<string> Strings;
            internal long? Number;
            // A reference identifies either a bounded structure snapshot or a
            // primitive value slot stored in MachineState. It is symbolic only;
            // no host pointer is created.
            internal string ReferenceIdentity;
            internal bool IsValueReference;
            internal bool Complete;

            internal static Value Unknown(string description)
            {
                var value = new Value();
                value.Strings.Add("<" + description + ">");
                return value;
            }

            internal static Value FromNumber(long number)
            {
                return new Value { Number = number, Complete = true };
            }

            internal static Value FromString(string text)
            {
                var value = new Value { Complete = true };
                value.Strings.Add(text ?? string.Empty);
                return value;
            }

            internal static Value FromReference(string identity)
            {
                return new Value { ReferenceIdentity = identity, Complete = true };
            }

            internal static Value FromValueReference(string identity)
            {
                return new Value { ReferenceIdentity = identity, IsValueReference = true, Complete = true };
            }

            internal static Value FromStrings(IEnumerable<string> values)
            {
                var result = new Value { Complete = true };
                foreach (var value in values ?? Enumerable.Empty<string>())
                {
                    if (!result.Strings.Contains(value ?? string.Empty, StringComparer.Ordinal))
                        result.Strings.Add(value ?? string.Empty);
                    if (result.Strings.Count >= MaximumValueAlternatives) break;
                }
                if (result.Strings.Count == 0) return Unknown("empty-resource-value");
                return result;
            }

            internal Value Clone()
            {
                var result = new Value { Number = Number, ReferenceIdentity = ReferenceIdentity, IsValueReference = IsValueReference, Complete = Complete };
                result.Strings.AddRange(Strings);
                return result;
            }

            internal string Render()
            {
                if (!string.IsNullOrEmpty(ReferenceIdentity)) return IsValueReference ? "&value" : "&record";
                if (Number.HasValue) return Number.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return string.Join(" | ", Strings.ToArray());
            }

            internal IEnumerable<string> TextAlternatives()
            {
                if (Number.HasValue)
                    return new[] { Number.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) };
                return Strings.Count == 0 ? new[] { "<unknown>" } : Strings;
            }
        }

        private sealed class MachineState
        {
            internal MachineState()
            {
                StringVariables = new Dictionary<string, Value>(StringComparer.Ordinal);
                NumberVariables = new Dictionary<string, Value>(StringComparer.Ordinal);
                Objects = new Dictionary<string, Dictionary<string, Value>>(StringComparer.Ordinal);
                ReferencedObjects = new Dictionary<string, Dictionary<string, Value>>(StringComparer.Ordinal);
                ReferencedValues = new Dictionary<string, Value>(StringComparer.Ordinal);
                RootCandidates = new List<string> { "HKCR" };
                LastResult = Value.Unknown("RESULT");
            }

            internal Dictionary<string, Value> StringVariables;
            internal Dictionary<string, Value> NumberVariables;
            internal Dictionary<string, Dictionary<string, Value>> Objects;
            internal Dictionary<string, Dictionary<string, Value>> ReferencedObjects;
            internal Dictionary<string, Value> ReferencedValues;
            internal int NextReferenceIdentity;
            internal List<string> RootCandidates;
            internal Value LastResult;

            internal MachineState Clone()
            {
                var result = new MachineState();
                result.StringVariables.Clear();
                result.NumberVariables.Clear();
                foreach (var pair in StringVariables) result.StringVariables.Add(pair.Key, pair.Value.Clone());
                foreach (var pair in NumberVariables) result.NumberVariables.Add(pair.Key, pair.Value.Clone());
                foreach (var pair in Objects) result.Objects.Add(pair.Key, CloneMembers(pair.Value));
                foreach (var pair in ReferencedObjects) result.ReferencedObjects.Add(pair.Key, CloneMembers(pair.Value));
                foreach (var pair in ReferencedValues) result.ReferencedValues.Add(pair.Key, pair.Value.Clone());
                result.NextReferenceIdentity = NextReferenceIdentity;
                result.RootCandidates.Clear();
                result.RootCandidates.AddRange(RootCandidates);
                result.LastResult = LastResult.Clone();
                return result;
            }
        }

        private sealed class Frame
        {
            internal Frame()
            {
                Strings = new Dictionary<int, Value>();
                Numbers = new Dictionary<int, Value>();
                Objects = new Dictionary<string, Dictionary<string, Value>>(StringComparer.Ordinal);
            }

            internal Dictionary<int, Value> Strings;
            internal Dictionary<int, Value> Numbers;
            internal Dictionary<string, Dictionary<string, Value>> Objects;

            internal Frame Clone()
            {
                var result = new Frame();
                foreach (var pair in Strings) result.Strings.Add(pair.Key, pair.Value.Clone());
                foreach (var pair in Numbers) result.Numbers.Add(pair.Key, pair.Value.Clone());
                foreach (var pair in Objects) result.Objects.Add(pair.Key, CloneMembers(pair.Value));
                return result;
            }
        }

        private static Dictionary<string, Value> CloneMembers(Dictionary<string, Value> members)
        {
            var result = new Dictionary<string, Value>(StringComparer.Ordinal);
            foreach (var pair in members) result.Add(pair.Key, pair.Value.Clone());
            return result;
        }

        private sealed class WorkItem
        {
            internal int InstructionIndex;
            internal Frame Frame;
            internal MachineState State;
            internal Dictionary<int, int> Visits;

            internal WorkItem Clone()
            {
                return new WorkItem
                {
                    InstructionIndex = InstructionIndex,
                    Frame = Frame.Clone(),
                    State = State.Clone(),
                    Visits = new Dictionary<int, int>(Visits)
                };
            }
        }

        private sealed class Outcome
        {
            internal MachineState State;
            internal Value ReturnValue;
        }

        private sealed class CallBinding
        {
            internal Value Value;
            internal InstallScriptOperand Source;
            internal string ReferenceIdentity;
        }

        private sealed class Context
        {
            internal InstallScriptProgram Program;
            internal InstallScriptStaticAnalysis Result;
            internal Dictionary<string, string[]> Resources;
            internal HashSet<int> RootSetterFunctions;
            internal HashSet<int> LocalizationFunctions;
            internal HashSet<int> RelevantFunctions;
            internal Dictionary<int, int> EffectDistances;
            internal int MaximumInstructions;
            internal int MaximumCallDepth;
            internal int MaximumEffects;
            internal HashSet<string> NoticeSet;
            internal HashSet<string> WarningSet;
            internal HashSet<string> EffectSet;
            internal Dictionary<int, int> FunctionInvocations;
            internal Dictionary<int, List<int>> HandlerFunctions;
        }

        /// <summary>
        /// Analyze selected entry points. Resource values are optional decoded
        /// StringTable_*.ips mappings keyed by InstallScript string identifier.
        /// </summary>
        public static InstallScriptStaticAnalysis Analyze(
            InstallScriptProgram program,
            IDictionary<string, string[]> resources,
            string[] entryPoints,
            int maximumInstructions,
            int maximumCallDepth,
            int maximumEffects)
        {
            if (program == null) throw new ArgumentNullException("program");
            if (maximumInstructions <= 0) throw new ArgumentOutOfRangeException("maximumInstructions");
            if (maximumCallDepth <= 0) throw new ArgumentOutOfRangeException("maximumCallDepth");
            if (maximumEffects <= 0) throw new ArgumentOutOfRangeException("maximumEffects");

            var context = new Context
            {
                Program = program,
                Result = new InstallScriptStaticAnalysis(),
                Resources = new Dictionary<string, string[]>(StringComparer.Ordinal),
                RootSetterFunctions = FindRootSetterFunctions(program),
                LocalizationFunctions = FindLocalizationFunctions(program),
                MaximumInstructions = maximumInstructions,
                MaximumCallDepth = maximumCallDepth,
                MaximumEffects = maximumEffects,
                NoticeSet = new HashSet<string>(StringComparer.Ordinal),
                WarningSet = new HashSet<string>(StringComparer.Ordinal),
                EffectSet = new HashSet<string>(StringComparer.Ordinal),
                FunctionInvocations = new Dictionary<int, int>(),
                HandlerFunctions = FindHandlerFunctions(program)
            };
            context.EffectDistances = FindEffectDistances(program, context.RootSetterFunctions, context.LocalizationFunctions, context.HandlerFunctions);
            context.RelevantFunctions = new HashSet<int>(context.EffectDistances.Keys);
            if (resources != null)
                foreach (var pair in resources) context.Resources[pair.Key] = pair.Value ?? new string[0];

            AddOpcodeCoverage(context);
            AddPropertyHandlerEvidence(context);
            var roots = SelectEntryPoints(program, entryPoints);
            foreach (var function in roots)
            {
                context.Result.EntryPoints.Add(function.Name);
                ExecuteFunction(context, function, new Value[0], new MachineState(), function.Name, 0, new HashSet<int>());
                if (context.Result.Truncated) break;
            }
            if (context.Result.EntryPoints.Count == 0)
                AddWarning(context, "No decoded InstallScript entry point was available for static emulation.");
            return context.Result;
        }

        private static List<InstallScriptFunction> SelectEntryPoints(InstallScriptProgram program, string[] requested)
        {
            var names = requested == null || requested.Length == 0
                ? new[] { "program", "Preprogram", "Postprogram", "OnFirstUIBefore", "OnFirstUIAfter", "OnMaintUIBefore", "OnMaintUIAfter", "OnMoveData", "OnMoving", "OnMoved", "OnEnd" }
                : requested;
            var result = new List<InstallScriptFunction>();
            foreach (var name in names)
            {
                var function = program.Functions.FirstOrDefault(candidate => candidate.BodyDecoded && string.Equals(candidate.Name, name, StringComparison.Ordinal));
                if (function != null && !result.Contains(function)) result.Add(function);
            }
            if (result.Count == 0)
            {
                var fallback = program.Functions.FirstOrDefault(function => function.BodyDecoded && string.IsNullOrEmpty(function.DllName));
                if (fallback != null) result.Add(fallback);
            }
            return result;
        }

        private static HashSet<int> FindRootSetterFunctions(InstallScriptProgram program)
        {
            var candidates = new HashSet<int>();
            foreach (var function in program.Functions.Where(item => item.BodyDecoded && item.Parameters.Count == 1 && item.Parameters[0] != 0))
            {
                var calls = function.Instructions.Count(item => item.Opcode == 0x0020 || item.Opcode == 0x0021);
                var assignment = function.Instructions.Any(item =>
                    item.Opcode == 0x0006 && item.Destination != null &&
                    item.Destination.Kind == InstallScriptOperandKind.LocalNumberVariable && item.Destination.IntegerValue >= 32 &&
                    item.Operands.Count == 1 && item.Operands[0].Kind == InstallScriptOperandKind.LocalNumberVariable && item.Operands[0].IntegerValue == 0);
                var returnsZero = function.Instructions.Any(item => item.Operation == "Return" && item.Operands.Any(operand => operand.Kind == InstallScriptOperandKind.Integer && operand.IntegerValue == 0));
                if (calls == 0 && assignment && returnsZero) candidates.Add(function.Index);
            }

            // Require at least one callsite using a documented Windows HKEY
            // constant before treating an anonymous generated wrapper as the
            // compiler's RegDBSetDefaultRoot/HKEYCURRENTROOTKEY assignment.
            candidates.RemoveWhere(index => !program.Functions.Any(function => function.Instructions.Any(instruction =>
                instruction.Opcode == 0x0021 && instruction.CallTargetIndex == index && instruction.Operands.Count == 1 &&
                instruction.Operands[0].Kind == InstallScriptOperandKind.Integer && MapRoot(instruction.Operands[0].IntegerValue) != null)));
            return candidates;
        }

        private static HashSet<int> FindLocalizationFunctions(InstallScriptProgram program)
        {
            var direct = new HashSet<int>(program.Functions.Where(function => function.Instructions.Any(instruction =>
                instruction.Opcode == 0x0020 && instruction.CallTargetIndex >= 0 && instruction.CallTargetIndex < program.Functions.Count &&
                program.Functions[instruction.CallTargetIndex].Name.EndsWith(".__LoadString", StringComparison.OrdinalIgnoreCase))).Select(function => function.Index));
            var reachable = new HashSet<int>(direct);
            var changed = true;
            while (changed)
            {
                changed = false;
                foreach (var function in program.Functions.Where(item => item.BodyDecoded))
                {
                    if (reachable.Contains(function.Index)) continue;
                    if (function.Instructions.Any(instruction => instruction.Opcode == 0x0021 && reachable.Contains(instruction.CallTargetIndex)))
                    {
                        reachable.Add(function.Index);
                        changed = true;
                    }
                }
            }
            return new HashSet<int>(reachable.Where(index => program.Functions[index].Parameters.Count == 1 && program.Functions[index].Parameters[0] == 0));
        }

        private static Dictionary<int, List<int>> FindHandlerFunctions(InstallScriptProgram program)
        {
            var result = new Dictionary<int, List<int>>();
            foreach (var instruction in program.Functions.SelectMany(function => function.Instructions).Where(item => item.Opcode == 0x002F))
            {
                if (instruction.Destination == null || instruction.Destination.Kind != InstallScriptOperandKind.Integer ||
                    instruction.Operands.Count == 0 || instruction.Operands[0].Kind != InstallScriptOperandKind.Integer)
                    continue;
                var handlerId = instruction.Destination.IntegerValue;
                var functionIndex = instruction.Operands[0].IntegerValue;
                if (handlerId < 0 || functionIndex < 0 || functionIndex >= program.Functions.Count || !program.Functions[functionIndex].BodyDecoded)
                    continue;
                List<int> functions;
                if (!result.TryGetValue(handlerId, out functions))
                {
                    functions = new List<int>();
                    result.Add(handlerId, functions);
                }
                if (!functions.Contains(functionIndex)) functions.Add(functionIndex);
            }
            return result;
        }

        private static Dictionary<int, int> FindEffectDistances(
            InstallScriptProgram program,
            HashSet<int> rootSetters,
            HashSet<int> localizationFunctions,
            Dictionary<int, List<int>> handlerFunctions)
        {
            var distances = new Dictionary<int, int>();
            foreach (var index in rootSetters.Concat(localizationFunctions)) distances[index] = 0;
            foreach (var function in program.Functions.Where(item => item.BodyDecoded))
            {
                // A BYREF helper can alter a caller value that later becomes a
                // registry key, path, or launch argument even when the helper
                // contains no imported side effect of its own.
                if (function.ParameterFlags.Any(flags => (flags & 0x02) != 0))
                    distances[function.Index] = 0;
                if (function.Instructions.Any(instruction =>
                    instruction.Opcode == 0x0020 && instruction.CallTargetIndex >= 0 && instruction.CallTargetIndex < program.Functions.Count &&
                    IsRelevantImportedOperation(program.Functions[instruction.CallTargetIndex].Name)))
                    distances[function.Index] = 0;
            }

            // Propagate relevance to generated wrappers and entry functions.
            // Unrelated UI/component-runtime calls are summarized as unknown
            // returns instead of exploring large loops that cannot contribute
            // registry, process, or file evidence.
            var changed = true;
            while (changed)
            {
                changed = false;
                foreach (var function in program.Functions.Where(item => item.BodyDecoded))
                {
                    foreach (var instruction in function.Instructions.Where(item => item.Opcode == 0x0021))
                    {
                        int targetDistance;
                        if (!distances.TryGetValue(instruction.CallTargetIndex, out targetDistance)) continue;
                        int current;
                        var candidate = targetDistance + 1;
                        if (!distances.TryGetValue(function.Index, out current) || candidate < current)
                        {
                            distances[function.Index] = candidate;
                            changed = true;
                        }
                    }
                    foreach (var instruction in function.Instructions.Where(item => item.Opcode == 0x0030 && item.Destination != null))
                    {
                        List<int> targets;
                        if (!handlerFunctions.TryGetValue(instruction.Destination.IntegerValue, out targets)) continue;
                        foreach (var target in targets)
                        {
                            int targetDistance;
                            if (!distances.TryGetValue(target, out targetDistance)) continue;
                            int current;
                            var candidate = targetDistance + 1;
                            if (!distances.TryGetValue(function.Index, out current) || candidate < current)
                            {
                                distances[function.Index] = candidate;
                                changed = true;
                            }
                        }
                    }
                }
            }
            return distances;
        }

        private static bool IsRelevantImportedOperation(string name)
        {
            var shortName = name.Contains(".") ? name.Substring(name.LastIndexOf('.') + 1) : name;
            return shortName.StartsWith("_RegSet", StringComparison.OrdinalIgnoreCase) ||
                shortName.StartsWith("_RegCreate", StringComparison.OrdinalIgnoreCase) ||
                shortName.StartsWith("_RegDelete", StringComparison.OrdinalIgnoreCase) ||
                shortName.StartsWith("RegDBSet", StringComparison.OrdinalIgnoreCase) ||
                shortName.StartsWith("RegDBCreate", StringComparison.OrdinalIgnoreCase) ||
                shortName.StartsWith("RegDBDelete", StringComparison.OrdinalIgnoreCase) ||
                shortName.Equals("CreateRegistrySet", StringComparison.OrdinalIgnoreCase) ||
                shortName.Equals("_CreateRegistrySet", StringComparison.OrdinalIgnoreCase) ||
                shortName.Equals("CreateShellObjects", StringComparison.OrdinalIgnoreCase) ||
                shortName.Equals("_CreateShellObjects", StringComparison.OrdinalIgnoreCase) ||
                IsShortcutOperation(shortName) ||
                shortName.Equals("__LoadString", StringComparison.OrdinalIgnoreCase) ||
                IsLaunchOperation(shortName) || IsFileOperation(shortName);
        }

        private static void AddOpcodeCoverage(Context context)
        {
            var semantic = new HashSet<int>(new[] {
                0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
                0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F, 0x0010,
                0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018,
                0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x0020, 0x0021, 0x0023, 0x0024,
                0x0025, 0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002F,
                0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039,
                0x003A, 0x003C
            });
            foreach (var group in context.Program.Functions.SelectMany(function => function.Instructions).GroupBy(instruction => instruction.Opcode).OrderBy(group => group.Key))
            {
                var first = group.First();
                var evidence = new InstallScriptOpcodeEvidence(group.Key, first.Operation)
                {
                    Count = group.Count(),
                    OpaqueCount = group.Count(instruction => instruction.IsOpaque),
                Emulation = semantic.Contains(group.Key) ? "Evaluated" :
                        (group.Key == 0x0022 || group.Key == 0x0026 || group.Key == 0x0027 ||
                         group.Key == 0x003B || group.Key == 0x0129 ? "Structural" : "EvidenceOnly")
                };
                context.Result.OpcodeCoverage.Add(evidence);
                if (evidence.OpaqueCount != 0 || evidence.Emulation == "EvidenceOnly")
                    context.Result.UnsupportedOpcodes.Add("0x" + group.Key.ToString("X4") + " " + first.Operation);
            }
        }

        private static void AddPropertyHandlerEvidence(Context context)
        {
            // InstallShield 11.5 compiler output establishes the 0x003B shape:
            // the destination identifies a runtime-backed variable, the two
            // integer operands identify getter/setter functions, and the next
            // `slot = RESULT` instruction stores the opaque registration handle.
            // Expose that structure without guessing initial values or invoking
            // the handlers, which depend on the InstallShield runtime process.
            foreach (var function in context.Program.Functions.Where(item => item.BodyDecoded))
            {
                for (var index = 0; index < function.Instructions.Count; index++)
                {
                    var instruction = function.Instructions[index];
                    if (instruction.Opcode != 0x003B || instruction.Destination == null || instruction.Operands.Count < 2)
                        continue;

                    var getterIndex = instruction.Operands[0].IntegerValue;
                    var setterIndex = instruction.Operands[1].IntegerValue;
                    var getterValid = instruction.Operands[0].Kind == InstallScriptOperandKind.Integer &&
                        getterIndex >= 0 && getterIndex < context.Program.Functions.Count;
                    var setterValid = instruction.Operands[1].Kind == InstallScriptOperandKind.Integer &&
                        setterIndex >= 0 && setterIndex < context.Program.Functions.Count;
                    var evidence = new InstallScriptPropertyHandlerEvidence
                    {
                        Function = function.Name,
                        Offset = instruction.Offset,
                        VariableKind = instruction.Destination.Kind.ToString(),
                        VariableIndex = instruction.Destination.IntegerValue,
                        GetterFunctionIndex = getterIndex,
                        GetterFunction = getterValid ? context.Program.Functions[getterIndex].Name : string.Empty,
                        SetterFunctionIndex = setterIndex,
                        SetterFunction = setterValid ? context.Program.Functions[setterIndex].Name : string.Empty,
                        Complete = false
                    };

                    if (index + 1 < function.Instructions.Count)
                    {
                        var assignment = function.Instructions[index + 1];
                        if (assignment.Opcode == 0x0006 && assignment.Destination != null &&
                            assignment.Operands.Count == 1 &&
                            assignment.Operands[0].Kind == InstallScriptOperandKind.UserNumberVariable &&
                            assignment.Operands[0].EncodedTag == 0x08 && assignment.Operands[0].IntegerValue == 0)
                        {
                            evidence.HandleSlotKind = assignment.Destination.Kind.ToString();
                            evidence.HandleSlotIndex = assignment.Destination.IntegerValue;
                            evidence.Complete = getterValid && setterValid;
                        }
                    }

                    context.Result.PropertyHandlers.Add(evidence);
                }
            }
        }

        private static Dictionary<int, int> FindCatchEndIndexes(InstallScriptFunction function)
        {
            var result = new Dictionary<int, int>();
            var regions = new Stack<Tuple<int, int>>();
            for (var index = 0; index < function.Instructions.Count; index++)
            {
                var opcode = function.Instructions[index].Opcode;
                if (opcode == 0x0036)
                {
                    regions.Push(Tuple.Create(index, -1));
                    continue;
                }
                if (opcode == 0x0037 && regions.Count != 0)
                {
                    var region = regions.Pop();
                    regions.Push(Tuple.Create(region.Item1, index));
                    continue;
                }
                if (opcode == 0x0038 && regions.Count != 0)
                {
                    var region = regions.Pop();
                    if (region.Item2 >= 0) result[region.Item2] = index;
                }
            }
            return result;
        }

        private static List<Outcome> ExecuteFunction(
            Context context,
            InstallScriptFunction function,
            Value[] arguments,
            MachineState initialState,
            string entryPoint,
            int depth,
            HashSet<int> callStack)
        {
            if (depth >= context.MaximumCallDepth)
            {
                AddWarning(context, "InstallScript call-depth limit reached at " + function.Name + ".");
                return new List<Outcome> { new Outcome { State = initialState, ReturnValue = Value.Unknown("call-depth:" + function.Name) } };
            }
            int invocationCount;
            context.FunctionInvocations.TryGetValue(function.Index, out invocationCount);
            invocationCount++;
            context.FunctionInvocations[function.Index] = invocationCount;
            if (invocationCount > 32)
            {
                AddWarning(context, "Repeated InstallScript helper calls were bounded at " + function.Name + ".");
                return new List<Outcome> { new Outcome { State = initialState, ReturnValue = Value.Unknown("invocation-limit:" + function.Name) } };
            }
            if (!callStack.Add(function.Index))
            {
                AddWarning(context, "Recursive InstallScript call was bounded at " + function.Name + ".");
                return new List<Outcome> { new Outcome { State = initialState, ReturnValue = Value.Unknown("recursive:" + function.Name) } };
            }

            var frame = BindParameters(function, arguments);
            var labels = new Dictionary<int, int>();
            var catchEndIndexes = FindCatchEndIndexes(function);
            var branchBaseLabels = new int[function.Instructions.Count];
            var currentLabel = function.LabelIndex;
            for (var index = 0; index < function.Instructions.Count; index++)
            {
                foreach (var label in function.Instructions[index].LabelIndexes)
                {
                    if (!labels.ContainsKey(label)) labels.Add(label, index);
                    currentLabel = label;
                }
                branchBaseLabels[index] = currentLabel;
            }
            var pending = new Queue<WorkItem>();
            pending.Enqueue(new WorkItem { InstructionIndex = 0, Frame = frame, State = initialState, Visits = new Dictionary<int, int>() });
            var outcomes = new List<Outcome>();

            while (pending.Count != 0 && outcomes.Count < MaximumPathsPerCall && !context.Result.Truncated)
            {
                var work = pending.Dequeue();
                while (work.InstructionIndex >= 0 && work.InstructionIndex < function.Instructions.Count)
                {
                    if (++context.Result.ExploredInstructionCount > context.MaximumInstructions)
                    {
                        context.Result.Truncated = true;
                        AddWarning(context, "InstallScript static emulation reached its instruction limit.");
                        break;
                    }
                    int visits;
                    work.Visits.TryGetValue(work.InstructionIndex, out visits);
                    if (visits >= 2)
                    {
                        AddNotice(context, "InstallScript loop was bounded in " + function.Name + ".");
                        break;
                    }
                    work.Visits[work.InstructionIndex] = visits + 1;

                    var instruction = function.Instructions[work.InstructionIndex];
                    if (instruction.IsOpaque)
                    {
                        if (instruction.Destination != null)
                            WriteOperand(work.Frame, work.State, instruction.Destination, Value.Unknown("opaque-0x" + instruction.Opcode.ToString("X4")));
                        work.InstructionIndex++;
                        continue;
                    }

                    if (instruction.Opcode == 0x0001 || instruction.Opcode == 0x0005)
                    {
                        if (!TryJump(labels, branchBaseLabels[work.InstructionIndex], instruction.BranchTarget, work))
                            AddWarning(context, "InstallScript branch target " + instruction.BranchTarget + " is unresolved in " + function.Name + ".");
                        continue;
                    }
                    if (instruction.Opcode == 0x0004)
                    {
                        var condition = instruction.Operands.Count == 0 ? Value.Unknown("if-condition") : ReadOperand(work.Frame, work.State, instruction.Operands[0]);
                        var truth = GetTruth(condition);
                        if (truth.HasValue)
                        {
                            if (!truth.Value && !TryJump(labels, branchBaseLabels[work.InstructionIndex], instruction.BranchTarget, work))
                                AddWarning(context, "InstallScript conditional target " + instruction.BranchTarget + " is unresolved in " + function.Name + ".");
                            else if (truth.Value) work.InstructionIndex++;
                            continue;
                        }
                        // Generated InstallScript commonly emits `if false`
                        // around an error/abort block. Follow the false target
                        // as the successful static scenario. Other named event
                        // entry points are analyzed independently, while an
                        // unresolved condition is reported instead of causing
                        // exponential path multiplication.
                        AddNotice(context, "InstallScript unknown conditions were evaluated through their false branch for bounded static evidence.");
                        if (!TryJump(labels, branchBaseLabels[work.InstructionIndex], instruction.BranchTarget, work))
                            work.InstructionIndex++;
                        continue;
                    }
                    if (instruction.Opcode == 0x0002 || instruction.Opcode == 0x0003)
                    {
                        outcomes.Add(new Outcome { State = work.State, ReturnValue = Value.Unknown(instruction.Operation) });
                        break;
                    }
                    if (instruction.Opcode == 0x0036 || instruction.Opcode == 0x0038)
                    {
                        // Try and endcatch delimit protected regions. They do
                        // not alter the successful execution path by themselves.
                        work.InstructionIndex++;
                        continue;
                    }
                    if (instruction.Opcode == 0x0037)
                    {
                        int endIndex;
                        if (catchEndIndexes.TryGetValue(work.InstructionIndex, out endIndex))
                        {
                            // Catch bodies execute only after a runtime exception.
                            // Imported code is never invoked by this emulator, so
                            // keep exception-only effects out of normal ARP evidence.
                            AddNotice(context, "InstallScript catch-only effects were excluded from normal-path metadata.");
                            work.InstructionIndex = endIndex + 1;
                        }
                        else
                        {
                            AddWarning(context, "An InstallScript catch region could not be matched to endcatch in " + function.Name + ".");
                            work.InstructionIndex++;
                        }
                        continue;
                    }
                    if (instruction.Opcode == 0x0023 || instruction.Opcode == 0x0024 || instruction.Opcode == 0x0025)
                    {
                        var returned = instruction.Operands.Count == 0 ? Value.Unknown("void-return") : ReadOperand(work.Frame, work.State, instruction.Operands[0]);
                        outcomes.Add(new Outcome { State = work.State, ReturnValue = returned });
                        break;
                    }
                    if (instruction.Opcode == 0x0020 || instruction.Opcode == 0x0021)
                    {
                        if (instruction.CallTargetIndex < 0 || instruction.CallTargetIndex >= context.Program.Functions.Count)
                        {
                            work.State.LastResult = Value.Unknown("invalid-call-target");
                            work.InstructionIndex++;
                            continue;
                        }
                        var target = context.Program.Functions[instruction.CallTargetIndex];
                        var values = instruction.Operands.Select(operand => ReadOperand(work.Frame, work.State, operand)).ToArray();
                        RecordCall(context, entryPoint, function, instruction, target, values);
                        if (instruction.Opcode == 0x0020)
                        {
                            work.State.LastResult = HandleImportedCall(context, entryPoint, function, instruction, target, values, work.State);
                            work.InstructionIndex++;
                            continue;
                        }
                        if (context.RootSetterFunctions.Contains(target.Index))
                        {
                            SetRoot(work.State, values.Length == 0 ? Value.Unknown("registry-root") : values[0]);
                            work.State.LastResult = Value.FromNumber(0);
                            work.InstructionIndex++;
                            continue;
                        }
                        if (context.LocalizationFunctions.Contains(target.Index) && values.Length != 0)
                        {
                            work.State.LastResult = ResolveResource(context, values[0]);
                            work.InstructionIndex++;
                            continue;
                        }
                        int effectDistance;
                        if (!context.EffectDistances.TryGetValue(target.Index, out effectDistance) || effectDistance > 1)
                        {
                            work.State.LastResult = Value.Unknown("unmodeled-call:" + target.Name);
                            work.InstructionIndex++;
                            continue;
                        }

                        var bindings = CreateCallBindings(target, instruction.Operands, work.Frame, work.State);
                        var nestedStack = new HashSet<int>(callStack);
                        var nested = ExecuteFunction(context, target, bindings.Select(binding => binding.Value).ToArray(), work.State.Clone(), entryPoint, depth + 1, nestedStack);
                        if (nested.Count == 0)
                        {
                            work.State.LastResult = Value.Unknown("call:" + target.Name);
                            work.InstructionIndex++;
                            continue;
                        }
                        // A generated runtime helper can have dozens of error
                        // exits that are equivalent to its caller. Preserve a
                        // bounded set of distinct return/root states instead of
                        // multiplying every internal path into the outer entry
                        // point and starving later installation operations.
                        foreach (var outcome in nested
                            .GroupBy(item => item.ReturnValue.Render() + "\0" + string.Join("|", item.State.RootCandidates), StringComparer.Ordinal)
                            .Select(group => group.First())
                            .Take(MaximumNestedOutcomes))
                        {
                            var resumed = work.Clone();
                            resumed.State = outcome.State;
                            resumed.State.LastResult = outcome.ReturnValue;
                            ApplyCallBindings(bindings, resumed.Frame, resumed.State);
                            resumed.InstructionIndex++;
                            pending.Enqueue(resumed);
                        }
                        break;
                    }

                    if (instruction.Opcode == 0x002F)
                    {
                        // Handler records bind an event identifier to a decoded
                        // function. The global binding catalog is built once
                        // before execution, so the instruction itself is a no-op.
                        work.InstructionIndex++;
                        continue;
                    }
                    if (instruction.Opcode == 0x0030)
                    {
                        List<int> handlerIndexes;
                        if (instruction.Destination == null ||
                            !context.HandlerFunctions.TryGetValue(instruction.Destination.IntegerValue, out handlerIndexes))
                        {
                            work.State.LastResult = Value.Unknown("unresolved-handler");
                            work.InstructionIndex++;
                            continue;
                        }

                        var relevantHandlers = handlerIndexes
                            .Where(index => context.EffectDistances.ContainsKey(index))
                            .Take(MaximumNestedOutcomes)
                            .ToArray();
                        if (relevantHandlers.Length == 0)
                        {
                            work.State.LastResult = Value.Unknown("handler-without-static-effects");
                            work.InstructionIndex++;
                            continue;
                        }
                        if (handlerIndexes.Count > relevantHandlers.Length)
                            AddWarning(context, "InstallScript handler alternatives were bounded for event " + instruction.Destination.IntegerValue + ".");

                        foreach (var handlerIndex in relevantHandlers)
                        {
                            var target = context.Program.Functions[handlerIndex];
                            var nestedStack = new HashSet<int>(callStack);
                            var nested = ExecuteFunction(context, target, new Value[0], work.State.Clone(), entryPoint, depth + 1, nestedStack);
                            foreach (var outcome in nested.Take(MaximumNestedOutcomes))
                            {
                                var resumed = work.Clone();
                                resumed.State = outcome.State;
                                resumed.State.LastResult = outcome.ReturnValue;
                                resumed.InstructionIndex++;
                                pending.Enqueue(resumed);
                            }
                        }
                        break;
                    }

                    // These instructions use their encoded destination as an
                    // input object/string and publish the operation result via
                    // InstallScript's RESULT slot. Handling them before the
                    // ordinary destination-writing expressions preserves both
                    // the input value and the following `x = RESULT` sequence.
                    if (instruction.Opcode == 0x0028 || instruction.Opcode == 0x002A ||
                        instruction.Opcode == 0x002B || instruction.Opcode == 0x0031 ||
                        instruction.Opcode == 0x0032 || instruction.Opcode == 0x0033 ||
                        instruction.Opcode == 0x0034 || instruction.Opcode == 0x0035)
                    {
                        EvaluateResultOrMemberOperation(instruction, work.Frame, work.State);
                        work.InstructionIndex++;
                        continue;
                    }

                    // InstallScript encodes address creation and pointer
                    // parameter materialization as different operations. Keep
                    // the referenced member snapshot in machine state so a
                    // callee can read it after the caller frame is no longer
                    // directly addressable.
                    if (instruction.Opcode == 0x001A || instruction.Opcode == 0x001B || instruction.Opcode == 0x001C)
                    {
                        EvaluateReferenceOperation(instruction, work.Frame, work.State);
                        work.InstructionIndex++;
                        continue;
                    }

                    // UseDLL and UnUseDLL consume the encoded destination as a
                    // path and publish status through RESULT. Record the opaque
                    // module boundary without loading code into this process.
                    if (instruction.Opcode == 0x0039 || instruction.Opcode == 0x003A)
                    {
                        AddDllOperation(context, entryPoint, function, instruction, work.Frame, work.State);
                        work.State.LastResult = Value.Unknown(instruction.Opcode == 0x0039 ? "UseDLL-result" : "UnUseDLL-result");
                        work.InstructionIndex++;
                        continue;
                    }

                    EvaluateOperation(instruction, work.Frame, work.State);
                    if (instruction.Opcode == 0x0129 || instruction.Opcode == 0x0026)
                    {
                        outcomes.Add(new Outcome { State = work.State, ReturnValue = Value.Unknown("implicit-return") });
                        break;
                    }
                    work.InstructionIndex++;
                }
            }

            callStack.Remove(function.Index);
            if (outcomes.Count == 0)
                outcomes.Add(new Outcome { State = initialState, ReturnValue = Value.Unknown("incomplete:" + function.Name) });
            return outcomes;
        }

        private static Frame BindParameters(InstallScriptFunction function, Value[] arguments)
        {
            var frame = new Frame();
            var stringIndex = 0;
            var numberIndex = 0;
            for (var index = 0; index < function.Parameters.Count; index++)
            {
                var value = index < arguments.Length ? arguments[index].Clone() : Value.Unknown("argument:" + index);
                if (function.Parameters[index] == 0) frame.Strings[stringIndex++] = value;
                else frame.Numbers[numberIndex++] = value;
            }
            return frame;
        }

        private static List<CallBinding> CreateCallBindings(
            InstallScriptFunction target,
            IList<InstallScriptOperand> operands,
            Frame frame,
            MachineState state)
        {
            var result = new List<CallBinding>(operands.Count);
            for (var index = 0; index < operands.Count; index++)
            {
                var source = operands[index];
                var value = ReadOperand(frame, state, source);
                var byReference = index < target.ParameterFlags.Count && (target.ParameterFlags[index] & 0x02) != 0;
                if (!byReference || !IsWritableOperand(source))
                {
                    result.Add(new CallBinding { Value = value });
                    continue;
                }

                var stored = ReadStoredOperand(frame, state, source);
                if (stored != null && stored.IsValueReference && !string.IsNullOrEmpty(stored.ReferenceIdentity))
                {
                    // Forwarding a BYREF parameter must retain the original
                    // caller's slot rather than creating a reference to a copy.
                    result.Add(new CallBinding
                    {
                        Value = stored.Clone(),
                        Source = source,
                        ReferenceIdentity = stored.ReferenceIdentity
                    });
                    continue;
                }

                var identity = "value-reference:" + state.NextReferenceIdentity++.ToString(System.Globalization.CultureInfo.InvariantCulture);
                state.ReferencedValues[identity] = value.Clone();
                result.Add(new CallBinding
                {
                    Value = Value.FromValueReference(identity),
                    Source = source,
                    ReferenceIdentity = identity
                });
            }
            return result;
        }

        private static void ApplyCallBindings(IEnumerable<CallBinding> bindings, Frame frame, MachineState state)
        {
            foreach (var binding in bindings)
            {
                Value value;
                if (binding.Source == null || string.IsNullOrEmpty(binding.ReferenceIdentity) ||
                    !state.ReferencedValues.TryGetValue(binding.ReferenceIdentity, out value))
                    continue;
                WriteOperand(frame, state, binding.Source, value);
            }
        }

        private static bool IsWritableOperand(InstallScriptOperand operand)
        {
            if (operand == null) return false;
            return operand.Kind == InstallScriptOperandKind.LocalStringVariable ||
                operand.Kind == InstallScriptOperandKind.LocalNumberVariable ||
                operand.Kind == InstallScriptOperandKind.SystemStringVariable ||
                operand.Kind == InstallScriptOperandKind.UserStringVariable ||
                operand.Kind == InstallScriptOperandKind.SystemNumberVariable ||
                operand.Kind == InstallScriptOperandKind.UserNumberVariable;
        }

        private static bool TryJump(Dictionary<int, int> labels, int baseLabel, int relativeTarget, WorkItem work)
        {
            int instructionIndex;
            // INX branch operands are deltas from the most recently emitted
            // global label, not absolute function-local indexes.
            var target = baseLabel + relativeTarget;
            if (!labels.TryGetValue(target, out instructionIndex)) return false;
            work.InstructionIndex = instructionIndex;
            return true;
        }

        private static Value ReadOperand(Frame frame, MachineState state, InstallScriptOperand operand)
        {
            if (operand == null) return Value.Unknown("missing-operand");
            Value stored;
            switch (operand.Kind)
            {
                case InstallScriptOperandKind.Integer: return Value.FromNumber(operand.IntegerValue);
                case InstallScriptOperandKind.String: return Value.FromString(operand.StringValue);
                case InstallScriptOperandKind.LocalStringVariable:
                    stored = ReadVariable(frame.Strings, operand.IntegerValue, "local-string");
                    break;
                case InstallScriptOperandKind.LocalNumberVariable:
                    stored = ReadVariable(frame.Numbers, operand.IntegerValue, "local-number");
                    break;
                case InstallScriptOperandKind.SystemStringVariable:
                case InstallScriptOperandKind.UserStringVariable:
                    stored = ReadVariable(state.StringVariables, operand.Kind + ":" + operand.IntegerValue, "global-string");
                    break;
                case InstallScriptOperandKind.SystemNumberVariable:
                case InstallScriptOperandKind.UserNumberVariable:
                    // Generated wrappers place imported/user-call return values
                    // in the runtime RESULT slot, encoded as tag 0x08/index 0.
                    if (operand.EncodedTag == 0x08 && operand.IntegerValue == 0) return state.LastResult.Clone();
                    stored = ReadVariable(state.NumberVariables, operand.Kind + ":" + operand.IntegerValue, "global-number");
                    break;
                default: return Value.Unknown(operand.Kind + ":" + operand.IntegerValue);
            }
            return ResolveValueReference(state, stored);
        }

        private static Value ReadStoredOperand(Frame frame, MachineState state, InstallScriptOperand operand)
        {
            if (operand == null) return null;
            Value value;
            switch (operand.Kind)
            {
                case InstallScriptOperandKind.LocalStringVariable:
                    return frame.Strings.TryGetValue(operand.IntegerValue, out value) ? value.Clone() : null;
                case InstallScriptOperandKind.LocalNumberVariable:
                    return frame.Numbers.TryGetValue(operand.IntegerValue, out value) ? value.Clone() : null;
                case InstallScriptOperandKind.SystemStringVariable:
                case InstallScriptOperandKind.UserStringVariable:
                    return state.StringVariables.TryGetValue(operand.Kind + ":" + operand.IntegerValue, out value) ? value.Clone() : null;
                case InstallScriptOperandKind.SystemNumberVariable:
                case InstallScriptOperandKind.UserNumberVariable:
                    return state.NumberVariables.TryGetValue(operand.Kind + ":" + operand.IntegerValue, out value) ? value.Clone() : null;
                default:
                    return null;
            }
        }

        private static Value ResolveValueReference(MachineState state, Value value)
        {
            if (value == null || !value.IsValueReference || string.IsNullOrEmpty(value.ReferenceIdentity))
                return value == null ? Value.Unknown("missing-value") : value;
            Value referenced;
            return state.ReferencedValues.TryGetValue(value.ReferenceIdentity, out referenced)
                ? referenced.Clone()
                : Value.Unknown("unresolved-value-reference");
        }

        private static Value ReadVariable<TKey>(Dictionary<TKey, Value> variables, TKey key, string description)
        {
            Value value;
            return variables.TryGetValue(key, out value) ? value.Clone() : Value.Unknown(description + ":" + key);
        }

        private static void WriteOperand(Frame frame, MachineState state, InstallScriptOperand operand, Value value)
        {
            if (operand == null) return;
            var stored = ReadStoredOperand(frame, state, operand);
            if (stored != null && stored.IsValueReference && !string.IsNullOrEmpty(stored.ReferenceIdentity))
            {
                state.ReferencedValues[stored.ReferenceIdentity] = value.Clone();
                return;
            }
            switch (operand.Kind)
            {
                case InstallScriptOperandKind.LocalStringVariable: frame.Strings[operand.IntegerValue] = value.Clone(); break;
                case InstallScriptOperandKind.LocalNumberVariable: frame.Numbers[operand.IntegerValue] = value.Clone(); break;
                case InstallScriptOperandKind.SystemStringVariable:
                case InstallScriptOperandKind.UserStringVariable:
                    state.StringVariables[operand.Kind + ":" + operand.IntegerValue] = value.Clone();
                    break;
                case InstallScriptOperandKind.SystemNumberVariable:
                case InstallScriptOperandKind.UserNumberVariable:
                    state.NumberVariables[operand.Kind + ":" + operand.IntegerValue] = value.Clone();
                    break;
            }
        }

        private static void EvaluateOperation(InstallScriptInstruction instruction, Frame frame, MachineState state)
        {
            if (instruction.Destination == null) return;
            var values = instruction.Operands.Select(operand => ReadOperand(frame, state, operand)).ToArray();
            var current = ReadOperand(frame, state, instruction.Destination);
            Value result;
            switch (instruction.Opcode)
            {
                case 0x0006: result = values.Length == 0 ? Value.Unknown("assignment") : values[0]; break;
                case 0x0007: result = Add(values, false); break;
                case 0x0014: result = Add(values, true); break;
                case 0x0008: result = Numeric(values, (left, right) => right == 0 ? 0 : left % right); break;
                case 0x000F: result = Numeric(values, (left, right) => left - right); break;
                case 0x0010: result = Numeric(values, (left, right) => left * right); break;
                case 0x0011: result = Numeric(values, (left, right) => right == 0 ? 0 : left / right); break;
                case 0x0012: result = Numeric(values, (left, right) => left & right); break;
                case 0x0013: result = Numeric(values, (left, right) => left | right); break;
                case 0x0015: result = values.Length != 0 && values[0].Number.HasValue ? Value.FromNumber(~values[0].Number.Value) : Value.Unknown("bit-not"); break;
                case 0x0016: result = Numeric(values, (left, right) => left << (int)right); break;
                case 0x0017: result = Numeric(values, (left, right) => left >> (int)right); break;
                case 0x0018: result = Logical(values, false); break;
                case 0x0019: result = Logical(values, true); break;
                case 0x0009: result = Compare(values, comparison => comparison < 0); break;
                case 0x000A: result = Compare(values, comparison => comparison > 0); break;
                case 0x000B: result = Compare(values, comparison => comparison <= 0); break;
                case 0x000C: result = Compare(values, comparison => comparison >= 0); break;
                case 0x000D: result = Compare(values, comparison => comparison == 0); break;
                case 0x000E: result = Compare(values, comparison => comparison != 0); break;
                case 0x001D:
                    result = WriteStringCharacter(current, values);
                    break;
                case 0x001E:
                    result = ReadStringCharacter(values);
                    break;
                case 0x0029:
                    result = Substring(values);
                    break;
                case 0x002C:
                    long parsed;
                    result = values.Length != 0 && values[0].Strings.Count == 1 && long.TryParse(values[0].Strings[0], out parsed)
                        ? Value.FromNumber(parsed) : Value.Unknown("string-to-number");
                    break;
                case 0x002D:
                    result = values.Length != 0 && values[0].Number.HasValue
                        ? Value.FromString(values[0].Number.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)) : Value.Unknown("number-to-string");
                    break;
                case 0x003C:
                    // Observed builder output uses 0x003C to convert a string
                    // value to the pointer-sized value passed into Win32 API
                    // structures. Preserve the referenced text symbolically.
                    result = values.Length == 0 ? Value.Unknown("string-pointer") : values[0].Clone();
                    break;
                default: result = Value.Unknown("operation-0x" + instruction.Opcode.ToString("X4")); break;
            }
            WriteOperand(frame, state, instruction.Destination, result);
        }

        private static void EvaluateReferenceOperation(InstallScriptInstruction instruction, Frame frame, MachineState state)
        {
            if (instruction.Opcode == 0x001C)
            {
                // A pointer-typed parameter is already bound to the local
                // destination. The prologue materializes it in RESULT for the
                // generated member-access sequence that follows.
                state.LastResult = ReadOperand(frame, state, instruction.Destination);
                return;
            }

            if (instruction.Opcode == 0x001B)
            {
                // The compiler emits `destination = *pointer` as Indirect.
                // Resolve only symbolic primitive slots created by AddressOf;
                // structure fields continue through MemberRead/MemberWrite.
                if (instruction.Destination == null || instruction.Operands.Count == 0)
                    return;
                var reference = ReadStoredOperand(frame, state, instruction.Operands[0]);
                Value value;
                if (reference != null && reference.IsValueReference &&
                    !string.IsNullOrEmpty(reference.ReferenceIdentity) &&
                    state.ReferencedValues.TryGetValue(reference.ReferenceIdentity, out value))
                    WriteOperand(frame, state, instruction.Destination, value);
                else
                    WriteOperand(frame, state, instruction.Destination, Value.Unknown("indirect-unresolved-value"));
                return;
            }

            if (instruction.Destination == null || instruction.Operands.Count == 0)
                return;
            var source = instruction.Operands[0];
            var existing = ReadOperand(frame, state, source);
            if (!string.IsNullOrEmpty(existing.ReferenceIdentity))
            {
                WriteOperand(frame, state, instruction.Destination, existing);
                return;
            }

            Dictionary<string, Value> members;
            var sourceStore = GetObjectStore(frame, state, source);
            if (!sourceStore.TryGetValue(GetOperandIdentity(source), out members))
            {
                if (!IsWritableOperand(source))
                {
                    WriteOperand(frame, state, instruction.Destination, Value.Unknown("address-of-unresolved-value"));
                    return;
                }

                // Primitive AddressOf records a symbolic slot. The slot keeps
                // the current value and can be read by opcode 0x001B without
                // creating or dereferencing a native pointer.
                var valueIdentity = "value-reference:" + state.NextReferenceIdentity++.ToString(System.Globalization.CultureInfo.InvariantCulture);
                state.ReferencedValues[valueIdentity] = ReadOperand(frame, state, source);
                WriteOperand(frame, state, instruction.Destination, Value.FromValueReference(valueIdentity));
                return;
            }

            var identity = "object-reference:" + state.NextReferenceIdentity++.ToString(System.Globalization.CultureInfo.InvariantCulture);
            state.ReferencedObjects[identity] = CloneMembers(members);
            WriteOperand(frame, state, instruction.Destination, Value.FromReference(identity));
        }

        private static Value WriteStringCharacter(Value current, Value[] values)
        {
            if (!current.Complete || current.Strings.Count != 1 || values.Length < 2 || !values[0].Number.HasValue)
                return Value.Unknown("string-write");
            var index = values[0].Number.Value;
            if (index < 0 || index > int.MaxValue) return Value.Unknown("string-write-index");
            var character = values[1].Number.HasValue
                ? (char)values[1].Number.Value
                : values[1].Complete && values[1].Strings.Count == 1 && values[1].Strings[0].Length != 0 ? values[1].Strings[0][0] : '\0';
            var text = current.Strings[0];
            if (index >= text.Length) return Value.Unknown("string-write-range");
            var characters = text.ToCharArray();
            characters[(int)index] = character;
            return Value.FromString(new string(characters));
        }

        private static Value ReadStringCharacter(Value[] values)
        {
            if (values.Length < 2 || !values[0].Complete || values[0].Strings.Count != 1 || !values[1].Number.HasValue)
                return Value.Unknown("string-read");
            var text = values[0].Strings[0];
            var index = values[1].Number.Value;
            return index >= 0 && index < text.Length ? Value.FromNumber(text[(int)index]) : Value.Unknown("string-read-range");
        }

        private static Value Substring(Value[] values)
        {
            if (values.Length < 3 || !values[0].Complete || values[0].Strings.Count != 1 ||
                !values[1].Number.HasValue || !values[2].Number.HasValue)
                return Value.Unknown("substring");
            var text = values[0].Strings[0];
            var start = values[1].Number.Value;
            var count = values[2].Number.Value;
            if (start < 0 || count < 0 || start > text.Length || count > text.Length - start)
                return Value.Unknown("substring-range");
            return Value.FromString(text.Substring((int)start, (int)count));
        }

        private static Value FindString(Value current, Value[] values)
        {
            if (!current.Complete || current.Strings.Count != 1 || values.Length == 0 ||
                !values[0].Complete || values[0].Strings.Count != 1)
                return Value.Unknown("string-find");
            return Value.FromNumber(current.Strings[0].IndexOf(values[0].Strings[0], StringComparison.Ordinal));
        }

        private static Value CompareString(Value current, Value[] values)
        {
            if (!current.Complete || current.Strings.Count != 1 || values.Length == 0 ||
                !values[0].Complete || values[0].Strings.Count != 1)
                return Value.Unknown("string-compare");
            return Value.FromNumber(string.CompareOrdinal(current.Strings[0], values[0].Strings[0]));
        }

        private static void EvaluateResultOrMemberOperation(InstallScriptInstruction instruction, Frame frame, MachineState state)
        {
            var current = ReadOperand(frame, state, instruction.Destination);
            var values = instruction.Operands.Select(operand => ReadOperand(frame, state, operand)).ToArray();
            switch (instruction.Opcode)
            {
                case 0x0028:
                    state.LastResult = current.Complete && current.Strings.Count == 1
                        ? Value.FromNumber(current.Strings[0].Length) : Value.Unknown("string-length");
                    return;
                case 0x002A:
                    state.LastResult = FindString(current, values);
                    return;
                case 0x002B:
                    state.LastResult = CompareString(current, values);
                    return;
                case 0x0031:
                    // Resize returns the requested capacity while retaining the
                    // logical string content used by subsequent static calls.
                    state.LastResult = values.Length != 0 && values[0].Number.HasValue
                        ? Value.FromNumber(values[0].Number.Value) : Value.Unknown("resize");
                    return;
                case 0x0032:
                    state.LastResult = current.Complete && current.Strings.Count == 1
                        ? Value.FromNumber(current.Strings[0].Length) : Value.Unknown("sizeof");
                    return;
                case 0x0033:
                    WriteMember(frame, state, instruction.Destination, values);
                    state.LastResult = Value.FromNumber(0);
                    return;
                case 0x0034:
                    CopyObject(frame, state, instruction.Destination, instruction.Operands.Count == 0 ? null : instruction.Operands[0]);
                    state.LastResult = Value.FromNumber(0);
                    return;
                case 0x0035:
                    state.LastResult = ReadMember(frame, state, instruction.Destination, values);
                    return;
            }
        }

        private static Dictionary<string, Dictionary<string, Value>> GetObjectStore(Frame frame, MachineState state, InstallScriptOperand operand)
        {
            return operand != null && (operand.Kind == InstallScriptOperandKind.LocalNumberVariable || operand.Kind == InstallScriptOperandKind.LocalStringVariable)
                ? frame.Objects : state.Objects;
        }

        private static string GetOperandIdentity(InstallScriptOperand operand)
        {
            return operand == null ? "missing-object" : operand.Kind + ":" + operand.IntegerValue.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        private static void WriteMember(Frame frame, MachineState state, InstallScriptOperand target, Value[] values)
        {
            if (target == null || values.Length < 2 || !values[0].Complete || values[0].Strings.Count != 1) return;
            Dictionary<string, Value> members;
            var reference = ReadOperand(frame, state, target);
            if (!string.IsNullOrEmpty(reference.ReferenceIdentity))
            {
                if (!state.ReferencedObjects.TryGetValue(reference.ReferenceIdentity, out members))
                {
                    members = new Dictionary<string, Value>(StringComparer.Ordinal);
                    state.ReferencedObjects.Add(reference.ReferenceIdentity, members);
                }
            }
            else
            {
                var store = GetObjectStore(frame, state, target);
                var identity = GetOperandIdentity(target);
                if (!store.TryGetValue(identity, out members))
                {
                    members = new Dictionary<string, Value>(StringComparer.Ordinal);
                    store.Add(identity, members);
                }
            }
            members[values[0].Strings[0]] = values[1].Clone();
        }

        private static Value ReadMember(Frame frame, MachineState state, InstallScriptOperand target, Value[] values)
        {
            if (target == null || values.Length == 0 || !values[0].Complete || values[0].Strings.Count != 1)
                return Value.Unknown("member-read");
            Dictionary<string, Value> members;
            Value value;
            var reference = ReadOperand(frame, state, target);
            var found = !string.IsNullOrEmpty(reference.ReferenceIdentity)
                ? state.ReferencedObjects.TryGetValue(reference.ReferenceIdentity, out members)
                : GetObjectStore(frame, state, target).TryGetValue(GetOperandIdentity(target), out members);
            return found && members.TryGetValue(values[0].Strings[0], out value)
                ? value.Clone() : Value.Unknown("member:" + values[0].Strings[0]);
        }

        private static void CopyObject(Frame frame, MachineState state, InstallScriptOperand destination, InstallScriptOperand source)
        {
            if (destination == null || source == null) return;
            var sourceStore = GetObjectStore(frame, state, source);
            Dictionary<string, Value> sourceMembers;
            if (!sourceStore.TryGetValue(GetOperandIdentity(source), out sourceMembers)) return;
            GetObjectStore(frame, state, destination)[GetOperandIdentity(destination)] = CloneMembers(sourceMembers);
        }

        private static void AddDllOperation(
            Context context,
            string entryPoint,
            InstallScriptFunction function,
            InstallScriptInstruction instruction,
            Frame frame,
            MachineState state)
        {
            if (!CanAddEffect(context)) return;
            var path = ReadOperand(frame, state, instruction.Destination);
            var operation = instruction.Opcode == 0x0039 ? "Load" : "Unload";
            var identity = "dll\0" + entryPoint + "\0" + function.Index + "\0" + instruction.Offset + "\0" + operation + "\0" + path.Render();
            if (!context.EffectSet.Add(identity)) return;
            context.Result.DllOperations.Add(new InstallScriptDllOperation
            {
                EntryPoint = entryPoint,
                Function = function.Name,
                Offset = instruction.Offset,
                Operation = operation,
                Path = path.Render(),
                Complete = path.Complete && path.Strings.Count == 1
            });
        }

        private static Value Add(Value[] values, bool xorWhenNumeric)
        {
            if (values.Length < 2) return Value.Unknown("add");
            if (values[0].Number.HasValue && values[1].Number.HasValue)
                return Value.FromNumber(xorWhenNumeric ? values[0].Number.Value ^ values[1].Number.Value : values[0].Number.Value + values[1].Number.Value);
            var result = new Value { Complete = values[0].Complete && values[1].Complete };
            foreach (var left in values[0].TextAlternatives())
                foreach (var right in values[1].TextAlternatives())
                {
                    var combined = left + right;
                    if (!result.Strings.Contains(combined, StringComparer.Ordinal)) result.Strings.Add(combined);
                    if (result.Strings.Count >= MaximumValueAlternatives) return result;
                }
            return result;
        }

        private static Value Numeric(Value[] values, Func<long, long, long> operation)
        {
            return values.Length >= 2 && values[0].Number.HasValue && values[1].Number.HasValue
                ? Value.FromNumber(operation(values[0].Number.Value, values[1].Number.Value))
                : Value.Unknown("numeric-operation");
        }

        private static Value Logical(Value[] values, bool and)
        {
            if (values.Length < 2) return Value.Unknown("logical-operation");
            var left = GetTruth(values[0]);
            var right = GetTruth(values[1]);
            if (!left.HasValue || !right.HasValue) return Value.Unknown("logical-operation");
            return Value.FromNumber(and ? (left.Value && right.Value ? 1 : 0) : (left.Value || right.Value ? 1 : 0));
        }

        private static Value Compare(Value[] values, Func<int, bool> predicate)
        {
            if (values.Length < 2) return Value.Unknown("comparison");
            int comparison;
            if (values[0].Number.HasValue && values[1].Number.HasValue)
                comparison = values[0].Number.Value.CompareTo(values[1].Number.Value);
            else if (values[0].Complete && values[1].Complete && values[0].Strings.Count == 1 && values[1].Strings.Count == 1)
                comparison = string.CompareOrdinal(values[0].Strings[0], values[1].Strings[0]);
            else return Value.Unknown("comparison");
            return Value.FromNumber(predicate(comparison) ? 1 : 0);
        }

        private static bool? GetTruth(Value value)
        {
            if (value.Number.HasValue) return value.Number.Value != 0;
            if (value.Complete && value.Strings.Count == 1) return value.Strings[0].Length != 0;
            return null;
        }

        private static Value ResolveResource(Context context, Value key)
        {
            var values = new List<string>();
            var complete = key.Complete;
            foreach (var candidate in key.TextAlternatives())
            {
                string[] localized;
                if (context.Resources.TryGetValue(candidate, out localized) && localized.Length != 0)
                    values.AddRange(localized);
                else
                {
                    complete = false;
                    values.Add("<resource:" + candidate + ">");
                }
            }
            var result = Value.FromStrings(values.Distinct(StringComparer.Ordinal));
            result.Complete = complete;
            return result;
        }

        private static void RecordCall(Context context, string entryPoint, InstallScriptFunction function, InstallScriptInstruction instruction, InstallScriptFunction target, Value[] values)
        {
            if (!CanAddEffect(context)) return;
            var key = "call\0" + entryPoint + "\0" + function.Index + "\0" + instruction.Offset + "\0" + target.Index + "\0" + string.Join("\0", values.Select(value => value.Render()));
            if (!context.EffectSet.Add(key)) return;
            var evidence = new InstallScriptCallEvidence
            {
                EntryPoint = entryPoint,
                Function = function.Name,
                Offset = instruction.Offset,
                Target = target.Name,
                Complete = values.All(value => value.Complete)
            };
            foreach (var value in values) evidence.Arguments.Add(value.Render());
            context.Result.Calls.Add(evidence);
        }

        private static Value HandleImportedCall(Context context, string entryPoint, InstallScriptFunction function, InstallScriptInstruction instruction, InstallScriptFunction target, Value[] values, MachineState state)
        {
            var shortName = target.Name.Contains(".") ? target.Name.Substring(target.Name.LastIndexOf('.') + 1) : target.Name;
            if (shortName.Equals("RegDBSetDefaultRoot", StringComparison.OrdinalIgnoreCase))
            {
                SetRoot(state, values.Length == 0 ? Value.Unknown("registry-root") : values[0]);
                return Value.FromNumber(0);
            }
            if (shortName.Equals("_RegSetKeyValue", StringComparison.OrdinalIgnoreCase) && values.Length >= 7)
                AddRegistryWrites(context, entryPoint, function, instruction, state, values[2], values[3], MapRegistryType(values[4]), values[5], target.Name);
            else if (shortName.Equals("_RegSetKeyBinaryValue", StringComparison.OrdinalIgnoreCase) && values.Length >= 5)
                AddRegistryWrites(context, entryPoint, function, instruction, state, values[2], values[3], "REG_BINARY", values[4], target.Name);
            else if (shortName.Equals("RegDBSetKeyValueEx", StringComparison.OrdinalIgnoreCase) && values.Length >= 4)
                AddRegistryWrites(context, entryPoint, function, instruction, state, values[0], values[1], MapRegistryType(values[2]), values[3], target.Name);
            else if (shortName.Equals("RegDBSetKeyValue", StringComparison.OrdinalIgnoreCase) && values.Length >= 2)
                AddRegistryWrites(context, entryPoint, function, instruction, state, values[0], Value.FromString(string.Empty), "REG_SZ", values[1], target.Name);
            else if (shortName.Equals("RegDBCreateKeyValue", StringComparison.OrdinalIgnoreCase) && values.Length >= 2)
                AddRegistryWrites(context, entryPoint, function, instruction, state, values[0], values[1], "REG_SZ", Value.FromString(string.Empty), target.Name);
            else if (shortName.Equals("RegDBSetItem", StringComparison.OrdinalIgnoreCase) && values.Length >= 2)
                AddRegistryItem(context, entryPoint, function, instruction, values[0], values[1], target.Name);

            if (IsLaunchOperation(shortName)) AddExecutedPayload(context, entryPoint, function, instruction, shortName, values);
            if (IsFileOperation(shortName)) AddFileOperation(context, entryPoint, function, instruction, shortName, values);
            if (IsShortcutOperation(shortName)) AddShortcut(context, entryPoint, function, instruction, shortName, values);
            return Value.Unknown("return:" + target.Name);
        }

        private static void AddRegistryItem(Context context, string entryPoint, InstallScriptFunction function, InstallScriptInstruction instruction, Value itemValue, Value dataValue, string source)
        {
            if (!CanAddEffect(context)) return;
            var item = itemValue.Number;
            var name = item.HasValue ? MapRegistryItem(item.Value) : null;
            var identity = "regitem\0" + (item.HasValue ? item.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : itemValue.Render()) + "\0" + dataValue.Render();
            if (!context.EffectSet.Add(identity)) return;
            context.Result.RegistryItems.Add(new InstallScriptRegistryItemEvidence
            {
                EntryPoint = entryPoint,
                Function = function.Name,
                Offset = instruction.Offset,
                Item = item ?? -1,
                Name = name ?? "REGDB_ITEM_" + itemValue.Render(),
                Data = dataValue.Render(),
                Source = function.Name + " -> " + source,
                Complete = item.HasValue && name != null && dataValue.Complete
            });
        }

        private static string MapRegistryItem(long item)
        {
            // Values are defined by the official ISRTDefs.h shipped with the
            // InstallShield builder. They configure the later MaintenanceStart
            // registration rather than writing the registry immediately.
            switch (item)
            {
                case 1: return "AppPath";
                case 2: return "AppPathDefault";
                case 3: return "DisplayName";
                case 4: return "UninstallString";
                case 5: return "LogFile";
                case 6: return "ProductGuid";
                case 7: return "InstallLocation";
                case 8: return "Version";
                case 9: return "VersionMajor";
                case 10: return "VersionMinor";
                case 11: return "DisplayVersion";
                case 12: return "MaintenanceOption";
                case 13: return "Publisher";
                case 14: return "UrlInfoAbout";
                case 15: return "Contact";
                case 16: return "HelpLink";
                case 17: return "HelpTelephone";
                case 18: return "Readme";
                case 19: return "UrlUpdateInfo";
                case 20: return "Comments";
                case 21: return "ProductId";
                case 22: return "RegCompany";
                case 23: return "RegOwner";
                case 24: return "DisplayIcon";
                case 25: return "NoModify";
                case 26: return "NoRemove";
                case 27: return "NoRepair";
                case 28: return "ModifyPath";
                case 29: return "InstallDate";
                case 30: return "InstallSource";
                case 31: return "Language";
                case 32: return "SystemComponent";
                case 33: return "RegisteredOwner";
                case 34: return "RegisteredOrganization";
                case 35: return "MajorVersion";
                case 36: return "MinorVersion";
                default: return null;
            }
        }

        private static void SetRoot(MachineState state, Value value)
        {
            var roots = new List<string>();
            if (value.Number.HasValue)
            {
                var root = MapRoot(unchecked((int)value.Number.Value));
                if (root != null) roots.AddRange(root == "HKCU|HKLM" ? new[] { "HKCU", "HKLM" } : new[] { root });
            }
            if (roots.Count == 0) roots.Add("Unknown");
            state.RootCandidates.Clear();
            state.RootCandidates.AddRange(roots);
        }

        private static string MapRoot(int value)
        {
            switch (unchecked((uint)value))
            {
                case 0x80000000: return "HKCR";
                case 0x80000001: return "HKCU";
                case 0x80000002: return "HKLM";
                case 0x80000003: return "HKU";
                case 0x80000005: return "HKCC";
                default: return null;
            }
        }

        private static string MapRegistryType(Value value)
        {
            if (!value.Number.HasValue) return "REG_UNKNOWN";
            switch (value.Number.Value)
            {
                case 1: return "REG_SZ";
                case 2: return "REG_EXPAND_SZ";
                case 3: return "REG_BINARY";
                case 4: return "REG_DWORD";
                case 7: return "REG_MULTI_SZ";
                default: return "REGDB_TYPE_" + value.Number.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }
        }

        private static void AddRegistryWrites(Context context, string entryPoint, InstallScriptFunction function, InstallScriptInstruction instruction, MachineState state, Value keyValue, Value nameValue, string type, Value dataValue, string source)
        {
            foreach (var root in state.RootCandidates)
                foreach (var key in keyValue.TextAlternatives())
                    foreach (var name in nameValue.TextAlternatives())
                        foreach (var data in dataValue.TextAlternatives())
                        {
                            if (!CanAddEffect(context)) return;
                            var identity = "reg\0" + root + "\0" + key + "\0" + name + "\0" + type + "\0" + data;
                            if (!context.EffectSet.Add(identity)) continue;
                            var evidence = new InstallScriptRegistryWrite
                            {
                                EntryPoint = entryPoint,
                                Function = function.Name,
                                Offset = instruction.Offset,
                                Root = root,
                                Key = key,
                                Name = name,
                                Type = type,
                                Data = data,
                                Source = function.Name + " -> " + source,
                                Confidence = keyValue.Complete && nameValue.Complete && dataValue.Complete && root != "Unknown" ? "ExplicitStaticCall" : "PartialStaticCall",
                                Complete = keyValue.Complete && nameValue.Complete && dataValue.Complete && root != "Unknown"
                            };
                            evidence.RootCandidates.AddRange(state.RootCandidates);
                            context.Result.RegistryWrites.Add(evidence);
                        }
        }

        private static bool IsLaunchOperation(string name)
        {
            return name.IndexOf("LaunchApp", StringComparison.OrdinalIgnoreCase) >= 0 ||
                name.Equals("LaunchApplication", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("UninstallApplication", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("CreateProcess", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("CreateProcessA", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("CreateProcessW", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("WinExec", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("ShellExecute", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("ShellExecuteA", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("ShellExecuteW", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("ShellExecuteExA", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("ShellExecuteExW", StringComparison.OrdinalIgnoreCase);
        }

        private static void AddExecutedPayload(Context context, string entryPoint, InstallScriptFunction function, InstallScriptInstruction instruction, string operation, Value[] values)
        {
            if (!CanAddEffect(context)) return;
            var textual = values.Select(value => value.Render()).ToArray();
            var programIndex = FindProgramArgument(values);
            var program = programIndex >= 0 ? values[programIndex] : Value.Unknown("launched-program");
            var command = programIndex >= 0 && programIndex + 1 < values.Length ? values[programIndex + 1] : Value.Unknown("command-line");
            var identity = "exec\0" + entryPoint + "\0" + function.Index + "\0" + instruction.Offset + "\0" + string.Join("\0", textual);
            if (!context.EffectSet.Add(identity)) return;
            var evidence = new InstallScriptExecutedPayload
            {
                EntryPoint = entryPoint,
                Function = function.Name,
                Offset = instruction.Offset,
                Operation = operation,
                Program = program.Render(),
                CommandLine = command.Render(),
                Complete = program.Complete && command.Complete
            };
            evidence.Arguments.AddRange(textual);
            context.Result.ExecutedPayloads.Add(evidence);
        }

        private static int FindProgramArgument(Value[] values)
        {
            for (var index = 0; index < values.Length; index++)
                if (values[index].TextAlternatives().Any(text => text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || text.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)))
                    return index;
            return values.Length == 0 ? -1 : 0;
        }

        private static bool IsFileOperation(string name)
        {
            return name.Equals("CopyFile", StringComparison.OrdinalIgnoreCase) || name.Equals("XCopyFile", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("CopyFileA", StringComparison.OrdinalIgnoreCase) || name.Equals("CopyFileW", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("_FileCopy", StringComparison.OrdinalIgnoreCase) || name.Equals("MoveFile", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("MoveFileA", StringComparison.OrdinalIgnoreCase) || name.Equals("MoveFileW", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("MoveFileExA", StringComparison.OrdinalIgnoreCase) || name.Equals("MoveFileExW", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("RenameFile", StringComparison.OrdinalIgnoreCase) || name.Equals("DeleteFile", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("DeleteFileA", StringComparison.OrdinalIgnoreCase) || name.Equals("DeleteFileW", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("CreateDir", StringComparison.OrdinalIgnoreCase) || name.Equals("_CreateDir", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("DeleteDir", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsShortcutOperation(string name)
        {
            return name.Equals("AddFolderIcon", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("AddProgItemEx", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("CreateShortcut", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("ReplaceFolderIcon", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("ReplaceProgItem", StringComparison.OrdinalIgnoreCase);
        }

        private static void AddShortcut(Context context, string entryPoint, InstallScriptFunction function, InstallScriptInstruction instruction, string operation, Value[] values)
        {
            if (!CanAddEffect(context)) return;
            var folder = values.Length > 0 ? values[0] : Value.Unknown("shortcut-folder");
            var name = values.Length > 1 ? values[1] : Value.Unknown("shortcut-name");
            var command = values.Length > 2 ? values[2] : Value.Unknown("shortcut-command");
            var workingDirectory = values.Length > 3 ? values[3] : Value.Unknown("shortcut-working-directory");
            var iconPath = values.Length > 4 ? values[4] : Value.Unknown("shortcut-icon");
            var identity = "shortcut\0" + entryPoint + "\0" + function.Index + "\0" + instruction.Offset + "\0" + operation + "\0" + string.Join("\0", values.Select(value => value.Render()));
            if (!context.EffectSet.Add(identity)) return;
            var evidence = new InstallScriptShortcutEvidence
            {
                EntryPoint = entryPoint,
                Function = function.Name,
                Offset = instruction.Offset,
                Operation = operation,
                Folder = folder.Render(),
                Name = name.Render(),
                CommandLine = command.Render(),
                WorkingDirectory = workingDirectory.Render(),
                IconPath = iconPath.Render(),
                Complete = folder.Complete && name.Complete && command.Complete && workingDirectory.Complete && iconPath.Complete
            };
            evidence.Arguments.AddRange(values.Select(value => value.Render()));
            context.Result.Shortcuts.Add(evidence);
        }

        private static void AddFileOperation(Context context, string entryPoint, InstallScriptFunction function, InstallScriptInstruction instruction, string operation, Value[] values)
        {
            if (!CanAddEffect(context)) return;
            var strings = values.Where(value => value.Strings.Count != 0).ToArray();
            var source = strings.Length == 0 ? Value.Unknown("file-source") : strings[0];
            var destination = strings.Length < 2 ? Value.Unknown("file-destination") : strings[1];
            var identity = "file\0" + entryPoint + "\0" + function.Index + "\0" + instruction.Offset + "\0" + operation + "\0" + source.Render() + "\0" + destination.Render();
            if (!context.EffectSet.Add(identity)) return;
            var evidence = new InstallScriptFileOperation
            {
                EntryPoint = entryPoint,
                Function = function.Name,
                Offset = instruction.Offset,
                Operation = operation,
                Source = source.Render(),
                Destination = destination.Render(),
                Complete = source.Complete && (strings.Length < 2 || destination.Complete)
            };
            foreach (var value in values) evidence.Arguments.Add(value.Render());
            context.Result.FileOperations.Add(evidence);
        }

        private static bool CanAddEffect(Context context)
        {
            if (context.Result.Calls.Count + context.Result.RegistryWrites.Count + context.Result.RegistryItems.Count +
                context.Result.ExecutedPayloads.Count + context.Result.FileOperations.Count + context.Result.Shortcuts.Count < context.MaximumEffects)
                return true;
            context.Result.Truncated = true;
            AddWarning(context, "InstallScript static emulation reached its evidence limit.");
            return false;
        }

        private static void AddWarning(Context context, string warning)
        {
            if (context.WarningSet.Add(warning)) context.Result.Warnings.Add(warning);
        }

        private static void AddNotice(Context context, string notice)
        {
            if (context.NoticeSet.Add(notice)) context.Result.Notices.Add(notice);
        }
    }

    /// <summary>
    /// Performs bounded symbolic dialog tracing over the structural IR. The
    /// analyzer follows generated wrapper calls but does not evaluate external
    /// functions or mutate an emulated system.
    /// </summary>
}
