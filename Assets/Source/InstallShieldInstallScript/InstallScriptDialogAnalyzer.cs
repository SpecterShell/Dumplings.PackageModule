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

    public static class InstallScriptDialogAnalyzer
    {
        private sealed class DialogSummary
        {
            internal DialogSummary()
            {
                Function = string.Empty;
                Alternatives = new List<string>();
            }

            internal string Dialog;
            internal string Function;
            internal List<string> Alternatives;
            internal bool Complete;
        }

        public static List<InstallScriptDialogTrace> GetTraces(InstallScriptProgram program, string[] entryPoints)
        {
            if (program == null) throw new ArgumentNullException("program");
            var functionsByName = program.Functions
                .GroupBy(function => function.Name, StringComparer.Ordinal)
                .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
            var scenarios = new List<KeyValuePair<string, string[]>>();
            if (entryPoints != null && entryPoints.Length != 0)
            {
                foreach (var entryPoint in entryPoints)
                    scenarios.Add(new KeyValuePair<string, string[]>(entryPoint, new[] { entryPoint }));
            }
            else
            {
                // Event-handler projects expose separate first-install and
                // maintenance UI entry points. Older generated projects use a
                // single program function that dispatches the wizard runtime.
                if (functionsByName.ContainsKey("OnFirstUIBefore") || functionsByName.ContainsKey("OnFirstUIAfter"))
                {
                    scenarios.Add(new KeyValuePair<string, string[]>("FreshInstall", new[] { "OnFirstUIBefore", "OnFirstUIAfter" }));
                    scenarios.Add(new KeyValuePair<string, string[]>("Maintenance", new[] { "OnMaintUIBefore", "OnMaintUIAfter" }));
                }
                else if (functionsByName.ContainsKey("program"))
                {
                    scenarios.Add(new KeyValuePair<string, string[]>("FreshInstall", new[] { "program" }));
                }
            }

            var directDialogs = new Dictionary<int, string[]>();
            foreach (var function in program.Functions)
                directDialogs[function.Index] = ReadDirectDialogs(function).ToArray();
            var summaries = new Dictionary<int, DialogSummary>();
            var results = new List<InstallScriptDialogTrace>();

            foreach (var scenario in scenarios)
            {
                var trace = new InstallScriptDialogTrace { Scenario = scenario.Key, IsComplete = true };
                foreach (var entryPointName in scenario.Value)
                {
                    InstallScriptFunction entryPoint;
                    if (!functionsByName.TryGetValue(entryPointName, out entryPoint)) continue;
                    trace.EntryPoints.Add(entryPointName);
                    if (!entryPoint.BodyDecoded)
                    {
                        trace.IsComplete = false;
                        trace.Warnings.Add("Entry point '" + entryPointName + "' contains an opaque or truncated instruction range.");
                    }
                    if (ContainsCallTarget(program, entryPoint.Index, "ISRT._ShowWizardPages", 0, new HashSet<int>()))
                    {
                        trace.IsComplete = false;
                        trace.Warnings.Add("Entry point '" + entryPointName + "' delegates to the data-driven InstallShield _ShowWizardPages runtime; response dialog order is not encoded as Sd* calls in this INX.");
                    }

                    foreach (var instruction in entryPoint.Instructions)
                    {
                        if (instruction.Opcode != 0x20 && instruction.Opcode != 0x21) continue;
                        var callsiteDialogs = instruction.Operands
                            .Where(operand => operand.Kind == InstallScriptOperandKind.String && IsResponseDialog(operand.StringValue))
                            .Select(operand => operand.StringValue)
                            .Distinct(StringComparer.Ordinal)
                            .ToArray();
                        DialogSummary summary = null;
                        if (callsiteDialogs.Length == 1)
                        {
                            summary = new DialogSummary { Dialog = callsiteDialogs[0], Function = "CallsiteLiteral", Complete = true };
                        }
                        else if (instruction.Opcode == 0x21)
                        {
                            summary = ResolveSummary(program, instruction.CallTargetIndex, 0, directDialogs, summaries, new HashSet<int>());
                        }
                        if (summary == null) continue;
                        var step = new InstallScriptDialogStep
                        {
                            EntryPoint = entryPointName,
                            Offset = instruction.Offset,
                            Function = summary.Function,
                            Dialog = summary.Dialog,
                            Complete = summary.Complete
                        };
                        step.Alternatives.AddRange(summary.Alternatives);
                        trace.Steps.Add(step);
                        if (!summary.Complete || summary.Alternatives.Count != 0) trace.IsComplete = false;
                    }
                }

                if (trace.EntryPoints.Count == 0) continue;
                CollapseCompletionDialogs(trace);
                foreach (var step in trace.Steps)
                    if (!string.IsNullOrEmpty(step.Dialog)) trace.Dialogs.Add(step.Dialog);
                if (trace.Steps.Any(step => step.Alternatives.Count != 0))
                    trace.Warnings.Add("Scenario '" + scenario.Key + "' contains conditional dialog alternatives that require scenario or VM evidence.");
                results.Add(trace);
            }
            return results;
        }

        private static bool ContainsCallTarget(InstallScriptProgram program, int functionIndex, string targetName, int depth, ISet<int> visited)
        {
            if (functionIndex < 0 || functionIndex >= program.Functions.Count || depth > 4 || !visited.Add(functionIndex)) return false;
            try
            {
                foreach (var instruction in program.Functions[functionIndex].Instructions)
                {
                    if (instruction.Opcode != 0x20 && instruction.Opcode != 0x21) continue;
                    if (instruction.CallTargetIndex < 0 || instruction.CallTargetIndex >= program.Functions.Count) continue;
                    var target = program.Functions[instruction.CallTargetIndex];
                    if (string.Equals(target.Name, targetName, StringComparison.Ordinal)) return true;
                    if (instruction.Opcode == 0x21 && ContainsCallTarget(program, target.Index, targetName, depth + 1, visited)) return true;
                }
                return false;
            }
            finally
            {
                visited.Remove(functionIndex);
            }
        }

        public static List<InstallScriptDialogTrace> GetTraces(InstallScriptProgram program)
        {
            return GetTraces(program, null);
        }

        private static DialogSummary ResolveSummary(
            InstallScriptProgram program,
            int functionIndex,
            int depth,
            IDictionary<int, string[]> directDialogs,
            IDictionary<int, DialogSummary> cache,
            ISet<int> visited)
        {
            if (functionIndex < 0 || functionIndex >= program.Functions.Count || depth > 2 || !visited.Add(functionIndex)) return null;
            try
            {
                DialogSummary cached;
                if (depth == 0 && cache.TryGetValue(functionIndex, out cached)) return cached;
                var function = program.Functions[functionIndex];
                var dialogs = directDialogs[functionIndex];
                DialogSummary result;
                if (dialogs.Length == 1)
                {
                    result = new DialogSummary { Dialog = dialogs[0], Function = function.Name, Complete = function.BodyDecoded };
                }
                else if (dialogs.Length > 1)
                {
                    result = new DialogSummary { Function = function.Name, Complete = false };
                    result.Alternatives.AddRange(dialogs);
                }
                else
                {
                    var nested = new List<string>();
                    var nestedFunction = string.Empty;
                    foreach (var instruction in function.Instructions)
                    {
                        if (instruction.Opcode != 0x21) continue;
                        var summary = ResolveSummary(program, instruction.CallTargetIndex, depth + 1, directDialogs, cache, visited);
                        if (summary == null) continue;
                        if (!string.IsNullOrEmpty(summary.Dialog) && !nested.Contains(summary.Dialog))
                        {
                            nested.Add(summary.Dialog);
                            if (nestedFunction.Length == 0) nestedFunction = summary.Function;
                        }
                        foreach (var alternative in summary.Alternatives)
                            if (!string.IsNullOrEmpty(alternative) && !nested.Contains(alternative)) nested.Add(alternative);
                    }
                    if (nested.Count == 0) return null;
                    result = new DialogSummary { Function = nested.Count == 1 ? nestedFunction : function.Name, Complete = nested.Count == 1 && function.BodyDecoded };
                    if (nested.Count == 1) result.Dialog = nested[0];
                    else result.Alternatives.AddRange(nested);
                }
                if (depth == 0) cache[functionIndex] = result;
                return result;
            }
            finally
            {
                visited.Remove(functionIndex);
            }
        }

        private static List<string> ReadDirectDialogs(InstallScriptFunction function)
        {
            var result = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var instruction in function.Instructions)
            {
                if (instruction.Destination != null && instruction.Destination.Kind == InstallScriptOperandKind.String &&
                    IsResponseDialog(instruction.Destination.StringValue) && seen.Add(instruction.Destination.StringValue))
                    result.Add(instruction.Destination.StringValue);
                foreach (var operand in instruction.Operands)
                {
                    if (operand.Kind == InstallScriptOperandKind.String && IsResponseDialog(operand.StringValue) && seen.Add(operand.StringValue))
                        result.Add(operand.StringValue);
                }
            }
            return result;
        }

        private static bool IsResponseDialog(string value)
        {
            if (string.IsNullOrEmpty(value)) return false;
            if (value == "LicenseDialog") return true;
            if (!value.StartsWith("Sd", StringComparison.Ordinal)) return false;
            var suffix = value.Substring(2);
            return suffix.StartsWith("Welcome", StringComparison.Ordinal) ||
                suffix.StartsWith("License", StringComparison.Ordinal) ||
                suffix.StartsWith("AskDestPath", StringComparison.Ordinal) ||
                suffix.StartsWith("StartCopy", StringComparison.Ordinal) ||
                suffix.StartsWith("Finish", StringComparison.Ordinal) ||
                suffix == "FeatureTree" || suffix == "ComponentTree";
        }

        private static void CollapseCompletionDialogs(InstallScriptDialogTrace trace)
        {
            var output = new List<InstallScriptDialogStep>();
            var handled = new HashSet<string>(StringComparer.Ordinal);
            foreach (var step in trace.Steps)
            {
                if (IsCompletionDialog(step.Dialog))
                {
                    if (!handled.Add(step.EntryPoint)) continue;
                    var matching = trace.Steps
                        .Where(candidate => candidate.EntryPoint == step.EntryPoint && IsCompletionDialog(candidate.Dialog))
                        .ToArray();
                    if (matching.Length > 1)
                    {
                        var alternative = new InstallScriptDialogStep
                        {
                            EntryPoint = step.EntryPoint,
                            Offset = step.Offset,
                            Function = "ConditionalCompletionDialog",
                            Complete = false
                        };
                        foreach (var dialog in matching.Select(candidate => candidate.Dialog).Distinct(StringComparer.Ordinal))
                            alternative.Alternatives.Add(dialog);
                        output.Add(alternative);
                        trace.IsComplete = false;
                        continue;
                    }
                }
                output.Add(step);
            }
            trace.Steps.Clear();
            trace.Steps.AddRange(output);
        }

        private static bool IsCompletionDialog(string value)
        {
            return !string.IsNullOrEmpty(value) &&
                (value == "SdFinish" || value == "SdFinishReboot" || value == "SdFinishUpdate");
        }
    }

    /// <summary>Reads modern decoded InstallScript INX bytecode into a safe structural IR.</summary>
}
