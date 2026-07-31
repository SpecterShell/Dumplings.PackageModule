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
        private const int MaximumFrameworkDepth = 8;
        private const int MaximumFrameworkSteps = 128;

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

            // Program-style InstallScript projects enter the UI through an
            // imported runtime function. Official InstallShield framework
            // source shows that _ShowWizardPages calls the exported
            // IfxOnShowWizardPages callback, so follow that callback before
            // falling back to the ordinary named-entry-point tracer.
            if ((entryPoints == null || entryPoints.Length == 0) &&
                !functionsByName.ContainsKey("OnFirstUIBefore") &&
                functionsByName.ContainsKey("program") &&
                functionsByName.ContainsKey("IfxOnShowWizardPages") &&
                ContainsCallTarget(program, functionsByName["program"].Index, "ISRT._ShowWizardPages", 0, new HashSet<int>()))
            {
                var frameworkTraces = GetFrameworkWizardTraces(program, functionsByName["program"], functionsByName["IfxOnShowWizardPages"]);
                if (frameworkTraces.Count != 0) return frameworkTraces;
            }

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
                var trace = new InstallScriptDialogTrace { Scenario = scenario.Key, Source = "DirectBytecode", IsComplete = true };
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

        /// <summary>
        /// Reconstructs program-style wizard branches through the callback
        /// contract documented by InstallShield's EventsObjectPriv.rul and
        /// EventsSetupPriv.rul framework sources. The runtime condition values
        /// are intentionally not guessed; branch classification relies only on
        /// the response-dialog families reached by each callback child.
        /// </summary>
        private static List<InstallScriptDialogTrace> GetFrameworkWizardTraces(
            InstallScriptProgram program,
            InstallScriptFunction programEntry,
            InstallScriptFunction callback)
        {
            var result = new List<InstallScriptDialogTrace>();
            var reachability = new Dictionary<int, bool>();
            var branchTraces = new List<InstallScriptDialogTrace>();

            foreach (var instruction in callback.Instructions)
            {
                if (instruction.Opcode != 0x20 && instruction.Opcode != 0x21) continue;
                if (instruction.CallTargetIndex < 0 || instruction.CallTargetIndex >= program.Functions.Count) continue;
                if (!CanReachResponseDialog(program, instruction.CallTargetIndex, 0, new HashSet<int>(), reachability)) continue;

                var trace = new InstallScriptDialogTrace
                {
                    Scenario = "FrameworkBranch",
                    Source = "FrameworkCallback",
                    IsComplete = callback.BodyDecoded
                };
                trace.EntryPoints.Add(programEntry.Name);
                trace.EntryPoints.Add(callback.Name);
                var remainingSteps = MaximumFrameworkSteps;
                CollectOrderedDialogs(
                    program,
                    instruction.CallTargetIndex,
                    programEntry.Name,
                    instruction.Offset,
                    0,
                    new HashSet<int>(),
                    reachability,
                    trace,
                    ref remainingSteps);
                if (trace.Steps.Count == 0) continue;

                CollapseCompletionDialogs(trace);
                foreach (var step in trace.Steps)
                {
                    if (!string.IsNullOrEmpty(step.Dialog)) trace.Dialogs.Add(step.Dialog);
                    if (!step.Complete || step.Alternatives.Count != 0) trace.IsComplete = false;
                }
                branchTraces.Add(trace);
            }

            foreach (var trace in branchTraces)
            {
                var candidates = new List<string>();
                foreach (var step in trace.Steps)
                {
                    if (!string.IsNullOrEmpty(step.Dialog)) candidates.Add(step.Dialog);
                    else candidates.AddRange(step.Alternatives);
                }
                if (candidates.Any(dialog => dialog.StartsWith("SdWelcomeMaint", StringComparison.Ordinal)))
                    trace.Scenario = "Maintenance";
                else if (candidates.Any(dialog => dialog.StartsWith("SdWelcomeUpdate", StringComparison.Ordinal)))
                    trace.Scenario = "Update";
                else if (candidates.Any(dialog => dialog.StartsWith("SdWelcome", StringComparison.Ordinal)))
                    trace.Scenario = "FreshInstall";
                else
                    trace.Scenario = "FrameworkBranch";

                // The call order is static evidence, but MODE, MAINTENANCE,
                // feature selection, and BACK/NEXT branches can still suppress
                // or repeat pages. Keep generated response templates reviewable
                // rather than falsely marking them complete.
                trace.IsComplete = false;
                trace.Warnings.Add(
                    "Dialog order was reconstructed through InstallShield's _ShowWizardPages/IfxOnShowWizardPages callback contract; conditional or optional pages still require a recorded VM response file.");
            }

            // Keep at most one branch per recognized scenario. If a customized
            // callback exposes several candidates, retain all unknown branches
            // rather than merging unrelated dialog orders.
            foreach (var scenario in new[] { "FreshInstall", "Maintenance", "Update" })
            {
                var matching = branchTraces.Where(trace => trace.Scenario == scenario).ToArray();
                if (matching.Length == 1) result.Add(matching[0]);
                else if (matching.Length > 1)
                {
                    foreach (var trace in matching)
                    {
                        trace.Warnings.Add("Multiple callback branches matched scenario '" + scenario + "'; runtime selection remains unresolved.");
                        result.Add(trace);
                    }
                }
            }
            result.AddRange(branchTraces.Where(trace => trace.Scenario == "FrameworkBranch"));
            return result;
        }

        /// <summary>
        /// Memoizes whether a function can reach a recognized response dialog.
        /// This prevents ordered collection from descending into every helper
        /// and UI implementation function in large framework scripts.
        /// </summary>
        private static bool CanReachResponseDialog(
            InstallScriptProgram program,
            int functionIndex,
            int depth,
            ISet<int> visited,
            IDictionary<int, bool> cache)
        {
            if (functionIndex < 0 || functionIndex >= program.Functions.Count || depth > MaximumFrameworkDepth) return false;
            bool cached;
            if (cache.TryGetValue(functionIndex, out cached)) return cached;
            if (!visited.Add(functionIndex)) return false;
            try
            {
                var function = program.Functions[functionIndex];
                if (ReadDirectDialogs(function).Count != 0)
                {
                    cache[functionIndex] = true;
                    return true;
                }
                foreach (var instruction in function.Instructions)
                {
                    if (instruction.Opcode != 0x20 && instruction.Opcode != 0x21) continue;
                    if (instruction.Operands.Any(operand => operand.Kind == InstallScriptOperandKind.String && IsResponseDialog(operand.StringValue)))
                    {
                        cache[functionIndex] = true;
                        return true;
                    }
                    if (CanReachResponseDialog(program, instruction.CallTargetIndex, depth + 1, visited, cache))
                    {
                        cache[functionIndex] = true;
                        return true;
                    }
                }
                cache[functionIndex] = false;
                return false;
            }
            finally
            {
                visited.Remove(functionIndex);
            }
        }

        /// <summary>
        /// Flattens only call edges that lead to response dialogs. Calls remain
        /// in bytecode order; mutually exclusive completion calls are collapsed
        /// later into alternatives by CollapseCompletionDialogs.
        /// </summary>
        private static void CollectOrderedDialogs(
            InstallScriptProgram program,
            int functionIndex,
            string entryPoint,
            long callsiteOffset,
            int depth,
            ISet<int> visited,
            IDictionary<int, bool> reachability,
            InstallScriptDialogTrace trace,
            ref int remainingSteps)
        {
            if (remainingSteps <= 0)
            {
                trace.IsComplete = false;
                if (!trace.Warnings.Contains("The framework dialog trace exceeded the parser step limit."))
                    trace.Warnings.Add("The framework dialog trace exceeded the parser step limit.");
                return;
            }
            if (functionIndex < 0 || functionIndex >= program.Functions.Count || depth > MaximumFrameworkDepth || !visited.Add(functionIndex))
            {
                trace.IsComplete = false;
                return;
            }
            try
            {
                var function = program.Functions[functionIndex];
                var directDialogs = ReadDirectDialogs(function);
                if (directDialogs.Count != 0)
                {
                    var step = new InstallScriptDialogStep
                    {
                        EntryPoint = entryPoint,
                        Offset = callsiteOffset,
                        Function = function.Name,
                        Dialog = directDialogs.Count == 1 ? directDialogs[0] : null,
                        Complete = function.BodyDecoded && directDialogs.Count == 1
                    };
                    if (directDialogs.Count > 1) step.Alternatives.AddRange(directDialogs);
                    trace.Steps.Add(step);
                    remainingSteps--;
                    return;
                }

                if (!function.BodyDecoded) trace.IsComplete = false;
                foreach (var instruction in function.Instructions)
                {
                    if (remainingSteps <= 0) break;
                    if (instruction.Opcode != 0x20 && instruction.Opcode != 0x21) continue;
                    var callsiteDialogs = instruction.Operands
                        .Where(operand => operand.Kind == InstallScriptOperandKind.String && IsResponseDialog(operand.StringValue))
                        .Select(operand => operand.StringValue)
                        .Distinct(StringComparer.Ordinal)
                        .ToArray();
                    if (callsiteDialogs.Length != 0)
                    {
                        var step = new InstallScriptDialogStep
                        {
                            EntryPoint = entryPoint,
                            Offset = instruction.Offset,
                            Function = "CallsiteLiteral",
                            Dialog = callsiteDialogs.Length == 1 ? callsiteDialogs[0] : null,
                            Complete = callsiteDialogs.Length == 1
                        };
                        if (callsiteDialogs.Length > 1) step.Alternatives.AddRange(callsiteDialogs);
                        trace.Steps.Add(step);
                        remainingSteps--;
                        continue;
                    }
                    if (!CanReachResponseDialog(program, instruction.CallTargetIndex, depth + 1, new HashSet<int>(visited), reachability)) continue;
                    CollectOrderedDialogs(
                        program,
                        instruction.CallTargetIndex,
                        entryPoint,
                        instruction.Offset,
                        depth + 1,
                        visited,
                        reachability,
                        trace,
                        ref remainingSteps);
                }
            }
            finally
            {
                visited.Remove(functionIndex);
            }
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
                suffix.StartsWith("SelectFolder", StringComparison.Ordinal) ||
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
