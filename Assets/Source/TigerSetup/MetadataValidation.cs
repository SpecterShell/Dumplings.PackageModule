// SPDX-License-Identifier: Apache-2.0
// Structural rules grounded in MIT TigerSetup v0.14.0 metadata.rs and identity.rs.
// Container/schema selection and payload-range authentication remain in PowerShell.
// This validator never resolves host environment variables or executes programs.
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Globalization;

namespace Dumplings.TigerSetup
{
    public static class MetadataValidation
    {
        private static readonly StringComparer Identity = StringComparer.OrdinalIgnoreCase;
        private static string S(Dictionary<string, object> m, string key) { return (string)m[key]; }
        private static long N(Dictionary<string, object> m, string key) { return Convert.ToInt64(m[key]); }
        private static List<object> L(Dictionary<string, object> m, string key) { return (List<object>)m[key]; }
        private static Dictionary<string, object> M(object value) { return (Dictionary<string, object>)value; }
        private static void Require(bool valid, string field) { if (!valid) throw new InvalidDataException("Invalid TigerSetup metadata: " + field); }
        private static bool Match(string value, string pattern) { return Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)); }
        private static int Bytes(string value) { return Encoding.UTF8.GetByteCount(value); }
        private static bool Control(string value) { foreach (char c in value) if (char.IsControl(c)) return true; return false; }
        private static bool Space(string value) { foreach (char c in value) if (char.IsWhiteSpace(c)) return true; return false; }
        private static bool Hash(string value) { return Match(value, "\\A[0-9a-f]{64}\\z"); }
        private static void Word(string value, int maximum, string field) { Require(Bytes(value) <= maximum && Match(value, "\\A[a-z][a-z0-9-]*[a-z0-9]\\z|\\A[a-z]\\z"), field); }
        private static void Enum(Dictionary<string, object> m, string key, int low, int high) { Require(N(m, key) >= low && N(m, key) <= high, key + " enum"); }
        private static void Unique(HashSet<string> seen, string value, string field) { Require(seen.Add(value), field + " duplicate " + value); }

        private static void Path(string path)
        {
            Require(!string.IsNullOrEmpty(path) && !path.Contains('\\'), "relative path " + path);
            foreach (string part in path.Split('/')) {
                Require(part.Length > 0 && part != "." && part != ".." && !Control(part) &&
                    part.IndexOfAny(new char[] { ':', '*', '?', '"', '<', '>', '|' }) < 0 &&
                    !part.EndsWith(" ") && !part.EndsWith("."), "relative path " + path);
                string stem = part.Split('.')[0];
                Require(!Match(stem.ToUpperInvariant(), "\\A(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\\z"), "device path " + path);
            }
        }
        private static void OptionalPath(Dictionary<string, object> m, string key) { if (S(m, key).Length > 0) Path(S(m, key)); }
        private static void RegistryKey(string key, bool single = false)
        {
            Require(key.Length > 0 && Bytes(key) <= 512 && !Control(key), "registry key");
            Require(!single || !key.Contains('\\'), "registration key must be one component");
            foreach (string part in key.Split('\\')) Require(part.Trim().Length > 0 && Bytes(part) <= 255, "registry component");
        }
        private static void ProgId(string value) { Require(Bytes(value) <= 39 && Match(value, "\\A[A-Za-z][A-Za-z0-9._-]*\\z"), "ProgID " + value); }
        private static void Extension(string value) { Require(Bytes(value) <= 64 && Match(value, "\\A\\.[A-Za-z0-9_-]+\\z"), "extension " + value); }
        private static bool Boolean(string value) { return Match(value, "\\A(true|false|on|off|yes|no|1|0)\\z") || Match(value.ToLowerInvariant(), "\\A(true|false|on|off|yes|no)\\z"); }
        private static string Label(Dictionary<string, object> m)
        {
            // map<string,string> is encoded as repeated messages; duplicate map
            // keys use the last value, exactly as the engine's generated map does.
            string label = "";
            foreach (object row in L(m, "labels")) { var item = M(row); if (S(item, "key") == "en-US") label = S(item, "value"); }
            return label;
        }
        private static void Predicate(Dictionary<string, object> resource, Dictionary<string, Dictionary<string, object>> options)
        {
            var predicate = resource.ContainsKey("when") ? resource["when"] as Dictionary<string, object> : null;
            if (predicate != null && S(predicate, "option").Length == 0) predicate = null;
            string name = predicate != null ? S(predicate, "option") : resource.ContainsKey("option") ? S(resource, "option") : "";
            if (name.Length == 0) return;
            Dictionary<string, object> option;
            Require(options.TryGetValue(name, out option), "predicate option " + name);
            string value = predicate != null ? S(predicate, "equals") : "true";
            if (N(option, "kind") != 4) Require(Boolean(value), "predicate Boolean value");
            else {
                bool found = false;
                foreach (object choice in L(option, "choices")) if (Identity.Equals(value, S(M(choice), "value"))) found = true;
                Require(found, "predicate choice value");
            }
        }

        /// <summary>Validate all declared resource families before projecting registry identity or writing files.</summary>
        /// <param name="metadata">Detached MetadataReader tree after required sections and container schema have been checked; never mutated.</param>
        public static void Validate(Dictionary<string, object> metadata)
        {
            var package = M(metadata["package"]);
            string id = S(package, "id"), name = S(package, "name");
            Require(Bytes(id) <= 128 && !id.EndsWith(".") && Match(id, "\\A[A-Za-z0-9][A-Za-z0-9._-]*\\z"), "package id");
            Require(Bytes(name) <= 64 && name.Length > 0 && !name.StartsWith(" ") && !name.EndsWith(" ") && !name.EndsWith("."), "package name");
            foreach (var rune in name.EnumerateRunes()) Require(System.Text.Rune.IsLetter(rune) || System.Text.Rune.IsNumber(rune) || " .-_".Contains(rune.ToString()), "package name character");
            Require(Match(S(package, "version"), "\\A(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\z"), "package version");
            var install = M(metadata["install"]);
            Enum(install, "existing_scope", 0, 3);
            var files = new HashSet<string>(Identity);
            var directories = new HashSet<string>(Identity);
            foreach (object row in L(metadata, "directories")) { string path = S(M(row), "path"); Path(path); directories.Add(path); }
            foreach (object row in L(metadata, "files")) {
                var file = M(row); string path = S(file, "path"), entry = S(file, "entry"); Path(path); Path(entry);
                foreach (string prefix in new[] { ".tigersetup/actions/", ".tigersetup/dependencies/" }) Require(!path.StartsWith(prefix, StringComparison.Ordinal) && !entry.StartsWith(prefix, StringComparison.Ordinal), "reserved application path");
                Unique(files, path, "file");
                for (int p = path.IndexOf('/'); p >= 0; p = path.IndexOf('/', p + 1)) Require(directories.Contains(path.Substring(0, p)), "undeclared parent directory " + path);
            }
            foreach (string directory in directories) Require(!files.Contains(directory), "file/directory collision");
            foreach (object row in L(metadata, "payload")) Path(S(M(row), "entry"));
            var options = new Dictionary<string, Dictionary<string, object>>(Identity);
            foreach (object row in L(metadata, "options")) {
                var option = M(row); string key = S(option, "name"); Word(key, 32, "option name"); Enum(option, "kind", 0, 4);
                Require(options.TryAdd(key, option), "duplicate option");
                long kind = N(option, "kind");
                if (kind == 0 || kind == 1 || kind == 4) Require(Label(option).Trim().Length > 0, "option en-US label");
                if (kind != 4) Require(L(option, "choices").Count == 0 && S(option, "default_choice").Length == 0, "Boolean option with choices");
                else {
                    Require(L(option, "choices").Count >= 2 && L(option, "choices").Count <= 8, "choice count");
                    var values = new HashSet<string>(Identity);
                    foreach (object value in L(option, "choices")) { var choice = M(value); string text = S(choice, "value"); Word(text, 32, "choice value"); Require(!Boolean(text), "Boolean choice value"); Unique(values, text, "choice"); Require(Label(choice).Trim().Length > 0, "choice en-US label"); }
                    Require(values.Contains(S(option, "default_choice")), "default choice");
                }
            }
            // Predicates on every resource are checked, including resources that
            // the fresh-install defaults would otherwise leave inactive.
            foreach (string group in new[] { "files", "shortcuts", "path_entries", "registry_values", "dependencies", "environment_variables", "file_associations", "url_protocols", "app_paths", "context_menu_verbs", "firewall_rules", "actions", "quiescence" })
                foreach (object row in L(metadata, group)) Predicate(M(row), options);
            foreach (object row in L(metadata, "shortcuts")) {
                var shortcut = M(row); Enum(shortcut, "location", 1, 4); string link = S(shortcut, "name");
                Path(link); Require(!link.Contains('/') && !link.StartsWith(" ") && link.EnumerateRunes().CountRunes() <= 128 && !Match(link.Split('.')[0].TrimEnd().ToUpperInvariant(), "\\A(CONIN\\$|CONOUT\\$|COM[0-9\u00b9\u00b2\u00b3]|LPT[0-9\u00b9\u00b2\u00b3])\\z"), "shortcut name");
                string url = S(shortcut, "url");
                if (url.Length == 0) {
                    Path(S(shortcut, "target")); OptionalPath(shortcut, "working_directory");
                    Require(Bytes(S(shortcut, "app_user_model_id")) <= 128 && !Space(S(shortcut, "app_user_model_id")) && !Control(S(shortcut, "app_user_model_id")), "AppUserModelID");
                } else {
                    Require(Bytes(url) <= 2048 && !Space(url) && !Control(url) && Match(url.ToLowerInvariant(), "\\A(https?|file)://"), "shortcut URL");
                    foreach (string key in new[] { "target", "arguments", "working_directory", "app_user_model_id" }) Require(S(shortcut, key).Length == 0, "URL shortcut " + key);
                }
                OptionalPath(shortcut, "icon"); OptionalPath(shortcut, "folder");
            }
            foreach (object row in L(metadata, "path_entries")) OptionalPath(M(row), "path");
            foreach (object row in L(metadata, "environment_variables")) {
                string variable = S(M(row), "name"); Require(variable.Length > 0 && Bytes(variable) <= 255 && !Space(variable) && !Control(variable) && !variable.Contains('=') && !Identity.Equals(variable, "Path"), "environment name");
            }
            var progIds = new HashSet<string>(Identity);
            foreach (object row in L(metadata, "file_associations")) {
                var association = M(row); string progId = S(association, "prog_id"); ProgId(progId); Unique(progIds, progId, "ProgID");
                Require(L(association, "extensions").Count > 0, "association extensions"); foreach (object ext in L(association, "extensions")) Extension((string)ext);
                Path(S(association, "executable")); OptionalPath(association, "icon");
            }
            var schemes = new HashSet<string>(Identity);
            foreach (object row in L(metadata, "url_protocols")) {
                var protocol = M(row); string scheme = S(protocol, "scheme");
                Require(Bytes(scheme) <= 64 && Match(scheme, "\\A[a-z][a-z0-9+.-]*\\z") && !Match(scheme, "\\A(http|https|file|ftp|mailto|ms-settings|ms-windows-store|shell)\\z"), "protocol scheme"); Unique(schemes, scheme, "protocol");
                if (S(protocol, "prog_id").Length > 0) { ProgId(S(protocol, "prog_id")); Unique(progIds, S(protocol, "prog_id"), "ProgID"); }
                Path(S(protocol, "executable")); OptionalPath(protocol, "icon");
            }
            var appPaths = new HashSet<string>(Identity);
            foreach (object row in L(metadata, "app_paths")) { string path = S(M(row), "executable"); Path(path); Require(path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase), "App Paths executable"); Unique(appPaths, path.Substring(path.LastIndexOf('/') + 1), "App Paths"); }
            var verbs = new HashSet<string>(Identity);
            foreach (object row in L(metadata, "context_menu_verbs")) {
                var verb = M(row); Enum(verb, "target", 1, 3); string key = S(verb, "verb"); Require(Bytes(key) <= 64 && Match(key, "\\A[A-Za-z0-9_.-]+\\z") && S(verb, "label").Trim().Length > 0, "context verb");
                Path(S(verb, "executable")); OptionalPath(verb, "icon"); Require(L(verb, "extensions").Count == 0 || N(verb, "target") == 1, "context target extensions");
                foreach (object ext in L(verb, "extensions")) Extension((string)ext);
                Unique(verbs, N(verb, "target") + "|" + key + "|" + string.Join(",", L(verb, "extensions")), "context verb");
            }
            var rules = new HashSet<string>(Identity);
            foreach (object row in L(metadata, "firewall_rules")) {
                var rule = M(row); string key = S(rule, "name"); Require(key.Trim().Length > 0 && Bytes(key) <= 255 && !Control(key) && !key.Contains('|'), "firewall name"); Unique(rules, key, "firewall");
                Path(S(rule, "program")); Enum(rule, "direction", 1, 2); Enum(rule, "action", 1, 2); Enum(rule, "protocol", 0, 2);
                if (S(rule, "local_ports").Length > 0) {
                    Require(N(rule, "protocol") > 0, "firewall ports protocol");
                    foreach (string part in S(rule, "local_ports").Split(',')) {
                        string[] range = part.Trim().Split('-'); ushort low = 0, high;
                        Require(range.Length <= 2 && ushort.TryParse(range[0].Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out low) && low > 0, "firewall port");
                        Require(ushort.TryParse(range[range.Length - 1].Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out high) && high >= low, "firewall port range");
                    }
                }
            }
            foreach (object row in L(metadata, "registry_values")) {
                var value = M(row); RegistryKey(S(value, "key")); Require(!Control(S(value, "name")), "registry value name"); Enum(value, "kind", 1, 3); Enum(value, "root", 0, 2);
                if (N(value, "root") > 0) foreach (object scope in L(install, "scopes")) Require(Convert.ToInt64(scope) == (N(value, "root") == 1 ? 2 : 1), "registry root/scope mismatch");
                uint number; if (N(value, "kind") == 3) Require(uint.TryParse(S(value, "data"), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out number), "DWORD data");
            }
            var registration = metadata["registration"] as Dictionary<string, object>;
            if (registration != null) { if (S(registration, "key_name").Length > 0) RegistryKey(S(registration, "key_name"), true); OptionalPath(registration, "display_icon"); }
            var legacy = metadata["legacy"] as Dictionary<string, object>;
            if (legacy != null) { Require(S(legacy, "installer_type") == "inno", "legacy installer type"); RegistryKey(S(legacy, "registration_key"), true); }
            var dependencies = new HashSet<string>(Identity);
            foreach (object row in L(metadata, "dependencies")) {
                var dependency = M(row); string key = S(dependency, "id"); Require(key.Trim().Length > 0, "dependency id"); Unique(dependencies, key, "dependency");
                string version = S(dependency, "minimum_version"); Require(version.Length == 0 || Match(version, "\\A[0-9]{1,9}(\\.[0-9]{1,9}){0,3}\\z"), "dependency version");
                var detector = dependency["detect"] as Dictionary<string, object>; Require(detector != null, "dependency detector"); Enum(detector, "kind", 1, 4);
                if (N(detector, "kind") == 1 || N(detector, "kind") == 3) Require(S(detector, "path").Length > 0, "detector path");
                if (N(detector, "kind") == 2) Require(L(detector, "keys").Count > 0 && S(detector, "value").Length > 0, "registry detector");
                if (N(detector, "kind") == 4) Require(S(detector, "pattern").Length > 0, "registration detector");
                var acquisition = dependency["acquisition"] as Dictionary<string, object>;
                if (acquisition == null) continue;
                Enum(acquisition, "source", 1, 3);
                if (N(acquisition, "source") == 1) Require(S(acquisition, "package_identifier").Length > 0, "WinGet dependency identifier");
                if (N(acquisition, "source") == 2) Require(S(acquisition, "url").Length > 0 && Hash(S(acquisition, "sha256")), "URL dependency");
                if (N(acquisition, "source") == 3) Require(S(acquisition, "entry").StartsWith(".tigersetup/dependencies/", StringComparison.Ordinal) && S(acquisition, "entry").Length > 24 && Hash(S(acquisition, "sha256")) && (ulong)acquisition["size"] > 0 && dependency["install"] != null, "embedded dependency");
                Require(S(acquisition, "sha256").Length == 0 || Hash(S(acquisition, "sha256")), "dependency hash");
            }
            var actions = new HashSet<string>(Identity);
            foreach (object row in L(metadata, "actions")) { var action = M(row); Action(action); Require(N(action, "phase") <= 4, "standalone quiescence action"); Unique(actions, S(action, "name"), "action"); }
            foreach (object row in L(metadata, "quiescence")) {
                var entry = M(row); Word(S(entry, "name"), 48, "quiescence name"); Unique(actions, S(entry, "name"), "quiescence"); Operations(L(entry, "run_on"), 1, 5);
                Require(entry["stop"] != null, "quiescence stop");
                foreach (string key in new[] { "stop", "resume" }) {
                    var action = entry[key] as Dictionary<string, object>; if (action == null) continue; Action(action);
                    Require(S(action, "name") == S(entry, "name") && N(action, "phase") == (key == "stop" ? 5 : 6) && action["when"] == null, "quiescence program");
                }
                var codes = L(M(entry["stop"]), "success_codes");
                foreach (object code in L(entry, "not_running_codes")) Require(codes.Count == 0 ? Convert.ToInt32(code) != 0 : !codes.Contains(code), "quiescence exit-code overlap");
            }
            var launch = metadata["launch"] as Dictionary<string, object>;
            if (launch != null) {
                string executable = S(launch, "executable"); Path(executable); Require(executable.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && files.Contains(executable), "launch executable");
                OptionalPath(launch, "working_directory"); Require(S(launch, "working_directory").Length == 0 || directories.Contains(S(launch, "working_directory")), "launch working directory");
            }
        }

        private static void Operations(List<object> operations, int low, int high)
        {
            var seen = new HashSet<long>();
            foreach (object value in operations) { long n = Convert.ToInt64(value); Require(n >= low && n <= high && seen.Add(n), "action operation"); }
        }
        private static void Action(Dictionary<string, object> action)
        {
            Word(S(action, "name"), 48, "action name"); Enum(action, "phase", 1, 6); Enum(action, "kind", 1, 3); Enum(action, "on_failure", 0, 2);
            long phase = N(action, "phase"); var operations = L(action, "run_on");
            if (phase >= 5) Require(operations.Count == 0, "quiescence action operations");
            else { Require(operations.Count > 0, "action operations"); Operations(operations, phase <= 2 ? 1 : 5, phase <= 2 ? 4 : 5); }
            string command = S(action, "command"), entry = S(action, "entry"), file = S(action, "file_name");
            Require((command.Length == 0) != (entry.Length == 0), "action command/entry");
            if (entry.Length > 0) {
                Path(entry); Path(file); Require(entry.StartsWith(".tigersetup/actions/", StringComparison.Ordinal) && entry.Length > 19 && !file.Contains('/') && (ulong)action["size"] > 0 && Hash(S(action, "sha256")), "packaged action");
            } else Require(!Control(command) && file.Length == 0 && (ulong)action["size"] == 0 && S(action, "sha256").Length == 0, "command action fields");
            string program = entry.Length > 0 ? file : command;
            string extension = System.IO.Path.GetExtension(program).ToLowerInvariant();
            Require(N(action, "kind") == 1 ? extension == ".exe" : N(action, "kind") == 2 ? extension == ".ps1" : extension == ".cmd" || extension == ".bat", "action program kind");
            foreach (object argument in L(action, "arguments")) foreach (char c in (string)argument) Require(!char.IsControl(c) || c == '\t', "action argument");
            string directory = S(action, "working_directory"); Require(!Control(directory), "action working directory");
            if (phase == 4) Require(!command.ToUpperInvariant().Contains("%INSTALLROOT%") && !directory.ToUpperInvariant().Contains("%INSTALLROOT%"), "post-uninstall install root");
        }
        private static int CountRunes(this StringRuneEnumerator runes) { int count = 0; foreach (var rune in runes) count++; return count; }
    }
}
