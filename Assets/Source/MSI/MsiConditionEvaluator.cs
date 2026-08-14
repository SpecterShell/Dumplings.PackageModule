// SPDX-License-Identifier: Apache-2.0
// Independently implemented from the Windows Installer conditional-statement specification:
// https://learn.microsoft.com/windows/win32/msi/conditional-statement-syntax

namespace Dumplings.WindowsInstaller.Conditions
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;

    /// <summary>Possible outcomes of bounded static MSI condition evaluation.</summary>
    public enum MsiConditionState
    {
        None,
        False,
        True,
        Unknown,
        Invalid
    }

    /// <summary>The Windows Installer namespace referenced by a condition symbol.</summary>
    public enum MsiConditionSymbolKind
    {
        Property,
        EnvironmentVariable,
        ComponentActionState,
        ComponentInstalledState,
        FeatureActionState,
        FeatureInstalledState
    }

    /// <summary>One symbol observed while evaluating a condition.</summary>
    public sealed class MsiConditionSymbolReference
    {
        internal MsiConditionSymbolReference(MsiConditionSymbolKind kind, string name, bool isKnown, bool? isPresent, string value)
        {
            Kind = kind;
            Name = name;
            IsKnown = isKnown;
            IsPresent = isPresent;
            Value = value;
        }

        public MsiConditionSymbolKind Kind { get; private set; }
        public string Name { get; private set; }
        public bool IsKnown { get; private set; }
        public bool? IsPresent { get; private set; }
        public string Value { get; private set; }
    }

    /// <summary>Structured output from the MSI condition evaluator.</summary>
    public sealed class MsiConditionEvaluationResult
    {
        internal MsiConditionEvaluationResult(string expression)
        {
            Expression = expression;
            State = MsiConditionState.Invalid;
            Symbols = new List<MsiConditionSymbolReference>();
            UnknownSymbols = new List<string>();
            ErrorPosition = -1;
        }

        public string Expression { get; internal set; }
        public MsiConditionState State { get; internal set; }
        public bool? Value { get; internal set; }
        public bool IsValid { get { return State != MsiConditionState.Invalid; } }
        public bool IsComplete { get { return State == MsiConditionState.None || State == MsiConditionState.True || State == MsiConditionState.False; } }
        public int TokenCount { get; internal set; }
        public int ErrorPosition { get; internal set; }
        public string ErrorMessage { get; internal set; }
        public List<MsiConditionSymbolReference> Symbols { get; private set; }
        public List<string> UnknownSymbols { get; private set; }
    }

    internal enum EvaluationValueKind
    {
        Number,
        String,
        Unknown
    }

    /// <summary>
    /// A value known exactly, known only to be present, or unresolved in the
    /// virtual MSI session. The evaluator never substitutes host state.
    /// </summary>
    internal sealed class EvaluationValue
    {
        internal EvaluationValueKind Kind;
        internal long Number;
        internal string Text;
        internal bool? IsPresent;

        internal static EvaluationValue FromNumber(long number)
        {
            return new EvaluationValue { Kind = EvaluationValueKind.Number, Number = number, IsPresent = true };
        }

        internal static EvaluationValue FromString(string text)
        {
            text = text ?? string.Empty;
            return new EvaluationValue { Kind = EvaluationValueKind.String, Text = text, IsPresent = text.Length != 0 };
        }

        internal static EvaluationValue Unknown(bool? isPresent)
        {
            return new EvaluationValue { Kind = EvaluationValueKind.Unknown, IsPresent = isPresent };
        }

        internal bool TryGetNumber(out long value)
        {
            if (Kind == EvaluationValueKind.Number)
            {
                value = Number;
                return true;
            }

            if (Kind == EvaluationValueKind.String && long.TryParse(Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value)) return true;
            value = 0;
            return false;
        }

        internal string Render()
        {
            if (Kind == EvaluationValueKind.Number) return Number.ToString(CultureInfo.InvariantCulture);
            if (Kind == EvaluationValueKind.String) return Text;
            return null;
        }
    }

    internal sealed class EvaluationTrace
    {
        private readonly MsiConditionEvaluationResult result;
        private readonly HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);

        internal EvaluationTrace(MsiConditionEvaluationResult result)
        {
            this.result = result;
        }

        internal void Add(MsiConditionSymbolKind kind, string name, EvaluationValue value)
        {
            var identity = ((int)kind).ToString(CultureInfo.InvariantCulture) + "\0" + name;
            if (!seen.Add(identity)) return;
            var isKnown = value.Kind != EvaluationValueKind.Unknown;
            result.Symbols.Add(new MsiConditionSymbolReference(kind, name, isKnown, value.IsPresent, value.Render()));
            if (!isKnown) result.UnknownSymbols.Add(GetPrefix(kind) + name);
        }

        private static string GetPrefix(MsiConditionSymbolKind kind)
        {
            switch (kind)
            {
                case MsiConditionSymbolKind.EnvironmentVariable: return "%";
                case MsiConditionSymbolKind.ComponentActionState: return "$";
                case MsiConditionSymbolKind.ComponentInstalledState: return "?";
                case MsiConditionSymbolKind.FeatureActionState: return "&";
                case MsiConditionSymbolKind.FeatureInstalledState: return "!";
                default: return string.Empty;
            }
        }
    }

    /// <summary>
    /// Virtual Windows Installer session values used by static evaluation. Property and
    /// feature/component identifiers are case-sensitive; environment names are not.
    /// </summary>
    public sealed class MsiConditionEvaluationContext
    {
        private readonly Dictionary<string, string> properties = new Dictionary<string, string>(StringComparer.Ordinal);
        private readonly HashSet<string> presentProperties = new HashSet<string>(StringComparer.Ordinal);
        private readonly HashSet<string> absentProperties = new HashSet<string>(StringComparer.Ordinal);
        private readonly Dictionary<string, string> environmentVariables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, long> componentActionStates = new Dictionary<string, long>(StringComparer.Ordinal);
        private readonly Dictionary<string, long> componentInstalledStates = new Dictionary<string, long>(StringComparer.Ordinal);
        private readonly Dictionary<string, long> featureActionStates = new Dictionary<string, long>(StringComparer.Ordinal);
        private readonly Dictionary<string, long> featureInstalledStates = new Dictionary<string, long>(StringComparer.Ordinal);

        /// <summary>
        /// Treat unprovided symbols as the runtime's absent value rather than unresolved
        /// static state. The static-analysis default is false so missing runtime evidence
        /// cannot incorrectly reject a possible path.
        /// </summary>
        public bool UnspecifiedSymbolsAreAbsent { get; set; }

        public void SetProperty(string name, string value)
        {
            ValidateName(name, "property");
            properties[name] = value ?? string.Empty;
            presentProperties.Remove(name);
            absentProperties.Remove(name);
        }

        public void MarkPropertyPresent(string name)
        {
            ValidateName(name, "property");
            properties.Remove(name);
            absentProperties.Remove(name);
            presentProperties.Add(name);
        }

        public void MarkPropertyAbsent(string name)
        {
            ValidateName(name, "property");
            properties.Remove(name);
            presentProperties.Remove(name);
            absentProperties.Add(name);
        }

        public void SetEnvironmentVariable(string name, string value)
        {
            ValidateName(name, "environment variable");
            environmentVariables[name] = value ?? string.Empty;
        }

        public void SetComponentActionState(string name, long value) { SetState(componentActionStates, name, value); }
        public void SetComponentInstalledState(string name, long value) { SetState(componentInstalledStates, name, value); }
        public void SetFeatureActionState(string name, long value) { SetState(featureActionStates, name, value); }
        public void SetFeatureInstalledState(string name, long value) { SetState(featureInstalledStates, name, value); }

        private static void ValidateName(string name, string kind)
        {
            if (string.IsNullOrEmpty(name)) throw new ArgumentException("An MSI " + kind + " name cannot be empty.", "name");
        }

        private static void SetState(Dictionary<string, long> states, string name, long value)
        {
            ValidateName(name, "state symbol");
            states[name] = value;
        }

        internal EvaluationValue Resolve(MsiConditionSymbolKind kind, string name, EvaluationTrace trace)
        {
            EvaluationValue value;
            string text;
            long number;
            switch (kind)
            {
                case MsiConditionSymbolKind.Property:
                    if (properties.TryGetValue(name, out text)) value = EvaluationValue.FromString(text);
                    else if (presentProperties.Contains(name)) value = EvaluationValue.Unknown(true);
                    else if (absentProperties.Contains(name) || UnspecifiedSymbolsAreAbsent) value = EvaluationValue.FromString(string.Empty);
                    else value = EvaluationValue.Unknown(null);
                    break;
                case MsiConditionSymbolKind.EnvironmentVariable:
                    if (environmentVariables.TryGetValue(name, out text)) value = EvaluationValue.FromString(text);
                    else if (UnspecifiedSymbolsAreAbsent) value = EvaluationValue.FromString(string.Empty);
                    else value = EvaluationValue.Unknown(null);
                    break;
                case MsiConditionSymbolKind.ComponentActionState:
                    value = componentActionStates.TryGetValue(name, out number) ? EvaluationValue.FromNumber(number) : ResolveMissingState();
                    break;
                case MsiConditionSymbolKind.ComponentInstalledState:
                    value = componentInstalledStates.TryGetValue(name, out number) ? EvaluationValue.FromNumber(number) : ResolveMissingState();
                    break;
                case MsiConditionSymbolKind.FeatureActionState:
                    value = featureActionStates.TryGetValue(name, out number) ? EvaluationValue.FromNumber(number) : ResolveMissingState();
                    break;
                case MsiConditionSymbolKind.FeatureInstalledState:
                    value = featureInstalledStates.TryGetValue(name, out number) ? EvaluationValue.FromNumber(number) : ResolveMissingState();
                    break;
                default:
                    value = EvaluationValue.Unknown(null);
                    break;
            }

            trace.Add(kind, name, value);
            return value;
        }

        private EvaluationValue ResolveMissingState()
        {
            // INSTALLSTATE_UNKNOWN is -1 when a complete runtime context is requested.
            return UnspecifiedSymbolsAreAbsent ? EvaluationValue.FromNumber(-1) : EvaluationValue.Unknown(null);
        }
    }

    /// <summary>Parses and evaluates Windows Installer conditional expressions without invoking MSI.</summary>
    public static class MsiConditionEvaluator
    {
        public static MsiConditionEvaluationResult Evaluate(string expression, MsiConditionEvaluationContext context, int maximumTokenCount, int maximumDepth)
        {
            if (expression == null) throw new ArgumentNullException("expression");
            if (maximumTokenCount <= 0) throw new ArgumentOutOfRangeException("maximumTokenCount");
            if (maximumDepth <= 0) throw new ArgumentOutOfRangeException("maximumDepth");
            if (context == null) context = new MsiConditionEvaluationContext();

            var result = new MsiConditionEvaluationResult(expression);
            if (string.IsNullOrWhiteSpace(expression))
            {
                result.State = MsiConditionState.None;
                return result;
            }

            try
            {
                var lexer = new Lexer(expression, maximumTokenCount);
                var tokens = lexer.ReadAll();
                result.TokenCount = tokens.Count - 1;
                var parser = new Parser(tokens, maximumDepth);
                var root = parser.Parse();
                var trace = new EvaluationTrace(result);
                var truth = root.Evaluate(context, trace);
                result.State = truth == ConditionTruth.True ? MsiConditionState.True : truth == ConditionTruth.False ? MsiConditionState.False : MsiConditionState.Unknown;
                result.Value = truth == ConditionTruth.Unknown ? (bool?)null : truth == ConditionTruth.True;
            }
            catch (ConditionParseException exception)
            {
                result.State = MsiConditionState.Invalid;
                result.ErrorPosition = exception.Position;
                result.ErrorMessage = exception.Message;
            }

            return result;
        }

        private enum TokenKind
        {
            End,
            LeftParenthesis,
            RightParenthesis,
            Integer,
            String,
            Symbol,
            Comparison,
            Not,
            And,
            Or,
            Xor,
            Eqv,
            Imp
        }

        private enum ConditionTruth
        {
            False,
            True,
            Unknown
        }

        private sealed class Token
        {
            internal TokenKind Kind;
            internal string Text;
            internal int Position;
            internal long Integer;
            internal MsiConditionSymbolKind SymbolKind;
            internal string SymbolName;
        }

        private sealed class Lexer
        {
            private readonly string expression;
            private readonly int maximumTokenCount;
            private int position;

            internal Lexer(string expression, int maximumTokenCount)
            {
                this.expression = expression;
                this.maximumTokenCount = maximumTokenCount;
            }

            internal List<Token> ReadAll()
            {
                var result = new List<Token>();
                while (true)
                {
                    var token = Read();
                    result.Add(token);
                    if (token.Kind == TokenKind.End) break;
                    if (result.Count > maximumTokenCount) throw Error("The MSI condition exceeds the token limit.", token.Position);
                }
                return result;
            }

            private Token Read()
            {
                while (position < expression.Length && char.IsWhiteSpace(expression[position])) position++;
                if (position >= expression.Length) return NewToken(TokenKind.End, string.Empty, position);

                var start = position;
                var current = expression[position];
                if (current == '(')
                {
                    position++;
                    return NewToken(TokenKind.LeftParenthesis, "(", start);
                }
                if (current == ')')
                {
                    position++;
                    return NewToken(TokenKind.RightParenthesis, ")", start);
                }
                if (current == '"') return ReadString();
                if (char.IsDigit(current) || ((current == '-' || current == '+') && position + 1 < expression.Length && char.IsDigit(expression[position + 1]))) return ReadInteger();

                Token comparison;
                if (TryReadComparison(out comparison)) return comparison;

                if (current == '%' || current == '$' || current == '?' || current == '&' || current == '!') return ReadPrefixedSymbol();
                if (IsIdentifierStart(current)) return ReadWord();
                throw Error("Unexpected character in MSI condition.", start);
            }

            private Token ReadString()
            {
                var start = position++;
                var contentStart = position;
                while (position < expression.Length && expression[position] != '"') position++;
                if (position >= expression.Length) throw Error("The MSI string literal is not terminated.", start);
                var text = expression.Substring(contentStart, position - contentStart);
                position++;
                return NewToken(TokenKind.String, text, start);
            }

            private Token ReadInteger()
            {
                var start = position;
                if (expression[position] == '-' || expression[position] == '+') position++;
                while (position < expression.Length && char.IsDigit(expression[position])) position++;
                var text = expression.Substring(start, position - start);
                long value;
                if (!long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value)) throw Error("The MSI integer literal is outside the supported 64-bit range.", start);
                var token = NewToken(TokenKind.Integer, text, start);
                token.Integer = value;
                return token;
            }

            private bool TryReadComparison(out Token token)
            {
                var operators = new[] { "~><", "~<<", "~>>", "~<>", "~<=", "~>=", "~=", "~<", "~>", "><", "<<", ">>", "<>", "<=", ">=", "=", "<", ">" };
                foreach (var candidate in operators)
                {
                    if (position + candidate.Length > expression.Length || string.CompareOrdinal(expression, position, candidate, 0, candidate.Length) != 0) continue;
                    token = NewToken(TokenKind.Comparison, candidate, position);
                    position += candidate.Length;
                    return true;
                }
                token = null;
                return false;
            }

            private Token ReadPrefixedSymbol()
            {
                var start = position;
                var prefix = expression[position++];
                if (position >= expression.Length || !IsIdentifierStart(expression[position])) throw Error("The MSI state or environment prefix must be followed by an identifier.", start);
                var nameStart = position;
                while (position < expression.Length && IsIdentifierPart(expression[position])) position++;
                var token = NewToken(TokenKind.Symbol, expression.Substring(start, position - start), start);
                token.SymbolName = expression.Substring(nameStart, position - nameStart);
                token.SymbolKind = prefix == '%' ? MsiConditionSymbolKind.EnvironmentVariable :
                    prefix == '$' ? MsiConditionSymbolKind.ComponentActionState :
                    prefix == '?' ? MsiConditionSymbolKind.ComponentInstalledState :
                    prefix == '&' ? MsiConditionSymbolKind.FeatureActionState : MsiConditionSymbolKind.FeatureInstalledState;
                return token;
            }

            private Token ReadWord()
            {
                var start = position++;
                while (position < expression.Length && IsIdentifierPart(expression[position])) position++;
                var text = expression.Substring(start, position - start);
                switch (text.ToUpperInvariant())
                {
                    case "NOT": return NewToken(TokenKind.Not, text, start);
                    case "AND": return NewToken(TokenKind.And, text, start);
                    case "OR": return NewToken(TokenKind.Or, text, start);
                    case "XOR": return NewToken(TokenKind.Xor, text, start);
                    case "EQV": return NewToken(TokenKind.Eqv, text, start);
                    case "IMP": return NewToken(TokenKind.Imp, text, start);
                    default:
                        var token = NewToken(TokenKind.Symbol, text, start);
                        token.SymbolKind = MsiConditionSymbolKind.Property;
                        token.SymbolName = text;
                        return token;
                }
            }

            private static bool IsIdentifierStart(char value)
            {
                return value == '_' || char.IsLetter(value);
            }

            private static bool IsIdentifierPart(char value)
            {
                return value == '_' || value == '.' || char.IsLetterOrDigit(value);
            }

            private static Token NewToken(TokenKind kind, string text, int position)
            {
                return new Token { Kind = kind, Text = text, Position = position };
            }

            private static ConditionParseException Error(string message, int position)
            {
                return new ConditionParseException(message, position);
            }
        }

        private abstract class ConditionNode
        {
            internal abstract ConditionTruth Evaluate(MsiConditionEvaluationContext context, EvaluationTrace trace);
        }

        private abstract class ValueNode
        {
            internal abstract EvaluationValue Evaluate(MsiConditionEvaluationContext context, EvaluationTrace trace);
        }

        private sealed class LiteralValueNode : ValueNode
        {
            private readonly EvaluationValue value;

            internal LiteralValueNode(EvaluationValue value) { this.value = value; }
            internal override EvaluationValue Evaluate(MsiConditionEvaluationContext context, EvaluationTrace trace) { return value; }
        }

        private sealed class SymbolValueNode : ValueNode
        {
            private readonly MsiConditionSymbolKind kind;
            private readonly string name;

            internal SymbolValueNode(MsiConditionSymbolKind kind, string name)
            {
                this.kind = kind;
                this.name = name;
            }

            internal override EvaluationValue Evaluate(MsiConditionEvaluationContext context, EvaluationTrace trace)
            {
                return context.Resolve(kind, name, trace);
            }
        }

        private sealed class TruthNode : ConditionNode
        {
            private readonly ValueNode value;

            internal TruthNode(ValueNode value) { this.value = value; }
            internal override ConditionTruth Evaluate(MsiConditionEvaluationContext context, EvaluationTrace trace) { return GetTruth(value.Evaluate(context, trace)); }
        }

        private sealed class ComparisonNode : ConditionNode
        {
            private readonly ValueNode left;
            private readonly ValueNode right;
            private readonly string operation;

            internal ComparisonNode(ValueNode left, string operation, ValueNode right)
            {
                this.left = left;
                this.operation = operation;
                this.right = right;
            }

            internal override ConditionTruth Evaluate(MsiConditionEvaluationContext context, EvaluationTrace trace)
            {
                return Compare(left.Evaluate(context, trace), operation, right.Evaluate(context, trace));
            }
        }

        private sealed class NotNode : ConditionNode
        {
            private readonly ConditionNode value;

            internal NotNode(ConditionNode value) { this.value = value; }
            internal override ConditionTruth Evaluate(MsiConditionEvaluationContext context, EvaluationTrace trace)
            {
                var result = value.Evaluate(context, trace);
                return result == ConditionTruth.Unknown ? result : result == ConditionTruth.True ? ConditionTruth.False : ConditionTruth.True;
            }
        }

        private sealed class LogicalNode : ConditionNode
        {
            private readonly ConditionNode left;
            private readonly ConditionNode right;
            private readonly TokenKind operation;

            internal LogicalNode(ConditionNode left, TokenKind operation, ConditionNode right)
            {
                this.left = left;
                this.operation = operation;
                this.right = right;
            }

            internal override ConditionTruth Evaluate(MsiConditionEvaluationContext context, EvaluationTrace trace)
            {
                var leftValue = left.Evaluate(context, trace);
                var rightValue = right.Evaluate(context, trace);
                switch (operation)
                {
                    case TokenKind.And:
                        if (leftValue == ConditionTruth.False || rightValue == ConditionTruth.False) return ConditionTruth.False;
                        return leftValue == ConditionTruth.True && rightValue == ConditionTruth.True ? ConditionTruth.True : ConditionTruth.Unknown;
                    case TokenKind.Or:
                        if (leftValue == ConditionTruth.True || rightValue == ConditionTruth.True) return ConditionTruth.True;
                        return leftValue == ConditionTruth.False && rightValue == ConditionTruth.False ? ConditionTruth.False : ConditionTruth.Unknown;
                    case TokenKind.Xor:
                        if (leftValue == ConditionTruth.Unknown || rightValue == ConditionTruth.Unknown) return ConditionTruth.Unknown;
                        return leftValue != rightValue ? ConditionTruth.True : ConditionTruth.False;
                    case TokenKind.Eqv:
                        if (leftValue == ConditionTruth.Unknown || rightValue == ConditionTruth.Unknown) return ConditionTruth.Unknown;
                        return leftValue == rightValue ? ConditionTruth.True : ConditionTruth.False;
                    case TokenKind.Imp:
                        if (leftValue == ConditionTruth.False || rightValue == ConditionTruth.True) return ConditionTruth.True;
                        if (leftValue == ConditionTruth.True && rightValue == ConditionTruth.False) return ConditionTruth.False;
                        return ConditionTruth.Unknown;
                    default:
                        return ConditionTruth.Unknown;
                }
            }
        }

        private sealed class Parser
        {
            private readonly List<Token> tokens;
            private readonly int maximumDepth;
            private int index;

            internal Parser(List<Token> tokens, int maximumDepth)
            {
                this.tokens = tokens;
                this.maximumDepth = maximumDepth;
            }

            internal ConditionNode Parse()
            {
                var result = ParseImplication(0);
                if (Current.Kind != TokenKind.End) throw Error("Unexpected token after the MSI condition expression.", Current.Position);
                return result;
            }

            private ConditionNode ParseImplication(int depth) { return ParseBinary(ParseEquivalence, TokenKind.Imp, depth); }
            private ConditionNode ParseEquivalence(int depth) { return ParseBinary(ParseExclusiveOr, TokenKind.Eqv, depth); }
            private ConditionNode ParseExclusiveOr(int depth) { return ParseBinary(ParseOr, TokenKind.Xor, depth); }
            private ConditionNode ParseOr(int depth) { return ParseBinary(ParseAnd, TokenKind.Or, depth); }
            private ConditionNode ParseAnd(int depth) { return ParseBinary(ParseNot, TokenKind.And, depth); }

            private delegate ConditionNode ParseDelegate(int depth);

            private ConditionNode ParseBinary(ParseDelegate lowerPrecedence, TokenKind operation, int depth)
            {
                var left = lowerPrecedence(depth);
                while (Current.Kind == operation)
                {
                    index++;
                    left = new LogicalNode(left, operation, lowerPrecedence(depth));
                }
                return left;
            }

            private ConditionNode ParseNot(int depth)
            {
                if (Current.Kind != TokenKind.Not) return ParseTerm(depth);
                var position = Current.Position;
                index++;
                EnsureDepth(depth + 1, position);
                return new NotNode(ParseNot(depth + 1));
            }

            private ConditionNode ParseTerm(int depth)
            {
                EnsureDepth(depth, Current.Position);
                if (Current.Kind == TokenKind.LeftParenthesis)
                {
                    var position = Current.Position;
                    index++;
                    EnsureDepth(depth + 1, position);
                    var nested = ParseImplication(depth + 1);
                    if (Current.Kind != TokenKind.RightParenthesis) throw Error("The MSI condition is missing a closing parenthesis.", position);
                    index++;
                    return nested;
                }

                var left = ParseValue();
                if (Current.Kind != TokenKind.Comparison) return new TruthNode(left);
                var operation = Current.Text;
                index++;
                return new ComparisonNode(left, operation, ParseValue());
            }

            private ValueNode ParseValue()
            {
                var token = Current;
                index++;
                switch (token.Kind)
                {
                    case TokenKind.Integer: return new LiteralValueNode(EvaluationValue.FromNumber(token.Integer));
                    case TokenKind.String: return new LiteralValueNode(EvaluationValue.FromString(token.Text));
                    case TokenKind.Symbol: return new SymbolValueNode(token.SymbolKind, token.SymbolName);
                    default: throw Error("An MSI condition value was expected.", token.Position);
                }
            }

            private Token Current { get { return tokens[index]; } }

            private void EnsureDepth(int depth, int position)
            {
                if (depth > maximumDepth) throw Error("The MSI condition exceeds the nesting-depth limit.", position);
            }

            private static ConditionParseException Error(string message, int position)
            {
                return new ConditionParseException(message, position);
            }
        }

        private sealed class ConditionParseException : Exception
        {
            internal ConditionParseException(string message, int position) : base(message)
            {
                Position = position;
            }

            internal int Position { get; private set; }
        }

        private static ConditionTruth GetTruth(EvaluationValue value)
        {
            if (value.Kind == EvaluationValueKind.Number) return value.Number == 0 ? ConditionTruth.False : ConditionTruth.True;
            if (value.Kind == EvaluationValueKind.String) return string.IsNullOrEmpty(value.Text) ? ConditionTruth.False : ConditionTruth.True;
            if (value.IsPresent.HasValue) return value.IsPresent.Value ? ConditionTruth.True : ConditionTruth.False;
            return ConditionTruth.Unknown;
        }

        private static ConditionTruth Compare(EvaluationValue left, string operation, EvaluationValue right)
        {
            if (left.Kind == EvaluationValueKind.Unknown || right.Kind == EvaluationValueKind.Unknown) return ConditionTruth.Unknown;

            var ignoreCase = operation.Length > 0 && operation[0] == '~';
            var core = ignoreCase ? operation.Substring(1) : operation;
            long leftNumber;
            long rightNumber;
            var numericContext = left.Kind == EvaluationValueKind.Number || right.Kind == EvaluationValueKind.Number;

            if (numericContext)
            {
                if (!left.TryGetNumber(out leftNumber) || !right.TryGetNumber(out rightNumber))
                    return core == "<>" ? ConditionTruth.True : ConditionTruth.False;
                return EvaluateNumericComparison(leftNumber, core, rightNumber);
            }

            var comparison = string.Compare(left.Text, right.Text, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
            switch (core)
            {
                case "=": return FromBoolean(comparison == 0);
                case "<>": return FromBoolean(comparison != 0);
                case "<": return FromBoolean(comparison < 0);
                case ">": return FromBoolean(comparison > 0);
                case "<=": return FromBoolean(comparison <= 0);
                case ">=": return FromBoolean(comparison >= 0);
                case "><": return FromBoolean((left.Text ?? string.Empty).IndexOf(right.Text ?? string.Empty, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) >= 0);
                case "<<": return FromBoolean((left.Text ?? string.Empty).StartsWith(right.Text ?? string.Empty, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal));
                case ">>": return FromBoolean((left.Text ?? string.Empty).EndsWith(right.Text ?? string.Empty, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal));
                default: return ConditionTruth.Unknown;
            }
        }

        private static ConditionTruth EvaluateNumericComparison(long left, string operation, long right)
        {
            switch (operation)
            {
                case "=": return FromBoolean(left == right);
                case "<>": return FromBoolean(left != right);
                case "<": return FromBoolean(left < right);
                case ">": return FromBoolean(left > right);
                case "<=": return FromBoolean(left <= right);
                case ">=": return FromBoolean(left >= right);
                case "><": return FromBoolean((left & right) != 0);
                case "<<": return FromBoolean(((ulong)left >> 16 & 0xFFFFUL) == (ulong)right);
                case ">>": return FromBoolean(((ulong)left & 0xFFFFUL) == (ulong)right);
                default: return ConditionTruth.Unknown;
            }
        }

        private static ConditionTruth FromBoolean(bool value)
        {
            return value ? ConditionTruth.True : ConditionTruth.False;
        }
    }
}
