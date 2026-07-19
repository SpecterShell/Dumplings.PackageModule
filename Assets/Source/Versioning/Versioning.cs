// SPDX-License-Identifier: Apache-2.0
/*
WinGetVersion is adapted from the Windows Package Manager version comparator:
https://github.com/microsoft/winget-cli/blob/master/src/AppInstallerSharedLib/Versions.cpp

The Windows Package Manager source is licensed under the MIT License.
ChunkVersion is original Dumplings code licensed under the repository's Apache-2.0 license.
*/
#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;

namespace Dumplings.Versioning
{
    /// <summary>
    /// Compares package versions using the same part model and precedence rules as WinGet.
    /// </summary>
    public sealed class WinGetVersion : IComparable, IComparable<WinGetVersion>, IEquatable<WinGetVersion>
    {
        public enum ApproximateComparator
        {
            None,
            LessThan,
            GreaterThan,
        }

        private const string LatestValue = "Latest";
        private const string UnknownValue = "Unknown";
        private readonly List<Part> _parts = new();

        public string Value { get; }
        public ApproximateComparator Approximation { get; }
        public bool IsApproximate => Approximation != ApproximateComparator.None;
        public bool IsLatest => Approximation != ApproximateComparator.LessThan && IsBaseLatest;
        public bool IsUnknown => IsBaseUnknown;

        public WinGetVersion(string value)
        {
            ArgumentNullException.ThrowIfNull(value);
            Value = value.Trim();

            string baseVersion = Value;
            if (baseVersion.StartsWith("< ", StringComparison.OrdinalIgnoreCase))
            {
                Approximation = ApproximateComparator.LessThan;
                baseVersion = baseVersion.Substring(2);
            }
            else if (baseVersion.StartsWith("> ", StringComparison.OrdinalIgnoreCase))
            {
                Approximation = ApproximateComparator.GreaterThan;
                baseVersion = baseVersion.Substring(2);
            }

            int digitPosition = IndexOfAsciiDigit(baseVersion);
            int splitPosition = baseVersion.IndexOf('.');
            if (digitPosition >= 0 && (splitPosition < 0 || digitPosition < splitPosition))
            {
                baseVersion = baseVersion.Substring(digitPosition);
            }

            int position = 0;
            while (position < baseVersion.Length)
            {
                int nextPosition = baseVersion.IndexOf('.', position);
                int length = (nextPosition < 0 ? baseVersion.Length : nextPosition) - position;
                _parts.Add(new Part(baseVersion.Substring(position, length)));
                position += length + 1;
            }

            while (_parts.Count > 0 && _parts[_parts.Count - 1].IsZero)
            {
                _parts.RemoveAt(_parts.Count - 1);
            }

            if (IsApproximate && IsBaseUnknown)
            {
                throw new ArgumentException("An approximate WinGet version cannot use Unknown as its base version.", nameof(value));
            }
        }

        public static WinGetVersion Parse(string value) => new(value);

        public static bool TryParse(string? value, out WinGetVersion? version)
        {
            try
            {
                version = value is null ? null : new WinGetVersion(value);
                return version is not null;
            }
            catch (ArgumentException)
            {
                version = null;
                return false;
            }
        }

        public static WinGetVersion CreateLatest() => new(LatestValue);
        public static WinGetVersion CreateUnknown() => new(UnknownValue);

        public int CompareTo(WinGetVersion? other)
        {
            if (other is null)
            {
                return 1;
            }

            if (IsBaseLatest || other.IsBaseLatest)
            {
                if (IsBaseLatest && other.IsBaseLatest)
                {
                    return CompareApproximation(other);
                }

                return IsBaseLatest ? 1 : -1;
            }

            if (IsBaseUnknown || other.IsBaseUnknown)
            {
                if (IsBaseUnknown && other.IsBaseUnknown)
                {
                    return CompareApproximation(other);
                }

                return IsBaseUnknown ? -1 : 1;
            }

            int partCount = Math.Max(_parts.Count, other._parts.Count);
            for (int index = 0; index < partCount; index++)
            {
                Part left = index < _parts.Count ? _parts[index] : Part.Zero;
                Part right = index < other._parts.Count ? other._parts[index] : Part.Zero;
                int result = left.CompareTo(right);
                if (result != 0)
                {
                    // PowerShell's Sort-Object Top/Bottom heap compares against exactly -1 and
                    // 1 instead of checking only the sign. Keep the public IComparable result
                    // canonical even when an inner string comparer returns another magnitude.
                    return result < 0 ? -1 : 1;
                }
            }

            return CompareApproximation(other);
        }

        int IComparable.CompareTo(object? obj)
        {
            if (obj is null)
            {
                return 1;
            }

            return obj is WinGetVersion other
                ? CompareTo(other)
                : throw new ArgumentException($"Object must be a {nameof(WinGetVersion)}.", nameof(obj));
        }

        public bool Equals(WinGetVersion? other) => other is not null && CompareTo(other) == 0;
        public override bool Equals(object? obj) => obj is WinGetVersion other && Equals(other);

        public override int GetHashCode()
        {
            HashCode hash = new();
            hash.Add(Approximation);
            if (IsBaseLatest)
            {
                hash.Add(LatestValue, StringComparer.OrdinalIgnoreCase);
            }
            else if (IsBaseUnknown)
            {
                hash.Add(UnknownValue, StringComparer.OrdinalIgnoreCase);
            }
            else
            {
                foreach (Part part in _parts)
                {
                    hash.Add(part.Integer);
                    hash.Add(part.Other, StringComparer.OrdinalIgnoreCase);
                }
            }

            return hash.ToHashCode();
        }

        public override string ToString() => Value;

        public static bool operator <(WinGetVersion left, WinGetVersion right) => left.CompareTo(right) < 0;
        public static bool operator >(WinGetVersion left, WinGetVersion right) => left.CompareTo(right) > 0;
        public static bool operator <=(WinGetVersion left, WinGetVersion right) => left.CompareTo(right) <= 0;
        public static bool operator >=(WinGetVersion left, WinGetVersion right) => left.CompareTo(right) >= 0;
        public static bool operator ==(WinGetVersion? left, WinGetVersion? right) => EqualityComparer<WinGetVersion>.Default.Equals(left, right);
        public static bool operator !=(WinGetVersion? left, WinGetVersion? right) => !(left == right);

        private bool IsBaseLatest => _parts.Count == 1 && _parts[0].Integer == 0 && string.Equals(_parts[0].Other, LatestValue, StringComparison.OrdinalIgnoreCase);
        private bool IsBaseUnknown => _parts.Count == 1 && _parts[0].Integer == 0 && string.Equals(_parts[0].Other, UnknownValue, StringComparison.OrdinalIgnoreCase);

        private int CompareApproximation(WinGetVersion other) => GetApproximationRank(Approximation).CompareTo(GetApproximationRank(other.Approximation));

        private static int GetApproximationRank(ApproximateComparator approximation) => approximation switch
        {
            ApproximateComparator.LessThan => 0,
            ApproximateComparator.None => 1,
            ApproximateComparator.GreaterThan => 2,
            _ => throw new ArgumentOutOfRangeException(nameof(approximation)),
        };

        private static int IndexOfAsciiDigit(string value)
        {
            for (int index = 0; index < value.Length; index++)
            {
                if (value[index] >= '0' && value[index] <= '9')
                {
                    return index;
                }
            }

            return -1;
        }

        private sealed class Part : IComparable<Part>
        {
            public static readonly Part Zero = new(0, string.Empty);

            public ulong Integer { get; }
            public string Other { get; }
            public bool IsZero => Integer == 0 && Other.Length == 0;

            public Part(string value)
            {
                string part = value.Trim();
                int digitCount = 0;
                while (digitCount < part.Length && part[digitCount] >= '0' && part[digitCount] <= '9')
                {
                    digitCount++;
                }

                if (digitCount == 0)
                {
                    Other = part;
                    return;
                }

                string integerText = part.Substring(0, digitCount);
                if (!ulong.TryParse(integerText, NumberStyles.None, CultureInfo.InvariantCulture, out ulong integer))
                {
                    Other = part;
                    return;
                }

                Integer = integer;
                Other = part.Substring(digitCount);
            }

            private Part(ulong integer, string other)
            {
                Integer = integer;
                Other = other;
            }

            public int CompareTo(Part? other)
            {
                if (other is null)
                {
                    return 1;
                }

                int result = Integer.CompareTo(other.Integer);
                if (result != 0)
                {
                    return result;
                }

                if (Other.Length == 0 || other.Other.Length == 0)
                {
                    return Other.Length == other.Other.Length ? 0 : (Other.Length == 0 ? 1 : -1);
                }

                return StringComparer.OrdinalIgnoreCase.Compare(Other, other.Other);
            }
        }
    }

    /// <summary>
    /// Compares loosely structured versions as groups of unbounded numeric and textual parts.
    /// </summary>
    public sealed class ChunkVersion : IComparable, IComparable<ChunkVersion>, IEquatable<ChunkVersion>
    {
        private readonly List<Group> _groups;

        public string Value { get; }

        public ChunkVersion(string value)
        {
            ArgumentNullException.ThrowIfNull(value);
            Value = value.Trim();
            if (Value.Length == 0)
            {
                throw new ArgumentException("A chunk version cannot be empty.", nameof(value));
            }
            _groups = ParseGroups(Value);
        }

        public static ChunkVersion Parse(string value) => new(value);

        public static bool TryParse(string? value, out ChunkVersion? version)
        {
            if (value is null)
            {
                version = null;
                return false;
            }

            try
            {
                version = new ChunkVersion(value);
                return true;
            }
            catch (ArgumentException)
            {
                version = null;
                return false;
            }
        }

        public int CompareTo(ChunkVersion? other)
        {
            if (other is null)
            {
                return 1;
            }

            int groupCount = Math.Max(_groups.Count, other._groups.Count);
            for (int index = 0; index < groupCount; index++)
            {
                Group left = index < _groups.Count ? _groups[index] : Group.Zero;
                Group right = index < other._groups.Count ? other._groups[index] : Group.Zero;
                int result = left.CompareTo(right);
                if (result != 0)
                {
                    // Sort-Object's optimized heap path expects canonical comparison values.
                    return result < 0 ? -1 : 1;
                }
            }

            return 0;
        }

        int IComparable.CompareTo(object? obj)
        {
            if (obj is null)
            {
                return 1;
            }

            return obj is ChunkVersion other
                ? CompareTo(other)
                : throw new ArgumentException($"Object must be a {nameof(ChunkVersion)}.", nameof(obj));
        }

        public bool Equals(ChunkVersion? other) => other is not null && CompareTo(other) == 0;
        public override bool Equals(object? obj) => obj is ChunkVersion other && Equals(other);

        public override int GetHashCode()
        {
            HashCode hash = new();
            foreach (Group group in _groups)
            {
                hash.Add(group);
            }

            return hash.ToHashCode();
        }

        public override string ToString() => Value;

        public static bool operator <(ChunkVersion left, ChunkVersion right) => left.CompareTo(right) < 0;
        public static bool operator >(ChunkVersion left, ChunkVersion right) => left.CompareTo(right) > 0;
        public static bool operator <=(ChunkVersion left, ChunkVersion right) => left.CompareTo(right) <= 0;
        public static bool operator >=(ChunkVersion left, ChunkVersion right) => left.CompareTo(right) >= 0;
        public static bool operator ==(ChunkVersion? left, ChunkVersion? right) => EqualityComparer<ChunkVersion>.Default.Equals(left, right);
        public static bool operator !=(ChunkVersion? left, ChunkVersion? right) => !(left == right);

        private static List<Group> ParseGroups(string value)
        {
            List<Group> groups = new();
            int start = 0;
            for (int index = 0; index <= value.Length; index++)
            {
                if (index == value.Length || value[index] == '-' || value[index] == '+' || value[index] == '_')
                {
                    groups.Add(Group.Parse(value, start, index - start));
                    start = index + 1;
                }
            }

            while (groups.Count > 0 && groups[groups.Count - 1].IsZero)
            {
                groups.RemoveAt(groups.Count - 1);
            }

            return groups;
        }

        private enum PartKind
        {
            Text,
            Numeric,
        }

        private sealed class Group : IComparable<Group>, IEquatable<Group>
        {
            public static readonly Group Zero = new(new List<Part>());
            private readonly List<Part> _parts;

            public bool IsZero => _parts.Count == 0;

            private Group(List<Part> parts)
            {
                _parts = parts;
            }

            public static Group Parse(string value, int start, int length)
            {
                List<Part> parts = new();
                int end = start + length;
                int index = start;
                while (index < end)
                {
                    if (IsAsciiDigit(value[index]))
                    {
                        int tokenStart = index++;
                        while (index < end && IsAsciiDigit(value[index]))
                        {
                            index++;
                        }

                        parts.Add(Part.Numeric(value.Substring(tokenStart, index - tokenStart)));
                    }
                    else if (char.IsLetter(value[index]))
                    {
                        int tokenStart = index++;
                        while (index < end && char.IsLetter(value[index]))
                        {
                            index++;
                        }

                        parts.Add(Part.Text(value.Substring(tokenStart, index - tokenStart)));
                    }
                    else
                    {
                        index++;
                    }
                }

                while (parts.Count > 0 && parts[parts.Count - 1].IsZero)
                {
                    parts.RemoveAt(parts.Count - 1);
                }

                return new Group(parts);
            }

            public int CompareTo(Group? other)
            {
                if (other is null)
                {
                    return 1;
                }

                int partCount = Math.Max(_parts.Count, other._parts.Count);
                for (int index = 0; index < partCount; index++)
                {
                    Part left = index < _parts.Count ? _parts[index] : Part.Zero;
                    Part right = index < other._parts.Count ? other._parts[index] : Part.Zero;
                    int result = left.CompareTo(right);
                    if (result != 0)
                    {
                        return result;
                    }
                }

                return 0;
            }

            public bool Equals(Group? other) => other is not null && CompareTo(other) == 0;
            public override bool Equals(object? obj) => obj is Group other && Equals(other);

            public override int GetHashCode()
            {
                HashCode hash = new();
                foreach (Part part in _parts)
                {
                    hash.Add(part);
                }

                return hash.ToHashCode();
            }

            private static bool IsAsciiDigit(char value) => value >= '0' && value <= '9';
        }

        private sealed class Part : IComparable<Part>, IEquatable<Part>
        {
            public static readonly Part Zero = new(PartKind.Numeric, "0");

            private PartKind Kind { get; }
            private string Value { get; }
            public bool IsZero => Kind == PartKind.Numeric && Value == "0";

            private Part(PartKind kind, string value)
            {
                Kind = kind;
                Value = value;
            }

            public static Part Numeric(string value)
            {
                int nonZero = 0;
                while (nonZero < value.Length - 1 && value[nonZero] == '0')
                {
                    nonZero++;
                }

                return new Part(PartKind.Numeric, value.Substring(nonZero));
            }

            public static Part Text(string value) => new(PartKind.Text, value);

            public int CompareTo(Part? other)
            {
                if (other is null)
                {
                    return 1;
                }

                if (Kind != other.Kind)
                {
                    return Kind == PartKind.Text ? -1 : 1;
                }

                if (Kind == PartKind.Text)
                {
                    return StringComparer.OrdinalIgnoreCase.Compare(Value, other.Value);
                }

                int result = Value.Length.CompareTo(other.Value.Length);
                return result != 0 ? result : string.CompareOrdinal(Value, other.Value);
            }

            public bool Equals(Part? other) => other is not null && CompareTo(other) == 0;
            public override bool Equals(object? obj) => obj is Part other && Equals(other);

            public override int GetHashCode() => Kind == PartKind.Text
                ? HashCode.Combine(Kind, StringComparer.OrdinalIgnoreCase.GetHashCode(Value))
                : HashCode.Combine(Kind, Value);
        }
    }
}
