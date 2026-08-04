// SPDX-License-Identifier: Apache-2.0
//
// Source behavior:
// - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-codegen/src/embedded_assets.rs
// - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-utils/src/assets.rs
// Behavioral reference only (no copied code): https://github.com/Mas0nShi/tauri-dumper

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Dumplings.Tauri
{
    /// <summary>Describes one file-backed PE section used for VA translation.</summary>
    public sealed class TauriPeSection
    {
        public string Name { get; set; }
        public uint VirtualAddress { get; set; }
        public uint RawOffset { get; set; }
        public uint RawSize { get; set; }
    }

    /// <summary>One structurally valid Rust (&amp;str, &amp;[u8]) asset-map entry.</summary>
    public sealed class TauriAssetRecordData
    {
        public string Name { get; set; }
        public bool IsSafeName { get; set; }
        public long HeaderOffset { get; set; }
        public long NameOffset { get; set; }
        public long DataOffset { get; set; }
        public long StoredSize { get; set; }
    }

    /// <summary>A non-authoritative identifier-like string retained as evidence.</summary>
    public sealed class TauriStringCandidateData
    {
        public string Kind { get; set; }
        public string Value { get; set; }
        public long Offset { get; set; }
    }

    /// <summary>Strict incremental Brotli validation and expanded-size evidence.</summary>
    public sealed class TauriBrotliMeasurementData
    {
        public bool Success { get; set; }
        public long ExpandedSize { get; set; }
        public string Error { get; set; }
    }

    /// <summary>
    /// Scans PE read-only-data sections for the static records emitted by Rust for
    /// Tauri's PHF map. The scanner performs only mechanical range and UTF-8 checks;
    /// PowerShell validates map coherence and compression before accepting records.
    /// </summary>
    public static class TauriExecutableScanner
    {
        private const int ScanBufferSize = 1024 * 1024;
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private static readonly Regex PackageIdentifierPattern = new Regex(
            @"^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*){2,}$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private static readonly Regex PermissionIdentifierPattern = new Regex(
            @"^[a-z0-9][a-z0-9-]*(?::[a-z0-9][a-z0-9-]*)+$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private static readonly HashSet<string> ReverseDomainRoots = new HashSet<string>(StringComparer.Ordinal)
        {
            "app", "ai", "cloud", "cn", "co", "com", "de", "dev", "fr", "gg", "io", "jp", "me", "net", "org", "rs", "tech", "uk", "xyz"
        };

        /// <summary>
        /// Finds pointer-sized asset records in sections named <c>.rdata</c>.
        /// Caller-owned stream position is restored before this method returns.
        /// </summary>
        public static TauriAssetRecordData[] FindAssetRecords(
            Stream stream,
            ulong imageBase,
            int pointerSize,
            TauriPeSection[] sections,
            int maximumNameBytes,
            long maximumStoredBytes,
            int maximumRecords)
        {
            ValidateArguments(stream, pointerSize, sections, maximumNameBytes, maximumStoredBytes, maximumRecords);
            long originalPosition = stream.Position;
            List<TauriAssetRecordData> records = new List<TauriAssetRecordData>();
            byte[] buffer = ArrayPool<byte>.Shared.Rent(ScanBufferSize + (pointerSize * 4));
            try
            {
                int recordSize = pointerSize * 4;
                foreach (TauriPeSection scanSection in sections)
                {
                    if (!string.Equals(scanSection.Name, ".rdata", StringComparison.Ordinal)) continue;
                    long sectionStart = scanSection.RawOffset;
                    long sectionEnd = CheckedEnd(sectionStart, scanSection.RawSize, stream.Length, ".rdata section");
                    long blockStart = AlignUp(sectionStart, pointerSize);

                    // Scan in fixed blocks and include a record-sized overlap. Candidate
                    // names and payloads are read only after all four words look plausible.
                    while (blockStart + recordSize <= sectionEnd)
                    {
                        int bodyLength = (int)Math.Min(ScanBufferSize, sectionEnd - blockStart);
                        int readLength = (int)Math.Min((long)bodyLength + recordSize - 1, sectionEnd - blockStart);
                        ReadExactlyAt(stream, blockStart, buffer, readLength);

                        for (int localOffset = 0; localOffset < bodyLength && localOffset + recordSize <= readLength; localOffset += pointerSize)
                        {
                            ulong namePointer = ReadWord(buffer, localOffset, pointerSize);
                            ulong nameLength = ReadWord(buffer, localOffset + pointerSize, pointerSize);
                            ulong dataPointer = ReadWord(buffer, localOffset + (pointerSize * 2), pointerSize);
                            ulong dataLength = ReadWord(buffer, localOffset + (pointerSize * 3), pointerSize);
                            if (nameLength == 0 || nameLength > (ulong)maximumNameBytes || dataLength > (ulong)maximumStoredBytes) continue;

                            if (!TryResolveVirtualAddress(namePointer, nameLength, imageBase, sections, stream.Length, out long nameOffset)) continue;
                            long dataOffset = -1;
                            // Rust represents an empty slice with a non-dereferenceable dangling
                            // pointer. A zero-length asset therefore needs no VA translation.
                            if (dataLength != 0 && !TryResolveVirtualAddress(dataPointer, dataLength, imageBase, sections, stream.Length, out dataOffset)) continue;

                            string name;
                            try
                            {
                                byte[] nameBytes = new byte[(int)nameLength];
                                ReadExactlyAt(stream, nameOffset, nameBytes, nameBytes.Length);
                                name = StrictUtf8.GetString(nameBytes);
                            }
                            catch (DecoderFallbackException)
                            {
                                continue;
                            }

                            if (!IsRootedAssetName(name)) continue;
                            records.Add(new TauriAssetRecordData
                            {
                                Name = name,
                                IsSafeName = IsSafeRootedAssetName(name),
                                HeaderOffset = blockStart + localOffset,
                                NameOffset = nameOffset,
                                DataOffset = dataOffset,
                                StoredSize = checked((long)dataLength)
                            });
                            if (records.Count > maximumRecords)
                            {
                                throw new InvalidDataException($"The Tauri candidate record count exceeds the {maximumRecords}-record limit.");
                            }
                        }

                        blockStart += bodyLength;
                    }
                }

                records.Sort((left, right) => left.HeaderOffset.CompareTo(right.HeaderOffset));
                return records.ToArray();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                stream.Position = originalPosition;
            }
        }

        /// <summary>
        /// Finds reverse-domain and Tauri ACL-shaped ASCII tokens. These values are
        /// evidence only because optimized Rust output does not preserve config ownership.
        /// </summary>
        public static TauriStringCandidateData[] FindIdentifierCandidates(
            Stream stream,
            TauriPeSection[] sections,
            int maximumCandidates,
            int maximumTokenLength)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("The stream must be readable and seekable.", nameof(stream));
            if (sections == null) throw new ArgumentNullException(nameof(sections));
            if (maximumCandidates < 1) throw new ArgumentOutOfRangeException(nameof(maximumCandidates));
            if (maximumTokenLength < 3 || maximumTokenLength > 4096) throw new ArgumentOutOfRangeException(nameof(maximumTokenLength));

            long originalPosition = stream.Position;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(ScanBufferSize);
            List<TauriStringCandidateData> result = new List<TauriStringCandidateData>();
            HashSet<string> observed = new HashSet<string>(StringComparer.Ordinal);
            try
            {
                foreach (TauriPeSection section in sections)
                {
                    if (!string.Equals(section.Name, ".rdata", StringComparison.Ordinal)) continue;
                    long sectionStart = section.RawOffset;
                    long sectionEnd = CheckedEnd(sectionStart, section.RawSize, stream.Length, ".rdata section");
                    StringBuilder token = new StringBuilder(Math.Min(maximumTokenLength, 256));
                    long tokenOffset = -1;
                    bool overflowed = false;

                    for (long blockStart = sectionStart; blockStart < sectionEnd;)
                    {
                        int count = (int)Math.Min(buffer.Length, sectionEnd - blockStart);
                        ReadExactlyAt(stream, blockStart, buffer, count);
                        for (int index = 0; index < count; index++)
                        {
                            byte value = buffer[index];
                            if (IsIdentifierByte(value))
                            {
                                if (token.Length == 0) tokenOffset = blockStart + index;
                                if (token.Length < maximumTokenLength) token.Append((char)value);
                                else overflowed = true;
                            }
                            else
                            {
                                AddIdentifierCandidate(token, tokenOffset, overflowed, observed, result, maximumCandidates);
                                token.Clear();
                                tokenOffset = -1;
                                overflowed = false;
                            }
                        }
                        blockStart += count;
                    }
                    AddIdentifierCandidate(token, tokenOffset, overflowed, observed, result, maximumCandidates);
                }
                return result.ToArray();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                stream.Position = originalPosition;
            }
        }

        /// <summary>
        /// Validates one exact Brotli range by requiring OperationStatus.Done,
        /// complete input consumption, and bounded output. Stream position is restored.
        /// </summary>
        public static TauriBrotliMeasurementData MeasureBrotli(Stream stream, long offset, long length, long maximumExpandedBytes)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("The stream must be readable and seekable.", nameof(stream));
            if (offset < 0 || length <= 0 || offset > stream.Length || length > stream.Length - offset) return BrotliFailure("The stored Brotli range is empty or outside the PE file.");
            if (maximumExpandedBytes < 1) throw new ArgumentOutOfRangeException(nameof(maximumExpandedBytes));

            long originalPosition = stream.Position;
            byte[] input = ArrayPool<byte>.Shared.Rent(64 * 1024);
            byte[] output = ArrayPool<byte>.Shared.Rent(64 * 1024);
            BrotliDecoder decoder = default;
            try
            {
                stream.Position = offset;
                long storedRemaining = length;
                int inputOffset = 0;
                int inputCount = 0;
                long expanded = 0;
                while (true)
                {
                    if (inputOffset == inputCount && storedRemaining > 0)
                    {
                        int requested = (int)Math.Min(input.Length, storedRemaining);
                        int read = stream.Read(input, 0, requested);
                        if (read <= 0) return BrotliFailure("The stored Brotli range is truncated.");
                        inputOffset = 0;
                        inputCount = read;
                        storedRemaining -= read;
                    }

                    OperationStatus status = decoder.Decompress(
                        input.AsSpan(inputOffset, inputCount - inputOffset),
                        output.AsSpan(),
                        out int consumed,
                        out int written);
                    inputOffset += consumed;
                    expanded += written;
                    if (expanded > maximumExpandedBytes) return BrotliFailure($"The Brotli output exceeds the {maximumExpandedBytes}-byte limit.");

                    if (status == OperationStatus.Done)
                    {
                        if (inputOffset != inputCount || storedRemaining != 0) return BrotliFailure("The Brotli stream has trailing stored bytes.");
                        return new TauriBrotliMeasurementData { Success = true, ExpandedSize = expanded };
                    }
                    if (status == OperationStatus.InvalidData) return BrotliFailure("The stored payload is not a complete Brotli stream.");
                    if (status == OperationStatus.NeedMoreData && inputOffset == inputCount && storedRemaining == 0)
                    {
                        return BrotliFailure("The stored Brotli stream is truncated.");
                    }
                    if (status == OperationStatus.NeedMoreData && inputOffset != inputCount)
                    {
                        return BrotliFailure("The Brotli decoder requested more input before consuming the current range.");
                    }
                }
            }
            catch (Exception exception) when (exception is InvalidDataException || exception is IOException)
            {
                return BrotliFailure(exception.Message);
            }
            finally
            {
                decoder.Dispose();
                ArrayPool<byte>.Shared.Return(input);
                ArrayPool<byte>.Shared.Return(output);
                stream.Position = originalPosition;
            }
        }

        private static void ValidateArguments(Stream stream, int pointerSize, TauriPeSection[] sections, int maximumNameBytes, long maximumStoredBytes, int maximumRecords)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("The stream must be readable and seekable.", nameof(stream));
            if (pointerSize != 4 && pointerSize != 8) throw new ArgumentOutOfRangeException(nameof(pointerSize));
            if (sections == null || sections.Length == 0) throw new ArgumentException("At least one PE section is required.", nameof(sections));
            if (maximumNameBytes < 1 || maximumNameBytes > 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(maximumNameBytes));
            if (maximumStoredBytes < 0) throw new ArgumentOutOfRangeException(nameof(maximumStoredBytes));
            if (maximumRecords < 1) throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }

        private static TauriBrotliMeasurementData BrotliFailure(string error)
        {
            return new TauriBrotliMeasurementData { Success = false, ExpandedSize = 0, Error = error };
        }

        private static ulong ReadWord(byte[] buffer, int offset, int pointerSize)
        {
            return pointerSize == 4
                ? BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4))
                : BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset, 8));
        }

        private static bool TryResolveVirtualAddress(
            ulong pointer,
            ulong length,
            ulong imageBase,
            TauriPeSection[] sections,
            long streamLength,
            out long fileOffset)
        {
            fileOffset = -1;
            if (pointer < imageBase) return false;
            ulong relative = pointer - imageBase;
            foreach (TauriPeSection section in sections)
            {
                ulong start = section.VirtualAddress;
                ulong rawSize = section.RawSize;
                if (relative < start) continue;
                ulong delta = relative - start;
                if (delta > rawSize || length > rawSize - delta) continue;
                ulong candidate = (ulong)section.RawOffset + delta;
                if (candidate > (ulong)long.MaxValue || length > (ulong)long.MaxValue - candidate) return false;
                long end = checked((long)(candidate + length));
                if (end > streamLength) return false;
                fileOffset = checked((long)candidate);
                return true;
            }
            return false;
        }

        private static bool IsSafeRootedAssetName(string name)
        {
            if (!IsRootedAssetName(name)) return false;
            string[] components = name.Substring(1).Split('/');
            foreach (string component in components)
            {
                if (component.Length == 0 || component == "." || component == ".." || component.IndexOf(':') >= 0) return false;
                foreach (char character in component)
                {
                    if (char.IsControl(character)) return false;
                }
            }
            return true;
        }

        private static bool IsRootedAssetName(string name)
        {
            return !string.IsNullOrEmpty(name) && name.Length > 1 && name[0] == '/' && name.IndexOf('\0') < 0 && name.IndexOf('\\') < 0;
        }

        private static bool IsIdentifierByte(byte value)
        {
            return (value >= (byte)'a' && value <= (byte)'z') ||
                   (value >= (byte)'A' && value <= (byte)'Z') ||
                   (value >= (byte)'0' && value <= (byte)'9') ||
                   value == (byte)'.' || value == (byte)':' || value == (byte)'-';
        }

        private static void AddIdentifierCandidate(
            StringBuilder token,
            long offset,
            bool overflowed,
            HashSet<string> observed,
            List<TauriStringCandidateData> output,
            int maximumCandidates)
        {
            if (overflowed || offset < 0 || token.Length < 3 || output.Count >= maximumCandidates) return;
            string value = token.ToString();
            string kind = null;
            if (PackageIdentifierPattern.IsMatch(value) && ReverseDomainRoots.Contains(value.Substring(0, value.IndexOf('.'))))
            {
                kind = "PackageIdentifier";
            }
            else if (PermissionIdentifierPattern.IsMatch(value))
            {
                string[] segments = value.Split(':');
                foreach (string segment in segments)
                {
                    if (segment == "default" || segment.StartsWith("allow-", StringComparison.Ordinal) || segment.StartsWith("deny-", StringComparison.Ordinal))
                    {
                        kind = "AclPermission";
                        break;
                    }
                }
            }
            if (kind == null || !observed.Add(kind + "\0" + value)) return;
            output.Add(new TauriStringCandidateData { Kind = kind, Value = value, Offset = offset });
        }

        private static long AlignUp(long value, int alignment)
        {
            long remainder = value % alignment;
            return remainder == 0 ? value : checked(value + alignment - remainder);
        }

        private static long CheckedEnd(long offset, uint length, long streamLength, string description)
        {
            if (offset < 0 || offset > streamLength || length > streamLength - offset)
            {
                throw new InvalidDataException($"The {description} is outside the PE file.");
            }
            return offset + length;
        }

        private static void ReadExactlyAt(Stream stream, long offset, byte[] buffer, int count)
        {
            if (offset < 0 || count < 0 || offset > stream.Length || count > stream.Length - offset)
            {
                throw new EndOfStreamException("The requested Tauri PE range is truncated.");
            }
            stream.Position = offset;
            int total = 0;
            while (total < count)
            {
                int read = stream.Read(buffer, total, count - total);
                if (read <= 0) throw new EndOfStreamException("The requested Tauri PE range is truncated.");
                total += read;
            }
        }
    }
}
