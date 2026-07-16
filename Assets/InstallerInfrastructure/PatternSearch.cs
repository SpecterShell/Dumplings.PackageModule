// SPDX-License-Identifier: MIT
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;

namespace Dumplings.InstallerInfrastructure
{
    public static class PatternSearch
    {
        public static long[] FindFile(string path, byte[] pattern, long start, long length, int maximum, bool reverse, int alignment)
        {
            using FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return FindStream(stream, pattern, start, length, maximum, reverse, alignment, false);
        }

        public static long[] FindStream(Stream stream, byte[] pattern, long start, long length, int maximum, bool reverse, int alignment, bool restorePosition)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("The stream must be readable and seekable.", nameof(stream));
            Validate(pattern, maximum, alignment);
            if (start < 0 || start > stream.Length) throw new ArgumentOutOfRangeException(nameof(start));
            long available = stream.Length - start;
            long boundedLength = length <= 0 ? available : Math.Min(length, available);
            if (boundedLength < pattern.Length) return Array.Empty<long>();

            long original = stream.Position;
            List<long> results = new List<long>(Math.Min(maximum, 128));
            const int chunkSize = 1024 * 1024;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(chunkSize + pattern.Length - 1);
            int[] shifts = CreateShiftTable(pattern);
            try
            {
                if (reverse)
                {
                    long chunkEnd = start + boundedLength;
                    while (chunkEnd > start && results.Count < maximum)
                    {
                        int primaryLength = (int)Math.Min(chunkSize, chunkEnd - start);
                        long chunkStart = chunkEnd - primaryLength;
                        int suffixLength = (int)Math.Min(pattern.Length - 1L, start + boundedLength - chunkEnd);
                        int windowLength = primaryLength + suffixLength;
                        ReadExactly(stream, chunkStart, buffer, windowLength);
                        FindWindowReverse(buffer, windowLength, pattern, chunkStart, chunkEnd, results, maximum, alignment);
                        chunkEnd = chunkStart;
                    }
                }
                else
                {
                    int carryLength = 0;
                    long consumed = 0;
                    stream.Position = start;
                    while (consumed < boundedLength)
                    {
                        int requested = (int)Math.Min(chunkSize, boundedLength - consumed);
                        int read = stream.Read(buffer, carryLength, requested);
                        if (read <= 0) break;
                        int windowLength = carryLength + read;
                        long baseOffset = start + consumed - carryLength;
                        FindWindowForward(buffer, windowLength, pattern, shifts, baseOffset, start, start + boundedLength, results, maximum, alignment);
                        if (results.Count >= maximum) break;
                        carryLength = Math.Min(pattern.Length - 1, windowLength);
                        if (carryLength > 0) Buffer.BlockCopy(buffer, windowLength - carryLength, buffer, 0, carryLength);
                        consumed += read;
                    }
                }
            }
            finally
            {
                if (restorePosition) stream.Position = original;
                ArrayPool<byte>.Shared.Return(buffer);
            }
            return results.ToArray();
        }

        public static long[] FindBuffer(byte[] bytes, byte[] pattern, int start, int length, int maximum, bool reverse, int alignment)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            Validate(pattern, maximum, alignment);
            if (start < 0 || start > bytes.Length) throw new ArgumentOutOfRangeException(nameof(start));
            int boundedLength = length <= 0 ? bytes.Length - start : Math.Min(length, bytes.Length - start);
            int last = start + boundedLength - pattern.Length;
            List<long> results = new List<long>();
            if (reverse)
            {
                for (int index = last; index >= start && results.Count < maximum; index--)
                    if (index % alignment == 0 && Matches(bytes, pattern, index)) results.Add(index);
            }
            else
            {
                for (int index = start; index <= last && results.Count < maximum; index++)
                    if (index % alignment == 0 && Matches(bytes, pattern, index)) results.Add(index);
            }
            return results.ToArray();
        }

        private static void FindWindowForward(byte[] bytes, int byteCount, byte[] pattern, int[] shifts, long baseOffset, long minimum, long maximumOffset, List<long> results, int maximum, int alignment)
        {
            int last = byteCount - pattern.Length;
            int patternLast = pattern.Length - 1;
            int candidate = 0;
            while (candidate <= last)
            {
                int patternIndex = patternLast;
                while (patternIndex >= 0 && bytes[candidate + patternIndex] == pattern[patternIndex]) patternIndex--;
                if (patternIndex < 0)
                {
                    long offset = baseOffset + candidate;
                    if (offset >= minimum && offset + pattern.Length <= maximumOffset && offset % alignment == 0 &&
                        (results.Count == 0 || results[results.Count - 1] != offset))
                    {
                        results.Add(offset);
                        if (results.Count >= maximum) return;
                    }
                    candidate++;
                }
                else
                {
                    candidate += shifts[bytes[candidate + patternLast]];
                }
            }
        }

        private static void FindWindowReverse(byte[] bytes, int byteCount, byte[] pattern, long baseOffset, long maximumStartExclusive, List<long> results, int maximum, int alignment)
        {
            int last = Math.Min(byteCount - pattern.Length, checked((int)(maximumStartExclusive - baseOffset - 1)));
            for (int candidate = last; candidate >= 0 && results.Count < maximum; candidate--)
            {
                long offset = baseOffset + candidate;
                if (offset % alignment == 0 && Matches(bytes, pattern, candidate)) results.Add(offset);
            }
        }

        private static int[] CreateShiftTable(byte[] pattern)
        {
            int[] shifts = new int[256];
            for (int value = 0; value < shifts.Length; value++) shifts[value] = pattern.Length;
            int last = pattern.Length - 1;
            for (int index = 0; index < last; index++) shifts[pattern[index]] = last - index;
            return shifts;
        }

        private static void ReadExactly(Stream stream, long offset, byte[] buffer, int count)
        {
            stream.Position = offset;
            int total = 0;
            while (total < count)
            {
                int read = stream.Read(buffer, total, count - total);
                if (read <= 0) throw new EndOfStreamException($"Unexpected end of stream at offset {offset + total}.");
                total += read;
            }
        }

        private static bool Matches(byte[] bytes, byte[] pattern, int index)
        {
            for (int i = 0; i < pattern.Length; i++) if (bytes[index + i] != pattern[i]) return false;
            return true;
        }

        private static void Validate(byte[] pattern, int maximum, int alignment)
        {
            if (pattern == null || pattern.Length == 0) throw new ArgumentException("The pattern must not be empty.", nameof(pattern));
            if (maximum < 1) throw new ArgumentOutOfRangeException(nameof(maximum));
            if (alignment < 1) throw new ArgumentOutOfRangeException(nameof(alignment));
        }
    }
}
