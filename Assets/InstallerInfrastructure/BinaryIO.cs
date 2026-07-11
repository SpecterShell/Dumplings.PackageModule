// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;

namespace Dumplings.InstallerInfrastructure
{
    public sealed class BoundedReadStream : Stream
    {
        private readonly Stream source;
        private readonly long start;
        private readonly long length;
        private readonly bool leaveOpen;
        private long position;

        public BoundedReadStream(Stream source, long offset, long length, bool leaveOpen)
        {
            this.source = source ?? throw new ArgumentNullException(nameof(source));
            if (!source.CanRead || !source.CanSeek) throw new ArgumentException("The source stream must be readable and seekable.", nameof(source));
            if (offset < 0 || length < 0 || offset > source.Length || length > source.Length - offset) throw new ArgumentOutOfRangeException(nameof(length));
            start = offset;
            this.length = length;
            this.leaveOpen = leaveOpen;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => position; set => Seek(value, SeekOrigin.Begin); }
        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || count < 0 || offset + count > buffer.Length) throw new ArgumentOutOfRangeException(nameof(count));
            if (position >= length || count == 0) return 0;
            int requested = (int)Math.Min(count, length - position);
            source.Position = start + position;
            int read = source.Read(buffer, offset, requested);
            position += read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            long candidate = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => position + offset,
                SeekOrigin.End => length + offset,
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
            if (candidate < 0 || candidate > length) throw new IOException("The seek target is outside the bounded stream.");
            position = candidate;
            return position;
        }

        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing && !leaveOpen) source.Dispose();
            base.Dispose(disposing);
        }
    }

    public sealed class SeekableStreamContext : IDisposable
    {
        private readonly bool ownsStream;
        private bool disposed;
        public Stream Stream { get; }
        public long Length => Stream.Length;
        public string TemporaryPath { get; }

        private SeekableStreamContext(Stream stream, bool ownsStream, string temporaryPath)
        {
            Stream = stream;
            this.ownsStream = ownsStream;
            TemporaryPath = temporaryPath;
        }

        public static SeekableStreamContext Create(Stream source, long maximumBytes, long memoryThresholdBytes)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (!source.CanRead) throw new ArgumentException("The source stream must be readable.", nameof(source));
            if (maximumBytes < 1) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
            if (memoryThresholdBytes < 0) throw new ArgumentOutOfRangeException(nameof(memoryThresholdBytes));
            memoryThresholdBytes = Math.Min(memoryThresholdBytes, maximumBytes);
            if (source.CanSeek)
            {
                long remaining = source.Length - source.Position;
                if (remaining > maximumBytes) throw new InvalidDataException($"The stream exceeds the {maximumBytes}-byte spool limit.");
                return new SeekableStreamContext(new BoundedReadStream(source, source.Position, remaining, true), true, null);
            }

            MemoryStream memory = new MemoryStream();
            FileStream file = null;
            string path = null;
            byte[] buffer = new byte[1024 * 1024];
            long total = 0;
            try
            {
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    total += read;
                    if (total > maximumBytes) throw new InvalidDataException($"The stream exceeds the {maximumBytes}-byte spool limit.");
                    if (file == null && total > memoryThresholdBytes)
                    {
                        path = Path.Combine(Path.GetTempPath(), $"Dumplings-Seekable-{Guid.NewGuid():N}.tmp");
                        file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
                        memory.Position = 0;
                        memory.CopyTo(file);
                        memory.Dispose();
                        memory = null;
                    }
                    (file ?? (Stream)memory).Write(buffer, 0, read);
                }
                Stream result = file ?? (Stream)memory;
                result.Position = 0;
                return new SeekableStreamContext(result, true, path);
            }
            catch
            {
                file?.Dispose();
                memory?.Dispose();
                if (path != null) try { File.Delete(path); } catch { }
                throw;
            }
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            if (ownsStream) Stream.Dispose();
            if (TemporaryPath != null) try { File.Delete(TemporaryPath); } catch { }
        }
    }

    public static class BinaryIO
    {
        private static readonly uint[] CrcTable = CreateCrcTable();

        public static byte[] ReadExactly(Stream stream, long offset, int count, bool restorePosition)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("The stream must be readable and seekable.", nameof(stream));
            if (offset < 0 || count < 0 || offset > stream.Length || count > stream.Length - offset) throw new EndOfStreamException("The requested binary range is outside the stream.");
            long original = stream.Position;
            byte[] result = new byte[count];
            try
            {
                stream.Position = offset;
                int total = 0;
                while (total < count)
                {
                    int read = stream.Read(result, total, count - total);
                    if (read <= 0) throw new EndOfStreamException($"Unexpected end of stream at offset {offset + total}.");
                    total += read;
                }
                return result;
            }
            finally
            {
                if (restorePosition) stream.Position = original;
            }
        }

        public static long CopyBounded(Stream source, Stream destination, long maximumBytes, long expectedBytes)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (destination == null) throw new ArgumentNullException(nameof(destination));
            if (!source.CanRead || !destination.CanWrite) throw new ArgumentException("Source must be readable and destination must be writable.");
            if (maximumBytes < 0 || expectedBytes < -1 || expectedBytes > maximumBytes) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
            byte[] buffer = new byte[1024 * 1024];
            long total = 0;
            while (expectedBytes < 0 || total < expectedBytes)
            {
                int request = (int)Math.Min(buffer.Length, expectedBytes < 0 ? maximumBytes - total + 1 : expectedBytes - total);
                if (request <= 0)
                {
                    if (expectedBytes < 0 && source.ReadByte() >= 0) throw new InvalidDataException($"The stream exceeds the {maximumBytes}-byte limit.");
                    break;
                }
                int read = source.Read(buffer, 0, request);
                if (read <= 0)
                {
                    if (expectedBytes >= 0) throw new EndOfStreamException($"The stream ended after {total} bytes; expected {expectedBytes}.");
                    break;
                }
                total += read;
                if (total > maximumBytes) throw new InvalidDataException($"The stream exceeds the {maximumBytes}-byte limit.");
                destination.Write(buffer, 0, read);
            }
            return total;
        }

        public static bool SequenceEqual(byte[] left, byte[] right)
        {
            if (ReferenceEquals(left, right)) return true;
            if (left == null || right == null || left.Length != right.Length) return false;
            for (int i = 0; i < left.Length; i++) if (left[i] != right[i]) return false;
            return true;
        }

        public static uint Crc32(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            uint crc = uint.MaxValue;
            foreach (byte value in bytes) crc = CrcTable[(crc ^ value) & 0xFF] ^ (crc >> 8);
            return crc ^ uint.MaxValue;
        }

        public static uint Crc32(Stream stream, bool restorePosition, long maximumBytes)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead) throw new ArgumentException("The stream must be readable.", nameof(stream));
            long original = stream.CanSeek ? stream.Position : 0;
            uint crc = uint.MaxValue;
            long total = 0;
            byte[] buffer = new byte[1024 * 1024];
            try
            {
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    total += read;
                    if (total > maximumBytes) throw new InvalidDataException($"The stream exceeds the {maximumBytes}-byte CRC limit.");
                    for (int i = 0; i < read; i++) crc = CrcTable[(crc ^ buffer[i]) & 0xFF] ^ (crc >> 8);
                }
                return crc ^ uint.MaxValue;
            }
            finally
            {
                if (restorePosition && stream.CanSeek) stream.Position = original;
            }
        }

        private static uint[] CreateCrcTable()
        {
            uint[] table = new uint[256];
            for (uint i = 0; i < table.Length; i++)
            {
                uint crc = i;
                for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? 0xEDB88320U ^ (crc >> 1) : crc >> 1;
                table[i] = crc;
            }
            return table;
        }
    }
}
