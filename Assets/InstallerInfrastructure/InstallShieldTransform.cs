// SPDX-License-Identifier: MIT
using System;
using System.IO;

namespace Dumplings.InstallerInfrastructure
{
    /// <summary>Read-only streaming view that applies the InstallShield nibble/XOR transform.</summary>
    public sealed class InstallShieldDecodedStream : Stream
    {
        private readonly Stream source;
        private readonly long blockSize;
        private readonly byte[] key;
        private readonly bool streamMode;
        private readonly bool leaveOpen;
        private long position;

        public InstallShieldDecodedStream(Stream source, long blockSize, byte[] seed, byte[] magic, bool streamMode, bool leaveOpen)
        {
            this.source = source ?? throw new ArgumentNullException(nameof(source));
            if (!source.CanRead) throw new ArgumentException("The source stream must be readable.", nameof(source));
            if (blockSize <= 0) throw new ArgumentOutOfRangeException(nameof(blockSize));
            if (seed == null || seed.Length == 0) throw new ArgumentException("A decode seed is required.", nameof(seed));
            if (magic == null || magic.Length == 0) throw new ArgumentException("A decode magic sequence is required.", nameof(magic));

            this.blockSize = blockSize;
            this.streamMode = streamMode;
            this.leaveOpen = leaveOpen;
            position = source.CanSeek ? source.Position : 0;
            key = new byte[seed.Length];
            for (int index = 0; index < seed.Length; index++) key[index] = (byte)(seed[index] ^ magic[index % magic.Length]);
        }

        public override bool CanRead => true;
        public override bool CanSeek => source.CanSeek;
        public override bool CanWrite => false;
        public override long Length => source.Length;
        public override long Position
        {
            get => source.CanSeek ? source.Position : position;
            set
            {
                if (!source.CanSeek) throw new NotSupportedException();
                source.Position = value;
                position = value;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || count < 0 || offset > buffer.Length - count) throw new ArgumentOutOfRangeException(nameof(count));

            long start = Position;
            int read = source.Read(buffer, offset, count);
            int done = 0;
            while (done < read)
            {
                long absolute = start + done;
                long blockOffset = absolute % blockSize;
                long blockStart = absolute - blockOffset;
                long keyOffset = streamMode ? blockStart % 1024 : 0;
                int keyIndex = (int)((blockOffset + keyOffset) % key.Length);
                int blockLength = (int)Math.Min(read - done, blockSize - blockOffset);
                for (int index = 0; index < blockLength; index++)
                {
                    int value = buffer[offset + done + index];
                    int swapped = ((value << 4) | (value >> 4)) & 0xff;
                    buffer[offset + done + index] = (byte)(~(key[keyIndex] ^ swapped) & 0xff);
                    if (++keyIndex == key.Length) keyIndex = 0;
                }
                done += blockLength;
            }
            position = start + read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (!source.CanSeek) throw new NotSupportedException();
            position = source.Seek(offset, origin);
            return position;
        }

        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing && !leaveOpen) source.Dispose();
            base.Dispose(disposing);
        }
    }
}
