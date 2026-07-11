// SPDX-License-Identifier: MIT
using System;

namespace Dumplings.InstallerInfrastructure
{
    /// <summary>Mechanical InstallShield nibble/XOR transform.</summary>
    public static class InstallShieldTransform
    {
        public static byte[] Decode(byte[] data, int blockSize, byte[] seed, byte[] magic, bool streamMode)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (blockSize <= 0) throw new ArgumentOutOfRangeException(nameof(blockSize));
            if (seed == null || seed.Length == 0) return data;
            if (magic == null || magic.Length == 0) throw new ArgumentException("A decode magic sequence is required.", nameof(magic));

            byte[] key = new byte[seed.Length];
            for (int index = 0; index < seed.Length; index++) key[index] = (byte)(seed[index] ^ magic[index % magic.Length]);
            for (int done = 0; done < data.Length; done += blockSize)
            {
                int length = Math.Min(blockSize, data.Length - done);
                int offset = streamMode ? done % 1024 : 0;
                for (int index = 0; index < length; index++)
                {
                    int value = data[done + index];
                    int swapped = ((value << 4) | (value >> 4)) & 0xff;
                    data[done + index] = (byte)(~(key[(index + offset) % key.Length] ^ swapped) & 0xff);
                }
            }
            return data;
        }

        public static byte[] DecodeRange(byte[] data, int start, int length, int offset, byte[] seed, byte[] magic)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (start < 0 || length < 0 || start > data.Length - length) throw new ArgumentOutOfRangeException(nameof(length));
            if (seed == null || seed.Length == 0) return data;
            if (magic == null || magic.Length == 0) throw new ArgumentException("A decode magic sequence is required.", nameof(magic));
            byte[] key = new byte[seed.Length];
            for (int index = 0; index < seed.Length; index++) key[index] = (byte)(seed[index] ^ magic[index % magic.Length]);
            for (int index = 0; index < length; index++)
            {
                int value = data[start + index];
                int swapped = ((value << 4) | (value >> 4)) & 0xff;
                data[start + index] = (byte)(~(key[(index + offset) % key.Length] ^ swapped) & 0xff);
            }
            return data;
        }
    }
}
