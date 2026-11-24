// SPDX-License-Identifier: Apache-2.0
// Independently implemented from bounded observations of the Paquet Builder 2.6
// runtime. The stream uses a 4096-byte LZSS window and a 314-symbol adaptive
// Huffman tree with the canonical position codes described below.

using System;
using System.IO;

namespace Dumplings.PaquetBuilder
{
    public sealed class ClassicDecodeResult
    {
        public ClassicDecodeResult(byte[] data, long bytesConsumed, int paddingBytes)
        {
            Data = data;
            BytesConsumed = bytesConsumed;
            PaddingBytes = paddingBytes;
        }

        public byte[] Data { get; }
        public long BytesConsumed { get; }

        public int PaddingBytes { get; }
    }

    public static class PaquetBuilderClassicDecoder
    {
        private const int WindowSize = 4096;
        private const int LookAheadSize = 60;
        private const int Threshold = 2;
        private const int CharacterCount = 256 - Threshold + LookAheadSize;
        private const int TreeSize = CharacterCount * 2 - 1;
        private const int Root = TreeSize - 1;
        private const ushort MaximumFrequency = 0x8000;

        // The position alphabet is a canonical Huffman code. Keeping only its
        // lengths avoids embedding decoder tables copied from a runtime image.
        private static readonly byte[] PositionCodeLengths = CreatePositionCodeLengths();
        private static readonly byte[] PositionCodes = CreatePositionCodes(PositionCodeLengths);
        private static readonly byte[] PositionDecodeSymbols = new byte[256];
        private static readonly byte[] PositionDecodeLengths = new byte[256];

        static PaquetBuilderClassicDecoder()
        {
            for (int prefix = 0; prefix < 256; prefix++)
            {
                bool matched = false;
                for (int symbol = 0; symbol < PositionCodeLengths.Length; symbol++)
                {
                    int length = PositionCodeLengths[symbol];
                    int mask = 0xFF << (8 - length);
                    if ((prefix & mask) != PositionCodes[symbol])
                    {
                        continue;
                    }

                    PositionDecodeSymbols[prefix] = (byte)symbol;
                    PositionDecodeLengths[prefix] = (byte)length;
                    matched = true;
                    break;
                }

                if (!matched)
                {
                    throw new InvalidOperationException("The Paquet Builder position-code table is incomplete.");
                }
            }
        }

        public static ClassicDecodeResult Decode(
            Stream source,
            long offset,
            long maximumCompressedBytes,
            int expectedLength)
        {
            return Decode(source, offset, maximumCompressedBytes, expectedLength, 0);
        }

        public static ClassicDecodeResult Decode(
            Stream source,
            long offset,
            long maximumCompressedBytes,
            int expectedLength,
            int maximumZeroPaddingBytes)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            if (!source.CanRead || !source.CanSeek)
            {
                throw new ArgumentException("The Paquet Builder source stream must be readable and seekable.", nameof(source));
            }

            if (offset < 0 || maximumCompressedBytes <= 0 || expectedLength < 0 || maximumZeroPaddingBytes < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), "Paquet Builder decode bounds must be non-negative and non-empty.");
            }

            if (offset > source.Length || maximumCompressedBytes > source.Length - offset)
            {
                throw new InvalidDataException("The Paquet Builder compressed range is outside the source stream.");
            }

            long originalPosition = source.Position;
            try
            {
                source.Position = offset;
                var input = new BitInput(source, maximumCompressedBytes, maximumZeroPaddingBytes);
                var output = new byte[expectedLength];
                var ring = new byte[WindowSize];
                Array.Fill(ring, (byte)0x20, 0, WindowSize - LookAheadSize);

                var frequency = new ushort[TreeSize + 1];
                var parent = new short[TreeSize + CharacterCount];
                var child = new short[TreeSize];
                StartHuffman(frequency, parent, child);

                int ringPosition = WindowSize - LookAheadSize;
                int outputPosition = 0;
                while (outputPosition < expectedLength)
                {
                    int symbol = DecodeCharacter(input, frequency, parent, child);
                    if (symbol < 256)
                    {
                        byte value = (byte)symbol;
                        output[outputPosition++] = value;
                        ring[ringPosition] = value;
                        ringPosition = (ringPosition + 1) & (WindowSize - 1);
                        continue;
                    }

                    int sourcePosition = (ringPosition - DecodePosition(input) - 1) & (WindowSize - 1);
                    int copyLength = symbol - 255 + Threshold;
                    if (copyLength > expectedLength - outputPosition)
                    {
                        throw new InvalidDataException("A Paquet Builder back-reference exceeds the declared output size.");
                    }

                    for (int index = 0; index < copyLength; index++)
                    {
                        byte value = ring[(sourcePosition + index) & (WindowSize - 1)];
                        output[outputPosition++] = value;
                        ring[ringPosition] = value;
                        ringPosition = (ringPosition + 1) & (WindowSize - 1);
                    }
                }

                return new ClassicDecodeResult(output, input.BytesConsumed, input.PaddingBytes);
            }
            finally
            {
                source.Position = originalPosition;
            }
        }

        private static void StartHuffman(ushort[] frequency, short[] parent, short[] child)
        {
            int node;
            for (node = 0; node < CharacterCount; node++)
            {
                frequency[node] = 1;
                child[node] = (short)(node + TreeSize);
                parent[node + TreeSize] = (short)node;
            }

            int pair = 0;
            for (; node <= Root; node++)
            {
                frequency[node] = (ushort)(frequency[pair] + frequency[pair + 1]);
                child[node] = (short)pair;
                parent[pair] = parent[pair + 1] = (short)node;
                pair += 2;
            }

            frequency[TreeSize] = ushort.MaxValue;
            parent[Root] = 0;
        }

        private static void ReconstructHuffman(ushort[] frequency, short[] parent, short[] child)
        {
            int leaf = 0;
            for (int node = 0; node < TreeSize; node++)
            {
                if (child[node] >= TreeSize)
                {
                    frequency[leaf] = (ushort)((frequency[node] + 1) >> 1);
                    child[leaf++] = child[node];
                }
            }

            int pair = 0;
            for (int node = CharacterCount; node < TreeSize; node++)
            {
                ushort combined = (ushort)(frequency[pair] + frequency[pair + 1]);
                int insertion = node - 1;
                while (combined < frequency[insertion])
                {
                    insertion--;
                }

                insertion++;
                if (insertion < node)
                {
                    Array.Copy(frequency, insertion, frequency, insertion + 1, node - insertion);
                    Array.Copy(child, insertion, child, insertion + 1, node - insertion);
                }

                frequency[insertion] = combined;
                child[insertion] = (short)pair;
                pair += 2;
            }

            for (int node = 0; node < TreeSize; node++)
            {
                int value = child[node];
                if (value >= TreeSize)
                {
                    parent[value] = (short)node;
                }
                else
                {
                    parent[value] = parent[value + 1] = (short)node;
                }
            }
        }

        private static void UpdateHuffman(int symbol, ushort[] frequency, short[] parent, short[] child)
        {
            if (frequency[Root] == MaximumFrequency)
            {
                ReconstructHuffman(frequency, parent, child);
            }

            int node = parent[symbol + TreeSize];
            do
            {
                ushort updated = ++frequency[node];
                if (updated > frequency[node + 1])
                {
                    int target = node + 1;
                    while (updated > frequency[++target])
                    {
                    }

                    target--;
                    frequency[node] = frequency[target];
                    frequency[target] = updated;

                    int firstChild = child[node];
                    parent[firstChild] = (short)target;
                    if (firstChild < TreeSize)
                    {
                        parent[firstChild + 1] = (short)target;
                    }

                    int secondChild = child[target];
                    child[target] = (short)firstChild;
                    parent[secondChild] = (short)node;
                    if (secondChild < TreeSize)
                    {
                        parent[secondChild + 1] = (short)node;
                    }

                    child[node] = (short)secondChild;
                    node = target;
                }

                node = parent[node];
            }
            while (node != 0);
        }

        private static int DecodeCharacter(BitInput input, ushort[] frequency, short[] parent, short[] child)
        {
            int node = child[Root];
            while (node < TreeSize)
            {
                node += input.ReadBit();
                node = child[node];
            }

            int symbol = node - TreeSize;
            UpdateHuffman(symbol, frequency, parent, child);
            return symbol;
        }

        private static int DecodePosition(BitInput input)
        {
            int value = input.ReadByte();
            int position = PositionDecodeSymbols[value] << 6;
            int remainingBits = PositionDecodeLengths[value] - 2;
            while (remainingBits-- > 0)
            {
                value = (value << 1) | input.ReadBit();
            }

            return position | (value & 0x3F);
        }

        private static byte[] CreatePositionCodeLengths()
        {
            var lengths = new byte[64];
            for (int index = 0; index < lengths.Length; index++)
            {
                lengths[index] = index == 0 ? (byte)3
                    : index <= 3 ? (byte)4
                    : index <= 11 ? (byte)5
                    : index <= 23 ? (byte)6
                    : index <= 47 ? (byte)7
                    : (byte)8;
            }

            return lengths;
        }

        private static byte[] CreatePositionCodes(byte[] lengths)
        {
            var codes = new byte[lengths.Length];
            int code = 0;
            int previousLength = lengths[0];
            for (int symbol = 0; symbol < lengths.Length; symbol++)
            {
                int length = lengths[symbol];
                if (symbol != 0)
                {
                    code = (code + 1) << (length - previousLength);
                }

                codes[symbol] = (byte)(code << (8 - length));
                previousLength = length;
            }

            return codes;
        }

        private sealed class BitInput
        {
            private readonly Stream source;
            private readonly long maximumBytes;
            private readonly int maximumZeroPaddingBytes;
            private ushort buffer;
            private int availableBits;

            public BitInput(Stream source, long maximumBytes, int maximumZeroPaddingBytes)
            {
                this.source = source;
                this.maximumBytes = maximumBytes;
                this.maximumZeroPaddingBytes = maximumZeroPaddingBytes;
            }

            public long BytesConsumed { get; private set; }

            public int PaddingBytes { get; private set; }

            public int ReadBit()
            {
                Fill();
                ushort snapshot = buffer;
                buffer <<= 1;
                availableBits--;
                return snapshot >> 15;
            }

            public int ReadByte()
            {
                Fill();
                ushort snapshot = buffer;
                buffer <<= 8;
                availableBits -= 8;
                return snapshot >> 8;
            }

            private void Fill()
            {
                while (availableBits <= 8)
                {
                    int value;
                    if (BytesConsumed >= maximumBytes)
                    {
                        if (PaddingBytes >= maximumZeroPaddingBytes)
                        {
                            throw new EndOfStreamException("The Paquet Builder GPacker stream ended before the declared output was decoded.");
                        }

                        // The 2.7 memory-stream callback returns a zero byte at EOF. Keep
                        // that historical behavior explicit and tightly bounded instead
                        // of allowing an unterminated malformed stream to decode forever.
                        PaddingBytes++;
                        value = 0;
                    }
                    else
                    {
                        value = source.ReadByte();
                        if (value < 0)
                        {
                            throw new EndOfStreamException("The Paquet Builder GPacker stream is truncated.");
                        }

                        BytesConsumed++;
                    }

                    buffer |= (ushort)(value << (8 - availableBits));
                    availableBits += 8;
                }
            }
        }
    }
}
