// SPDX-License-Identifier: Apache-2.0
// Independently implemented from the AP32/aPLib format documentation and the
// token dispatch observed in Paquet Builder 2.8's package runtime. This source
// does not copy or redistribute the restrictively licensed aPLib sources.
//
// AP32 body token grammar, after the first literal byte:
//
//   0                 literal byte
//   10 + gamma + ...  repeated or new long-distance match
//   110 + byte        7-bit short distance, 2- or 3-byte match; zero ends data
//   111 + 4 bits      one-byte match at distance 1..15, or a zero literal

// Tag bits are read most-significant bit first from bytes interleaved with the
// literal, distance, and length bytes. The AP32 wrapper supplies independent
// compressed/output sizes and CRC32 values; PowerShell validates those fields.

using System;
using System.IO;

namespace Dumplings.PaquetBuilder
{
    public sealed class ApLibDecodeResult
    {
        public ApLibDecodeResult(byte[] data, int bytesConsumed)
        {
            Data = data;
            BytesConsumed = bytesConsumed;
        }

        public byte[] Data { get; }

        public int BytesConsumed { get; }
    }

    public static class PaquetBuilderApLibDecoder
    {
        public static ApLibDecodeResult Decode(byte[] source, int offset, int count, int expectedLength)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            if (offset < 0 || count <= 0 || offset > source.Length - count)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), "The aPLib input range is invalid.");
            }

            if (expectedLength <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(expectedLength), "The aPLib output length must be positive.");
            }

            var input = new Input(source, offset, count);
            var output = new byte[expectedLength];
            int outputPosition = 0;
            int lastDistance = 0;
            bool lastWasMatch = false;

            // Every valid aPLib stream starts with one byte stored verbatim.
            output[outputPosition++] = input.ReadByte();

            while (true)
            {
                if (input.ReadBit() == 0)
                {
                    WriteLiteral(output, ref outputPosition, input.ReadByte());
                    lastWasMatch = false;
                    continue;
                }

                if (input.ReadBit() == 0)
                {
                    int encodedDistance = input.ReadGamma();
                    int distance;
                    int length;

                    if (!lastWasMatch && encodedDistance == 2)
                    {
                        if (lastDistance <= 0)
                        {
                            throw new InvalidDataException("The aPLib stream reuses a match distance before defining one.");
                        }

                        distance = lastDistance;
                        length = input.ReadGamma();
                    }
                    else
                    {
                        int bias = lastWasMatch ? 2 : 3;
                        if (encodedDistance < bias)
                        {
                            throw new InvalidDataException("The aPLib stream contains an invalid long-match distance code.");
                        }

                        long distanceHigh = (long)(encodedDistance - bias) << 8;
                        distanceHigh += input.ReadByte();
                        if (distanceHigh <= 0 || distanceHigh > int.MaxValue)
                        {
                            throw new InvalidDataException("The aPLib stream contains an out-of-range match distance.");
                        }

                        distance = (int)distanceHigh;
                        length = input.ReadGamma();
                        if (distance >= 32000)
                        {
                            length = CheckedIncrement(length);
                        }

                        if (distance >= 1280)
                        {
                            length = CheckedIncrement(length);
                        }

                        if (distance < 128)
                        {
                            length = CheckedIncrement(CheckedIncrement(length));
                        }

                        lastDistance = distance;
                    }

                    CopyMatch(output, ref outputPosition, distance, length);
                    lastWasMatch = true;
                    continue;
                }

                if (input.ReadBit() == 0)
                {
                    int shortCode = input.ReadByte();
                    int distance = shortCode >> 1;
                    if (distance == 0)
                    {
                        if (outputPosition != expectedLength)
                        {
                            throw new InvalidDataException("The aPLib end marker appears before the declared output length.");
                        }

                        return new ApLibDecodeResult(output, input.BytesConsumed);
                    }

                    int length = 2 + (shortCode & 1);
                    CopyMatch(output, ref outputPosition, distance, length);
                    lastDistance = distance;
                    lastWasMatch = true;
                    continue;
                }

                int tinyDistance = 0;
                for (int index = 0; index < 4; index++)
                {
                    tinyDistance = (tinyDistance << 1) | input.ReadBit();
                }

                if (tinyDistance == 0)
                {
                    WriteLiteral(output, ref outputPosition, 0);
                }
                else
                {
                    CopyMatch(output, ref outputPosition, tinyDistance, 1);
                }

                lastWasMatch = false;
            }
        }

        private static int CheckedIncrement(int value)
        {
            if (value == int.MaxValue)
            {
                throw new InvalidDataException("The aPLib match length overflows the supported integer range.");
            }

            return value + 1;
        }

        private static void WriteLiteral(byte[] output, ref int outputPosition, byte value)
        {
            if (outputPosition >= output.Length)
            {
                throw new InvalidDataException("The aPLib stream exceeds the declared output length.");
            }

            output[outputPosition++] = value;
        }

        private static void CopyMatch(byte[] output, ref int outputPosition, int distance, int length)
        {
            if (distance <= 0 || distance > outputPosition)
            {
                throw new InvalidDataException("The aPLib stream references data before the start of its output.");
            }

            if (length <= 0 || length > output.Length - outputPosition)
            {
                throw new InvalidDataException("The aPLib match exceeds the declared output length.");
            }

            // Byte-wise copying intentionally permits the overlapping matches used by LZ streams.
            for (int index = 0; index < length; index++)
            {
                output[outputPosition] = output[outputPosition - distance];
                outputPosition++;
            }
        }

        private sealed class Input
        {
            private readonly byte[] source;
            private readonly int start;
            private readonly int end;
            private int position;
            private int tag;
            private int availableBits;

            public Input(byte[] source, int offset, int count)
            {
                this.source = source;
                start = offset;
                end = offset + count;
                position = offset;
            }

            public int BytesConsumed => position - start;

            public byte ReadByte()
            {
                if (position >= end)
                {
                    throw new EndOfStreamException("The aPLib stream is truncated.");
                }

                return source[position++];
            }

            public int ReadBit()
            {
                if (availableBits == 0)
                {
                    tag = ReadByte();
                    availableBits = 8;
                }

                int bit = (tag >> 7) & 1;
                tag = (tag << 1) & 0xFF;
                availableBits--;
                return bit;
            }

            public int ReadGamma()
            {
                int value = 1;
                while (true)
                {
                    if (value > (int.MaxValue >> 1))
                    {
                        throw new InvalidDataException("The aPLib gamma value exceeds the supported integer range.");
                    }

                    value = (value << 1) | ReadBit();
                    if (ReadBit() == 0)
                    {
                        return value;
                    }
                }
            }
        }
    }
}
