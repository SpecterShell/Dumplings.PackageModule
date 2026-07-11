// SPDX-License-Identifier: MIT
// Copyright (c) 2006-2009 The Gentee Group.
// C# adaptation of the MIT-licensed Gentee 3.6.1 LZGE decoder.

using System;
using System.IO;

namespace Dumplings.Gentee
{
    public static class LzgeDecoder
    {
        private const int HuffmanBlockSize = 10000;
        private const int LiteralAlphabet = 256;
        private const int MatchLength = 2;
        private const int MinimumOffset = 2;
        private const int LengthSlotCount = 18;
        private const int PretreeAlphabet = 20;
        private const int PretreeMaximumCode = 15;

        private static readonly int[] OffsetBits = {
            0, 0, 0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7,
            7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14,
            15, 15, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
            17, 17, 17, 17
        };

        private static readonly int[] BaseLengthBits = {
            0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 21
        };

        public static byte[] Decode(byte[] input, int outputSize)
        {
            return Decode(input, outputSize, null);
        }

        public static byte[] Decode(byte[] input, int outputSize, byte[] solidPrefix)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (outputSize < 0) throw new ArgumentOutOfRangeException(nameof(outputSize));
            solidPrefix = solidPrefix ?? Array.Empty<byte>();
            if ((long)solidPrefix.Length + outputSize > int.MaxValue) throw new InvalidDataException("LZGE output exceeds Int32 limits.");

            int totalSize = solidPrefix.Length + outputSize;
            byte[] output = new byte[totalSize];
            Buffer.BlockCopy(solidPrefix, 0, output, 0, solidPrefix.Length);
            if (outputSize == 0) return output;

            int maxBit = Bits(totalSize);
            int maxOffset = (1 << Math.Min(21, maxBit)) - 1;
            int[] rangeMinimum = new int[OffsetBits.Length];
            int range = MinimumOffset;
            int numberOfOffsets = 3;
            while (numberOfOffsets < OffsetBits.Length)
            {
                rangeMinimum[numberOfOffsets] = range;
                range += 1 << OffsetBits[numberOfOffsets];
                if (range - 1 >= maxOffset) { numberOfOffsets++; break; }
                numberOfOffsets++;
            }

            int[] lengthBits = (int[])BaseLengthBits.Clone();
            lengthBits[lengthBits.Length - 1] = maxBit;
            int[] lengthMinimum = new int[lengthBits.Length];
            int lengthBase = MatchLength;
            for (int i = 0; i < lengthBits.Length; i++)
            {
                lengthMinimum[i] = lengthBase;
                lengthBase += 1 << lengthBits[i];
            }

            BitReader reader = new BitReader(input);
            HuffmanTree tree = new HuffmanTree(LiteralAlphabet + LengthSlotCount * numberOfOffsets + 1, reader, false);
            int[] recentOffsets = { 3, 4, 5 };
            int outputPosition = solidPrefix.Length;
            int outputEnd = totalSize;

            while (outputPosition < outputEnd)
            {
                tree.ReadTree();
                int blockItems = 0;
                while (blockItems < HuffmanBlockSize && outputPosition < outputEnd)
                {
                    int value = tree.ReadSymbol();
                    if (value < LiteralAlphabet)
                    {
                        output[outputPosition++] = (byte)value;
                    }
                    else
                    {
                        value -= LiteralAlphabet;
                        int footer;
                        int lengthFooter;
                        if (value == LengthSlotCount * numberOfOffsets)
                        {
                            footer = 0;
                            lengthFooter = LengthSlotCount;
                        }
                        else
                        {
                            lengthFooter = value % LengthSlotCount;
                            footer = value / LengthSlotCount;
                        }
                        if (lengthFooter < 0 || lengthFooter >= lengthBits.Length) throw new InvalidDataException("Invalid LZGE length slot.");
                        int length = reader.ReadBits(lengthBits[lengthFooter]) + lengthMinimum[lengthFooter];
                        int offset;
                        if (lengthFooter == LengthSlotCount)
                        {
                            offset = reader.ReadBits(maxBit);
                        }
                        else
                        {
                            if (footer < 0 || footer >= numberOfOffsets) throw new InvalidDataException("Invalid LZGE offset slot.");
                            offset = reader.ReadBits(OffsetBits[footer]) + rangeMinimum[footer];
                            if (footer == 0)
                            {
                                offset = recentOffsets[0];
                            }
                            else if (footer == 1)
                            {
                                offset = recentOffsets[1];
                                recentOffsets[1] = recentOffsets[0];
                                recentOffsets[0] = offset;
                            }
                            else
                            {
                                if (footer == 2) offset = recentOffsets[2];
                                recentOffsets[2] = recentOffsets[1];
                                recentOffsets[1] = recentOffsets[0];
                                recentOffsets[0] = offset;
                            }
                        }
                        if (offset <= 0 || offset > outputPosition || length < 0 || length > outputEnd - outputPosition)
                            throw new InvalidDataException("Invalid LZGE match range.");
                        for (int i = 0; i < length; i++) output[outputPosition + i] = output[outputPosition - offset + i];
                        outputPosition += length;
                    }
                    blockItems++;
                }
            }

            if (solidPrefix.Length == 0) return output;
            byte[] result = new byte[outputSize];
            Buffer.BlockCopy(output, solidPrefix.Length, result, 0, outputSize);
            return result;
        }

        private static int Bits(int value)
        {
            uint unsignedValue = unchecked((uint)value);
            for (int i = 1; i < 32; i++) if (unsignedValue < (1u << i)) return i;
            return 32;
        }

        private sealed class BitReader
        {
            private readonly byte[] data;
            private int byteOffset;
            private int bit = 7;

            internal BitReader(byte[] data) { this.data = data; }

            internal int ReadBits(int count)
            {
                if (count < 0 || count > 31) throw new InvalidDataException("Invalid LZGE bit count.");
                int result = 0;
                for (int i = 0; i < count; i++)
                {
                    if (byteOffset >= data.Length) throw new EndOfStreamException("The LZGE stream is truncated.");
                    result |= ((data[byteOffset] >> bit) & 1) << i;
                    if (bit == 0) { bit = 7; byteOffset++; } else { bit--; }
                }
                return result;
            }
        }

        private sealed class HuffmanTree
        {
            private const int PretreeZero2 = 16;
            private const int PretreeZero4 = 17;
            private const int PretreeZero6 = 18;
            private const int PretreeBig = 19;
            private const int PretreeOffset1 = 4;
            private const int PretreeOffset2 = 8;
            private const int PretreeOffset3 = 24;

            private readonly int symbolCount;
            private readonly BitReader reader;
            private readonly bool fixedTree;
            private readonly byte[] previousLength;
            private Node[] nodes;
            private int root;

            internal HuffmanTree(int symbolCount, BitReader reader, bool fixedTree)
            {
                this.symbolCount = symbolCount;
                this.reader = reader;
                this.fixedTree = fixedTree;
                previousLength = new byte[Math.Max(2048, symbolCount)];
                nodes = new Node[Math.Max(symbolCount * 2 + 4, 4096)];
            }

            internal void ReadTree()
            {
                int bits = reader.ReadBits(symbolCount < 32 ? 2 : 3) + 1;
                int minimum = reader.ReadBits(bits);
                reader.ReadBits(bits); // Maximum-minus-minimum is not needed for decoding.
                int[] frequencies = new int[symbolCount];
                if (fixedTree)
                {
                    for (int i = 0; i < symbolCount; i++) frequencies[i] = reader.ReadBits(bits);
                }
                else
                {
                    HuffmanTree pretree = new HuffmanTree(PretreeAlphabet, reader, true);
                    pretree.ReadTree();
                    int i = 0;
                    while (i < symbolCount)
                    {
                        int value = pretree.ReadSymbol();
                        frequencies[i] = value;
                        if (value > PretreeMaximumCode)
                        {
                            int count;
                            switch (value)
                            {
                                case PretreeZero2: count = reader.ReadBits(2) + PretreeOffset1; break;
                                case PretreeZero4: count = reader.ReadBits(4) + PretreeOffset2; break;
                                case PretreeZero6: count = reader.ReadBits(6) + PretreeOffset3; break;
                                case PretreeBig: count = reader.ReadBits(bits); break;
                                default: throw new InvalidDataException("Invalid LZGE pretree symbol.");
                            }
                            if (value == PretreeBig)
                            {
                                frequencies[i] = count;
                            }
                            else
                            {
                                if (count <= 0 || count > symbolCount - i) throw new InvalidDataException("Invalid LZGE zero run.");
                                for (int zero = 0; zero < count; zero++) frequencies[i + zero] = 0;
                                i += count;
                                continue;
                            }
                        }
                        i++;
                    }
                }

                for (int i = 0; i < symbolCount; i++)
                {
                    int oldLength = previousLength[i];
                    previousLength[i] = 0;
                    if (frequencies[i] <= PretreeMaximumCode)
                    {
                        frequencies[i] = (frequencies[i] + oldLength) % (PretreeMaximumCode + 1);
                        previousLength[i] = (byte)frequencies[i];
                    }
                    if (frequencies[i] != 0) frequencies[i] += minimum - 1;
                }
                BuildNormalizedTree(frequencies);
            }

            internal int ReadSymbol()
            {
                int current = root;
                while (nodes[current].Left >= 0)
                {
                    int bit = reader.ReadBits(1);
                    current = bit == 0 ? nodes[current].Left : nodes[current].Right;
                    if (current < 0 || current >= nodes.Length) throw new InvalidDataException("Invalid LZGE Huffman path.");
                }
                if (current >= symbolCount) throw new InvalidDataException("Invalid LZGE Huffman symbol.");
                return current;
            }

            private void BuildNormalizedTree(int[] frequencies)
            {
                Array.Clear(nodes, 0, nodes.Length);
                for (int i = 0; i < nodes.Length; i++) { nodes[i].Left = -1; nodes[i].Right = -1; }
                for (int i = 0; i < symbolCount; i++) nodes[i].Frequency = frequencies[i];
                int[] previous = new int[2048];
                for (int i = 0; i < previous.Length; i++) previous[i] = -1;
                int codes = symbolCount;
                int nodeIndex = -1;
                while (true)
                {
                    int count = 0;
                    for (int current = 0; current < codes; current++)
                    {
                        int frequency = nodes[current].Frequency;
                        if (frequency == 0) continue;
                        if (frequency >= previous.Length) throw new InvalidDataException("LZGE Huffman depth exceeds limits.");
                        count++;
                        if (previous[frequency] >= 0)
                        {
                            if (codes >= nodes.Length) throw new InvalidDataException("LZGE Huffman tree exceeds limits.");
                            nodeIndex = codes++;
                            nodes[nodeIndex].Frequency = frequency - 1;
                            nodes[nodeIndex].Left = previous[frequency];
                            nodes[nodeIndex].Right = current;
                            previous[frequency] = -1;
                            nodes[current].Frequency = 0;
                            if (nodes[nodeIndex].Frequency == 0) break;
                        }
                        else
                        {
                            previous[frequency] = current;
                            nodes[current].Frequency = 0;
                        }
                    }
                    if (count == 1)
                    {
                        if (codes >= nodes.Length || previous[1] < 0) throw new InvalidDataException("Invalid single-symbol LZGE Huffman tree.");
                        nodeIndex = codes;
                        nodes[nodeIndex].Frequency = 0;
                        nodes[nodeIndex].Left = previous[1];
                        nodes[nodeIndex].Right = -1;
                    }
                    if (nodeIndex < 0) throw new InvalidDataException("Empty LZGE Huffman tree.");
                    if (nodes[nodeIndex].Frequency == 0) break;
                }
                root = nodeIndex;
            }

            private struct Node
            {
                internal int Frequency;
                internal int Left;
                internal int Right;
            }
        }
    }
}
