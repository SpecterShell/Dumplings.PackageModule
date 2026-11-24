// SPDX-License-Identifier: Apache-2.0
//
// This schema-specific reader was independently implemented from the Metakit
// file-format documentation and X/MIT-licensed reference sources:
// https://www.equi4.com/metakit/format.html
// https://github.com/jcw/metakit
//
// It intentionally supports only the TclKit VFS schema used by legacy
// InstallBuilder media. It does not load Metakit, Tcl, or installer code.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace Dumplings.InstallBuilder
{
    public sealed class InstallBuilderMetakitEntry
    {
        internal InstallBuilderMetakitEntry(int index, string path, long logicalSize, long storedSize, long offset, string compression, long modifiedUnixSeconds)
        {
            Index = index;
            Path = path;
            Size = logicalSize;
            StoredSize = storedSize;
            Offset = offset;
            Compression = compression;
            ModifiedUnixSeconds = modifiedUnixSeconds;
        }

        public int Index { get; }
        public string Path { get; }
        public long Size { get; }
        public long StoredSize { get; }
        public long Offset { get; }
        public string Compression { get; }
        public long ModifiedUnixSeconds { get; }
    }

    public sealed class InstallBuilderMetakitArchive : IDisposable
    {
        private const string VfsSchema = "dirs[name:S,parent:I,files[name:S,size:I,date:I,contents:B]]";
        private const int MaximumVfsPathCharacters = 32768;
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private readonly FileStream stream;
        private readonly List<InstallBuilderMetakitEntry> entries;
        private bool disposed;

        private InstallBuilderMetakitArchive(FileStream stream, long headerOffset, long length, long rootPosition, int rootLength, List<InstallBuilderMetakitEntry> entries)
        {
            this.stream = stream;
            this.entries = entries;
            HeaderOffset = headerOffset;
            Length = length;
            RootPosition = rootPosition;
            RootLength = rootLength;
        }

        public long HeaderOffset { get; }
        public long Length { get; }
        public long RootPosition { get; }
        public int RootLength { get; }
        public IReadOnlyList<InstallBuilderMetakitEntry> Entries => entries;

        public static InstallBuilderMetakitArchive Open(string path, long headerOffset, int maximumEntries, int maximumMetadataBytes)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("A Metakit source path is required.", nameof(path));
            }

            if (maximumEntries <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maximumEntries));
            }

            if (maximumMetadataBytes < 1024)
            {
                throw new ArgumentOutOfRangeException(nameof(maximumMetadataBytes));
            }

            FileStream source = new FileStream(Path.GetFullPath(path), FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536, FileOptions.RandomAccess);
            try
            {
                Layout layout = ReadLayout(source, headerOffset);
                List<InstallBuilderMetakitEntry> catalog = ReadCatalog(source, layout, maximumEntries, maximumMetadataBytes);
                return new InstallBuilderMetakitArchive(source, layout.HeaderOffset, layout.Length, layout.RootPosition, layout.RootLength, catalog);
            }
            catch
            {
                source.Dispose();
                throw;
            }
        }

        public byte[] ReadEntry(int index, long maximumExpandedBytes)
        {
            ThrowIfDisposed();
            InstallBuilderMetakitEntry entry = GetEntry(index);
            if (entry.Size > maximumExpandedBytes || entry.Size > int.MaxValue)
            {
                throw new InvalidDataException("The Metakit VFS entry exceeds the configured in-memory output limit.");
            }

            using (MemoryStream output = new MemoryStream((int)entry.Size))
            {
                CopyEntry(entry, output, maximumExpandedBytes);
                return output.ToArray();
            }
        }

        public long CopyEntry(int index, Stream destination, long maximumExpandedBytes)
        {
            ThrowIfDisposed();
            if (destination == null || !destination.CanWrite)
            {
                throw new ArgumentException("A writable destination stream is required.", nameof(destination));
            }

            return CopyEntry(GetEntry(index), destination, maximumExpandedBytes);
        }

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            stream.Dispose();
        }

        private InstallBuilderMetakitEntry GetEntry(int index)
        {
            if (index < 0 || index >= entries.Count)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            return entries[index];
        }

        private long CopyEntry(InstallBuilderMetakitEntry entry, Stream destination, long maximumExpandedBytes)
        {
            if (maximumExpandedBytes < 0 || entry.Size > maximumExpandedBytes)
            {
                throw new InvalidDataException("The Metakit VFS entry exceeds the configured output limit.");
            }

            stream.Position = entry.Offset;
            using (RangeStream range = new RangeStream(stream, entry.StoredSize, true))
            {
                if (entry.Compression == "None")
                {
                    CopyBounded(range, destination, entry.Size, maximumExpandedBytes);
                }
                else if (entry.Compression == "Zlib")
                {
                    using (ZLibStream decoder = new ZLibStream(range, CompressionMode.Decompress, true))
                    {
                        CopyBounded(decoder, destination, entry.Size, maximumExpandedBytes);
                    }
                }
                else
                {
                    throw new NotSupportedException($"The Metakit VFS entry '{entry.Path}' uses an unsupported compression framing.");
                }
            }

            return entry.Size;
        }

        private static void CopyBounded(Stream source, Stream destination, long expectedBytes, long maximumBytes)
        {
            byte[] buffer = new byte[81920];
            long written = 0;
            while (true)
            {
                int read = source.Read(buffer, 0, buffer.Length);
                if (read == 0)
                {
                    break;
                }

                if (written > maximumBytes - read || written > expectedBytes - read)
                {
                    throw new InvalidDataException("The expanded Metakit VFS entry exceeds its declared or configured size.");
                }

                destination.Write(buffer, 0, read);
                written += read;
            }

            if (written != expectedBytes)
            {
                throw new InvalidDataException($"The expanded Metakit VFS entry length is {written}, but the catalog declares {expectedBytes} bytes.");
            }
        }

        private static Layout ReadLayout(FileStream source, long headerOffset)
        {
            byte[] header = ReadAt(source, headerOffset, 8, source.Length);
            bool littleEndian;
            if (header[0] == 0x4A && header[1] == 0x4C && header[2] == 0x1A && header[3] == 0)
            {
                littleEndian = true;
            }
            else if (header[0] == 0x4C && header[1] == 0x4A && header[2] == 0x1A && header[3] == 0)
            {
                littleEndian = false;
            }
            else
            {
                throw new InvalidDataException("The selected range does not begin with a current Metakit header.");
            }

            long length = ReadUInt32BigEndian(header, 4);
            if (length < 24 || headerOffset > source.Length - length)
            {
                throw new InvalidDataException("The Metakit logical end is outside the installer.");
            }

            byte[] footer = ReadAt(source, headerOffset + length - 16, 16, source.Length);
            bool skipTail = ((footer[0] & 0xF0) == 0x90 || (footer[0] == 0x80 && ReadUInt24BigEndian(footer, 1) == 0)) && ReadUInt32BigEndian(footer, 4) > 0;
            int rootLength = checked((int)ReadUInt24BigEndian(footer, 9));
            long rootPosition = ReadUInt32BigEndian(footer, 12);
            if (!skipTail || footer[8] != 0x80 || rootLength <= 0 || rootPosition <= 0 || rootPosition > length - rootLength)
            {
                throw new InvalidDataException("The Metakit commit footer is malformed.");
            }

            return new Layout(headerOffset, length, rootPosition, rootLength, littleEndian);
        }

        private static List<InstallBuilderMetakitEntry> ReadCatalog(FileStream source, Layout layout, int maximumEntries, int maximumMetadataBytes)
        {
            ReadBudget metadataBudget = new ReadBudget(maximumMetadataBytes);
            byte[] rootBytes = ReadRelative(source, layout, layout.RootPosition, layout.RootLength, metadataBudget);
            Cursor root = new Cursor(rootBytes);
            RequireZero(root.ReadValue(), "root format code");
            int schemaLength = RequireCount(root.ReadValue(), maximumMetadataBytes, "Metakit schema length");
            string schema = StrictUtf8.GetString(root.ReadBytes(schemaLength));
            if (!string.Equals(schema, VfsSchema, StringComparison.Ordinal))
            {
                throw new NotSupportedException($"Unsupported Metakit VFS schema: {schema}");
            }

            if (root.ReadValue() != 1)
            {
                throw new InvalidDataException("The Metakit VFS root must contain exactly one row.");
            }

            Location directorySequenceLocation = ReadLocation(root, layout);
            root.RequireEnd("Metakit root descriptor");

            Cursor directorySequence = new Cursor(ReadRelative(source, layout, directorySequenceLocation.Position, directorySequenceLocation.Size, metadataBudget));
            RequireZero(directorySequence.ReadValue(), "directory sequence format code");
            int directoryCount = RequireCount(directorySequence.ReadValue(), maximumEntries, "directory count");
            ByteColumn directoryNames = ReadByteColumn(directorySequence, layout);
            Location directoryParents = ReadLocation(directorySequence, layout);
            Location fileSequenceLocation = ReadLocation(directorySequence, layout);
            directorySequence.RequireEnd("directory sequence descriptor");

            string[] directoryNameValues = ReadStringColumn(source, layout, directoryNames, directoryCount, metadataBudget);
            long[] parentValues = ReadIntegerColumn(source, layout, directoryParents, directoryCount, metadataBudget);
            string[] directoryPaths = ResolveDirectoryPaths(directoryNameValues, parentValues);

            Cursor fileSequences = new Cursor(ReadRelative(source, layout, fileSequenceLocation.Position, fileSequenceLocation.Size, metadataBudget));
            List<InstallBuilderMetakitEntry> catalog = new List<InstallBuilderMetakitEntry>();
            HashSet<string> catalogPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int directoryIndex = 0; directoryIndex < directoryCount; directoryIndex++)
            {
                RequireZero(fileSequences.ReadValue(), "file sequence format code");
                int fileCount = RequireCount(fileSequences.ReadValue(), maximumEntries - catalog.Count, "file count");
                if (fileCount == 0)
                {
                    continue;
                }

                ByteColumn fileNames = ReadByteColumn(fileSequences, layout);
                Location fileSizes = ReadLocation(fileSequences, layout);
                Location fileDates = ReadLocation(fileSequences, layout);
                ByteColumn fileContents = ReadByteColumn(fileSequences, layout);

                string[] names = ReadStringColumn(source, layout, fileNames, fileCount, metadataBudget);
                long[] sizes = ReadIntegerColumn(source, layout, fileSizes, fileCount, metadataBudget);
                long[] dates = ReadIntegerColumn(source, layout, fileDates, fileCount, metadataBudget);
                DataRange[] contents = ReadByteColumnRanges(source, layout, fileContents, fileCount, metadataBudget);
                for (int fileIndex = 0; fileIndex < fileCount; fileIndex++)
                {
                    if (sizes[fileIndex] < 0)
                    {
                        throw new InvalidDataException("A Metakit VFS file has a negative logical size.");
                    }

                    string path = CombineVfsPath(directoryPaths[directoryIndex], names[fileIndex]);
                    if (!catalogPaths.Add(path))
                    {
                        throw new InvalidDataException($"The Metakit VFS contains a duplicate file path: {path}");
                    }

                    string compression = ClassifyCompression(source, contents[fileIndex], sizes[fileIndex]);
                    catalog.Add(new InstallBuilderMetakitEntry(catalog.Count, path, sizes[fileIndex], contents[fileIndex].Length, contents[fileIndex].Offset, compression, dates[fileIndex]));
                }
            }

            fileSequences.RequireEnd("file subview descriptor column");
            return catalog;
        }

        private static ByteColumn ReadByteColumn(Cursor cursor, Layout layout)
        {
            Location data = ReadLocation(cursor, layout);
            Location sizes = data.Size > 0 ? ReadLocation(cursor, layout) : Location.Empty;
            Location memos = ReadLocation(cursor, layout);
            return new ByteColumn(data, sizes, memos);
        }

        private static DataRange[] ReadByteColumnRanges(FileStream source, Layout layout, ByteColumn column, int rowCount, ReadBudget metadataBudget)
        {
            long[] sizes = column.Data.Size > 0 ? ReadIntegerColumn(source, layout, column.Sizes, rowCount, metadataBudget) : new long[rowCount];
            DataRange[] ranges = new DataRange[rowCount];
            long inlineOffset = 0;
            for (int row = 0; row < rowCount; row++)
            {
                if (sizes[row] < 0 || inlineOffset > column.Data.Size - sizes[row])
                {
                    throw new InvalidDataException("The Metakit byte-column size vector exceeds its data column.");
                }

                ranges[row] = new DataRange(layout.HeaderOffset + column.Data.Position + inlineOffset, sizes[row]);
                inlineOffset += sizes[row];
            }

            if (inlineOffset != column.Data.Size)
            {
                throw new InvalidDataException("The Metakit byte-column sizes do not cover the data column exactly.");
            }

            if (column.Memos.Size > 0)
            {
                Cursor memos = new Cursor(ReadRelative(source, layout, column.Memos.Position, column.Memos.Size, metadataBudget));
                int row = 0;
                while (!memos.End)
                {
                    long delta = memos.ReadValue();
                    if (delta < 0 || row > int.MaxValue - delta)
                    {
                        throw new InvalidDataException("The Metakit memo row delta is invalid.");
                    }

                    row += (int)delta;
                    if (row < 0 || row >= rowCount)
                    {
                        throw new InvalidDataException("The Metakit memo row points outside the byte column.");
                    }

                    Location memo = ReadLocation(memos, layout);
                    ranges[row] = new DataRange(layout.HeaderOffset + memo.Position, memo.Size);
                    row++;
                }
            }

            return ranges;
        }

        private static string[] ReadStringColumn(FileStream source, Layout layout, ByteColumn column, int rowCount, ReadBudget metadataBudget)
        {
            DataRange[] ranges = ReadByteColumnRanges(source, layout, column, rowCount, metadataBudget);
            string[] values = new string[rowCount];
            for (int row = 0; row < rowCount; row++)
            {
                if (ranges[row].Length > 32768)
                {
                    throw new InvalidDataException("A Metakit VFS path component exceeds the configured limit.");
                }

                int byteCount = checked((int)ranges[row].Length);
                metadataBudget.Consume(byteCount);
                byte[] bytes = ReadAt(source, ranges[row].Offset, byteCount, source.Length);
                int length = bytes.Length;
                if (length > 0 && bytes[length - 1] == 0)
                {
                    length--;
                }

                string value = StrictUtf8.GetString(bytes, 0, length);
                if (value.Length == 0 || value == "." || value == ".." || value.IndexOf('\0') >= 0 || value.IndexOf('/') >= 0 || value.IndexOf('\\') >= 0)
                {
                    throw new InvalidDataException("A Metakit VFS path component is empty, traverses its parent, or contains a path separator.");
                }

                values[row] = value;
            }

            return values;
        }

        private static long[] ReadIntegerColumn(FileStream source, Layout layout, Location location, int rowCount, ReadBudget metadataBudget)
        {
            long[] values = new long[rowCount];
            if (rowCount == 0)
            {
                if (location.Size != 0)
                {
                    throw new InvalidDataException("A zero-row Metakit integer column contains data.");
                }

                return values;
            }

            byte[] data = ReadRelative(source, layout, location.Position, location.Size, metadataBudget);
            int width = CalculateIntegerWidth(rowCount, data.Length);
            for (int row = 0; row < rowCount; row++)
            {
                values[row] = ReadInteger(data, row, width, layout.LittleEndian);
            }

            return values;
        }

        private static int CalculateIntegerWidth(int rowCount, int byteCount)
        {
            int width = checked((byteCount * 8) / rowCount);
            if (rowCount <= 7 && byteCount > 0 && byteCount <= 6)
            {
                int[,] widths =
                {
                    { 8, 16, 1, 32, 2, 4 },
                    { 4, 8, 1, 16, 2, 0 },
                    { 2, 4, 8, 1, 0, 16 },
                    { 2, 4, 0, 8, 1, 0 },
                    { 1, 2, 4, 0, 8, 0 },
                    { 1, 2, 4, 0, 0, 8 },
                    { 1, 2, 0, 4, 0, 0 }
                };
                width = widths[rowCount - 1, byteCount - 1];
            }

            if (width < 0 || width > 32 || (width != 0 && (width & (width - 1)) != 0))
            {
                throw new InvalidDataException("The Metakit adaptive integer column has an unsupported width.");
            }

            return width;
        }

        private static long ReadInteger(byte[] data, int index, int width, bool littleEndian)
        {
            if (width == 0)
            {
                return 0;
            }

            if (width < 8)
            {
                int bitOffset = index * width;
                return (data[bitOffset >> 3] >> (bitOffset & 7)) & ((1 << width) - 1);
            }

            int byteWidth = width >> 3;
            int offset = checked(index * byteWidth);
            if (offset < 0 || offset > data.Length - byteWidth)
            {
                throw new InvalidDataException("The Metakit integer column is truncated.");
            }

            if (width == 8)
            {
                return unchecked((sbyte)data[offset]);
            }

            uint value = 0;
            if (littleEndian)
            {
                for (int byteIndex = byteWidth - 1; byteIndex >= 0; byteIndex--)
                {
                    value = (value << 8) | data[offset + byteIndex];
                }
            }
            else
            {
                for (int byteIndex = 0; byteIndex < byteWidth; byteIndex++)
                {
                    value = (value << 8) | data[offset + byteIndex];
                }
            }

            if (width == 16)
            {
                return unchecked((short)value);
            }

            return unchecked((int)value);
        }

        private static string[] ResolveDirectoryPaths(string[] names, long[] parents)
        {
            string[] paths = new string[names.Length];
            byte[] states = new byte[names.Length];
            int rootCount = 0;
            for (int start = 0; start < names.Length; start++)
            {
                if (states[start] == 2)
                {
                    continue;
                }

                List<int> chain = new List<int>();
                int current = start;
                while (states[current] != 2)
                {
                    if (states[current] == 1)
                    {
                        throw new InvalidDataException("The Metakit VFS directory graph contains a cycle.");
                    }

                    states[current] = 1;
                    chain.Add(current);
                    long parent = parents[current];
                    if (parent == -1)
                    {
                        if (!string.Equals(names[current], "<root>", StringComparison.Ordinal))
                        {
                            throw new InvalidDataException("The Metakit VFS root directory name is invalid.");
                        }

                        rootCount++;
                        break;
                    }

                    if (parent < 0 || parent >= names.Length)
                    {
                        throw new InvalidDataException("A Metakit VFS directory parent is outside the directory table.");
                    }

                    current = (int)parent;
                }

                for (int chainIndex = chain.Count - 1; chainIndex >= 0; chainIndex--)
                {
                    int index = chain[chainIndex];
                    long parent = parents[index];
                    if (parent == -1)
                    {
                        paths[index] = string.Empty;
                    }
                    else
                    {
                        string parentPath = paths[(int)parent];
                        string path = string.IsNullOrEmpty(parentPath) ? names[index] : parentPath + "/" + names[index];
                        if (path.Length > MaximumVfsPathCharacters)
                        {
                            throw new InvalidDataException("A Metakit VFS path exceeds the configured limit.");
                        }

                        paths[index] = path;
                    }

                    states[index] = 2;
                }
            }

            if (rootCount != 1)
            {
                throw new InvalidDataException("The Metakit VFS directory graph must contain exactly one root.");
            }

            return paths;
        }

        private static string CombineVfsPath(string directory, string name)
        {
            return string.IsNullOrEmpty(directory) ? name : directory + "/" + name;
        }

        private static string ClassifyCompression(FileStream source, DataRange range, long logicalSize)
        {
            if (range.Length == logicalSize)
            {
                return "None";
            }

            if (range.Length < 2)
            {
                return "Unknown";
            }

            byte[] header = ReadAt(source, range.Offset, 2, source.Length);
            int combined = (header[0] << 8) | header[1];
            return (header[0] & 0x0F) == 8 && (header[0] >> 4) <= 7 && combined % 31 == 0 && (header[1] & 0x20) == 0 ? "Zlib" : "Unknown";
        }

        private static Location ReadLocation(Cursor cursor, Layout layout)
        {
            long size = cursor.ReadValue();
            if (size < 0 || size > layout.Length)
            {
                throw new InvalidDataException("A Metakit column size is invalid.");
            }

            if (size == 0)
            {
                return Location.Empty;
            }

            long position = cursor.ReadValue();
            if (position <= 0 || position > layout.Length - size)
            {
                throw new InvalidDataException("A Metakit column range is outside the database.");
            }

            return new Location(position, checked((int)size));
        }

        private static byte[] ReadRelative(FileStream source, Layout layout, long position, int count, ReadBudget metadataBudget)
        {
            if (count < 0 || position < 0 || position > layout.Length - count)
            {
                throw new InvalidDataException("A Metakit metadata range exceeds the database or configured limit.");
            }

            metadataBudget.Consume(count);
            return ReadAt(source, layout.HeaderOffset + position, count, source.Length);
        }

        private static byte[] ReadAt(FileStream source, long offset, int count, long limit)
        {
            if (offset < 0 || count < 0 || offset > limit - count)
            {
                throw new InvalidDataException("A Metakit range is outside the source file.");
            }

            byte[] bytes = new byte[count];
            source.Position = offset;
            int total = 0;
            while (total < bytes.Length)
            {
                int read = source.Read(bytes, total, bytes.Length - total);
                if (read == 0)
                {
                    throw new EndOfStreamException("The Metakit source is truncated.");
                }

                total += read;
            }

            return bytes;
        }

        private static long ReadUInt24BigEndian(byte[] bytes, int offset)
        {
            return ((long)bytes[offset] << 16) | ((long)bytes[offset + 1] << 8) | bytes[offset + 2];
        }

        private static long ReadUInt32BigEndian(byte[] bytes, int offset)
        {
            return ((long)bytes[offset] << 24) | ((long)bytes[offset + 1] << 16) | ((long)bytes[offset + 2] << 8) | bytes[offset + 3];
        }

        private static int RequireCount(long value, int maximum, string name)
        {
            if (value < 0 || value > maximum)
            {
                throw new InvalidDataException($"The {name} exceeds the configured limit.");
            }

            return checked((int)value);
        }

        private static void RequireZero(long value, string name)
        {
            if (value != 0)
            {
                throw new NotSupportedException($"The {name} is not supported.");
            }
        }

        private void ThrowIfDisposed()
        {
            if (disposed)
            {
                throw new ObjectDisposedException(nameof(InstallBuilderMetakitArchive));
            }
        }

        private sealed class Cursor
        {
            private readonly byte[] bytes;
            private int position;

            internal Cursor(byte[] bytes)
            {
                this.bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));
            }

            internal bool End => position == bytes.Length;

            internal long ReadValue()
            {
                if (position >= bytes.Length)
                {
                    throw new EndOfStreamException("A Metakit variable-length integer is truncated.");
                }

                bool negative = bytes[position] == 0;
                long value = 0;
                for (int count = 0; count < 6; count++)
                {
                    if (position >= bytes.Length)
                    {
                        throw new EndOfStreamException("A Metakit variable-length integer is truncated.");
                    }

                    byte current = bytes[position++];
                    value = checked((value << 7) + current);
                    if ((current & 0x80) != 0)
                    {
                        long decoded = value - 0x80;
                        return negative ? ~decoded : decoded;
                    }
                }

                throw new InvalidDataException("A Metakit variable-length integer exceeds six bytes.");
            }

            internal byte[] ReadBytes(int count)
            {
                if (count < 0 || position > bytes.Length - count)
                {
                    throw new EndOfStreamException("A Metakit descriptor is truncated.");
                }

                byte[] result = new byte[count];
                Buffer.BlockCopy(bytes, position, result, 0, count);
                position += count;
                return result;
            }

            internal void RequireEnd(string name)
            {
                if (!End)
                {
                    throw new InvalidDataException($"The {name} contains unconsumed bytes.");
                }
            }
        }

        private sealed class ReadBudget
        {
            private long remaining;

            internal ReadBudget(long maximumBytes)
            {
                remaining = maximumBytes;
            }

            internal void Consume(long count)
            {
                if (count < 0 || count > remaining)
                {
                    throw new InvalidDataException("Metakit metadata exceeds the configured cumulative read limit.");
                }

                remaining -= count;
            }
        }

        private sealed class RangeStream : Stream
        {
            private readonly Stream source;
            private readonly bool leaveOpen;
            private long remaining;

            internal RangeStream(Stream source, long length, bool leaveOpen)
            {
                this.source = source;
                this.leaveOpen = leaveOpen;
                remaining = length;
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (remaining == 0)
                {
                    return 0;
                }

                int requested = (int)Math.Min(count, remaining);
                int read = source.Read(buffer, offset, requested);
                if (read == 0)
                {
                    throw new EndOfStreamException("The Metakit entry is truncated.");
                }

                remaining -= read;
                return read;
            }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            protected override void Dispose(bool disposing)
            {
                if (disposing && !leaveOpen)
                {
                    source.Dispose();
                }

                base.Dispose(disposing);
            }
        }

        private sealed class Layout
        {
            internal Layout(long headerOffset, long length, long rootPosition, int rootLength, bool littleEndian)
            {
                HeaderOffset = headerOffset;
                Length = length;
                RootPosition = rootPosition;
                RootLength = rootLength;
                LittleEndian = littleEndian;
            }

            internal long HeaderOffset { get; }
            internal long Length { get; }
            internal long RootPosition { get; }
            internal int RootLength { get; }
            internal bool LittleEndian { get; }
        }

        private readonly struct Location
        {
            internal static readonly Location Empty = new Location(0, 0);

            internal Location(long position, int size)
            {
                Position = position;
                Size = size;
            }

            internal long Position { get; }
            internal int Size { get; }
        }

        private readonly struct ByteColumn
        {
            internal ByteColumn(Location data, Location sizes, Location memos)
            {
                Data = data;
                Sizes = sizes;
                Memos = memos;
            }

            internal Location Data { get; }
            internal Location Sizes { get; }
            internal Location Memos { get; }
        }

        private readonly struct DataRange
        {
            internal DataRange(long offset, long length)
            {
                Offset = offset;
                Length = length;
            }

            internal long Offset { get; }
            internal long Length { get; }
        }
    }
}
