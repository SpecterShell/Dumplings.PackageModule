// SPDX-License-Identifier: LGPL-2.1-or-later
// Managed SharpCompress companion provider for Gentee's modified PPMd-I model.

using System;
using System.IO;
using SharpCompress.Compressors.PPMd.I1;

namespace SharpCompress.Compressors.PPMd.Gentee;

/// <summary>
/// Stateful provider for the Gentee PPMd-I variant used by GEA archives.
/// </summary>
public sealed class GenteePpmdDecoder : IDisposable
{
    private readonly int _allocatorSize;
    private readonly Model _model = new(gentee: true);
    private bool _disposed;

    /// <summary>
    /// Create one stateful decoder for a GEA archive.
    /// </summary>
    /// <param name="allocatorSize">
    /// PPMd model memory in bytes from the GEA archive header. The model is retained
    /// across order-1 continuation records until this instance is disposed.
    /// </param>
    public GenteePpmdDecoder(int allocatorSize)
    {
        if (allocatorSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(allocatorSize));
        }
        _allocatorSize = allocatorSize;
    }

    /// <summary>
    /// Decode one bounded GEA PPMd record and preserve its model for continuation records.
    /// </summary>
    /// <param name="input">Readable stream positioned at the record's range-coded bytes.</param>
    /// <param name="compressedSize">Exact record size from the GEA block header, in bytes.</param>
    /// <param name="outputSize">Exact expanded block size from the GEA catalog, in bytes.</param>
    /// <param name="modelOrder">
    /// Orders 2 through 16 initialize a model; order 1 continues the retained model while
    /// starting a new independent range stream.
    /// </param>
    /// <returns>The exact expanded bytes for the record.</returns>
    /// <exception cref="InvalidDataException">
    /// The stream is truncated, consumes a different byte count, lacks its PPMd end marker,
    /// or produces a different output length.
    /// </exception>
    public byte[] DecodeBlock(Stream input, int compressedSize, int outputSize, int modelOrder)
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(GenteePpmdDecoder));
        }
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }
        if (compressedSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(compressedSize));
        }
        if (outputSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputSize));
        }
        if (modelOrder is < 1 or > Model.MAXIMUM_ORDER)
        {
            throw new ArgumentOutOfRangeException(nameof(modelOrder));
        }

        // Never expose the next GEA record to the range decoder. CreateInstall's
        // buffered extractor can over-read its cache, but the declared block size
        // remains the authoritative physical boundary in the archive format.
        using var bounded = new ExactLengthReadStream(input, compressedSize);
        var output = new byte[outputSize];
        _model.DecodeGenteeBlock(bounded, output, outputSize, modelOrder, _allocatorSize);
        if (bounded.BytesRead != compressedSize)
        {
            throw new InvalidDataException(
                $"The Gentee PPMd block consumed {bounded.BytesRead} of {compressedSize} bytes."
            );
        }
        return output;
    }

    public void Dispose()
    {
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Present exactly one declared compressed record without taking ownership of its source.
    /// </summary>
    private sealed class ExactLengthReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _length;

        public ExactLengthReadStream(Stream inner, long length)
        {
            _inner = inner;
            _length = length;
        }

        public long BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position
        {
            get => BytesRead;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (BytesRead >= _length)
            {
                return 0;
            }
            var allowed = (int)Math.Min(count, _length - BytesRead);
            var read = _inner.Read(buffer, offset, allowed);
            if (read == 0)
            {
                throw new EndOfStreamException("The Gentee PPMd block is truncated.");
            }
            BytesRead += read;
            return read;
        }

        public override int ReadByte()
        {
            if (BytesRead >= _length)
            {
                throw new EndOfStreamException("The Gentee PPMd block is truncated.");
            }
            var value = _inner.ReadByte();
            if (value < 0)
            {
                throw new EndOfStreamException("The Gentee PPMd block is truncated.");
            }
            BytesRead++;
            return value;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
