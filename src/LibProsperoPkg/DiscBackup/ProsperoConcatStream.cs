// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// A read-only, seekable stream that presents an ordered set of source-stream windows as one
// contiguous stream. Used to reassemble a split disc-backup package (app_0.pkg + app_sc.pkg + ...)
// on the fly without materialising a multi-gigabyte temp file.

using System;
using System.Collections.Generic;
using System.IO;

namespace LibProsperoPkg.DiscBackup;

/// <summary>
/// Presents a sequence of <c>(source, offset, length)</c> windows as a single contiguous,
/// read-only, seekable stream. A read never crosses a segment boundary in one call (callers
/// that need a fixed count should loop, e.g. via <see cref="Stream.CopyTo(Stream)"/> or a
/// read-exactly helper).
/// </summary>
public sealed class ProsperoConcatStream : Stream
{
    private sealed class Segment
    {
        public required Stream Source { get; init; }
        public required long SourceOffset { get; init; }
        public required long SegmentLength { get; init; }
        public long VirtualStart { get; init; }
    }

    private readonly Segment[] _segments;
    private readonly bool _ownsSources;
    private long _position;
    private bool _disposed;

    /// <inheritdoc/>
    public override bool CanRead => true;

    /// <inheritdoc/>
    public override bool CanSeek => true;

    /// <inheritdoc/>
    public override bool CanWrite => false;

    /// <inheritdoc/>
    public override long Length { get; }

    /// <inheritdoc/>
    public override long Position
    {
        get => _position;
        set => Seek(value, SeekOrigin.Begin);
    }

    /// <summary>
    /// Builds a concatenation of the supplied windows, in the order given. When
    /// <paramref name="ownsSources"/> is <see langword="true"/> the source streams are disposed
    /// with this stream.
    /// </summary>
    /// <exception cref="ArgumentException">No segments were supplied.</exception>
    public ProsperoConcatStream(IEnumerable<(Stream source, long offset, long length)> segments, bool ownsSources = false)
    {
        ArgumentNullException.ThrowIfNull(segments);

        var list = new List<Segment>();
        long running = 0;
        foreach ((Stream source, long offset, long length) in segments)
        {
            ArgumentNullException.ThrowIfNull(source);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfNegative(length);
            // Every read seeks its backing source by absolute position, so a non-seekable source cannot
            // back a segment. Reject it here rather than failing on the first read.
            if (!source.CanSeek)
                throw new ArgumentException("Concat-stream sources must be seekable.", nameof(segments));

            list.Add(new Segment
            {
                Source = source,
                SourceOffset = offset,
                SegmentLength = length,
                VirtualStart = running,
            });
            running += length;
        }

        if (list.Count == 0)
            throw new ArgumentException("At least one segment is required.", nameof(segments));

        _segments = [.. list];
        _ownsSources = ownsSources;
        Length = running;
    }

    /// <inheritdoc/>
    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (offset + count > buffer.Length)
            throw new ArgumentException("The buffer is too small for the requested range.");
        return Read(buffer.AsSpan(offset, count));
    }

    /// <inheritdoc/>
    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.IsEmpty || _position >= Length)
            return 0;

        Segment s = _segments[FindSegment(_position)];
        long withinSegment = _position - s.VirtualStart;
        int toRead = (int)Math.Min(buffer.Length, s.SegmentLength - withinSegment);
        if (toRead <= 0)
            return 0;

        s.Source.Position = s.SourceOffset + withinSegment;
        int read = s.Source.Read(buffer[..toRead]);
        _position += read;
        return read;
    }

    /// <inheritdoc/>
    public override long Seek(long offset, SeekOrigin origin)
    {
        long target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => Length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (target < 0)
            throw new IOException("Cannot seek before the start of the stream.");
        _position = target;
        return _position;
    }

    private int FindSegment(long position)
    {
        int lo = 0, hi = _segments.Length - 1;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) >> 1;
            if (_segments[mid].VirtualStart <= position)
                lo = mid;
            else
                hi = mid - 1;
        }
        return lo;
    }

    /// <inheritdoc/>
    public override void Flush()
    {
        // Read-only stream: nothing to flush.
    }

    /// <inheritdoc/>
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing && _ownsSources)
            {
                foreach (Segment s in _segments)
                    s.Source.Dispose();
            }
            _disposed = true;
        }
        base.Dispose(disposing);
    }
}
