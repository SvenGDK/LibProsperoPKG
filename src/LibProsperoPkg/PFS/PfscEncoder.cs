// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// PFSC block encoder. A plain PFSC writer only emits
// a PFSC header with every block stored at full size (no compression). This encoder produces
// per-block compression.
//
// The format produced here is byte-for-byte readable by the existing
// LibProsperoPkg.PFS.PFSCReader (validated by round-trip), so it works for PS5 image workflows.
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using LibProsperoPkg.Util;

namespace LibProsperoPkg.PFS;

/// <summary>
/// Options controlling how a PFSC image is produced. Exposes the tunable
/// surface for PFSC encoding (<c>--block-size</c>, <c>--compression-level</c>,
/// <c>--threshold-gain</c>, <c>--min-compress-size</c>).
/// </summary>
public sealed class PfscEncoderOptions
{
    /// <summary>Logical PFSC block size. Must be a power of two between 4 KiB and 2 MiB. Default 64 KiB.</summary>
    public int BlockSize { get; set; } = 0x10000;

    /// <summary>zlib compression level used for each block (default: maximum).</summary>
    public CompressionLevel CompressionLevel { get; set; } = CompressionLevel.SmallestSize;

    /// <summary>
    /// Minimum per-block gain percent (0-100) required to keep a block compressed.
    /// A block whose gain is below this stays raw. Default 0 (keep any gain).
    /// </summary>
    public int ThresholdGain { get; set; } = 0;

    /// <summary>
    /// Files smaller than this are stored raw (never PFSC-wrapped). Default 0.
    /// </summary>
    public long MinCompressSize { get; set; } = 0;

    /// <summary>Validates the option values, throwing on anything out of range.</summary>
    public void Validate()
    {
        if (BlockSize < 0x1000 || BlockSize > 0x200000)
            throw new ArgumentOutOfRangeException(nameof(BlockSize), BlockSize, "Block size must be between 4096 and 2097152.");
        if ((BlockSize & (BlockSize - 1)) != 0)
            throw new ArgumentException("Block size must be a power of two.", nameof(BlockSize));
        if (ThresholdGain < 0 || ThresholdGain > 100)
            throw new ArgumentOutOfRangeException(nameof(ThresholdGain), ThresholdGain, "Threshold gain must be between 0 and 100.");
        if (MinCompressSize < 0)
            throw new ArgumentOutOfRangeException(nameof(MinCompressSize), MinCompressSize, "Minimum compress size must be non-negative.");
    }
}

/// <summary>Statistics describing a completed PFSC encode.</summary>
public sealed class PfscEncodeStats
{
    /// <summary>Logical (uncompressed) size of the source payload.</summary>
    public long RawSize { get; init; }
    /// <summary>Size of the produced PFSC image (header + stored blocks).</summary>
    public long EncodedSize { get; init; }
    /// <summary>Total number of logical blocks.</summary>
    public long BlockCount { get; init; }
    /// <summary>Number of blocks that were stored compressed.</summary>
    public long CompressedBlocks { get; init; }
    /// <summary>True when the payload was stored raw (no PFSC wrapper) because compression gave no benefit.</summary>
    public bool StoredRaw { get; init; }
    /// <summary>Percentage saved relative to the raw size (negative if it grew).</summary>
    public double GainPercent => RawSize == 0 ? 0.0 : (RawSize - EncodedSize) / (double)RawSize * 100.0;
}

/// <summary>
/// Encodes raw data into a PFSC-compressed image. The header layout, offset
/// table and per-block compress/raw decision follow the PFSC payload layout,
/// and the output is decodable by <see cref="PFSCReader"/>.
/// </summary>
public static class PfscEncoder
{
    /// <summary>The 4-byte PFSC magic ('P','F','S','C').</summary>
    public const uint Magic = 0x43534650;

    // PFSC header constants (see PFSCReader).
    private const int BlockOffsetsOffset = 0x400;
    private const int InitialDataOffset = 0x10000;
    private const int OffsetEntrySize = 8;
    private const int Unk8 = 6;

    /// <summary>
    /// Returns the PFSC header size (including any extra blocks needed for a
    /// large offset table) for an image with <paramref name="blockCount"/> blocks.
    /// </summary>
    public static long HeaderSize(long blockCount, int blockSize)
    {
        if (blockCount < 0) throw new ArgumentOutOfRangeException(nameof(blockCount));
        long pointerTable = (blockCount + 1) * (long)OffsetEntrySize;
        long capacity = InitialDataOffset - BlockOffsetsOffset;
        long extra = Math.Max(0, pointerTable - capacity);
        long extraBlocks = extra > 0 ? (extra + blockSize - 1) / blockSize : 0;
        return InitialDataOffset + extraBlocks * (long)blockSize;
    }

    /// <summary>
    /// Encodes <paramref name="raw"/> into a PFSC image returned as a byte array.
    /// When compression yields no benefit (e.g. tiny or incompressible payloads)
    /// the original bytes are returned unchanged and <c>StoredRaw</c> is set.
    /// </summary>
    public static byte[] Encode(byte[] raw, PfscEncoderOptions? options, out PfscEncodeStats stats)
    {
        ArgumentNullException.ThrowIfNull(raw);
        using var input = new MemoryStream(raw, writable: false);
        using var output = new MemoryStream();
        stats = Encode(input, raw.Length, output, options);
        return stats.StoredRaw ? raw : output.ToArray();
    }

    /// <summary>
    /// Streams a PFSC image of the first <paramref name="length"/> bytes of
    /// <paramref name="input"/> into <paramref name="output"/>.
    /// </summary>
    /// <remarks>
    /// <paramref name="output"/> must be seekable: the encoder reserves the
    /// header, streams each block (holding only one block in memory at a time)
    /// and then rewrites the header with the final offset table. This keeps the
    /// memory footprint flat even for multi-gigabyte images.
    /// </remarks>
    /// <returns>Statistics describing the encode.</returns>
    public static PfscEncodeStats Encode(Stream input, long length, Stream output, PfscEncoderOptions? options = null, Action<long>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        options ??= new PfscEncoderOptions();
        options.Validate();
        if (!output.CanSeek)
            throw new ArgumentException("Output stream must be seekable.", nameof(output));

        int blockSize = options.BlockSize;

        // Tiny / below-threshold payloads are copied through verbatim.
        if (length == 0 || length < options.MinCompressSize)
        {
            CopyExact(input, output, length);
            return new PfscEncodeStats
            {
                RawSize = length,
                EncodedSize = length,
                BlockCount = 0,
                CompressedBlocks = 0,
                StoredRaw = true,
            };
        }

        long blockCount = (length + blockSize - 1) / blockSize;
        long headerSize = HeaderSize(blockCount, blockSize);
        long outStart = output.Position;

        var offsets = new long[blockCount + 1];
        offsets[0] = headerSize;

        // Reserve header space and stream blocks after it.
        output.Position = outStart + headerSize;

        var blockBuf = new byte[blockSize];
        long compressedBlocks = 0;
        long produced = 0;
        for (long bi = 0; bi < blockCount; bi++)
        {
            int filled = ReadUpTo(input, blockBuf, 0, blockSize);
            // Zero the padding tail so the logical block is deterministic.
            if (filled < blockSize)
                Array.Clear(blockBuf, filled, blockSize - filled);

            byte[] compressed = Deflate(blockBuf, blockSize, options.CompressionLevel);
            double gain = (blockSize - compressed.Length) / (double)blockSize * 100.0;
            bool storeCompressed = compressed.Length < blockSize && gain >= options.ThresholdGain;

            if (storeCompressed)
            {
                output.Write(compressed, 0, compressed.Length);
                offsets[bi + 1] = offsets[bi] + compressed.Length;
                compressedBlocks++;
            }
            else
            {
                output.Write(blockBuf, 0, blockSize);
                offsets[bi + 1] = offsets[bi] + blockSize;
            }
            produced += filled;
            progress?.Invoke(produced);
        }

        long encodedSize = offsets[blockCount];

        // If nothing compressed, or the wrapper is not smaller, fall back to raw.
        if (compressedBlocks == 0 || encodedSize >= length)
        {
            output.Position = outStart;
            output.SetLength(outStart);
            input.Position = 0; // caller-provided substreams start at 0
            CopyExact(input, output, length);
            return new PfscEncodeStats
            {
                RawSize = length,
                EncodedSize = length,
                BlockCount = blockCount,
                CompressedBlocks = 0,
                StoredRaw = true,
            };
        }

        // Rewrite the header now that the offset table is known.
        output.Position = outStart;
        WriteHeader(output, blockSize, headerSize, blockCount, offsets);
        output.Position = outStart + encodedSize;
        output.SetLength(outStart + encodedSize);

        return new PfscEncodeStats
        {
            RawSize = length,
            EncodedSize = encodedSize,
            BlockCount = blockCount,
            CompressedBlocks = compressedBlocks,
            StoredRaw = false,
        };
    }

    private static void WriteHeader(Stream s, int blockSize, long headerSize, long blockCount, IReadOnlyList<long> offsets)
    {
        var start = s.Position;
        s.WriteUInt32LE(Magic);     // 0x00 : 'PFSC'
        s.WriteInt32LE(0);          // 0x04 : unk4 (always 0)
        s.WriteInt32LE(Unk8);       // 0x08 : unk8 (always 6)
        s.WriteInt32LE(blockSize);  // 0x0C : block size (32-bit)
        s.WriteInt64LE(blockSize);  // 0x10 : block size (64-bit)
        s.WriteInt64LE(BlockOffsetsOffset); // 0x18 : block offsets table pointer
        s.WriteInt64LE(headerSize); // 0x20 : data start offset
        s.WriteInt64LE(blockCount * (long)blockSize); // 0x28 : logical data length

        s.Position = start + BlockOffsetsOffset;
        for (long i = 0; i <= blockCount; i++)
            s.WriteInt64LE(offsets[(int)i]);
    }

    // Produces a zlib stream (2-byte header + raw DEFLATE + adler32), matching
    // Python's zlib.compress. PFSCReader skips the 2-byte header and inflates the
    // remainder with a raw DeflateStream, ignoring the trailing checksum.
    private static byte[] Deflate(byte[] data, int count, CompressionLevel level)
    {
        using var ms = new MemoryStream(count);
        using (var zs = new ZLibStream(ms, level, leaveOpen: true))
            zs.Write(data, 0, count);
        return ms.ToArray();
    }

    private static int ReadUpTo(Stream s, byte[] buffer, int offset, int count)
    {
        int total = 0;
        while (total < count)
        {
            int n = s.Read(buffer, offset + total, count - total);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    private static void CopyExact(Stream input, Stream output, long count)
    {
        if (count <= 0) return;
        var buf = new byte[Math.Min(count, 1 << 20)];
        long remaining = count;
        while (remaining > 0)
        {
            int toRead = (int)Math.Min(remaining, buf.Length);
            int n = ReadUpTo(input, buf, 0, toRead);
            if (n == 0) throw new EndOfStreamException("Unexpected end of input while copying raw payload.");
            output.Write(buf, 0, n);
            remaining -= n;
        }
    }

    /// <summary>
    /// Returns true when a file should be kept raw (never PFSC-compressed)
    /// because it is an executable/already-packed payload.
    /// </summary>
    /// <param name="fileName">The base file name (e.g. <c>eboot.bin</c>).</param>
    /// <param name="relativePath">The file's path within the image (e.g. <c>sce_module/foo.prx</c>).</param>
    public static bool ShouldSkipExecutableCompression(string fileName, string relativePath)
    {
        string name = (fileName ?? string.Empty).ToLowerInvariant();
        string path = (relativePath ?? string.Empty).ToLowerInvariant().Replace('\\', '/');
        return (name.StartsWith("eboot", StringComparison.Ordinal) && name.EndsWith(".bin", StringComparison.Ordinal))
            || (name.StartsWith("param", StringComparison.Ordinal) && name.EndsWith(".sfx", StringComparison.Ordinal))
            || name.EndsWith(".prx", StringComparison.Ordinal)
            || name.EndsWith(".sprx", StringComparison.Ordinal)
            || name.EndsWith(".json", StringComparison.Ordinal)
            || name.EndsWith(".txt", StringComparison.Ordinal)
            || name.EndsWith(".png", StringComparison.Ordinal)
            || name.EndsWith("keystone", StringComparison.Ordinal)
            || path.Contains("sce_module", StringComparison.Ordinal)
            || path.Contains("sce_sys", StringComparison.Ordinal);
    }
}
