// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Writer for the PS5 PFSv3 (and PFSv2) compression file format — the "PFSC" container.
// Each block is Kraken-compressed with OodleKrakenEncoder; blocks that do not compress — or cannot be
// expressed without the encoder's length escapes — fall back to STORED (uncompressed), matching the
// target format's incompressible-data behavior (isBlockCompressed = 0). Both paths round-trip
// byte-exact through the decoder.
//
// Every byte the writer emits was validated against reference output: the 32-byte header, the 7-entry section directory (8-byte aligned, data
// padded to 0x400), the git/shuffle constant sections (id=1/2), the bit-packed block-boundary table
// (id=3) with its stored-block flags (0xCC/0x0C), single-chunk compressed flag (0x06), two-chunk
// compressed flag (0x26) and saturating size hint, the per-block SHA3-256 hash table (id=4), and the
// SHA3-256 file digest at 0x28. Compressed output is validated by decompressing it
// and comparing byte-for-byte against the original input.
#nullable enable
using LibProsperoPkg.PFS.Compression.Oodle;
using System;
using System.Buffers.Binary;
using System.IO;

namespace LibProsperoPkg.PFS.Compression;

/// <summary>
/// Produces a valid PS5 PFSv3/PFSv2 compression container ("PFSC"). Each block is
/// Kraken-compressed with <see cref="Oodle.OodleKrakenEncoder"/>; incompressible blocks are
/// stored uncompressed. Both paths round-trip byte-exact through the decoder.
/// </summary>
public static class CompressedPfsFileWriter
{
    /// <summary>The default logical block size for PS5 v3 containers (256 KiB).</summary>
    public const int DefaultBlockSize = 0x40000;

    private const int HeaderSize = 0x48;
    private const int DirectoryEntrySize = 16;
    private const int SectionCount = 7;
    private const int SectionAlignment = 8;
    private const int DataAlignment = 0x400;

    private const uint Magic = 0x43534650;     // 'PFSC'
    private const uint EncodeParam0C = 0x0802;  // constant for v3 / Kraken / 256 KiB / window 18

    // Stored-block boundary-table flags (id=3, bits 48..55 of the first u64).
    private const ulong StoredFlagBase = 0x0C;       // bits 50,51 — every stored block
    private const ulong StoredFlagLargeHalf = 0xC0;  // bits 54,55 — added when size > blockSize/2
    private const ulong CompressedFlag = 0x06;       // bits 49,50 — single-chunk Kraken-compressed block
    private const ulong MultiChunkFlag = 0x20;       // bit 53 — added when the block is two newLZ chunks
    private const ulong BoundaryShuffleShift = 44;
    private const ulong BoundaryFlagShift = 48;
    private const ulong SizeHintShift = 44;
    private const ulong SizeHintMax = 0x1FFFF;       // 17-bit saturating (compressedSize - 1) hint

    // id=1: 20-byte tool git hash (constant in every sample — SHA-1 of the encoder source revision).
    private static readonly byte[] GitHash =
    [
        0x23, 0x98, 0x7d, 0x16, 0xc9, 0x20, 0x9a, 0xc7, 0x28, 0x37,
        0x19, 0x32, 0x7e, 0x0f, 0x50, 0x6b, 0xbc, 0xf4, 0x59, 0xf4,
    ];

    // id=2: 64-byte shuffle-pattern field-width table (constant; the SoA decompositions of the 13
    // PfsShufflePattern entries). Emitted verbatim — CLI/nwonly output always uses shuffle NONE.
    private static readonly byte[] ShuffleTable =
    [
        0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x08, 0x02, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x06, 0x02, 0x02, 0x04, 0x00, 0x00,
        0x01, 0x01, 0x06, 0x01, 0x01, 0x06, 0x00, 0x00, 0x04, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
    ];

    /// <summary>
    /// Builds a stored (uncompressed) PFSv3 compression container for <paramref name="payload"/> and
    /// returns the complete container bytes.
    /// </summary>
    /// <param name="payload">The uncompressed data to wrap (the logical file the container expands to).</param>
    /// <param name="level">
    /// The Kraken level recorded in the header (default 7, matching "--oformat nwonly"). It has no effect
    /// on stored data but is preserved so the container is indistinguishable from a tool-produced one and
    /// its file digest matches.
    /// </param>
    /// <param name="blockSize">The logical block size (default 256 KiB). Must be positive.</param>
    /// <returns>The serialized PFSv3 container.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="payload"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="blockSize"/> is not positive.</exception>
    /// <exception cref="PlatformNotSupportedException">SHA3-256 is unavailable on this host.</exception>
    public static byte[] WriteStored(ReadOnlySpan<byte> payload, int level = 7, int blockSize = DefaultBlockSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(blockSize);
        if (!PfsDigest.IsSupported)
            throw new PlatformNotSupportedException(
                "SHA3-256 is required for the PS5 PFSv3 compression format but is not available on this host.");

        int blockCount = payload.Length == 0 ? 1 : (payload.Length + blockSize - 1) / blockSize;

        int sec1Size = GitHash.Length;
        int sec2Size = ShuffleTable.Length;
        int sec3Size = (blockCount + 1) * DirectoryEntrySize;
        int sec4Size = blockCount * PfsDigest.DigestLength;
        int sec5Size = blockCount * DirectoryEntrySize;

        int off1 = HeaderSize + SectionCount * DirectoryEntrySize;   // 0xB8
        int off2 = Align(off1 + sec1Size, SectionAlignment);
        int off3 = Align(off2 + sec2Size, SectionAlignment);
        int off4 = Align(off3 + sec3Size, SectionAlignment);
        int off5 = Align(off4 + sec4Size, SectionAlignment);
        int off6 = Align(off5 + sec5Size, SectionAlignment);        // id=6 is empty
        int off7 = Align(off6, DataAlignment);                      // block data, padded to 0x400

        long totalSize = (long)off7 + payload.Length;
        var buffer = new byte[checked((int)totalSize)];
        Span<byte> span = buffer;

        // ---- header ----
        BinaryPrimitives.WriteUInt32LittleEndian(span, Magic);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x04..], 3);                 // version 3
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x06..], SectionCount);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x08..], (uint)blockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x0C..], EncodeParam0C);
        ulong encodeParam10 = (ulong)CompressionAlgorithm.Kraken
                              | ((ulong)(byte)(sbyte)level << 8)
                              | (PfsCompressionConstants.KrakenWindowBits << 16);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x10..], encodeParam10);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x18..], (ulong)payload.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x20..], (ulong)totalSize);
        // span[0x28..0x48] file digest — filled in last.

        // ---- section directory @0x48 (ids 1..7) ----
        WriteDirectoryEntry(span, 0, 1, off1, sec1Size);
        WriteDirectoryEntry(span, 1, 2, off2, sec2Size);
        WriteDirectoryEntry(span, 2, 3, off3, sec3Size);
        WriteDirectoryEntry(span, 3, 4, off4, sec4Size);
        WriteDirectoryEntry(span, 4, 5, off5, sec5Size);
        WriteDirectoryEntry(span, 5, 6, off6, 0);
        WriteDirectoryEntry(span, 6, 7, off7, payload.Length);

        // ---- id=1 git hash, id=2 shuffle table ----
        GitHash.CopyTo(span[off1..]);
        ShuffleTable.CopyTo(span[off2..]);

        // ---- id=3 boundary table + id=4 hashes (one pass over blocks) ----
        int halfBlock = blockSize / 2;
        long cumulative = 0;
        for (int i = 0; i < blockCount; i++)
        {
            int size = payload.Length == 0
                ? 0
                : (int)Math.Min(blockSize, payload.Length - cumulative);

            ulong flags = StoredFlagBase | (size > halfBlock ? StoredFlagLargeHalf : 0);
            ulong sizeHint = (ulong)Math.Min(Math.Max(size - 1, 0), (long)SizeHintMax);

            int e = off3 + i * DirectoryEntrySize;
            // e0 = compOffset | (shuffle=0 << 44) | (flags << 48); stored => compOffset == uncompOffset.
            BinaryPrimitives.WriteUInt64LittleEndian(span[e..],
                (ulong)cumulative | (flags << (int)BoundaryFlagShift));
            // e1 = uncompOffset | (sizeHint << 44).
            BinaryPrimitives.WriteUInt64LittleEndian(span[(e + 8)..],
                (ulong)cumulative | (sizeHint << (int)SizeHintShift));

            ReadOnlySpan<byte> block = size == 0 ? default : payload.Slice((int)cumulative, size);
            int h = off4 + i * PfsDigest.DigestLength;
            PfsDigest.ComputeBlockDigest(block, span.Slice(h, PfsDigest.DigestLength));

            if (size > 0)
                block.CopyTo(span[(off7 + (int)cumulative)..]);

            cumulative += size;
        }

        // Sentinel boundary entry: totals, no flags / hint.
        int sentinel = off3 + blockCount * DirectoryEntrySize;
        BinaryPrimitives.WriteUInt64LittleEndian(span[sentinel..], (ulong)payload.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(sentinel + 8)..], (ulong)payload.Length);

        // id=5 aux: left zero (a per-block dedup signature that the format does not integrity-check
        // and the decompressor ignores for stored blocks; validated to round-trip).

        // ---- file digest @0x28 = SHA3-256(header32 || id2 || id3 || id4) ----
        byte[] digest = PfsDigest.ComputeFileDigest(
            span.Slice(0x08, PfsDigest.FileDigestHeaderParamsLength),
            span.Slice(off2, sec2Size),
            span.Slice(off3, sec3Size),
            span.Slice(off4, sec4Size));
        digest.CopyTo(span[0x28..]);

        return buffer;
    }

    /// <summary>
    /// Builds a stored PFSv3 container for <paramref name="payload"/> and writes it to
    /// <paramref name="destination"/>.
    /// </summary>
    public static void WriteStored(Stream destination, ReadOnlySpan<byte> payload, int level = 7, int blockSize = DefaultBlockSize)
    {
        ArgumentNullException.ThrowIfNull(destination);
        destination.Write(WriteStored(payload, level, blockSize));
    }

    /// <summary>
    /// Builds a Kraken-compressed PFSv3 container for <paramref name="payload"/>. Each logical block is
    /// compressed with the Kraken encoder; blocks that do not compress below their stored
    /// size are written stored (isBlockCompressed = 0), matching the target format's incompressible-data behavior.
    /// The resulting container round-trips byte-exact through the decoder.
    /// </summary>
    /// <param name="payload">The uncompressed data to wrap.</param>
    /// <param name="level">The Kraken level recorded in the header (default 7, matching "--oformat nwonly").</param>
    /// <param name="blockSize">The logical block size (default 256 KiB). Must be positive.</param>
    /// <param name="useHuffmanArrays">When true (the default), the literal/command/length streams within
    /// each chunk are Huffman-coded (entropy chunk type 2) where that is smaller than the raw form,
    /// producing markedly smaller blocks. Pass false for raw entropy arrays (larger, useful for
    /// debugging/determinism). Both forms round-trip byte-exact through the decoder.</param>
    /// <returns>The serialized PFSv3 container.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="blockSize"/> is not positive.</exception>
    /// <exception cref="PlatformNotSupportedException">SHA3-256 is unavailable on this host.</exception>
    public static byte[] WriteCompressed(ReadOnlySpan<byte> payload, int level = 7, int blockSize = DefaultBlockSize, bool useHuffmanArrays = true)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(blockSize);
        if (!PfsDigest.IsSupported)
            throw new PlatformNotSupportedException(
                "SHA3-256 is required for the PS5 PFSv3 compression format but is not available on this host.");

        int blockCount = payload.Length == 0 ? 1 : (payload.Length + blockSize - 1) / blockSize;

        // Compress (or store) each block up-front so the section sizes and offsets are known.
        var blockBytes = new byte[blockCount][];   // bytes that land in section 7
        var blockIsCompressed = new bool[blockCount];
        var blockMultiChunk = new bool[blockCount];
        var blockFirstChunkComp = new int[blockCount];
        var blockUncompSize = new int[blockCount];
        long cumulativeUncomp = 0;
        long totalCompressed = 0;
        for (int i = 0; i < blockCount; i++)
        {
            int size = payload.Length == 0 ? 0 : (int)Math.Min(blockSize, payload.Length - cumulativeUncomp);
            blockUncompSize[i] = size;

            ReadOnlySpan<byte> block = size == 0 ? default : payload.Slice((int)cumulativeUncomp, size);
            EncodedBlock? encoded = size == 0 ? null : OodleKrakenEncoder.EncodeBlock(block, useHuffmanArrays);
            if (encoded is EncodedBlock eb && eb.Payload.Length < size)
            {
                blockBytes[i] = eb.Payload;
                blockIsCompressed[i] = true;
                blockMultiChunk[i] = eb.MultiChunk;
                blockFirstChunkComp[i] = eb.FirstChunkCompSize;
            }
            else
            {
                blockBytes[i] = block.ToArray();
                blockIsCompressed[i] = false;
            }

            totalCompressed += blockBytes[i].Length;
            cumulativeUncomp += size;
        }

        int sec1Size = GitHash.Length;
        int sec2Size = ShuffleTable.Length;
        int sec3Size = (blockCount + 1) * DirectoryEntrySize;
        int sec4Size = blockCount * PfsDigest.DigestLength;
        int sec5Size = blockCount * DirectoryEntrySize;

        int off1 = HeaderSize + SectionCount * DirectoryEntrySize;
        int off2 = Align(off1 + sec1Size, SectionAlignment);
        int off3 = Align(off2 + sec2Size, SectionAlignment);
        int off4 = Align(off3 + sec3Size, SectionAlignment);
        int off5 = Align(off4 + sec4Size, SectionAlignment);
        int off6 = Align(off5 + sec5Size, SectionAlignment);
        int off7 = Align(off6, DataAlignment);

        long totalSize = off7 + totalCompressed;
        var buffer = new byte[checked((int)totalSize)];
        Span<byte> span = buffer;

        // ---- header ----
        BinaryPrimitives.WriteUInt32LittleEndian(span, Magic);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x04..], 3);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x06..], SectionCount);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x08..], (uint)blockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x0C..], EncodeParam0C);
        ulong encodeParam10 = (ulong)CompressionAlgorithm.Kraken
                              | ((ulong)(byte)(sbyte)level << 8)
                              | (PfsCompressionConstants.KrakenWindowBits << 16);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x10..], encodeParam10);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x18..], (ulong)payload.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x20..], (ulong)totalSize);

        // ---- section directory @0x48 (ids 1..7) ----
        WriteDirectoryEntry(span, 0, 1, off1, sec1Size);
        WriteDirectoryEntry(span, 1, 2, off2, sec2Size);
        WriteDirectoryEntry(span, 2, 3, off3, sec3Size);
        WriteDirectoryEntry(span, 3, 4, off4, sec4Size);
        WriteDirectoryEntry(span, 4, 5, off5, sec5Size);
        WriteDirectoryEntry(span, 5, 6, off6, 0);
        WriteDirectoryEntry(span, 6, 7, off7, checked((int)totalCompressed));

        GitHash.CopyTo(span[off1..]);
        ShuffleTable.CopyTo(span[off2..]);

        // ---- id=3 boundary table + id=4 hashes + section-7 data (one pass over blocks) ----
        int halfBlock = blockSize / 2;
        long cumulativeComp = 0;
        cumulativeUncomp = 0;
        for (int i = 0; i < blockCount; i++)
        {
            int usize = blockUncompSize[i];
            byte[] data = blockBytes[i];
            int csize = data.Length;

            ulong flags;
            ulong sizeHint;
            if (blockIsCompressed[i])
            {
                // Single chunk -> 0x06, hint = whole compressed size - 1. Two chunks -> 0x26, hint =
                // first chunk's compressed size - 1 (the rebuilder splits the block on that value).
                flags = blockMultiChunk[i] ? CompressedFlag | MultiChunkFlag : CompressedFlag;
                int hintBase = blockMultiChunk[i] ? blockFirstChunkComp[i] : csize;
                sizeHint = (ulong)Math.Min(Math.Max(hintBase - 1, 0), (long)SizeHintMax);
            }
            else
            {
                flags = StoredFlagBase | (usize > halfBlock ? StoredFlagLargeHalf : 0);
                sizeHint = (ulong)Math.Min(Math.Max(csize - 1, 0), (long)SizeHintMax);
            }

            int e = off3 + i * DirectoryEntrySize;
            // e0 = compOffset | (shuffle=0 << 44) | (flags << 48).
            BinaryPrimitives.WriteUInt64LittleEndian(span[e..],
                (ulong)cumulativeComp | (flags << (int)BoundaryFlagShift));
            // e1 = uncompOffset | (sizeHint << 44).
            BinaryPrimitives.WriteUInt64LittleEndian(span[(e + 8)..],
                (ulong)cumulativeUncomp | (sizeHint << (int)SizeHintShift));

            ReadOnlySpan<byte> rawBlock = usize == 0 ? default : payload.Slice((int)cumulativeUncomp, usize);
            int h = off4 + i * PfsDigest.DigestLength;
            PfsDigest.ComputeBlockDigest(rawBlock, span.Slice(h, PfsDigest.DigestLength));

            if (csize > 0)
                data.CopyTo(span[(off7 + (int)cumulativeComp)..]);

            cumulativeComp += csize;
            cumulativeUncomp += usize;
        }

        // Sentinel boundary entry: totals, no flags / hint.
        int sentinel = off3 + blockCount * DirectoryEntrySize;
        BinaryPrimitives.WriteUInt64LittleEndian(span[sentinel..], (ulong)cumulativeComp);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(sentinel + 8)..], (ulong)payload.Length);

        // ---- file digest @0x28 = SHA3-256(header32 || id2 || id3 || id4) ----
        byte[] digest = PfsDigest.ComputeFileDigest(
            span.Slice(0x08, PfsDigest.FileDigestHeaderParamsLength),
            span.Slice(off2, sec2Size),
            span.Slice(off3, sec3Size),
            span.Slice(off4, sec4Size));
        digest.CopyTo(span[0x28..]);

        return buffer;
    }

    private static void WriteDirectoryEntry(Span<byte> span, int index, ushort id, int offset, int size)
    {
        int p = HeaderSize + index * DirectoryEntrySize;
        BinaryPrimitives.WriteUInt16LittleEndian(span[p..], id);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(p + 2)..], (uint)offset);
        // span[p+6 .. p+10] reserved (0)
        BinaryPrimitives.WriteUInt32LittleEndian(span[(p + 10)..], (uint)size);
        // span[p+14 .. p+16] reserved (0)
    }

    private static int Align(int value, int alignment) => (value + alignment - 1) & ~(alignment - 1);
}
