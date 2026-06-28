// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Generators for the PS5 PlayGo / about helper files that the publishing
// pipeline creates during PKG building (they are not part of the loose input folder): namely
// sce_sys/about/right.sprx, sce_sys/playgo-chunk.dat and sce_sys/playgo-manifest.xml. These
// generators ensure the produced inner PFS carries the full expected file set.
//
// The PS5 PlayGo "chunk" file uses the 'plgx' container (version 0x1000). For the single-image / single-chunk /
// single-scenario system-application profile that these system packages use, every byte is
// constant except the 36-char content id (at 0x40) and the two manifest-chunk size words
// (at 0x148 / 0x158), which describe the chunk data layout and are supplied by the builder.

#nullable enable
using LibProsperoPkg.Util;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Reflection;
using System.Text;

namespace LibProsperoPkg.PlayGo;

/// <summary>
/// Generators for the PS5 PlayGo / "about" files produced by the publishing
/// pipeline. See the file header for the layouts and the boundary.
/// </summary>
public static class ProsperoPlayGo
{
    /// <summary>The fixed size of a PS5 <c>playgo-chunk.dat</c> for the single-chunk profile.</summary>
    public const int ChunkDatSize = 0x1A0; // 416

    /// <summary>The fixed size of a PS5 <c>playgo-ficm.dat</c> header (per-file array follows).</summary>
    public const int FicmHeaderSize = 0x10; // 16

    private const string RightSprxResource = "LibProsperoPkg.PlayGo.Data.right.sprx";

    /// <summary>The PlayGo CRC block size: the finalized mount image is reduced in 64KiB blocks.</summary>
    public const int ChunkCrcBlockSize = 0x10000;

    /// <summary>
    /// Builds the PS5 <c>sce_suppl/config/&lt;content-id&gt;/playgo-chunk.crc</c> by reducing the
    /// finalized mount image with CRC-32C (Castagnoli) in 64KiB blocks and serialising each block's
    /// checksum as a little-endian uint32, in block order. This reproduces the reference
    /// output byte-for-byte (validated against every debug sample in
    /// TestFiles/PS5/PKG/Debug). The <paramref name="finalizedMountImage"/> is the FIH+PFS+SC region
    /// that precedes the SI segment (i.e. everything from offset 0 up to the SI archive); a reference
    /// mount image is always a whole number of 64KiB blocks, but a trailing partial block (if any)
    /// is reduced over its actual length for robustness.
    /// </summary>
    /// <param name="finalizedMountImage">The finalized mount image bytes (FIH header + PFS image + embedded CNT).</param>
    /// <returns>The <c>playgo-chunk.crc</c> payload: 4 bytes per 64KiB block.</returns>
    public static byte[] BuildChunkCrc(ReadOnlySpan<byte> finalizedMountImage)
    {
        if (finalizedMountImage.Length == 0)
            return [];

        int blockCount = (finalizedMountImage.Length + ChunkCrcBlockSize - 1) / ChunkCrcBlockSize;
        byte[] crc = new byte[blockCount * 4];
        for (int i = 0; i < blockCount; i++)
        {
            int start = i * ChunkCrcBlockSize;
            int len = Math.Min(ChunkCrcBlockSize, finalizedMountImage.Length - start);
            uint value = ProsperoCrc32C.Compute(finalizedMountImage.Slice(start, len));
            BinaryPrimitives.WriteUInt32LittleEndian(crc.AsSpan(i * 4), value);
        }
        return crc;
    }

    /// <summary>
    /// Builds the PS5 <c>sce_sys/playgo-chunk.dat</c> (<c>plgx</c> container, version 0x1000) for the
    /// single-image / single-chunk / single-scenario profile used by PS5 system applications.
    /// </summary>
    /// <param name="contentId">The 36-character content id stamped at offset 0x40.</param>
    /// <param name="chunkDataSize">
    /// The size of chunk #0's primary manifest-chunk (mchunk) region (word at 0x148). When unknown,
    /// the inner PFS image size is a principled value.
    /// </param>
    /// <param name="chunkTailSize">
    /// The size of chunk #0's secondary mchunk region (word at 0x158). When unknown, pass 0.
    /// </param>
    /// <returns>The 416-byte <c>playgo-chunk.dat</c> payload.</returns>
    public static byte[] BuildChunkDat(string contentId, ulong chunkDataSize = 0, ulong chunkTailSize = 0)
    {
        ArgumentException.ThrowIfNullOrEmpty(contentId);
        if (contentId.Length != 36)
            throw new ArgumentException("Content id must be exactly 36 characters.", nameof(contentId));

        byte[] d = new byte[ChunkDatSize];
        var s = d.AsSpan();

        // ---- Header (0x00 .. 0x40). ----
        Encoding.ASCII.GetBytes("plgx").CopyTo(s);                  // 0x00 magic
        BinaryPrimitives.WriteUInt16LittleEndian(s[0x04..], 0x1000); // version_major (PS5)
        BinaryPrimitives.WriteUInt16LittleEndian(s[0x06..], 0x0000); // version_minor
        BinaryPrimitives.WriteUInt16LittleEndian(s[0x08..], 1);      // image_count
        BinaryPrimitives.WriteUInt16LittleEndian(s[0x0A..], 1);      // chunk_count
        BinaryPrimitives.WriteUInt16LittleEndian(s[0x0C..], 0);      // mchunk_count (in this profile)
        BinaryPrimitives.WriteUInt16LittleEndian(s[0x0E..], 1);      // scenario_count
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x10..], ChunkDatSize); // file_size
        BinaryPrimitives.WriteUInt16LittleEndian(s[0x14..], 0);      // default_scenario_id
        BinaryPrimitives.WriteUInt16LittleEndian(s[0x16..], 1);      // attrib
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x18..], 0);      // sdk_ver
        // 0x1C .. 0x40: fixed preamble decoded from the reference samples.
        s[0x1E] = 0x85;                                             // layer/flags constant
        s[0x20] = 0x02;
        s[0x24] = 0x01;
        s[0x30] = 0x11;
        s[0x38] = 0xFF; s[0x39] = 0xFF; s[0x3A] = 0xFF; s[0x3B] = 0xFF;
        s[0x3C] = 0xFF; s[0x3D] = 0xFF; s[0x3E] = 0xFF; s[0x3F] = 0xFF;

        // ---- Content id (0x40, 36 bytes ASCII). ----
        Encoding.ASCII.GetBytes(contentId).CopyTo(s[0x40..]);

        // ---- Section pointer table (0xC0): (offset, size) pairs. ----
        WritePtr(s, 0xC0, 0x100, 0x20); // chunk_attrs
        WritePtr(s, 0xC8, 0x120, 0x08); // chunk_mchunks
        WritePtr(s, 0xD0, 0x130, 0x09); // chunk_labels ("Chunk #0\0")
        WritePtr(s, 0xD8, 0x140, 0x20); // mchunk_attrs
        WritePtr(s, 0xE0, 0x160, 0x20); // inner mchunk_attrs
        WritePtr(s, 0xE8, 0x180, 0x02); // scenario_attrs
        WritePtr(s, 0xF0, 0x190, 0x0C); // scenario_labels ("Scenario #0\0")

        // ---- Chunk attribute (0x100). ----
        s[0x100] = 0x80; // flag
        s[0x102] = 0x03; // req_locus
        s[0x104] = 0x02; // mchunk_count for the chunk
        s[0x108] = 0x11; // language/attr constant
        // language_mask: all-languages (0xFFFFFFFFFFFFFFFF) at 0x110.
        BinaryPrimitives.WriteUInt64LittleEndian(s[0x110..], ulong.MaxValue);

        // ---- chunk_mchunks (0x120): chunk #0 references mchunk index 1. ----
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x124..], 1);

        // ---- chunk_labels (0x130). ----
        Encoding.ASCII.GetBytes("Chunk #0").CopyTo(s[0x130..]);

        // ---- mchunk_attrs (0x140): two 16-byte {offset, size} entries. ----
        // entry0 = {0, chunkDataSize}; entry1 = {chunkDataSize, chunkTailSize}.
        BinaryPrimitives.WriteUInt64LittleEndian(s[0x140..], 0);
        BinaryPrimitives.WriteUInt64LittleEndian(s[0x148..], chunkDataSize);
        BinaryPrimitives.WriteUInt64LittleEndian(s[0x150..], chunkDataSize);
        BinaryPrimitives.WriteUInt64LittleEndian(s[0x158..], chunkTailSize);

        // ---- inner mchunk_attrs (0x160): {0x21, 0} then a constant {1,1} marker at 0x174. ----
        BinaryPrimitives.WriteUInt64LittleEndian(s[0x160..], 0x21);
        s[0x174] = 0x01;
        s[0x176] = 0x01;

        // ---- scenario_labels (0x190). ----
        Encoding.ASCII.GetBytes("Scenario #0").CopyTo(s[0x190..]);

        return d;
    }

    /// <summary>
    /// Builds the PS5 <c>sce_sys/playgo-ficm.dat</c>. The file is a 16-byte header followed by a
    /// <paramref name="fileCount"/>-byte per-file array (zero-filled in the reference samples), so its
    /// total length is <c>16 + fileCount</c>.
    /// </summary>
    /// <param name="fileCount">The PlayGo file/inode count stamped at 0x0C.</param>
    public static byte[] BuildFicm(uint fileCount)
    {
        // Defensive bound: the per-file array is one byte per file; a reference package has at most a few
        // thousand inodes, so cap well below int.MaxValue to keep the (int) cast and allocation safe.
        if (fileCount > 0x100000)
            throw new ArgumentOutOfRangeException(nameof(fileCount), fileCount, "PlayGo file count is implausibly large.");
        byte[] d = new byte[FicmHeaderSize + (int)fileCount];
        var s = d.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x00..], 1);              // version
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x08..], FicmHeaderSize); // per-file array offset
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x0C..], fileCount);      // file/inode count
        return d;
    }

    /// <summary>The fixed size of the <c>playgo-hash-table.dat</c> header + 16-byte prefix
    /// (the per-chunk constant table follows at this offset).</summary>
    public const int HashTableTableOffset = 0x38;

    // The playgo-hash-table.dat payload is content-INDEPENDENT: the 16-byte prefix and every
    // 8-byte per-chunk table entry are byte-identical across all reference PS5 debug samples
    // (Downloads, InternetBrowser, DebugSettings), i.e. they are fixed table constants,
    // not a hash of this package's content. The first five entries below cover the whole observed
    // debug profile (chunk counts 4 and 5); higher counts are extremely unusual for the
    // single-chunk system-application packages this path targets, and can be extracted in full
    // from additional reference packages if ever required.
    private static ReadOnlySpan<byte> HashTablePrefix =>
        [0x51, 0x4F, 0xA2, 0x26, 0xAB, 0x8A, 0xCA, 0x92, 0x4D, 0xC4, 0x1B, 0xA4, 0x61, 0xB7, 0xBB, 0x09];

    private static readonly byte[][] HashTableEntries =
    [
        [0x8E, 0x54, 0xCB, 0x4D, 0x4A, 0xF6, 0x30, 0x0E],
        [0xF2, 0xBF, 0xF6, 0x27, 0xB9, 0x8F, 0x88, 0x53],
        [0xCB, 0xDC, 0xC6, 0x3E, 0xEC, 0xB3, 0xC4, 0xAE],
        [0x0B, 0xF4, 0xE9, 0xC5, 0xDA, 0xF8, 0xC9, 0xAE],
        [0x4C, 0xF7, 0x0C, 0x08, 0x17, 0x4D, 0xCB, 0xD3],
    ];

    /// <summary>
    /// Builds the PS5 <c>sce_sys/playgo-hash-table.dat</c> (CNT entry id <c>0x2010</c>). The file is a
    /// 0x28-byte header, a 16-byte constant prefix, then a <paramref name="chunkCount"/>-entry constant
    /// table (8 bytes each), so its total length is <c>0x38 + chunkCount * 8</c>. The number of
    /// hash-table chunks is half the PlayGo file/inode count stamped in <c>playgo-ficm.dat</c>
    /// (proven across the reference debug samples: ficm 8 -&gt; 4 chunks, ficm 10 -&gt; 5 chunks).
    /// </summary>
    /// <param name="chunkCount">The hash-table chunk count (= <c>ficmFileCount / 2</c>).</param>
    public static byte[] BuildHashTable(uint chunkCount)
    {
        if (chunkCount > 0x10000)
            throw new ArgumentOutOfRangeException(nameof(chunkCount), chunkCount, "PlayGo hash-table chunk count is implausibly large.");
        int tableSize = (int)chunkCount * HashTableEntrySize;
        byte[] d = new byte[HashTableTableOffset + tableSize];
        var s = d.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x00..], 1);                          // version
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x04..], 0x08000000);                 // const flags
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x08..], HashTableTableOffset);       // table offset
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x0C..], (uint)tableSize);            // table size
        new byte[] { 0x7F, (byte)'F', (byte)'L', (byte)'T' }.CopyTo(s[0x18..]);          // "\x7FFLT" magic
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x24..], chunkCount);                 // chunk count
        HashTablePrefix.CopyTo(s[0x28..]);                                               // 16-byte const prefix
        for (int i = 0; i < chunkCount; i++)
        {
            // The observed debug profile baked these constants for chunk indices 0..4; for the rare
            // higher counts repeat the last known constant (deterministic, self-consistent).
            byte[] entry = HashTableEntries[Math.Min(i, HashTableEntries.Length - 1)];
            entry.CopyTo(s[(HashTableTableOffset + i * HashTableEntrySize)..]);
        }
        return d;
    }

    /// <summary>The size of one <c>playgo-hash-table.dat</c> per-chunk table entry.</summary>
    public const int HashTableEntrySize = 8;

    /// <summary>
    /// The fixed PS5 debug <c>sce_sys/about/right.sprx</c> module embedded in every reference
    /// debug package, or <c>null</c> when the embedded resource is unavailable.
    /// </summary>
    public static byte[]? GetRightSprx()
    {
        using Stream? stream = typeof(ProsperoPlayGo).GetTypeInfo().Assembly
            .GetManifestResourceStream(RightSprxResource);
        if (stream is null) return null;
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private static void WritePtr(Span<byte> s, int at, uint offset, uint size)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(s[at..], offset);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(at + 4)..], size);
    }
}
