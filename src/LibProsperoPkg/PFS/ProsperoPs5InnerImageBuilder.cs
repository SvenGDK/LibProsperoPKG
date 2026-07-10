// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// PS5 nwonly INNER pfs_image.dat assembler. Lays out the inner files data-first (raw files block-aligned,
// compressed files packed), followed by the block-info table and the Kraken-compressed metadata block.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using LibProsperoPkg.PFS.Compression;
using System;
using System.Collections.Generic;
using System.IO;

namespace LibProsperoPkg.PFS;

/// <summary>One inner-image payload (a file's data or the metadata block) with its resolved on-disk placement.</summary>
public sealed class ProsperoPs5InnerPayload
{
    /// <summary>The uncompressed payload bytes.</summary>
    public byte[] Data = Array.Empty<byte>();

    /// <summary>When true the payload is stored raw (never compressed) and is placed block-aligned.</summary>
    public bool StoreRaw;

    /// <summary>When true the payload is placed at the next 64 KiB block boundary; otherwise packed contiguously.</summary>
    public bool BlockAligned;

    /// <summary>When true the on-disk cursor is advanced to the next 64 KiB block boundary <em>after</em> this
    /// payload, so it occupies whole blocks and the following payload starts block-aligned. Used for the
    /// sce_sys subtree, which forms a fully block-aligned region.</summary>
    public bool BlockAlignedAfter;
}

/// <summary>
/// Assembles the inner <c>pfs_image.dat</c>: data-first per-file layout (raw files block-aligned,
/// compressed files packed), a 32-byte block-info table, then the compressed metadata.
/// </summary>
public sealed class ProsperoPs5InnerImageBuilder
{
    /// <summary>The inner-image block size (64 KiB).</summary>
    public const int BlockSize = 0x10000;

    /// <summary>The per-file Kraken compression block size (256 KiB).</summary>
    public const int CompressBlockSize = 0x40000;

    private static int AlignUp(int v, int a) => (v + a - 1) & ~(a - 1);

    /// <summary>
    /// Kraken-compresses a payload into its concatenated on-disk bytes (256 KiB blocks). Returns the raw bytes
    /// when compression does not save at least 6.25%, or when <paramref name="storeRaw"/>.
    /// </summary>
    public static byte[] CompressPayload(byte[] raw, bool storeRaw)
    {
        if (storeRaw) return raw;
        var pf = ProsperoCompressedPfsFile.Parse(ProsperoCompressedPfsImage.Pack(raw, 7, CompressBlockSize));
        using var ms = new MemoryStream();
        foreach (var b in pf.Blocks)
        {
            var d = b.CompressedData.ToArray();
            ms.Write(d, 0, d.Length);
        }
        byte[] comp = ms.ToArray();
        return comp.Length <= (int)(((long)raw.Length * 15) >> 4) ? comp : raw;
    }

    /// <summary>
    /// Assembles the inner image. <paramref name="payloads"/> are, in on-disk order, the data files followed by
    /// the block-info table payload and the metadata block. Each payload is compressed per its flags and placed
    /// block-aligned or packed. Returns the block-aligned-tail on-disk image.
    /// </summary>
    public byte[] Build(IReadOnlyList<ProsperoPs5InnerPayload> payloads)
    {
        // First pass: compress + resolve offsets.
        var chunks = new List<(int offset, byte[] data)>();
        int pos = 0;
        foreach (var p in payloads)
        {
            byte[] data = CompressPayload(p.Data, p.StoreRaw);
            if (p.BlockAligned)
                pos = AlignUp(pos, BlockSize);
            chunks.Add((pos, data));
            pos += data.Length;
            if (p.BlockAlignedAfter)
                pos = AlignUp(pos, BlockSize);
        }

        byte[] img = new byte[pos];
        foreach (var (offset, data) in chunks)
            Array.Copy(data, 0, img, offset, data.Length);
        return img;
    }
}
