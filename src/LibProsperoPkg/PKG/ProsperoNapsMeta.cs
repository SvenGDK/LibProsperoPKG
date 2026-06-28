// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Producer for the NAPS metadata records (`common/etc/naps_meta_*.dat`) that reference tool
// streams into the SI (install-metadata) segment of a finalized image for the streaming output
// formats (`--oformat nwonly`). The NAPS record dispatcher
// (reference routine, "%s%s%s%s%s%snaps_meta_%d.dat" at the reference string location) routes each record id to a stored
// member; the content this type produces was decoded byte-for-byte from the reference debug packages.
//
// records and external inputs:
// * naps_meta_300/301/302/308.dat -> reproduced byte-exact. All four ids carry the same 48-byte
// plaintext descriptor record (validated byte-identical within every package). The record is six
// little-endian u64 fields and is fully derived from the finalized inner-image geometry (no key,
// no console secret), so it is produced exactly here and gated against three reference debug packages.
// * naps_meta_18.dat -> not reproduced. It is a keyed/encrypted per-package NAPS metric blob
// (3440 B for Downloads/InternetBrowser, 7936 B for DebugSettings) whose first 16 bytes are a
// constant across all packages (1A E5 3E 75 C0 58 78 9C CE 8E 03 A8 78 15 A6 8B) followed by
// AES-block-structured, per-package-divergent ciphertext. It is a reference finalization product with
// no off-console producer in any available binary; it is accepted/emitted verbatim, never fabricated.
//
// Decoded naps_meta_300 RECORD (48 bytes, all values little-endian; ground truth = the three debug
// packages in TestFiles/PS5/PKG/Debug/extracted/*/sce_suppl/common/etc/):
// 0x00 u64 = 0 reserved (record start offset)
// 0x08 u64 = 0 reserved
// 0x10 u64 = R inner-image data-region size (= innerImageSize - 0x10000)
// 0x18 u64 = 0x3E9 (1001) constant NAPS-meta kind/version id
// 0x20 u64 = R inner-image data-region size (repeated)
// 0x28 u64 = 0x10000 PFS block size (64 KiB)
// R validated: DebugSettings R=0x4C0000 (innerImageSize 0x4D0000 - 0x10000); Downloads/InternetBrowser
// R=0x40000 (innerImageSize 0x50000 - 0x10000). R equals the nested-image <metadata offset> reported
// by the package's own pfsimage.xml, i.e. the size of the compressed inner-image content that precedes
// the inner image's own metadata block.

using System;
using System.Buffers.Binary;

namespace LibProsperoPkg.PKG;

/// <summary>
/// Byte-exact producer for the PS5 <c>naps_meta_*.dat</c> records emitted into the SI
/// segment of a <c>--oformat nwonly</c> finalized image. The 48-byte <c>naps_meta_300/301/302/308</c>
/// descriptor is reproduced exactly from the inner-image geometry; <c>naps_meta_18.dat</c> is a keyed
/// blob and is accepted as an external input (see the file header). See <see cref="ProsperoSiArchive"/>.
/// </summary>
public static class ProsperoNapsMeta
{
    /// <summary>On-disk size of the <c>naps_meta_300/301/302/308</c> descriptor record, in bytes.</summary>
    public const int Meta300Length = 48;

    /// <summary>
    /// Constant NAPS-meta kind/version id stored at offset 0x18 of every <c>naps_meta_300</c> record
    /// (<c>0x3E9</c> = 1001). Validated as identical across all reference debug packages.
    /// </summary>
    public const ulong Meta300KindId = 0x3E9;

    /// <summary>PFS block size (64 KiB) stored at offset 0x28 of the <c>naps_meta_300</c> record.</summary>
    public const ulong PfsBlockSize = 0x10000;

    /// <summary>The four byte-identical <c>naps_meta_*</c> ids that share the 48-byte descriptor.</summary>
    public static ReadOnlySpan<int> Meta300Ids => [300, 301, 302, 308];

    /// <summary>
    /// Builds the byte-exact 48-byte <c>naps_meta_300</c> descriptor (also used verbatim for ids 301,
    /// 302 and 308) from the inner-image data-region size.
    /// </summary>
    /// <param name="innerImageDataRegionSize">
    /// The inner-image data-region size <c>R</c> (offsets 0x10 and 0x20): the size of the compressed
    /// inner-image content that precedes the inner image's own metadata block. Equals
    /// <c>innerImageSize - 0x10000</c> and the nested-image metadata offset reported in pfsimage.xml.
    /// </param>
    /// <returns>A fresh 48-byte array containing the descriptor.</returns>
    public static byte[] BuildMeta300(ulong innerImageDataRegionSize)
    {
        byte[] record = new byte[Meta300Length];
        Span<byte> s = record;
        // 0x00, 0x08 already zero.
        BinaryPrimitives.WriteUInt64LittleEndian(s.Slice(0x10, 8), innerImageDataRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(s.Slice(0x18, 8), Meta300KindId);
        BinaryPrimitives.WriteUInt64LittleEndian(s.Slice(0x20, 8), innerImageDataRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(s.Slice(0x28, 8), PfsBlockSize);
        return record;
    }

    /// <summary>
    /// Builds the <c>naps_meta_300</c> descriptor from the full block-aligned inner-image size (the
    /// value the finalized-image header carries at offset 0xA0). Equivalent to
    /// <see cref="BuildMeta300(ulong)"/> with <c>innerImageSize - 0x10000</c>.
    /// </summary>
    /// <param name="innerImageSize">Block-aligned inner-image size; must be at least one block.</param>
    public static byte[] BuildMeta300FromInnerImageSize(ulong innerImageSize)
    {
        if (innerImageSize < PfsBlockSize)
            throw new ArgumentOutOfRangeException(nameof(innerImageSize),
                $"inner-image size 0x{innerImageSize:X} is smaller than one 0x{PfsBlockSize:X} block");
        return BuildMeta300(innerImageSize - PfsBlockSize);
    }

}
