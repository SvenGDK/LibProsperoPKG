// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Produces the PS5 finalized image (\x7FFIH), in the "debug" variant
// (signed byte 0x00) used by consoles whose debug mode relaxes finalized-image verification.
//
// A finalized image is built from four consecutive segments:
// FIH / PFS / SC / SI:
//
//   FIH  [0x00000 .. 0x10000)                     header (LITTLE-endian fields) + finalization
//                                                  digest table. FIH offset (0) and FIH size
//                                                  (0x10000) are ALWAYS constant, as is the PFS
//                                                  offset (0x10000); only the sizes below vary.
//   PFS  [0x10000 .. 0x10000+pfs_image_size)      the shared, AES-XTS-encrypted outer PFS image.
//   SC   [pfs_end .. pfs_end+sc_size)             the embedded \x7FCNT metadata container; its own
//                                                  pfs_image_offset points back to the shared image
//                                                  at 0x10000.
//   SI   [sc_end .. EOF)                           a ZIP archive of install-time metadata
//                                                  (common/etc/*_meta_*.dat, pfsimage.xml,
//                                                  playgo-chunk.dat, config/<cid>/playgo-chunk.crc).
//
// The signed byte at offset 0x05 distinguishes the two finalized variants: 0x00 = debug,
// 0x80 = retail / submitted. This is THE single byte that separates a retail-submitted package
// from a debug one in a complete FIH .pkg file.
//
// The FIH header's structural fields are magic, signed byte, PFS image offset/size, and
// embedded-CNT/SC offset and size. The embedded CNT and shared PFS image are the output of
// ProsperoPkgBuilder, so the produced file is parsed and validated by ProsperoPkgReader
// (Type=FullDebug, embedded CNT round-trips). The FIH game-digest at 0x30/0x70/0xD0 is
// SHA3-256 of the plaintext outer superblock. The CNT package-digest self-seal at CNT+0xFE0
// is SHA3-256 of CNT[0:0xFE0]. The CNT GeneralDigests block and per-entry digest table are
// SHA3-256 of plaintext CNT regions and entries. The distinct FIH slot at 0xB0 is the
// nested-image-content digest: SHA3-256 of the uncompressed inner PFS image at its logical
// size. The CNT build path threads that exact preimage in. The standalone-finalize path has
// only a finished encrypted CNT, so it falls back to SHA3-256 of the outer image. The trailing
// SI ZIP is generated only when the caller passes one through the siArchive parameter; its
// container is deterministic and its keyed members are caller-supplied. A console in debug mode
// that does not enforce those keyed members accepts the image.

using System;
using System.Buffers.Binary;
using System.IO;

namespace LibProsperoPkg.PKG;

/// <summary>The finalized-image variant to emit.</summary>
public enum ProsperoFihVariant
{
    /// <summary>Debug finalized image (signed byte 0x00) for debug-mode consoles.</summary>
    Debug,

    /// <summary>Official finalized image (signed byte 0x80). The finalization digest table is
    /// debug/retail-key gated and not reproduced; emitting this is for structural tooling only.</summary>
    Official,
}

/// <summary>
/// Wraps a PS5 CNT metadata package into a finalized (FIH) image. See the file
/// header for the exact format and the reproduced fields.
/// </summary>
public static class ProsperoFihBuilder
{
    // CNT header field offsets (big-endian) reused to locate the shared PFS image.
    private const int CntPfsImageOffsetField = 0x410;
    private const int CntPfsImageSizeField = 0x418;

    /// <summary>
    /// Reads a CNT package and writes the corresponding finalized (FIH) image to
    /// <paramref name="fihOutputPath"/>. Returns the list of non-fatal warnings (notably that the
    /// finalization digest table is structurally populated for the selected variant).
    /// </summary>
    /// <param name="cntPath">Path to the PS5 CNT metadata package to finalize.</param>
    /// <param name="fihOutputPath">Path the finalized (FIH) image is written to.</param>
    /// <param name="variant">Finalized-image variant (Debug or Official).</param>
    /// <param name="logger">Optional progress callback.</param>
    /// <param name="siArchive">
    /// Optional trailing SI (install-metadata) segment to append after the embedded CNT, closing
    /// the four-segment FIH/PFS/SC/SI layout. Build it with <see cref="ProsperoSiArchive"/>. When
    /// null (the default) the image is written without an SI segment, exactly as before; a
    /// debug-mode console that does not enforce the SI accepts both forms.
    /// </param>
    /// <param name="siArchiveFactory">
    /// Optional alternative to <paramref name="siArchive"/>: a factory that receives the assembled,
    /// finalized mount image (FIH header + PFS image + embedded CNT — i.e. exactly the region the
    /// finalization process reduces for <c>playgo-chunk.crc</c>) and returns the SI bytes to append. This
    /// lets the SI be built with a deterministic <c>playgo-chunk.crc</c> derived from the finalized
    /// image. Ignored when <paramref name="siArchive"/> is non-null.
    /// </param>
    /// <param name="nestedImageDigest">
    /// Optional 32-byte FIH 0xB0 nested-image-content digest — SHA3-256 of the UNCOMPRESSED inner PFS
    /// image at its plain size. The CNT build
    /// path (<see cref="ProsperoPkgBuilder"/>) computes this while it still has the plaintext inner
    /// image and threads it in. When null, standalone finalize falls back to a best-effort SHA3-256
    /// of the outer image (it cannot recover the encrypted inner image on its own).
    /// </param>
    /// <param name="nestedImageSize">Plain (uncompressed) size of the inner PFS image, or 0 when not nwonly.</param>
    /// <param name="nestedMetaBaseBlocks">Inner mount metadata-base block index (MetaBaseLogical / block size), or 0.</param>
    /// <param name="nwonlyContentVersionHi">High 32 bits of the content-version word stamped into the FIH header.</param>
    /// <param name="nwonlyInnerContentInodes">Inner content-inode count (directories and files below uroot).</param>
    /// <param name="nwonlyAppFileCount">Application-payload file count for the FIH file-count field.</param>
    public static System.Collections.Generic.IReadOnlyList<string> BuildFromCnt(
        string cntPath, string fihOutputPath, ProsperoFihVariant variant = ProsperoFihVariant.Debug,
        Action<string>? logger = null, byte[]? siArchive = null,
        Func<byte[], byte[]>? siArchiveFactory = null, byte[]? nestedImageDigest = null,
        long nestedImageSize = 0, long nestedMetaBaseBlocks = 0,
        uint nwonlyContentVersionHi = 0, int nwonlyInnerContentInodes = 0, int nwonlyAppFileCount = 0)
    {
        ArgumentException.ThrowIfNullOrEmpty(cntPath);
        ArgumentException.ThrowIfNullOrEmpty(fihOutputPath);
        var log = logger ?? (_ => { });
        var warnings = new System.Collections.Generic.List<string>();

        byte[] cnt = File.ReadAllBytes(cntPath);
        if (cnt.Length < ProsperoPkgLayout.HeaderSize ||
            cnt[0] != ProsperoPkgLayout.CntMagic[0] || cnt[1] != ProsperoPkgLayout.CntMagic[1] ||
            cnt[2] != ProsperoPkgLayout.CntMagic[2] || cnt[3] != ProsperoPkgLayout.CntMagic[3])
            throw new InvalidDataException("Input is not a PS5 CNT metadata package.");

        ulong pfsImageOffset = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(CntPfsImageOffsetField));
        ulong pfsImageSize = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(CntPfsImageSizeField));
        if (pfsImageOffset == 0 || pfsImageSize == 0 ||
            pfsImageOffset + pfsImageSize > (ulong)cnt.Length)
            throw new InvalidDataException("CNT package has no embedded PFS image to finalize.");

        // Split the CNT into its metadata blob (header + entries + body, everything before the
        // image) and the shared encrypted PFS image.
        int metaLen = (int)pfsImageOffset;
        byte[] metadata = new byte[metaLen];
        Array.Copy(cnt, 0, metadata, 0, metaLen);
        byte[] image = new byte[(int)pfsImageSize];
        Array.Copy(cnt, (int)pfsImageOffset, image, 0, (int)pfsImageSize);

        // In the finalized image the embedded CNT's pfs_image_offset must point at the shared
        // image stored at the start of the body region (FIH offset 0x10000).
        BinaryPrimitives.WriteUInt64BigEndian(metadata.AsSpan(CntPfsImageOffsetField),
            ProsperoPkgLayout.FihHeaderRegionSize);

        ulong embeddedCntOffset = (ulong)ProsperoPkgLayout.FihHeaderRegionSize + pfsImageSize;
        byte[] header = BuildFihHeaderBlock(variant, pfsImageSize, embeddedCntOffset, image, warnings,
            nestedImageDigest: nestedImageDigest, nestedImageSize: nestedImageSize,
            nestedMetaBaseBlocks: nestedMetaBaseBlocks,
            nwonlyContentVersionHi: nwonlyContentVersionHi,
            nwonlyInnerContentInodes: nwonlyInnerContentInodes,
            nwonlyAppFileCount: nwonlyAppFileCount);

        log($"Writing finalized {(variant == ProsperoFihVariant.Debug ? "debug" : "official")} (FIH) image: " +
            $"image=0x{pfsImageSize:X} @0x{ProsperoPkgLayout.FihHeaderRegionSize:X}, CNT @0x{embeddedCntOffset:X}.");

        using (var fs = new FileStream(fihOutputPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            fs.Write(header, 0, header.Length);                 // 0x00000 .. 0x10000
            fs.Write(image, 0, image.Length);                   // 0x10000 .. +pfs_image_size
            fs.Write(metadata, 0, metadata.Length);             // embedded CNT

            // The trailing SI segment may be supplied directly, or built on demand from the
            // finalized mount image (header + image + metadata) so its playgo-chunk.crc is the
            // CRC-32C reduction produced for the finalized image.
            byte[]? si = siArchive;
            if (si is null && siArchiveFactory is not null)
            {
                byte[] mountImage = new byte[header.Length + image.Length + metadata.Length];
                Buffer.BlockCopy(header, 0, mountImage, 0, header.Length);
                Buffer.BlockCopy(image, 0, mountImage, header.Length, image.Length);
                Buffer.BlockCopy(metadata, 0, mountImage, header.Length + image.Length, metadata.Length);
                si = siArchiveFactory(mountImage);
            }
            if (si is { Length: > 0 })
            {
                fs.Write(si, 0, si.Length);                     // trailing SI segment
                log($"Appended SI segment: 0x{si.Length:X} bytes after the embedded CNT.");
            }
        }

        warnings.Add(
            "The finalized image carries a valid embedded CNT and PFS image: the game-digest " +
            "(0x30/0x70/0xD0) is SHA3-256 of the plaintext outer superblock, the CNT package-digest " +
            "self-seal sits at CNT+0xFE0, and the GeneralDigests block (content/header/system/param/" +
            "playgo/target) plus the per-entry digest table are SHA3-256 of the plaintext CNT regions " +
            "and entries. " +
            (nestedImageDigest is { Length: 32 }
                ? "The FIH 0xB0 slot holds the nested-image-content digest from the build pass: " +
                  "SHA3-256 of the uncompressed inner PFS image at its plain size."
                : "The FIH 0xB0 slot holds a fallback SHA3-256 of the outer image: a standalone finalize " +
                  "has only the encrypted CNT and cannot recover the plaintext inner image; the CNT build " +
                  "path emits the nested-image-content digest.") +
            " The image targets debug-mode consoles.");
        log("Done (FIH).");
        return warnings;
    }

    /// <summary>
    /// Builds the 0x10000-byte finalized-image (FIH) header block. This is a SHARED, cycle-free helper used
    /// by both the standalone FIH writer (<see cref="BuildFromCnt"/>) and the PS5 CNT builder so the
    /// fixed-info-digest (SHA3-256 of this block) is self-consistent. The image-content slot 0xB0 is the
    /// nested-image-content digest: when <paramref name="nestedImageDigest"/> is supplied (the CNT build path,
    /// which has the uncompressed inner image in hand) it is written verbatim as SHA3-256 of the
    /// UNCOMPRESSED inner PFS image at its plain size; when it
    /// is null (the standalone finalize path, which only has the finished encrypted CNT) it falls back to the
    /// best-effort SHA3-256(outer image). Cycle-free either way: both inputs are final before the CNT digest
    /// table is computed (using the embedded CNT metadata here would create a digest cycle).
    /// </summary>
    internal static byte[] BuildFihHeaderBlock(
        ProsperoFihVariant variant, ulong pfsImageSize, ulong embeddedCntOffset,
        byte[] image, System.Collections.Generic.List<string>? warnings = null,
        byte[]? nestedImageDigest = null, long nestedImageSize = 0, long nestedMetaBaseBlocks = 0,
        uint nwonlyContentVersionHi = 0, int nwonlyInnerContentInodes = 0, int nwonlyAppFileCount = 0)
    {
        byte[] h = new byte[ProsperoPkgLayout.FihHeaderRegionSize];

        // ---- Structural fields (little-endian). ----
        h[0] = ProsperoPkgLayout.FihMagic[0];
        h[1] = ProsperoPkgLayout.FihMagic[1];
        h[2] = ProsperoPkgLayout.FihMagic[2];
        h[3] = ProsperoPkgLayout.FihMagic[3];
        h[4] = 0x01;
        h[ProsperoPkgLayout.FihSignedByteOffset] = (byte)(variant == ProsperoFihVariant.Official ? 0x80 : 0x00);
        h[6] = 0x03;
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(0x08), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(ProsperoPkgLayout.FihPfsImageOffsetField), (ulong)ProsperoPkgLayout.FihHeaderRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(ProsperoPkgLayout.FihPfsImageSizeField), pfsImageSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x28), (ulong)ProsperoPkgLayout.FihHeaderRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(ProsperoPkgLayout.FihEmbeddedCntOffsetField), embeddedCntOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x60), (ulong)ProsperoPkgLayout.FihHeaderRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x68), 0x800000000000UL);

        // 0x50 = the inner mount's data-region block count (= metaBase block index = MetaBaseLogical / 64KiB).
        // The installer's transfer reads this to size the mount's data region; a zero value is rejected.
        if (nestedMetaBaseBlocks > 0)
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(ProsperoPkgLayout.FihDataRegionBlockCountField), (ulong)nestedMetaBaseBlocks);

        // ---- Finalized-image digest table. ----
        // game-digest == sblock-digest == SHA3-256(plaintext outer superblock block, 0x10000 bytes),
        // stored three times at 0x30/0x70/0xD0.
        // The FIH also records the
        // superblock's absolute offset (0x20) and size (0x28) so the loader can locate the hashed
        // block. See ProsperoImageDigests for the full digest construction.
        var (sbOffsetInImage, gameDigest) = ProsperoImageDigests.ComputeSblockDigestFromImage(image);
        if (sbOffsetInImage >= 0 && gameDigest is not null)
        {
            ulong sbAbsoluteOffset = (ulong)ProsperoPkgLayout.FihHeaderRegionSize + (ulong)sbOffsetInImage;
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x20), sbAbsoluteOffset);
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x28), (ulong)ProsperoImageDigests.BlockSize);
            CopyDigest(h, 0x30, gameDigest);
            CopyDigest(h, 0x70, gameDigest);
            CopyDigest(h, 0xD0, gameDigest);

            // ---- Outer-PFS / nested-image accounting. ----
            // The nwonly outer PFS uses the "data-first" layout
            //   [pfs_image.dat blocks][naps_pkg_layout.dat block][superblock][structural metadata...],
            // so the plaintext superblock sits exactly one block (the naps file) after the inner image.
            //   0x90 inner-image (pfs_image.dat) block count = sbBlockIndex - 1
            //   0x94 = 0x98 inner content-inode count         = dirs+files below uroot (nwonly), threaded in
            //   0x9C content-version echo                     = contentVersion major BCD << 24
            //   0xA0 block-aligned inner-image size           = 0x90 * blockSize
            //   0xA8 naps_pkg_layout.dat (map[0xD]) length    = nestedImageSize (the 0xB0 digest preimage length)
            //   0xB0 nested-image-content digest              = SHA3-256(naps_pkg_layout.dat) [written below]
            //   0xF0 app-payload (non-sce_sys) file count / 0xF8 flat-path-table accounting (=2)
            int blockSize = ProsperoPkgLayout.FihHeaderRegionSize;
            long sbBlockIndex = (long)sbOffsetInImage / blockSize;
            long totalBlocks = (long)pfsImageSize / blockSize;
            if (sbBlockIndex >= 1 && (long)sbOffsetInImage % blockSize == 0 &&
                (long)pfsImageSize % blockSize == 0 && totalBlocks > sbBlockIndex)
            {
                bool nwonly = nwonlyInnerContentInodes > 0;
                uint innerBlocks = (uint)(sbBlockIndex - 1);
                // 0x94/0x98: the inner content-inode count for the data-first nwonly image: dirs and files
                // below uroot. The legacy non-nwonly path keeps its outer meta-block count.
                uint metaOrInodes = nwonly ? (uint)nwonlyInnerContentInodes : (uint)(totalBlocks - innerBlocks);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ProsperoPkgLayout.FihInnerImageBlockCountField), innerBlocks);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ProsperoPkgLayout.FihMetaBlockCountField), metaOrInodes);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ProsperoPkgLayout.FihMetaBlockCountMirrorField), metaOrInodes);
                BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(ProsperoPkgLayout.FihInnerImageSizeField), (ulong)innerBlocks * (ulong)blockSize);

                // 0x9C: content-version echo (high 32 bits of the param/content_ver u64; major BCD in the top byte).
                if (nwonlyContentVersionHi != 0)
                    BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ProsperoPkgLayout.FihContentVersionField), nwonlyContentVersionHi);

                // 0xA8: naps_pkg_layout.dat length (= ctx.0x14e0 = size of map[0xD], the 0xB0 digest preimage).
                if (nestedImageSize > 0)
                    BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(ProsperoPkgLayout.FihInnerImageLogicalSizeField), (ulong)nestedImageSize);

                // 0xF0/0xF8: outer-PFS inode accounting. 0xF0 = app-payload (non-sce_sys) file count;
                // 0xF8 = flat-path-table accounting value.
                uint outerFileCount = nwonly && nwonlyAppFileCount > 0 ? (uint)nwonlyAppFileCount : ProsperoPkgLayout.FihOuterFileCount;
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ProsperoPkgLayout.FihOuterFileCountField), outerFileCount);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ProsperoPkgLayout.FihFlatPathTableBlockCountField), ProsperoPkgLayout.FihFlatPathTableBlockCount);
            }

            warnings?.Add(
                "FIH game-digest (0x30/0x70/0xD0) is SHA3-256 of the plaintext outer " +
                "superblock; the superblock offset/size are recorded at 0x20/0x28. The CNT package-digest " +
                "(CNT+0xFE0), content/header/system/param/playgo GeneralDigests and the per-entry digest " +
                "table are SHA3-256 of the plaintext CNT regions and entries. The FIH " +
                "0xB0 slot holds the nested-image-content digest: SHA3-256 of the uncompressed inner PFS " +
                "image when the builder threads it in, otherwise a fallback " +
                "SHA3-256 of the outer image.");
        }
        else
        {
            // No data-first plaintext superblock in this image (e.g. the legacy zlib inner path):
            // fall back to a well-formed, parseable best-effort game-digest.
            byte[] fallback = ProsperoImageDigests.Sha3_256(image);
            CopyDigest(h, 0x30, fallback);
            CopyDigest(h, 0x70, fallback);
            CopyDigest(h, 0xD0, fallback);
            warnings?.Add(
                "FIH game-digest filled best-effort: no plaintext outer superblock was found in the " +
                "image (the SHA3-256(superblock) path applies to the nwonly outer-PFS image).");
        }

        // The distinct 0xB0 slot is the nested-image-content digest:
        // 0xB0 = SHA3-256(map[0xD]) where map[0xD] is the naps_pkg_layout.dat content. FIH 0xA8
        // is its length. The CNT build path threads that digest in via nestedImageDigest; the standalone
        // finalize path, which only has the finished encrypted CNT, falls back to SHA3-256(outer image).
        // Cycle-free either way: the naps is final before the CNT digest table is computed.
        CopyDigest(h, 0xB0, nestedImageDigest is { Length: 32 }
            ? nestedImageDigest
            : ProsperoImageDigests.Sha3_256(image));

        return h;
    }

    private static void CopyDigest(byte[] dst, int offset, byte[] digest32)
    {
        Array.Copy(digest32, 0, dst, offset, Math.Min(32, digest32.Length));
    }

}
