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
// The FIH header's structural fields (magic, signed byte, PFS image offset/size,
// embedded-CNT/SC offset and size) are reproduced exactly, and the embedded CNT + shared PFS image
// are the byte-for-byte output of ProsperoPkgBuilder, so the produced file is fully
// parsed and validated by ProsperoPkgReader (Type=FullDebug, embedded CNT round-trips). What IS
// reproduced byte-exact: the FIH game-digest at 0x30/0x70/0xD0 (SHA3-256 of the plaintext outer
// superblock); the CNT package-digest self-seal at CNT+0xFE0 (SHA3-256 of CNT[0:0xFE0],
// ProsperoImageDigests.ComputePackageDigest); and the entire CNT GeneralDigests block —
// content-digest, header-digest, system-digest, param-digest, playgo-digest and the target slot —
// plus the per-entry digest table, all SHA3-256 of plaintext CNT regions/entries
// (ProsperoImageDigests + ProsperoPkgBuilder.ComputeGeneralDigests), validated against reference
// output. The distinct FIH slot at 0xB0 is the nested-image-content digest: SHA3-256 of the
// UNCOMPRESSED inner (nested) PFS
// image at its plain/logical size (NOT the outer image, NOT the stored/compressed pfs_image.dat);
// the CNT build path threads that exact preimage in, so the value is self-consistent with our own
// encoder (it matches reference output once the inner image is byte-identical). What
// is NOT emitted byte-faithfully: (1) the standalone-finalize path (BuildFromCnt) has only a finished
// encrypted CNT, so it cannot recover the plaintext inner image and falls back to a best-effort 0xB0
// over the outer image; (2) the trailing SI ZIP, generated only when the caller
// passes one (build it with ProsperoSiArchive and pass it via the siArchive parameter) — its
// container is reproducible but its keyed members are console products. A console in debug mode that
// does not enforce these will accept the image.

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
    /// finalization digest table is not byte-identical to a retail image).
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
    /// reference process reduces for <c>playgo-chunk.crc</c>) and returns the SI bytes to append. This
    /// lets the SI be built with a byte-exact, reproducible <c>playgo-chunk.crc</c> derived from the
    /// finalized image. Ignored when <paramref name="siArchive"/> is non-null.
    /// </param>
    /// <param name="nestedImageDigest">
    /// Optional 32-byte FIH 0xB0 nested-image-content digest — SHA3-256 of the UNCOMPRESSED inner PFS
    /// image at its plain size. The CNT build
    /// path (<see cref="ProsperoPkgBuilder"/>) computes this while it still has the plaintext inner
    /// image and threads it in. When null, standalone finalize falls back to a best-effort SHA3-256
    /// of the outer image (it cannot recover the encrypted inner image on its own).
    /// </param>
    public static System.Collections.Generic.IReadOnlyList<string> BuildFromCnt(
        string cntPath, string fihOutputPath, ProsperoFihVariant variant = ProsperoFihVariant.Debug,
        Action<string>? logger = null, byte[]? siArchive = null,
        Func<byte[], byte[]>? siArchiveFactory = null, byte[]? nestedImageDigest = null)
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
            nestedImageDigest: nestedImageDigest);

        log($"Writing finalized {(variant == ProsperoFihVariant.Debug ? "debug" : "official")} (FIH) image: " +
            $"image=0x{pfsImageSize:X} @0x{ProsperoPkgLayout.FihHeaderRegionSize:X}, CNT @0x{embeddedCntOffset:X}.");

        using (var fs = new FileStream(fihOutputPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            fs.Write(header, 0, header.Length);                 // 0x00000 .. 0x10000
            fs.Write(image, 0, image.Length);                   // 0x10000 .. +pfs_image_size
            fs.Write(metadata, 0, metadata.Length);             // embedded CNT

            // The trailing SI segment may be supplied directly, or built on demand from the
            // finalized mount image (header + image + metadata) so its playgo-chunk.crc is the
            // byte-exact CRC-32C reduction produced for the finalized image.
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
            "FIH writer reproduces the finalized-image structure and an exact, valid embedded " +
            "CNT + PFS image, including the byte-exact game-digest (0x30/0x70/0xD0), the CNT package-digest " +
            "self-seal (CNT+0xFE0), and the full GeneralDigests block (content/header/system/param/playgo/" +
            "target) plus the per-entry digest table — all SHA3-256 of plaintext CNT regions/entries, " +
            "reproduced byte-exact and validated against reference output. " +
            (nestedImageDigest is { Length: 32 }
                ? "The FIH 0xB0 slot is the nested-image-content digest threaded in from the build pass: " +
                  "SHA3-256 of the UNCOMPRESSED inner PFS image at its plain size, self-consistent with our encoder."
                : "The FIH 0xB0 slot here is a best-effort SHA3-256 of the outer image: standalone finalize " +
                  "has only the encrypted CNT, so it cannot recover the plaintext inner image the byte-exact " +
                  "0xB0 hashes; the CNT build path emits the exact nested-image-content digest.") +
            " The image is accepted by debug-mode consoles.");
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
        byte[]? nestedImageDigest = null)
    {
        byte[] h = new byte[ProsperoPkgLayout.FihHeaderRegionSize];

        // ---- Structural fields (reproduced exactly; little-endian). ----
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

        // ---- Finalized-image digest table. ----
        // game-digest == sblock-digest == SHA3-256(plaintext outer superblock block, 0x10000 bytes),
        // stored three times at 0x30/0x70/0xD0. Validated byte-exact against reference output.
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

            // ---- Outer-PFS block accounting, validated against reference output. The nwonly outer PFS uses the
            // "data-first" layout [pfs_image.dat blocks][naps_pkg_layout.dat block][superblock]
            // [structural metadata...], so the plaintext superblock sits exactly one block (the naps
            // file) after the inner image. From its image-relative block index we recover:
            //   0x90 inner-image (pfs_image.dat) block count = sbBlockIndex - 1
            //   0xA0 block-aligned inner-image size          = 0x90 * blockSize
            //   0x94 == 0x98 outer metadata block count      = totalBlocks - 0x90
            // Invariant 0x90 + 0x94 == pfsImageSize / blockSize holds on all three samples
            // (DS 0x4d+7=0x54, DL/IB 5+6=0xb).
            int blockSize = ProsperoPkgLayout.FihHeaderRegionSize;
            long sbBlockIndex = (long)sbOffsetInImage / blockSize;
            long totalBlocks = (long)pfsImageSize / blockSize;
            if (sbBlockIndex >= 1 && (long)sbOffsetInImage % blockSize == 0 &&
                (long)pfsImageSize % blockSize == 0 && totalBlocks > sbBlockIndex)
            {
                uint innerBlocks = (uint)(sbBlockIndex - 1);
                uint metaBlocks = (uint)(totalBlocks - innerBlocks);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ProsperoPkgLayout.FihInnerImageBlockCountField), innerBlocks);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ProsperoPkgLayout.FihMetaBlockCountField), metaBlocks);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ProsperoPkgLayout.FihMetaBlockCountMirrorField), metaBlocks);
                BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(ProsperoPkgLayout.FihInnerImageSizeField), (ulong)innerBlocks * (ulong)blockSize);
            }

            warnings?.Add(
                "FIH game-digest (0x30/0x70/0xD0) is byte-exact: SHA3-256 of the plaintext outer " +
                "superblock; the superblock offset/size are recorded at 0x20/0x28. The CNT package-digest " +
                "(CNT+0xFE0), content/header/system/param/playgo GeneralDigests and the per-entry digest " +
                "table are all reproduced byte-exact (SHA3-256 of plaintext CNT regions/entries). The FIH " +
                "0xB0 slot is the nested-image-content digest: SHA3-256 of the uncompressed inner PFS image " +
                "when the builder threads it in, else a best-effort " +
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
                "image (the byte-exact SHA3-256(superblock) path applies to the nwonly outer-PFS image).");
        }

        // The distinct 0xB0 slot is the nested-image-content digest:
        // 0xB0 = SHA3-256(map[0xD]) where map[0xD] is the UNCOMPRESSED nested (inner) PFS image
        // at its plain/logical size (*(ctx+0x14e0) bytes) — NOT the outer image and NOT the stored/compressed
        // pfs_image.dat. The CNT build path threads that exact preimage's digest in via nestedImageDigest; the
        // standalone finalize path (which only has the finished encrypted CNT) cannot recover the plaintext
        // inner image and falls back to SHA3-256(outer image). Cycle-free either way: both inputs are final
        // before the CNT digest table is computed. Self-consistent with our encoder and matches
        // reference output once the inner image is byte-identical.
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
