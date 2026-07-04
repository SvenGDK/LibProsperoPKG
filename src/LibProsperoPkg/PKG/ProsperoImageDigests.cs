// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PS5 finalized-image / CNT digest algorithms.
//
// The single digest primitive is SHA3-256, not SHA-256. Each named digest below hashes a
// plaintext-accessible region and is reproducible off-console. Each is recorded in
// sce_suppl/.../pfsimage.xml:
//
// game-digest == sblock-digest = SHA3-256( plaintext outer superblock block, 0x10000 bytes )
// Stored in the FIH header at 0x30, 0x70 and 0xD0 (three copies), in the CNT image-digest
// block (entry 0x0080) at +0x40 and +0x180, and in pfsimage.xml as <game-digest> and
// <sblock-digest>. The FIH locates the superblock via its own offset/size fields at
// 0x20 (absolute superblock offset) / 0x28 (0x10000). The
// superblock is the data-first outer-PFS metadata block (magic 0x0b2a3301 @ +8, version 2),
// left PLAINTEXT on disk, so SHA3-256 of it reproduces the stored digest exactly.
//
// fixed-info-digest = SHA3-256( FIH header block, 0x10000 bytes ) (pfsimage.xml mount-image)
// body-digest = SHA3-256( CNT body region [body-offset .. body-offset+body-size) )
// <per-entry digest> = SHA3-256( CNT entry payload ) for every CNT entry, stored in the CNT
// digest table (entry id 0x0001, count*32 bytes); the slot for the digest-table entry itself
// is left all-zero (it cannot hash itself). This covers all 13 CNT entries. param-digest is
// exactly this for the param.json entry (id 0x2000).
//
// package-digest = SHA3-256( CNT[0 : 0xFE0] ) stored at CNT+0xFE0
// The package-digest is a self-seal over the whole CNT header: SHA3-256 of the first 0xFE0
// bytes of the \x7fCNT container, written back into the header at +0xFE0. pfsimage.xml records it
// as <package-digest>. Because it seals the CNT header, it follows
// automatically once that header is byte-exact — the CNT builder produces it directly via
// ComputePackageDigest (SHA3-256). See ComputePackageDigest.
//
// CNT-header rollup digest = SHA3-256( CNT[off : off+size] ) stored at CNT+0x100
// where off = BE64 @ (CNT+0x20) and size = BE32 @ (CNT+0x1c) (= 0x2000 / 0x18A0),
// i.e. SHA3-256 of the CNT digest/entry-table region. This is what the CNT sub-region verifier
// recomputes and checks. See
// ComputeCntHeaderRollupDigest.
//
// content-digest = SHA3-256( CNT[0x40:0x78] ‖ game-digest(32) ‖ major-param-digest(32, all-zero) )
// CNT[0x40:0x78] (0x38 bytes) is the CNT header's content descriptor: content_id (36 bytes @0x40),
// 12 reserved zero bytes, drm_type (u32 @0x70) and content_type (u32 @0x74). The game-digest is
// appended when the package carries a game image (it does for nwonly); the major-param-digest slot
// is 32 zero bytes. Stored in the CNT GeneralDigests block (entry id 0x0080) at +0x20 and recorded
// as pfsimage.xml <content-digest>.
// header-digest = SHA3-256( CNT[0x00:0x40] ‖ CNT[0x400:0x480] )
// The CNT header prefix (0x40 bytes) concatenated with the 0x80-byte mount descriptor at CNT+0x400.
// The mount descriptor's pfs_image_offset field (CNT+0x410) must be the FINAL FIH-relative value
// 0x10000 (the value the FIH writer stamps into the embedded CNT), not the standalone physical
// image offset — see FihRelativeImageOffset and the builder's @0x410 override. Stored at GeneralDigests
// +0x60; recorded as pfsimage.xml <header-digest>.
// system-digest = SHA3-256( concat of per-entry digests of the system-media CNT entries, ascending id )
// e.g. SHA3-256( SHA3-256(icon0.png payload) ‖ SHA3-256(icon0.dds payload) ). Stored at GeneralDigests
// +0x80; pfsimage.xml <system-digest> (icon0.png id 0x1200 + icon0.dds id 0x1280).
// playgo-digest = SHA3-256( concat of per-entry digests of the playgo CNT entries, ascending id )
// SHA3-256( SHA3-256(playgo-chunk.dat) ‖ SHA3-256(playgo-hash-table.dat) ‖ SHA3-256(playgo-ficm.dat) ).
// Stored at GeneralDigests +0xE0 (ids 0x1001 / 0x2010 / 0x2011).
// param-digest = SHA3-256( param.json CNT entry payload ) (= the per-entry digest of id 0x2000).
// Stored at GeneralDigests +0xC0.
// target-digest = copy of game-digest. Stored at GeneralDigests +0x180 (slot 11).
//
// The GeneralDigests block (CNT entry id 0x0080, found in the CNT at the entry's data offset): u16 unk1
// = 0xD256, u16 type = 0x0102, 24 reserved bytes, u32 BE set_digests, then 14 × 32-byte
// slots {Content, Game, Header, System, MajorParam, Param, Playgo, Trophy, Manual, Keymap, Origin, Target,
// OriginGame, TargetGame}. For the nwonly debug package set_digests = 0x10DE (bits Content|Game|Header|System|
// Param|Playgo|Target) and the entry length is 0x1E0 (0x20 + 14×0x20). Every populated slot above reproduces
// byte-exact from the finished on-disk CNT — the digests are computed from plaintext-accessible CNT header
// regions and CNT entry payloads, so the whole block is producible by a managed library.
//
// Note. A block/file hash search (whole 0x10000 blocks and whole extracted files) cannot recover the
// content/header/system/playgo digests: content/header are SHA3 of specific CNT-header sub-slices, and
// system/playgo are SHA3 of a concatenation of per-entry digests — none is a single block or file. The
// structured preimages above are computed directly from the plaintext CNT header regions and entry
// payloads. The only FIH slot that is best-effort is 0xB0 (a nested-image-content hash); a full
// from-scratch build cannot byte-match a specific input because the managed Kraken inner encoder is not
// byte-identical to any given encoder (different pfs_image ⇒ different superblock ⇒ different
// game/content/header/package digests). The formulas here are exact and self-consistent.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace LibProsperoPkg.PKG;

/// <summary>
/// PS5 finalized-image and CNT digest algorithms. The one primitive is SHA3-256;
/// see the file header for the exact preimage of each digest and the boundary of what is and is
/// not reproducible off-console. All methods are managed (SHA-3, .NET 10).
/// </summary>
public static class ProsperoImageDigests
{
    /// <summary>Outer-PFS block size and superblock size (0x10000).</summary>
    public const int BlockSize = 0x10000;

    /// <summary>Length of every digest (SHA3-256, 32 bytes).</summary>
    public const int DigestSize = 32;

    /// <summary>The CNT entry id whose payload is the per-entry digest table itself.</summary>
    public const int DigestTableEntryId = 0x0001;

    /// <summary>
    /// Size of the CNT-header region the package-digest seals: SHA3-256(CNT[0 : 0xFE0]) is stored back
    /// into the header at <see cref="PackageDigestStoredOffset"/>.
    /// </summary>
    public const int PackageDigestRegionSize = 0xFE0;

    /// <summary>Offset in the CNT header where the package-digest (the 0xFE0 self-seal) is stored.</summary>
    public const int PackageDigestStoredOffset = 0xFE0;

    /// <summary>Offset in the CNT header where the CNT-header rollup digest is stored.</summary>
    public const int CntHeaderRollupStoredOffset = 0x100;

    // CNT header fields that locate the rollup preimage: size is BE32 @ +0x1c, offset is BE64 @ +0x20.
    private const int CntRollupSizeFieldOffset = 0x1c;
    private const int CntRollupOffsetFieldOffset = 0x20;

    /// <summary>
    /// CNT GeneralDigests block <c>type</c> for the PS5 nwonly debug package: a full 14-slot digest table
    /// (entry length 0x1E0). Written little-endian after the 0xD256 marker.
    /// </summary>
    public const ushort GeneralDigestsTypeFull = 0x0102;

    /// <summary>
    /// The <c>set_digests</c> bitmask (BE u32 at GeneralDigests +0x1c) for the nwonly debug package:
    /// 0x10DE = Content|Game|Header|System|Param|Playgo|Target.
    /// </summary>
    public const uint GeneralDigestsSetNwonly = 0x10DE;

    /// <summary>
    /// The header-digest mount-descriptor region size (CNT[0x400 : 0x480], 0x80 bytes) that is concatenated
    /// after the CNT header prefix.
    /// </summary>
    public const int HeaderDigestMountDescriptorSize = 0x80;

    /// <summary>The CNT header prefix size (CNT[0x00 : 0x40]) hashed into the header-digest.</summary>
    public const int HeaderDigestPrefixSize = 0x40;

    /// <summary>The content descriptor region size (CNT[0x40 : 0x78]) hashed into the content-digest.</summary>
    public const int ContentDescriptorSize = 0x38;

    /// <summary>
    /// The FIH-relative pfs_image_offset (0x10000) the finalized image stamps into the embedded CNT's mount
    /// descriptor at CNT+0x410. The header-digest (and package-digest) preimage must use this value, not the
    /// standalone physical image offset.
    /// </summary>
    public const ulong FihRelativeImageOffset = 0x10000;

    /// <summary>Offset of the pfs_image_offset field inside the CNT mount descriptor (CNT+0x410).</summary>
    public const int CntPfsImageOffsetField = 0x410;


    // Outer superblock identity: version (u64 LE) == 2 at +0x00 and this 4-byte magic at +0x08.
    private static ReadOnlySpan<byte> SuperblockMagic => [0x0b, 0x2a, 0x33, 0x01];

    /// <summary>
    /// SHA3-256, the single PS5 PFS/finalized-image digest primitive. Throws on a runtime without
    /// SHA-3 (the whole PS5 path requires it).
    /// </summary>
    public static byte[] Sha3_256(ReadOnlySpan<byte> data)
    {
        if (!SHA3_256.IsSupported)
            throw new PlatformNotSupportedException(
                "SHA3-256 is required for PS5 finalized-image digests but is not available on this platform/runtime.");
        return SHA3_256.HashData(data);
    }

    /// <summary>
    /// Computes the game-digest / sblock-digest = SHA3-256 of the plaintext outer superblock block
    /// (0x10000 bytes). This is the value the FIH header stores at 0x30/0x70/0xD0.
    /// </summary>
    public static byte[] ComputeSblockDigest(ReadOnlySpan<byte> superblockBlock)
    {
        if (superblockBlock.Length != BlockSize)
            throw new ArgumentException($"Superblock block must be exactly 0x{BlockSize:X} bytes.", nameof(superblockBlock));
        return Sha3_256(superblockBlock);
    }

    /// <summary>Alias of <see cref="ComputeSblockDigest"/> (the FIH calls it the game-digest).</summary>
    public static byte[] ComputeGameDigest(ReadOnlySpan<byte> superblockBlock) => ComputeSblockDigest(superblockBlock);

    /// <summary>
    /// Computes the fixed-info-digest = SHA3-256 of the FIH header block (0x10000 bytes), as recorded
    /// recorded in <c>pfsimage.xml &lt;fixed-info-digest&gt;</c>.
    /// </summary>
    public static byte[] ComputeFixedInfoDigest(ReadOnlySpan<byte> fihHeaderBlock)
    {
        if (fihHeaderBlock.Length != BlockSize)
            throw new ArgumentException($"FIH header block must be exactly 0x{BlockSize:X} bytes.", nameof(fihHeaderBlock));
        return Sha3_256(fihHeaderBlock);
    }

    /// <summary>
    /// Computes the CNT body-digest = SHA3-256 of the container body region (the bytes from the CNT
    /// header's body-offset for body-size bytes), as recorded in <c>pfsimage.xml &lt;body-digest&gt;</c>.
    /// </summary>
    public static byte[] ComputeBodyDigest(ReadOnlySpan<byte> cntBody) => Sha3_256(cntBody);

    /// <summary>Computes a single CNT entry's digest = SHA3-256 of its payload.</summary>
    public static byte[] ComputeEntryDigest(ReadOnlySpan<byte> entryPayload) => Sha3_256(entryPayload);

    /// <summary>
    /// Computes the content-digest = SHA3-256( CNT[0x40:0x78] ‖ game-digest(32) ‖ major-param-digest(32) ),
    /// stored in the CNT GeneralDigests block at +0x20 and recorded as pfsimage.xml &lt;content-digest&gt;.
    /// </summary>
    /// <param name="contentDescriptor">CNT[0x40:0x78] (0x38 bytes): content_id + reserved + drm_type + content_type.</param>
    /// <param name="gameDigest">The game-digest (32 bytes). Appended only when <paramref name="includeGame"/> is true.</param>
    /// <param name="majorParamDigest">The major-param-digest (32 bytes; all-zero for nwonly). Always appended.</param>
    /// <param name="includeGame">Whether the package carries a game image (nwonly: true).</param>
    public static byte[] ComputeContentDigest(
        ReadOnlySpan<byte> contentDescriptor, ReadOnlySpan<byte> gameDigest,
        ReadOnlySpan<byte> majorParamDigest, bool includeGame)
    {
        if (contentDescriptor.Length != ContentDescriptorSize)
            throw new ArgumentException($"Content descriptor must be exactly 0x{ContentDescriptorSize:X} bytes.", nameof(contentDescriptor));
        if (includeGame && gameDigest.Length != DigestSize)
            throw new ArgumentException($"Game-digest must be exactly {DigestSize} bytes.", nameof(gameDigest));
        if (majorParamDigest.Length != DigestSize)
            throw new ArgumentException($"Major-param-digest must be exactly {DigestSize} bytes.", nameof(majorParamDigest));

        int len = ContentDescriptorSize + (includeGame ? DigestSize : 0) + DigestSize;
        Span<byte> pre = len <= 256 ? stackalloc byte[len] : new byte[len];
        int p = 0;
        contentDescriptor.CopyTo(pre[p..]); p += ContentDescriptorSize;
        if (includeGame) { gameDigest.CopyTo(pre[p..]); p += DigestSize; }
        majorParamDigest.CopyTo(pre[p..]);
        return Sha3_256(pre);
    }

    /// <summary>
    /// Computes the header-digest = SHA3-256( CNT[0x00:0x40] ‖ CNT[0x400:0x480] ), stored in the CNT
    /// GeneralDigests block at +0x60 and recorded as pfsimage.xml &lt;header-digest&gt;. The mount descriptor
    /// must carry the FINAL FIH-relative pfs_image_offset (0x10000) at its +0x10 field (CNT+0x410); use
    /// <see cref="ForceFihRelativeImageOffset"/> on a private copy before hashing if it still holds the
    /// standalone physical offset.
    /// </summary>
    /// <param name="cntHeaderPrefix">CNT[0x00:0x40] (0x40 bytes).</param>
    /// <param name="mountDescriptor">CNT[0x400:0x480] (0x80 bytes), with pfs_image_offset already 0x10000.</param>
    public static byte[] ComputeHeaderDigest(ReadOnlySpan<byte> cntHeaderPrefix, ReadOnlySpan<byte> mountDescriptor)
    {
        if (cntHeaderPrefix.Length != HeaderDigestPrefixSize)
            throw new ArgumentException($"CNT header prefix must be exactly 0x{HeaderDigestPrefixSize:X} bytes.", nameof(cntHeaderPrefix));
        if (mountDescriptor.Length != HeaderDigestMountDescriptorSize)
            throw new ArgumentException($"Mount descriptor must be exactly 0x{HeaderDigestMountDescriptorSize:X} bytes.", nameof(mountDescriptor));

        Span<byte> pre = stackalloc byte[HeaderDigestPrefixSize + HeaderDigestMountDescriptorSize];
        cntHeaderPrefix.CopyTo(pre);
        mountDescriptor.CopyTo(pre[HeaderDigestPrefixSize..]);
        return Sha3_256(pre);
    }

    /// <summary>
    /// Forces the FIH-relative pfs_image_offset (0x10000) into a copy of a 0x80-byte mount descriptor
    /// (CNT[0x400:0x480]) so the header-digest preimage uses the finalized value. The field is the BE64 at
    /// offset 0x10 within the descriptor (= CNT+0x410). Returns the patched copy.
    /// </summary>
    public static byte[] ForceFihRelativeImageOffset(ReadOnlySpan<byte> mountDescriptor)
    {
        if (mountDescriptor.Length != HeaderDigestMountDescriptorSize)
            throw new ArgumentException($"Mount descriptor must be exactly 0x{HeaderDigestMountDescriptorSize:X} bytes.", nameof(mountDescriptor));
        byte[] copy = mountDescriptor.ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(copy.AsSpan(CntPfsImageOffsetField - 0x400, 8), FihRelativeImageOffset);
        return copy;
    }

    /// <summary>
    /// Computes a rolled-up digest = SHA3-256 over the concatenation of the supplied per-entry digests, in
    /// the order given. This is the system-digest (per-entry digests of the system-media entries) and the
    /// playgo-digest (per-entry digests of the playgo entries). Entries must already be ordered ascending by
    /// CNT entry id.
    /// </summary>
    public static byte[] ComputeConcatDigest(IReadOnlyList<byte[]> entryDigests)
    {
        ArgumentNullException.ThrowIfNull(entryDigests);
        byte[] pre = new byte[entryDigests.Count * DigestSize];
        for (int i = 0; i < entryDigests.Count; i++)
        {
            byte[] d = entryDigests[i];
            if (d is null || d.Length != DigestSize)
                throw new ArgumentException($"Entry digest [{i}] must be exactly {DigestSize} bytes.", nameof(entryDigests));
            d.CopyTo(pre.AsSpan(i * DigestSize, DigestSize));
        }
        return Sha3_256(pre);
    }


    /// <summary>
    /// Builds the CNT per-entry digest table (entry id 0x0001): <c>entries.Count * 32</c> bytes where
    /// slot k = SHA3-256(entries[k].payload), except the slot belonging to the digest-table entry
    /// itself (id == <see cref="DigestTableEntryId"/>) is left all-zero. Entries must be supplied in
    /// their on-disk order.
    /// </summary>
    public static byte[] BuildEntryDigestTable(IReadOnlyList<(int Id, ReadOnlyMemory<byte> Payload)> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        byte[] table = new byte[entries.Count * DigestSize];
        for (int k = 0; k < entries.Count; k++)
        {
            if (entries[k].Id == DigestTableEntryId)
                continue; // the digest table cannot hash itself; left zero.
            byte[] h = Sha3_256(entries[k].Payload.Span);
            h.CopyTo(table.AsSpan(k * DigestSize, DigestSize));
        }
        return table;
    }

    /// <summary>
    /// Computes the package-digest = SHA3-256 of the first <see cref="PackageDigestRegionSize"/> (0xFE0)
    /// bytes of the \x7fCNT container. This is the value stored back into the CNT header at
    /// <see cref="PackageDigestStoredOffset"/> and recorded as <c>pfsimage.xml &lt;package-digest&gt;</c>.
    /// It is a self-seal: it follows automatically once the CNT header is byte-exact.
    /// </summary>
    /// <param name="cnt">The CNT container bytes (at least 0xFE0 long; only [0:0xFE0] is read).</param>
    public static byte[] ComputePackageDigest(ReadOnlySpan<byte> cnt)
    {
        if (cnt.Length < PackageDigestRegionSize)
            throw new ArgumentException($"CNT must be at least 0x{PackageDigestRegionSize:X} bytes to seal the package-digest.", nameof(cnt));
        return Sha3_256(cnt[..PackageDigestRegionSize]);
    }

    /// <summary>
    /// Computes the CNT-header rollup digest = SHA3-256(CNT[off : off+size]) where <c>off</c> is the BE64
    /// at CNT+0x20 and <c>size</c> is the BE32 at CNT+0x1c (the CNT digest/entry-table region). This is the
    /// value stored at <see cref="CntHeaderRollupStoredOffset"/> and recomputed by the CNT sub-region
    /// verifier.
    /// </summary>
    public static byte[] ComputeCntHeaderRollupDigest(ReadOnlySpan<byte> cnt)
    {
        if (cnt.Length < CntRollupOffsetFieldOffset + 8)
            throw new ArgumentException("CNT is too small to contain the rollup header fields.", nameof(cnt));
        ulong off = BinaryPrimitives.ReadUInt64BigEndian(cnt.Slice(CntRollupOffsetFieldOffset, 8));
        uint size = BinaryPrimitives.ReadUInt32BigEndian(cnt.Slice(CntRollupSizeFieldOffset, 4));
        if (off > (ulong)cnt.Length || size > (ulong)cnt.Length - off)
            throw new ArgumentException($"CNT rollup region [0x{off:X}, +0x{size:X}) is outside the supplied CNT (0x{cnt.Length:X}).", nameof(cnt));
        return Sha3_256(cnt.Slice((int)off, (int)size));
    }

    /// <summary>
    /// Locates the plaintext outer superblock within a (possibly encrypted) outer-PFS image: scans
    /// block-aligned offsets for the superblock identity (version u64 == 2 at +0, magic at +8). The
    /// metadata superblock block is left plaintext on disk, so it is found even in the encrypted image.
    /// Returns the byte offset within <paramref name="image"/>, or -1 if not found.
    /// </summary>
    public static int LocateSuperblock(ReadOnlySpan<byte> image, int blockSize = BlockSize)
    {
        if (blockSize <= 0x10) return -1;
        for (int off = 0; off + blockSize <= image.Length; off += blockSize)
        {
            if (BinaryPrimitives.ReadUInt64LittleEndian(image.Slice(off, 8)) == 2UL &&
                image.Slice(off + 8, 4).SequenceEqual(SuperblockMagic))
                return off;
        }
        return -1;
    }

    /// <summary>
    /// Convenience for the FIH writer: locates the plaintext superblock inside the outer-PFS image
    /// and returns its offset (within the image) and the game/sblock digest (SHA3-256 of that block).
    /// Returns <c>(-1, null)</c> when no superblock is present.
    /// </summary>
    public static (int Offset, byte[]? Digest) ComputeSblockDigestFromImage(ReadOnlySpan<byte> image, int blockSize = BlockSize)
    {
        int off = LocateSuperblock(image, blockSize);
        if (off < 0) return (-1, null);
        return (off, ComputeSblockDigest(image.Slice(off, BlockSize)));
    }

}
