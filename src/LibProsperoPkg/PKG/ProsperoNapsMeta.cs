// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Builder for the NAPS metadata records (`common/etc/naps_meta_*.dat`) that are
// streamed into the SI (install-metadata) segment of a finalized image for the streaming output
// formats (`nwonly`). The NAPS record dispatcher routes each record id to a stored
// member by the `naps_meta_%d.dat` naming.
//
// Records and inputs:
// * naps_meta_300/301/302/308.dat -> all four ids carry the same 48-byte
// plaintext descriptor record. The record is six little-endian u64 fields and is fully derived from
// the finalized inner-image geometry (no key, no console secret), so it is produced exactly here.
// * naps_meta_18.dat -> produced by BuildMeta18. The plaintext is a back-to-back TLV record stream
// (per-record 16-byte header: 4-byte tag, 1-byte version, 3 zero, u64 payload length) carrying the
// inner-image geometry (phdr), the content-file table (file/fstr), the per-block info tables
// (ibcl/i2ob/i2op/ihsh/rhsh) with real block digests over the finalized image, the outer digest
// (obdg), a fixed tweak marker (twek) and the four 48-byte descriptor records (pgpl/pgil/pgpi/pgpu,
// identical to naps_meta_300). The stream is padded to a 16-byte multiple with a trailing zero record
// and encrypted with AES-128-XTS under a fixed embedded key set. The whole file is one XTS data unit.
//
// naps_meta_300 RECORD (48 bytes, all values little-endian):
// 0x00 u64 = 0 reserved (record start offset)
// 0x08 u64 = 0 reserved
// 0x10 u64 = R inner-image data-region size (= innerImageSize - 0x10000)
// 0x18 u64 = 0x3E9 (1001) constant NAPS-meta kind/version id
// 0x20 u64 = R inner-image data-region size (repeated)
// 0x28 u64 = 0x10000 PFS block size (64 KiB)
// R = innerImageSize - 0x10000. R equals the nested-image <metadata offset> reported
// by the package's own pfsimage.xml, i.e. the size of the compressed inner-image content that precedes
// the inner image's own metadata block.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LibProsperoPkg.PKG;

/// <summary>
/// Builder for the PS5 <c>naps_meta_*.dat</c> records emitted into the SI segment of a
/// <c>nwonly</c> finalized image. The 48-byte <c>naps_meta_300/301/302/308</c> descriptor is
/// derived from the inner-image geometry; <c>naps_meta_18.dat</c> is the
/// AES-128-XTS TLV metric blob built by <see cref="BuildMeta18"/> from the finalized image and its
/// content-file set. See <see cref="ProsperoSiArchive"/>.
/// </summary>
public static class ProsperoNapsMeta
{
    /// <summary>On-disk size of the <c>naps_meta_300/301/302/308</c> descriptor record, in bytes.</summary>
    public const int Meta300Length = 48;

    /// <summary>
    /// Constant NAPS-meta kind/version id stored at offset 0x18 of every <c>naps_meta_300</c> record
    /// (<c>0x3E9</c> = 1001). Identical across all debug packages.
    /// </summary>
    public const ulong Meta300KindId = 0x3E9;

    /// <summary>PFS block size (64 KiB) stored at offset 0x28 of the <c>naps_meta_300</c> record.</summary>
    public const ulong PfsBlockSize = 0x10000;

    /// <summary>The four <c>naps_meta_*</c> ids that share the 48-byte descriptor.</summary>
    public static ReadOnlySpan<int> Meta300Ids => [300, 301, 302, 308];

    /// <summary>
    /// Builds the 48-byte <c>naps_meta_300</c> descriptor (also used verbatim for ids 301,
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

    // ---- naps_meta_18 (AES-128-XTS TLV metric blob) ----

    /// <summary>Image block size used for the per-block info tables (64 KiB).</summary>
    private const int Meta18BlockSize = 0x10000;

    // Fixed AES-128-XTS key set for the naps_meta_18 data unit. Constant across all packages.
    private static readonly byte[] Meta18DataKey =
        [0x02, 0x2D, 0xCA, 0xF6, 0xD1, 0x11, 0xE5, 0x8F, 0x25, 0x93, 0x6E, 0xF5, 0x46, 0x93, 0x45, 0xAB];
    private static readonly byte[] Meta18TweakKey =
        [0xAD, 0xAC, 0x16, 0x37, 0x60, 0xDA, 0x51, 0x46, 0x98, 0xC2, 0x45, 0xAB, 0x4C, 0x9C, 0x42, 0x6C];
    private static readonly byte[] Meta18Tweak =
        [0x3C, 0xBA, 0x10, 0x7D, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    /// <summary>
    /// Builds the encrypted <c>naps_meta_18.dat</c> metric blob for a finalized image. The plaintext TLV
    /// carries the inner-image geometry (phdr), the content-file table (file/fstr), the per-block info
    /// tables (ibcl/i2ob/i2op/ihsh/rhsh) with real block digests over <paramref name="mountImage"/>, the
    /// outer digest (obdg), a fixed marker (twek) and the four 48-byte descriptor records
    /// (pgpl/pgil/pgpi/pgpu). The stream is padded to a 16-byte multiple and AES-128-XTS encrypted.
    /// </summary>
    /// <param name="innerImageSize">Block-aligned inner-image size (finalized-image header offset 0xA0).</param>
    /// <param name="mountImage">The finalized FIH+PFS+CNT mount image; block digests are computed over it.</param>
    /// <param name="contentFiles">Inner content files in load order: relative path and plain size.</param>
    /// <param name="inner">
    /// The assembled nwonly inner-image result. When supplied, the per-block info tables
    /// (ibcl/i2ob/i2op/ihsh) and the <c>file</c> record describe the compressed <b>inner</b>-image NAPS
    /// block map (afid raw extents + data-region hole ublocks + metadata ublocks) instead of an identity
    /// map over the outer <paramref name="mountImage"/>. When <see langword="null"/> (legacy inners), the
    /// exact previous outer-block behavior is kept. <c>obdg</c>/<c>rhsh</c> stay over the outer image in
    /// both cases.
    /// </param>
    /// <returns>The encrypted blob (length a multiple of 16), or an empty array when inputs are insufficient.</returns>
    public static byte[] BuildMeta18(
        ulong innerImageSize, byte[] mountImage, IReadOnlyList<(string Path, long Size)> contentFiles,
        LibProsperoPkg.PFS.ProsperoPs5InnerImageResult? inner = null)
    {
        ArgumentNullException.ThrowIfNull(mountImage);
        ArgumentNullException.ThrowIfNull(contentFiles);
        if (innerImageSize < PfsBlockSize || mountImage.Length < Meta18BlockSize)
            return [];

        uint innerBlocks = (uint)(innerImageSize / PfsBlockSize);
        int outerBlocks = mountImage.Length / Meta18BlockSize;

        // nwonly: build ibcl/i2ob/i2op/ihsh/file over the compressed INNER-image NAPS block map so the
        // installer derives a nonzero, 0x10000-aligned content package_size and clears the 0x80b21185
        // geometry gate. Legacy inners pass inner==null and keep the outer identity-map behavior.
        List<Meta18Block>? blocks = inner is not null ? BuildInnerBlocks(inner) : null;
        int metaFirstBlockIndex = blocks is null ? -1 : blocks.FindIndex(b => b.Tail == Meta300KindId);

        var plain = new List<byte>(4096);

        // phdr: [ver=1, 0x30, innerBlocks, innerImageSize, 1, blockSize] (six u32).
        {
            Span<byte> p = stackalloc byte[0x18];
            WriteU32(p, 0x00, 1);
            WriteU32(p, 0x04, 0x30);
            WriteU32(p, 0x08, innerBlocks);
            WriteU32(p, 0x0C, (uint)innerImageSize);
            WriteU32(p, 0x10, 1);
            WriteU32(p, 0x14, (uint)PfsBlockSize);
            WriteRecord(plain, "phdr", 1, p);
        }

        // file: one 0x18 entry per content file [u64 size, u32 index, u32 type, u32 field10, u32 flag].
        // afid file -> index = its first i2ob block index (= its position), type 1, field10 0, flag 0 for
        // the first file (keystone) else 1. The nwonly "*PFSmetadata" pseudo-file -> index = the first
        // metadata block's i2ob index, type 3, field10 0x3E9, flag 0.
        {
            var body = new byte[contentFiles.Count * 0x18];
            for (int i = 0; i < contentFiles.Count; i++)
            {
                Span<byte> e = body.AsSpan(i * 0x18, 0x18);
                bool isMeta = blocks is not null && contentFiles[i].Path == PfsMetadataFileName;
                uint idx = isMeta && metaFirstBlockIndex >= 0 ? (uint)metaFirstBlockIndex : (uint)i;
                uint type = isMeta ? 3u : 1u;
                uint field10 = isMeta ? (uint)Meta300KindId : 0u;
                uint flag = isMeta ? 0u : (i == 0 ? 0u : 1u);
                BinaryPrimitives.WriteUInt64LittleEndian(e[..8], (ulong)contentFiles[i].Size);
                WriteU32(e, 0x08, idx);
                WriteU32(e, 0x0C, type);
                WriteU32(e, 0x10, field10);
                WriteU32(e, 0x14, flag);
            }
            WriteRecord(plain, "file", 2, body);
        }

        // ibcl: one class byte per block. Inner path: 0x01 when the block's owning content file has
        // flag==1 (right.sprx/eboot), else 0x0F (keystone + every hole/metadata block).
        {
            if (blocks is not null)
            {
                var body = new byte[blocks.Count];
                for (int i = 0; i < blocks.Count; i++)
                    body[i] = blocks[i].OwnerFlag == 1 ? (byte)0x01 : (byte)0x0F;
                WriteRecord(plain, "ibcl", 1, body);
            }
            else
            {
                var body = new byte[outerBlocks];
                Array.Fill(body, (byte)0x0F);
                WriteRecord(plain, "ibcl", 1, body);
            }
        }

        // i2ob: 0x28 per block. Inner path:
        //   +0x00 u64 co (compressed offset in pfs_image.dat) +0x08 u32 cs (=c0+c1) +0x0C u32 ps (plaintext
        //   coverage) +0x10 u32 c0 (first 0x20000 sub-chunk) +0x14 u32 c1 (second) +0x18 u32 mb (=co>>16)
        //   +0x1C u32 0 +0x20 u32 1 +0x24 u32 flag (0x40090000 afid|0x40110000 hole|0x40450000 meta-full|
        //   0x40050000 meta-last).
        {
            if (blocks is not null)
            {
                var body = new byte[blocks.Count * 0x28];
                for (int i = 0; i < blocks.Count; i++)
                {
                    Meta18Block b = blocks[i];
                    Span<byte> e = body.AsSpan(i * 0x28, 0x28);
                    BinaryPrimitives.WriteUInt64LittleEndian(e[..8], b.Co);
                    WriteU32(e, 0x08, b.Cs);
                    WriteU32(e, 0x0C, b.Ps);
                    WriteU32(e, 0x10, b.C0);
                    WriteU32(e, 0x14, b.C1);
                    WriteU32(e, 0x18, (uint)(b.Co >> 16));
                    WriteU32(e, 0x20, 1);
                    WriteU32(e, 0x24, b.Flag);
                }
                WriteRecord(plain, "i2ob", 1, body);
            }
            else
            {
                var body = new byte[outerBlocks * 0x28];
                for (int i = 0; i < outerBlocks; i++)
                {
                    Span<byte> e = body.AsSpan(i * 0x28, 0x28);
                    BinaryPrimitives.WriteUInt64LittleEndian(e[..8], (ulong)i * Meta18BlockSize);
                    WriteU32(e, 0x08, (uint)Meta18BlockSize);
                    WriteU32(e, 0x0C, (uint)Meta18BlockSize);
                    WriteU32(e, 0x10, (uint)Meta18BlockSize);
                    WriteU32(e, 0x24, 0x40090000);
                }
                WriteRecord(plain, "i2ob", 1, body);
            }
        }

        // i2op: 0x10 per block [u64 co, u64 co>>16] (a pure projection of i2ob on the inner path; the
        // identity map for a legacy stored image).
        {
            if (blocks is not null)
            {
                var body = new byte[blocks.Count * 0x10];
                for (int i = 0; i < blocks.Count; i++)
                {
                    Span<byte> e = body.AsSpan(i * 0x10, 0x10);
                    BinaryPrimitives.WriteUInt64LittleEndian(e[..8], blocks[i].Co);
                    BinaryPrimitives.WriteUInt64LittleEndian(e.Slice(8, 8), blocks[i].Co >> 16);
                }
                WriteRecord(plain, "i2op", 1, body);
            }
            else
            {
                var body = new byte[outerBlocks * 0x10];
                for (int i = 0; i < outerBlocks; i++)
                {
                    Span<byte> e = body.AsSpan(i * 0x10, 0x10);
                    BinaryPrimitives.WriteUInt64LittleEndian(e[..8], (ulong)i * Meta18BlockSize);
                    BinaryPrimitives.WriteUInt64LittleEndian(e.Slice(8, 8), (ulong)i * Meta18BlockSize);
                }
                WriteRecord(plain, "i2op", 1, body);
            }
        }

        // ihsh: 0x30 per block [u32 idx, u32 size, 32B digest, u64 tail]. Inner path: holes carry
        // idx=0/size=ps, digest = SHA3-256 of the plaintext (zero-filled) hole block of size ps, and
        // tail=0. afid/metadata carry a per-block digest with tail=0 / 0x3E9;
        // their 40-byte ICV is the PFS image hasher's and is not reproducible offline, so it is a
        // best-effort SHA3-256 over the block's on-disk bytes. The gate verifies only geometry, not any
        // ihsh digest value.
        {
            if (blocks is not null)
            {
                var body = new byte[blocks.Count * 0x30];
                for (int i = 0; i < blocks.Count; i++)
                {
                    Meta18Block b = blocks[i];
                    Span<byte> e = body.AsSpan(i * 0x30, 0x30);
                    if (b.IsHole)
                    {
                        WriteU32(e, 0x00, 0);
                        WriteU32(e, 0x04, b.Ps);
                        byte[] h = ProsperoImageDigests.Sha3_256(InnerHoleDigestPreimage(b.Ps));
                        h.AsSpan(0, 32).CopyTo(e.Slice(0x08, 32));
                    }
                    else
                    {
                        byte[] h = ProsperoImageDigests.Sha3_256(InnerBlockBytes(inner!.Image, b.OnDiskOffset, (int)b.OnDiskLen));
                        h.AsSpan(0, 32).CopyTo(e.Slice(0x08, 32));
                        BinaryPrimitives.WriteUInt64LittleEndian(e.Slice(0x28, 8), b.Tail);
                    }
                }
                WriteRecord(plain, "ihsh", 1, body);
            }
            else
            {
                var body = new byte[outerBlocks * 0x30];
                for (int i = 0; i < outerBlocks; i++)
                {
                    Span<byte> e = body.AsSpan(i * 0x30, 0x30);
                    WriteU32(e, 0x00, (uint)i);
                    WriteU32(e, 0x04, (uint)Meta18BlockSize);
                    byte[] h = ProsperoImageDigests.Sha3_256(mountImage.AsSpan(i * Meta18BlockSize, Meta18BlockSize));
                    h.AsSpan(0, 32).CopyTo(e.Slice(0x08, 32));
                }
                WriteRecord(plain, "ihsh", 1, body);
            }
        }

        // rhsh: root digest over the superblock block, remainder zero (176 bytes).
        {
            var body = new byte[0xB0];
            (_, byte[]? sb) = ProsperoImageDigests.ComputeSblockDigestFromImage(mountImage);
            if (sb is { Length: >= 32 })
                sb.AsSpan(0, 32).CopyTo(body.AsSpan(0, 32));
            WriteRecord(plain, "rhsh", 1, body);
        }

        // fstr: content-file relative paths, each (including the last) NUL-terminated.
        {
            var sb = new StringBuilder();
            foreach (var (path, _) in contentFiles)
            {
                sb.Append(path.Replace('\\', '/'));
                sb.Append('\0');
            }
            WriteRecord(plain, "fstr", 1, Encoding.ASCII.GetBytes(sb.ToString()));
        }

        // twek: fixed marker [0, 4, 0, 0, 0].
        {
            Span<byte> p = stackalloc byte[0x14];
            WriteU32(p, 0x04, 4);
            WriteRecord(plain, "twek", 1, p);
        }

        // obdg: outer digest over the whole finalized image, remainder zero (128 bytes).
        {
            var body = new byte[0x80];
            byte[] od = ProsperoImageDigests.Sha3_256(mountImage);
            od.AsSpan(0, 32).CopyTo(body.AsSpan(0, 32));
            WriteRecord(plain, "obdg", 1, body);
        }

        // pgpl/pgil/pgpi/pgpu: the 48-byte descriptor, identical to naps_meta_300.
        {
            byte[] desc = BuildMeta300FromInnerImageSize(innerImageSize);
            WriteRecord(plain, "pgpl", 1, desc);
            WriteRecord(plain, "pgil", 1, desc);
            WriteRecord(plain, "pgpi", 1, desc);
            WriteRecord(plain, "pgpu", 1, desc);
        }

        // zero: trailing pad record sized so the plaintext ends on a 16-byte boundary.
        {
            int pad = (16 - (plain.Count % 16)) % 16;
            WriteRecord(plain, "zero", 1, new byte[pad]);
        }

        return AesXtsEncrypt(plain.ToArray());
    }

    private static void WriteU32(Span<byte> dst, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(dst.Slice(offset, 4), value);

    // Emits one TLV record: 4-byte tag (stored in reverse byte order), 1-byte version, 3 zero, u64 length, payload.
    private static void WriteRecord(List<byte> dst, string tag, byte version, ReadOnlySpan<byte> payload)
    {
        dst.Add((byte)tag[3]);
        dst.Add((byte)tag[2]);
        dst.Add((byte)tag[1]);
        dst.Add((byte)tag[0]);
        dst.Add(version);
        dst.Add(0);
        dst.Add(0);
        dst.Add(0);
        Span<byte> len = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(len, (ulong)payload.Length);
        for (int i = 0; i < 8; i++) dst.Add(len[i]);
        for (int i = 0; i < payload.Length; i++) dst.Add(payload[i]);
    }

    // AES-128-XTS over the whole buffer as a single data unit (length must be a multiple of 16).
    private static byte[] AesXtsEncrypt(byte[] plain)
    {
        using var aesData = Aes.Create();
        aesData.Mode = CipherMode.ECB;
        aesData.Padding = PaddingMode.None;
        aesData.Key = Meta18DataKey;
        using var aesTweak = Aes.Create();
        aesTweak.Mode = CipherMode.ECB;
        aesTweak.Padding = PaddingMode.None;
        aesTweak.Key = Meta18TweakKey;

        using ICryptoTransform dataEnc = aesData.CreateEncryptor();
        using ICryptoTransform tweakEnc = aesTweak.CreateEncryptor();

        byte[] t = tweakEnc.TransformFinalBlock(Meta18Tweak, 0, 16);
        var outp = new byte[plain.Length];
        var pp = new byte[16];
        for (int i = 0; i < plain.Length; i += 16)
        {
            for (int j = 0; j < 16; j++) pp[j] = (byte)(plain[i + j] ^ t[j]);
            byte[] cc = dataEnc.TransformFinalBlock(pp, 0, 16);
            for (int j = 0; j < 16; j++) outp[i + j] = (byte)(cc[j] ^ t[j]);
            t = GfMulAlpha(t);
        }
        return outp;
    }

    // Multiply a 128-bit little-endian tweak by the element x in GF(2^128), reduction polynomial 0x87.
    private static byte[] GfMulAlpha(byte[] t)
    {
        var r = new byte[16];
        int carry = 0;
        for (int i = 0; i < 16; i++)
        {
            int b = t[i];
            r[i] = (byte)(((b << 1) | carry) & 0xFF);
            carry = (b >> 7) & 1;
        }
        if (carry != 0) r[0] ^= 0x87;
        return r;
    }

    // ---- nwonly inner-image NAPS block map (for ibcl/i2ob/i2op/ihsh/file) --------------------------

    /// <summary>256 KiB uncompressed NAPS block used by the inner-image geometry.</summary>
    private const long Meta18UBlock = 0x40000;

    /// <summary>The pseudo content-file name the nwonly SI appends for the inner PFS metadata region.</summary>
    private const string PfsMetadataFileName = "*PFSmetadata";

    /// <summary>
    /// One entry of the compressed inner-image NAPS block map. <see cref="Co"/> is the block's byte offset
    /// inside the packed <c>pfs_image.dat</c>; <see cref="Cs"/> its stored/compressed size (== C0+C1);
    /// <see cref="Ps"/> the plaintext byte span it covers; <see cref="C0"/>/<see cref="C1"/> the two
    /// 0x20000 sub-chunk compressed sizes; <see cref="Flag"/> the block-class word. <see cref="OwnerFlag"/>
    /// drives ibcl; <see cref="Tail"/> is the ihsh trailer (0x3E9 for metadata). For a real (non-hole)
    /// block, <see cref="OnDiskOffset"/>/<see cref="OnDiskLen"/> locate its compressed bytes in the image.
    /// </summary>
    private readonly record struct Meta18Block(
        ulong Co, uint Cs, uint Ps, uint C0, uint C1, uint Flag,
        bool IsHole, uint OwnerFlag, ulong Tail, long OnDiskOffset, uint OnDiskLen);

    /// <summary>
    /// Derives the compressed inner-image NAPS block map for <paramref name="inner"/>: the 3-way afid raw
    /// extents (<see cref="LibProsperoPkg.PFS.ProsperoPs5InnerPlacement"/>), the data-region hole ublocks tiling
    /// <c>[DataEndLogical, MetaBaseLogical)</c>, and the metadata ublocks (<c>MetadataBlocks</c>). This is
    /// the same geometry <see cref="ProsperoNwonlyNapsGenerator"/> emits for <c>naps_pkg_layout.dat</c>.
    /// </summary>
    private static List<Meta18Block> BuildInnerBlocks(LibProsperoPkg.PFS.ProsperoPs5InnerImageResult inner)
    {
        var blocks = new List<Meta18Block>();

        // 1) afid raw extents: one entry per placed file (afid order). Raw, so cs=ps=c0=size, c1=0,
        //    flag 0x40090000. The first afid (keystone) has owner flag 0, the rest 1.
        var placements = inner.Placements;
        for (int i = 0; i < placements.Count; i++)
        {
            LibProsperoPkg.PFS.ProsperoPs5InnerPlacement p = placements[i];
            uint cs = (uint)p.OnDiskSize;
            blocks.Add(new Meta18Block(
                Co: (ulong)p.OnDiskOffset, Cs: cs, Ps: (uint)p.UncompressedSize, C0: cs, C1: 0,
                Flag: 0x40090000u, IsHole: false, OwnerFlag: i == 0 ? 0u : 1u, Tail: 0,
                OnDiskOffset: p.OnDiskOffset, OnDiskLen: cs));
        }

        // 2) data-region hole ublocks tiling [DataEndLogical, MetaBaseLogical) by 256 KiB. Each hole
        //    compresses to 0x10 bytes (two 8-byte 0x20000 sub-chunks); identical-plaintext holes reuse the
        //    same compressed offset (dedup, stride cs from BlockInfoOnDiskOffset). flag 0x40110000.
        long padding = inner.MetaBaseLogical - inner.DataEndLogical;
        if (padding > 0)
        {
            int nblk = (int)((padding + Meta18UBlock - 1) / Meta18UBlock);
            var holeCo = new Dictionary<uint, ulong>();
            ulong cursor = (ulong)inner.BlockInfoOnDiskOffset;
            for (int k = 0; k < nblk; k++)
            {
                uint ps = (uint)Math.Min(Meta18UBlock, padding - (long)k * Meta18UBlock);
                if (!holeCo.TryGetValue(ps, out ulong co))
                {
                    co = cursor;
                    holeCo[ps] = co;
                    cursor += 0x10;
                }
                blocks.Add(new Meta18Block(
                    Co: co, Cs: 0x10, Ps: ps, C0: 8, C1: 8, Flag: 0x40110000u,
                    IsHole: true, OwnerFlag: 0, Tail: 0, OnDiskOffset: 0, OnDiskLen: 0));
            }
        }

        // 3) metadata ublocks: co = MetadataOnDiskOffset + cumulative cs; c0 = first sub-chunk, c1 = cs-c0
        //    (0 when single-sub-chunk); flag 0x40450000 (two sub-chunks) / 0x40050000 (one); ihsh tail 0x3E9.
        IReadOnlyList<LibProsperoPkg.PFS.ProsperoInnerMetaBlockChunk> metaChunks = inner.MetadataBlocks;
        if (metaChunks.Count == 0 && inner.MetadataPlaintext.Length > 0)
        {
            var mf = LibProsperoPkg.PFS.Compression.ProsperoCompressedPfsFile.Parse(
                LibProsperoPkg.PFS.Compression.ProsperoCompressedPfsImage.Pack(
                    inner.MetadataPlaintext, 7, (int)Meta18UBlock));
            metaChunks = mf.Blocks.Select(b => new LibProsperoPkg.PFS.ProsperoInnerMetaBlockChunk(
                b.CompressedSize, b.UncompressedSize, b.IsMultiChunk, b.FirstChunkCompressedSize)).ToList();
        }
        ulong metaCursor = (ulong)inner.MetadataOnDiskOffset;
        foreach (LibProsperoPkg.PFS.ProsperoInnerMetaBlockChunk m in metaChunks)
        {
            uint cs = (uint)m.CompressedSize;
            uint c0 = m.IsMultiChunk ? (uint)m.FirstChunkCompressedSize : cs;
            uint c1 = m.IsMultiChunk ? cs - c0 : 0;
            uint flag = c1 > 0 ? 0x40450000u : 0x40050000u;
            blocks.Add(new Meta18Block(
                Co: metaCursor, Cs: cs, Ps: (uint)m.UncompressedSize, C0: c0, C1: c1, Flag: flag,
                IsHole: false, OwnerFlag: 0, Tail: Meta300KindId,
                OnDiskOffset: (long)metaCursor, OnDiskLen: cs));
            metaCursor += cs;
        }

        return blocks;
    }

    // ihsh preimage for a hole block: the plaintext (zero-filled) block content of the covered plaintext
    // size. SHA3-256 over it yields the hole digest for that plaintext size.
    private static byte[] InnerHoleDigestPreimage(uint plaintextSize) => new byte[plaintextSize];

    // Bounds-safe slice of a real block's compressed bytes from the inner image (for the ihsh digest).
    private static ReadOnlySpan<byte> InnerBlockBytes(byte[] image, long offset, int length)
    {
        if (image is null || offset < 0 || length <= 0 || offset >= image.Length)
            return ReadOnlySpan<byte>.Empty;
        int avail = (int)Math.Min((long)length, image.Length - offset);
        return image.AsSpan((int)offset, avail);
    }

}
