// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PS5 *finalized-image* outer-PFS STRUCTURE generator for the
// `--oformat nwonly` package. This assembles the plaintext outer-PFS
// filesystem image (the 11-block "data-first" layout in the reference package) from the two outer
// files that an nwonly image always contains - `pfs_image.dat` (the nested inner PFS image) and
// `naps_pkg_layout.dat` - plus the fixed metadata inodes (super-root dir, inode_flat_path_table,
// uroot dir), then signs it (plain SHA3-256 per block + superblock ICV) and applies the validated
// AES-XTS block encryption.
//
// Every byte format here is validated against the reference package's outer image (files/outer_full_correct.bin), block-by-block:
//
// * Layout (data-first): blocks [0..D-1] = file data (file0 then file1 ...), block D = superblock
// (plaintext), D+1 = inode table, D+2 = super-root dirents, D+3 = inode_flat_path_table (FLT),
// D+4 = uroot dirents. For the reference package D = 6 (5 blocks pfs_image.dat + 1 block naps),
// giving the validated 11-block image.
// * Inodes (fixed template): 0 = super-root dir (mode 0x416d, flags 0x2000c), 1 =
// inode_flat_path_table file (mode 0x816d, flags 0x2000c), 2 = uroot dir (mode 0x416d, nlink 3,
// flags 0xc), 3.. = the outer files in order (mode 0x816d, flags 0xd).
// * Super-root dirents: { inode_flat_path_table -> inode 1 (File), uroot -> inode 2 (Dir) }.
// * uroot dirents: { ".", "..", <file0> -> inode 3, <file1> -> inode 4, ... } (names lowercase).
// * \x7fFLT (block D+3): header { ver=1, hdrSize=0x10, dataOff=0x40 }, magic "\x7fFLT" @0x20,
// count @0x2c, the two fixed FLT seeds @0x30, then one 16-byte entry per FILE:
// { u64 pathHash (custom reduced-Keccak over the UPPERCASED name), u64 inode | fileOrdinal<<40 }.
// * Signing: each dinode stores SHA3-256(plaintext block) + block index per owned block; the
// super-root inode in the superblock stores SHA3-256(inode table) @0xb8; the superblock ICV
// @0x380 = SHA3-256(superblock[0:0x5a0] with the ICV field zeroed). See ProsperoOuterPfsSignature.
// * Encryption: pfs_image.dat blocks = plain XTS sector (block index); every other block (the
// small files + all metadata) = signed XTS sector (bit 47 | block index); the superblock block
// is left plaintext. See ProsperoOuterPfsImage.
//
// The FLT path-hash is a custom 3-lane reduced-Keccak permutation (round constant 0x8000000080008081)
// with two fixed 64-bit seeds, validated against the reference routine and
// byte-exact for both reference names ("pfs_image.dat", "naps_pkg_layout.dat").
#nullable enable
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace LibProsperoPkg.PFS;

/// <summary>
/// Describes one file that lives at the <em>outer</em> level of a PS5 nwonly finalized image.
/// An nwonly outer PFS always contains exactly two files - <c>pfs_image.dat</c> (the nested inner
/// image) and <c>naps_pkg_layout.dat</c> - but this type keeps the list general.
/// </summary>
public sealed class ProsperoOuterFile
{
    /// <summary>The outer file name (e.g. <c>pfs_image.dat</c>), stored lowercase in dirents.</summary>
    public required string Name { get; init; }

    /// <summary>The raw file bytes. Laid out block-by-block (zero-padded to the block size).</summary>
    public required byte[] Data { get; init; }

    /// <summary>
    /// The dinode <c>SizeCompressed</c> field (dinode+0x10). For <c>naps_pkg_layout.dat</c> this
    /// equals the file length; for <c>pfs_image.dat</c> it is the nested image's logical
    /// (uncompressed) size as recorded by the inner-image builder. Defaults to <see cref="Data"/>'s length.
    /// </summary>
    public long? SizeCompressed { get; init; }

    /// <summary>
    /// Whether this file's data blocks are AES-XTS encrypted as <em>signed</em> blocks (sector =
    /// bit 47 | block index). In the reference package <c>pfs_image.dat</c> is plain data and
    /// <c>naps_pkg_layout.dat</c> is signed.
    /// </summary>
    public bool Signed { get; init; }
}

/// <summary>
/// Build parameters for the outer-PFS structure generator. The timestamp/seed defaults reproduce
/// the reference package byte-exact; a reference build supplies the current time and a fresh seed.
/// </summary>
public sealed class ProsperoOuterPfsBuildParameters
{
    /// <summary>POSIX seconds stamped into every inode time field (default = reference package).</summary>
    public long TimestampSeconds { get; init; } = 0x6A31A5B9;

    /// <summary>Nanosecond fraction stamped into every inode time field (default = reference package).</summary>
    public uint TimestampNanoseconds { get; init; } = 0x14DC9380;

    /// <summary>The 16-byte crypt seed written at superblock+0x370 (and used for key derivation).</summary>
    public byte[]? Seed { get; init; }
}

/// <summary>
/// Result of building an outer-PFS image: the plaintext image, the per-block XTS classification,
/// and the metadata (superblock) block index.
/// </summary>
public sealed class ProsperoOuterPfsBuildResult
{
    /// <summary>The assembled plaintext outer-PFS image (a whole number of <see cref="ProsperoOuterPfsBuilder.BlockSize"/> blocks).</summary>
    public required byte[] Plaintext { get; init; }

    /// <summary>Per-block AES-XTS classification (Data / Signed / Plaintext), one entry per block.</summary>
    public required ProsperoOuterBlockKind[] BlockKinds { get; init; }

    /// <summary>Index of the plaintext metadata (superblock) block.</summary>
    public required int SuperblockIndex { get; init; }

    /// <summary>Total block count of the image.</summary>
    public int BlockCount => BlockKinds.Length;
}

/// <summary>
/// Assembles, signs, and encrypts the plaintext outer-PFS image of a PS5 nwonly finalized package.
/// See the file header for the full, validated byte layout; every piece is pinned to the
/// reference package by the external byte-exact harness.
/// </summary>
public static class ProsperoOuterPfsBuilder
{
    /// <summary>The outer finalized-image PFS block size (one block = one AES-XTS data unit).</summary>
    public const int BlockSize = ProsperoOuterPfsImage.DefaultBlockSize; // 0x10000

    // Fixed metadata inode/dirent names.
    private const string FlatPathTableName = "inode_flat_path_table";
    private const string UrootName = "uroot";

    // Number of fixed metadata inodes that precede the file inodes (super-root, FLT, uroot).
    private const int MetadataInodeCount = 3;

    // Inode mode / flag constants (validated against the reference inode table).
    private const ushort ModeDir = 0x416D;   // S_IFDIR | 0555
    private const ushort ModeFile = 0x816D;  // S_IFREG | 0555
    private const uint FlagsInternalMeta = 0x2000C; // @internal | unk2 | unk3 (super-root dir + FLT file)
    private const uint FlagsDir = 0x000C;           // unk2 | unk3 (uroot dir)
    private const uint FlagsFile = 0x000D;          // compressed | unk2 | unk3 (data files)

    // --- \x7fFLT custom reduced-Keccak path hash (validated against the reference routine) ---
    private const ulong FltRoundConstant = 0x8000000080008081UL;
    private const ulong FltSeed0 = 0x92CA8AAB26A24F51UL; // written at superblock-table+0x18 -> FLT @0x30
    private const ulong FltSeed1 = 0x09BBB761A41BC44DUL; // written at superblock-table+0x20 -> FLT @0x38

    // FLT block header constants.
    private const uint FltVersion = 1;
    private const uint FltHeaderSize = 0x10;
    private const uint FltDataOffset = 0x40;
    private static readonly byte[] FltMagic = { 0x7F, 0x46, 0x4C, 0x54 }; // "\x7fFLT"

    /// <summary>
    /// Builds the plaintext outer-PFS image (assembled + signed, not yet encrypted) for the given
    /// ordered outer <paramref name="files"/>. The metadata inodes/dirents/FLT and the superblock
    /// (including all SHA3-256 block hashes and the ICV) are produced here. Use
    /// <see cref="Encrypt"/> (or <see cref="ProsperoOuterPfsImage"/>'s block-kinds <c>Transform</c>
    /// overload with the returned <see cref="ProsperoOuterPfsBuildResult.BlockKinds"/>) to encrypt.
    /// </summary>
    public static ProsperoOuterPfsBuildResult BuildPlaintext(
        IReadOnlyList<ProsperoOuterFile> files, ProsperoOuterPfsBuildParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(parameters);
        if (files.Count == 0)
            throw new ArgumentException("At least one outer file is required.", nameof(files));

        // ---- 1. Plan the block layout (data-first). ----
        int dataBlockTotal = 0;
        var fileFirstBlock = new int[files.Count];
        var fileBlockCount = new int[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            ProsperoOuterFile f = files[i];
            ArgumentNullException.ThrowIfNull(f);
            int blocks = Math.Max(1, (f.Data.Length + BlockSize - 1) / BlockSize);
            fileFirstBlock[i] = dataBlockTotal;
            fileBlockCount[i] = blocks;
            dataBlockTotal += blocks;
        }

        int superblockIndex = dataBlockTotal;       // block D
        int inodeTableIndex = dataBlockTotal + 1;    // block D+1
        int superRootDirentIndex = dataBlockTotal + 2; // block D+2
        int fltIndex = dataBlockTotal + 3;           // block D+3
        int urootDirentIndex = dataBlockTotal + 4;   // block D+4
        int totalBlocks = dataBlockTotal + 5;

        var image = new byte[(long)totalBlocks * BlockSize];

        // ---- 2. Lay out file data blocks. ----
        for (int i = 0; i < files.Count; i++)
        {
            byte[] data = files[i].Data;
            Buffer.BlockCopy(data, 0, image, fileFirstBlock[i] * BlockSize, data.Length);
        }

        // ---- 3. Build the structural metadata blocks (super-root dirents, FLT, uroot dirents). ----
        BuildSuperRootDirents(image.AsSpan(superRootDirentIndex * BlockSize, BlockSize));
        BuildFlatPathTable(image.AsSpan(fltIndex * BlockSize, BlockSize), files);
        BuildUrootDirents(image.AsSpan(urootDirentIndex * BlockSize, BlockSize), files);

        // ---- 4. Build the inode table (block D+1) with per-block SHA3 hashes. ----
        BuildInodeTable(
            image, inodeTableIndex, parameters, files,
            fileFirstBlock, fileBlockCount,
            superRootDirentIndex, fltIndex, urootDirentIndex);

        // ---- 5. Build the superblock (block D): super-root inode hash (of the inode table) + seed + ICV. ----
        byte[] inodeTableHash = ProsperoOuterPfsSignature.ComputeBlockHash(
            image.AsSpan(inodeTableIndex * BlockSize, BlockSize));
        BuildSuperblock(
            image.AsSpan(superblockIndex * BlockSize, BlockSize),
            parameters, files.Count, totalBlocks, inodeTableIndex, inodeTableHash);

        // ---- 6. Classify blocks for AES-XTS. ----
        var kinds = new ProsperoOuterBlockKind[totalBlocks];
        for (int i = 0; i < files.Count; i++)
        {
            ProsperoOuterBlockKind kind = files[i].Signed
                ? ProsperoOuterBlockKind.Signed : ProsperoOuterBlockKind.Data;
            for (int j = 0; j < fileBlockCount[i]; j++)
                kinds[fileFirstBlock[i] + j] = kind;
        }
        kinds[superblockIndex] = ProsperoOuterBlockKind.Plaintext;
        kinds[inodeTableIndex] = ProsperoOuterBlockKind.Signed;
        kinds[superRootDirentIndex] = ProsperoOuterBlockKind.Signed;
        kinds[fltIndex] = ProsperoOuterBlockKind.Signed;
        kinds[urootDirentIndex] = ProsperoOuterBlockKind.Signed;

        return new ProsperoOuterPfsBuildResult
        {
            Plaintext = image,
            BlockKinds = kinds,
            SuperblockIndex = superblockIndex,
        };
    }

    /// <summary>
    /// Encrypts a plaintext outer-PFS image in place using the supplied AES-XTS key pair and the
    /// per-block classification from <see cref="BuildPlaintext"/>.
    /// </summary>
    public static void Encrypt(
        ProsperoOuterPfsBuildResult build, ReadOnlySpan<byte> tweakKey, ReadOnlySpan<byte> dataKey)
    {
        ArgumentNullException.ThrowIfNull(build);
        ProsperoOuterPfsImage.Transform(
            build.Plaintext, tweakKey, dataKey, BlockSize, build.BlockKinds, encrypt: true);
    }

    /// <summary>
    /// Convenience: builds the plaintext image and encrypts it with keys derived from the package
    /// <paramref name="contentId"/> + <paramref name="passcode"/> and the build seed, returning the
    /// final on-disk ciphertext image.
    /// </summary>
    public static byte[] BuildEncrypted(
        IReadOnlyList<ProsperoOuterFile> files, ProsperoOuterPfsBuildParameters parameters,
        string contentId, string passcode)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        if (parameters.Seed is not { Length: 16 })
            throw new ArgumentException("A 16-byte build seed is required to encrypt the image.", nameof(parameters));

        ProsperoOuterPfsBuildResult build = BuildPlaintext(files, parameters);
        byte[] ekpfs = ProsperoPfsKeys.DeriveEkpfs(contentId, passcode);
        var (tweak, data) = ProsperoPfsKeys.DeriveImageEncryptionKeys(ekpfs, parameters.Seed);
        Encrypt(build, tweak, data);
        return build.Plaintext;
    }

    // ------------------------------------------------------------------ structural blocks

    private static void BuildSuperRootDirents(Span<byte> block)
    {
        using var ms = new MemoryStream(BlockSize);
        new PfsDirent { InodeNumber = 1, Type = DirentType.File, Name = FlatPathTableName }.WriteToStream(ms);
        new PfsDirent { InodeNumber = 2, Type = DirentType.Directory, Name = UrootName }.WriteToStream(ms);
        CopyStream(ms, block);
    }

    private static void BuildUrootDirents(Span<byte> block, IReadOnlyList<ProsperoOuterFile> files)
    {
        using var ms = new MemoryStream(BlockSize);
        // The uroot directory is inode 2 and references itself for "." and "..".
        new PfsDirent { InodeNumber = 2, Type = DirentType.Dot, Name = "." }.WriteToStream(ms);
        new PfsDirent { InodeNumber = 2, Type = DirentType.DotDot, Name = ".." }.WriteToStream(ms);
        for (int i = 0; i < files.Count; i++)
        {
            new PfsDirent
            {
                InodeNumber = (uint)(MetadataInodeCount + i),
                Type = DirentType.File,
                Name = files[i].Name,
            }.WriteToStream(ms);
        }
        CopyStream(ms, block);
    }

    private static void BuildFlatPathTable(Span<byte> block, IReadOnlyList<ProsperoOuterFile> files)
    {
        // Header (16 bytes): ver, hdrSize, dataOff, reserved.
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x00..], FltVersion);
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x04..], FltHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x08..], FltDataOffset);
        // Magic + reserved + entry count @0x20.
        FltMagic.CopyTo(block[0x20..]);
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x2C..], (uint)files.Count);
        // Two fixed FLT seeds @0x30.
        BinaryPrimitives.WriteUInt64LittleEndian(block[0x30..], FltSeed0);
        BinaryPrimitives.WriteUInt64LittleEndian(block[0x38..], FltSeed1);
        // One 16-byte entry per file: { u64 pathHash, u64 inode | fileOrdinal<<40 }.
        int off = (int)FltDataOffset;
        for (int i = 0; i < files.Count; i++)
        {
            ulong inode = (ulong)(uint)(MetadataInodeCount + i);
            ulong packed = inode | ((ulong)(uint)i << 40);
            BinaryPrimitives.WriteUInt64LittleEndian(block[off..], FltPathHash(files[i].Name));
            BinaryPrimitives.WriteUInt64LittleEndian(block[(off + 8)..], packed);
            off += 16;
        }
    }

    // ------------------------------------------------------------------ inode table + superblock

    private static void BuildInodeTable(
        byte[] image, int inodeTableIndex, ProsperoOuterPfsBuildParameters p,
        IReadOnlyList<ProsperoOuterFile> files,
        int[] fileFirstBlock, int[] fileBlockCount,
        int superRootDirentIndex, int fltIndex, int urootDirentIndex)
    {
        var inodes = new List<DinodeS32>(MetadataInodeCount + files.Count);

        // inode 0: super-root directory (owns the super-root dirent block).
        inodes.Add(MakeMetaInode(ModeDir, nlink: 1, FlagsInternalMeta, size: BlockSize, p,
            image, new[] { superRootDirentIndex }));

        // inode 1: inode_flat_path_table file (owns the FLT block). Size = FLT content length.
        long fltSize = FltDataOffset + (long)files.Count * 16;
        inodes.Add(MakeMetaInode(ModeFile, nlink: 1, FlagsInternalMeta, size: fltSize, p,
            image, new[] { fltIndex }));

        // inode 2: uroot directory (owns the uroot dirent block). nlink = 2 + subdirectories (none here) + 1.
        inodes.Add(MakeMetaInode(ModeDir, nlink: 3, FlagsDir, size: BlockSize, p,
            image, new[] { urootDirentIndex }));

        // inode 3..: the outer files in order.
        for (int i = 0; i < files.Count; i++)
        {
            ProsperoOuterFile f = files[i];
            var blocks = new int[fileBlockCount[i]];
            for (int j = 0; j < blocks.Length; j++) blocks[j] = fileFirstBlock[i] + j;

            var di = new DinodeS32
            {
                Mode = (InodeMode)ModeFile,
                Nlink = 1,
                Flags = (InodeFlags)FlagsFile,
                Size = f.Data.Length,
                SizeCompressed = f.SizeCompressed ?? f.Data.Length,
                Blocks = (uint)blocks.Length,
            };
            StampTime(di, p);
            FillSignedBlocks(di, image, blocks);
            inodes.Add(di);
        }

        // Serialize the inode table into block D+1.
        using var ms = new MemoryStream(BlockSize);
        foreach (DinodeS32 di in inodes) di.WriteToStream(ms);
        CopyStream(ms, image.AsSpan(inodeTableIndex * BlockSize, BlockSize));
    }

    private static DinodeS32 MakeMetaInode(
        ushort mode, ushort nlink, uint flags, long size,
        ProsperoOuterPfsBuildParameters p, byte[] image, int[] ownedBlocks)
    {
        var di = new DinodeS32
        {
            Mode = (InodeMode)mode,
            Nlink = nlink,
            Flags = (InodeFlags)flags,
            Size = size,
            SizeCompressed = size,
        };
        StampTime(di, p);
        FillSignedBlocks(di, image, ownedBlocks);
        return di;
    }

    private static void StampTime(DinodeS32 di, ProsperoOuterPfsBuildParameters p)
    {
        di.Time1_sec = di.Time2_sec = di.Time3_sec = di.Time4_sec = p.TimestampSeconds;
        di.Time1_nsec = di.Time2_nsec = di.Time3_nsec = di.Time4_nsec = p.TimestampNanoseconds;
    }

    // Fills a signed dinode's direct-block entries with { SHA3-256(plaintext block), block index }.
    private static void FillSignedBlocks(DinodeS32 di, byte[] image, int[] blocks)
    {
        di.Blocks = (uint)blocks.Length;
        for (int j = 0; j < blocks.Length; j++)
        {
            int blk = blocks[j];
            byte[] hash = ProsperoOuterPfsSignature.ComputeBlockHash(
                image.AsSpan(blk * BlockSize, BlockSize));
            di.db[j].sig = hash;
            di.db[j].block = blk;
        }
    }

    private static void BuildSuperblock(
        Span<byte> block, ProsperoOuterPfsBuildParameters p,
        int fileCount, int totalBlocks, int inodeTableIndex, byte[] inodeTableHash)
    {
        int ninodes = MetadataInodeCount + fileCount;

        // The super-root inode is embedded in the superblock as its InodeBlockSig (DinodeS64),
        // storing SHA3-256(inode table) at sb+0xb8 and the inode-table block index at sb+0xd8.
        var superRoot = new DinodeS64
        {
            Mode = 0,
            Nlink = 1,
            Flags = 0,
            Size = BlockSize,
            SizeCompressed = BlockSize,
            Blocks = 1,
        };
        superRoot.Time1_sec = superRoot.Time2_sec = superRoot.Time3_sec = superRoot.Time4_sec = p.TimestampSeconds;
        superRoot.Time1_nsec = superRoot.Time2_nsec = superRoot.Time3_nsec = superRoot.Time4_nsec = p.TimestampNanoseconds;
        superRoot.db[0].sig = inodeTableHash;
        superRoot.db[0].block = inodeTableIndex;

        var hdr = new PfsHeader
        {
            Version = PfsHeader.VersionPs5,
            ReadOnly = 1,
            Mode = (PfsMode)0x0D,
            BlockSize = BlockSize,
            NBlock = 1,
            DinodeCount = ninodes,
            Ndblock = totalBlocks,
            DinodeBlockCount = 1,
            UnknownIndex = 1,
            Seed = p.Seed ?? new byte[16],
            InodeBlockSig = superRoot,
        };

        using var ms = new MemoryStream(BlockSize);
        hdr.WriteToStream(ms);
        CopyStream(ms, block);

        // The ICV covers superblock[0:0x5a0] with its own field zeroed.
        ProsperoOuterPfsSignature.WriteSuperblockIcv(block);
    }

    // ------------------------------------------------------------------ FLT path hash

    private static ulong Rotl(ulong x, int n) => (x << n) | (x >> (64 - n));
    private static ulong Rotr(ulong x, int n) => (x >> n) | (x << (64 - n));

    /// <summary>
    /// The \x7fFLT path hash: a custom 3-lane reduced-Keccak permutation over the UPPERCASED ASCII
    /// file name, with two fixed 64-bit seeds and round constant 0x8000000080008081.
    /// Validated byte-exact for the reference names.
    /// </summary>
    internal static ulong FltPathHash(string name)
    {
        byte[] nm = new byte[name.Length];
        for (int i = 0; i < name.Length; i++)
        {
            char ch = name[i];
            if (ch is >= 'a' and <= 'z') ch = (char)(ch - 32);
            nm[i] = (byte)ch;
        }

        int n = nm.Length;
        ulong a = FltSeed0;
        ulong b = Rotl(FltSeed0, 11);
        ulong c = Rotl(FltSeed0, 23);
        ulong tail = 0;

        if (n != 0)
        {
            int nwords = (n - 1) >> 3;
            int pos = 0;
            for (int w = 0; w < nwords; w++)
            {
                ulong word = BinaryPrimitives.ReadUInt64LittleEndian(nm.AsSpan(pos, 8));
                a ^= word;
                ulong t18 = Rotr(Rotl(c ^ b, 5) ^ a, 11);
                ulong t12 = Rotl(Rotl(c ^ a, 17) ^ b, 11);
                ulong c2 = Rotr(Rotl(b ^ a, 1) ^ c, 5);
                a = (~t12 & c2) ^ t18 ^ FltRoundConstant;
                b = (~c2 & t18) ^ t12;
                c = (~t18 & t12) ^ c2;
                pos += 8;
            }
            int rem = ((n - 1) & 7) + 1;
            Span<byte> tb = stackalloc byte[8];
            tb.Clear();
            nm.AsSpan(pos, rem).CopyTo(tb);
            tail = BinaryPrimitives.ReadUInt64LittleEndian(tb);
        }

        ulong x16 = b, x11 = c, x6 = tail ^ a ^ FltSeed1;
        ulong u17 = Rotl(x11 ^ x16, 5) ^ x6;
        ulong u18 = Rotl(x11 ^ x6, 17) ^ x16;
        ulong x11b = Rotl(x16 ^ x6, 1) ^ x11;
        return (~Rotl(u18, 11) & Rotr(x11b, 5)) ^ Rotr(u17, 11) ^ FltRoundConstant;
    }

    // ------------------------------------------------------------------ helpers

    private static void CopyStream(MemoryStream ms, Span<byte> dest)
    {
        if (ms.Length > dest.Length)
            throw new InvalidOperationException(
                $"Serialized {ms.Length} bytes exceeds the {dest.Length}-byte block.");
        ms.GetBuffer().AsSpan(0, (int)ms.Length).CopyTo(dest);
    }

}
