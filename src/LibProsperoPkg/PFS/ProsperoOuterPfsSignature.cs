// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PS5 outer-PFS *signing* primitives for the `--oformat nwonly`
// finalized image. The outer superblock builder and metadata writer outputs are Validated byte-exact against the reference
// package's outer PFS image (all 11 blocks reproduce the reference on-disk ciphertext, every stored
// hash and the superblock ICV match):
//
// * Per-block / dinode hash = plain SHA3-256(plaintext block). Stored at dinode+0x64 (32 bytes),
// immediately followed by the owning block index at dinode+0x84 (u32 LE) — a 36-byte {hash,blkIdx}
// entry, one per block an inode owns. The super-root inode in the superblock stores the same shape
// for the inode-table block (SHA3 at sb+0xb8, block index at sb+0xd8).
// * Superblock ICV (sb+0x380, 32 bytes) = SHA3-256( superblock[0:0x5a0] ) with the 32-byte ICV field
// itself zeroed for the computation (the ICV lives inside the hashed region).
// * Block AES-XTS sector numbering carries a "signed block" domain-separation flag: PS5 metadata /
// signed blocks use sector = 0x800000000000 | blockIndex, while plain file-data blocks use sector =
// blockIndex. (The superblock block is stored plaintext.) See <see cref="SignedBlockTweakFlag"/>.
//
// Hashes are computed over PLAINTEXT blocks BEFORE encryption (sign-then-encrypt order).
#nullable enable
using System;
using System.Security.Cryptography;

namespace LibProsperoPkg.PFS;

/// <summary>
/// PS5 outer-PFS signing primitives: the plain SHA3-256 per-block/dinode hash,
/// the superblock ICV, and the AES-XTS "signed block" sector flag. See the file header for the provenance.
/// </summary>
public static class ProsperoOuterPfsSignature
{
    /// <summary>Length of a 32-byte SHA3-256 hash as stored in dinodes and the superblock.</summary>
    public const int HashLength = 32;

    /// <summary>
    /// AES-XTS sector domain-separation flag OR'd into a PS5 signed / metadata block's sector number
    /// (bit 47). Plain file-data blocks use sector = blockIndex; signed blocks use
    /// <c>SignedBlockTweakFlag | blockIndex</c>.
    /// </summary>
    public const ulong SignedBlockTweakFlag = 0x800000000000UL;

    /// <summary>Byte length of the superblock region covered by the ICV hash.</summary>
    public const int SuperblockIcvCoverage = 0x5a0;

    /// <summary>Offset of the 32-byte ICV field within the superblock.</summary>
    public const int SuperblockIcvOffset = 0x380;

    /// <summary>Offset of the super-root inode hash (SHA3 of the inode-table block) in the superblock.</summary>
    public const int SuperblockRootHashOffset = 0xb8;

    /// <summary>Offset of the super-root inode's block index (u32 LE) in the superblock.</summary>
    public const int SuperblockRootBlockIndexOffset = 0xd8;

    /// <summary>
    /// The per-block / dinode integrity hash: plain SHA3-256 over the whole plaintext block.
    /// </summary>
    public static byte[] ComputeBlockHash(ReadOnlySpan<byte> plaintextBlock)
    {
        if (!SHA3_256.IsSupported)
            throw new PlatformNotSupportedException(
                "SHA3-256 is required for the PS5 outer-PFS block hash but is not available on this platform/runtime.");
        return SHA3_256.HashData(plaintextBlock);
    }

    /// <summary>
    /// Computes the AES-XTS sector number for a block: <paramref name="blockIndex"/> for plain
    /// file-data blocks, or <c>SignedBlockTweakFlag | blockIndex</c> for signed/metadata blocks.
    /// </summary>
    public static ulong BlockSector(int blockIndex, bool signed)
    {
        if (blockIndex < 0)
            throw new ArgumentOutOfRangeException(nameof(blockIndex));
        ulong sector = (ulong)(uint)blockIndex;
        if (signed)
            sector |= SignedBlockTweakFlag;
        return sector;
    }

    /// <summary>
    /// Computes the superblock ICV: SHA3-256 over <c>superblock[0 .. 0x5a0]</c> with the 32-byte ICV
    /// field (at <see cref="SuperblockIcvOffset"/>) treated as zero. Does not mutate the input.
    /// </summary>
    public static byte[] ComputeSuperblockIcv(ReadOnlySpan<byte> superblock)
    {
        if (superblock.Length < SuperblockIcvCoverage)
            throw new ArgumentException(
                $"Superblock must be at least 0x{SuperblockIcvCoverage:x} bytes to compute the ICV.", nameof(superblock));
        if (!SHA3_256.IsSupported)
            throw new PlatformNotSupportedException(
                "SHA3-256 is required for the PS5 outer-PFS superblock ICV but is not available on this platform/runtime.");

        Span<byte> region = stackalloc byte[SuperblockIcvCoverage];
        superblock[..SuperblockIcvCoverage].CopyTo(region);
        region.Slice(SuperblockIcvOffset, HashLength).Clear();
        return SHA3_256.HashData(region);
    }

    /// <summary>
    /// Computes the superblock ICV and writes it into the 32-byte ICV field at
    /// <see cref="SuperblockIcvOffset"/>. The field is zeroed before hashing, exactly matching the
    /// builder (which hashes the region with the not-yet-written ICV field still zero).
    /// </summary>
    public static void WriteSuperblockIcv(Span<byte> superblock)
    {
        byte[] icv = ComputeSuperblockIcv(superblock);
        icv.CopyTo(superblock.Slice(SuperblockIcvOffset, HashLength));
    }

}
