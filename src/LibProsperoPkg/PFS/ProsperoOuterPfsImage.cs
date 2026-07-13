// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PS5 *finalized-image* outer-PFS AES-XTS encryptor/decryptor — the encryption layer of
// the `nwonly` package. This is DISTINCT from the inner-PFS
// image crypto in ProsperoPfsImage:
//
// * Inner PFS (installable): AES-XTS over 0x1000-byte sub-sectors, superblock at block 0
// left plaintext, sectors numbered from the superblock. (ProsperoPfsImage.)
// * Outer finalized image (PS5 nwonly): each whole 0x10000 filesystem block is ONE AES-XTS data
// unit, sectors numbered by image block index (0-based from the image start), and the plaintext
// block is the *metadata* (superblock) block — which, in a PS5 read-only "data-first" image, sits
// near the END of the image (block 6 of 11), not block 0.
//
// The (tweak, data) key pair comes from the SHA3-256 EKPFS + new_crypt schedule in ProsperoPfsKeys,
// which is checked BIDIRECTIONALLY: decrypting the on-disk outer
// image yields coherent plaintext (the keystone file and the nested PFS superblock), and re-encrypting
// that plaintext yields the original ciphertext for every encrypted block. This type
// packages that primitive as a first-class, in-memory API (no temp
// files), ready for the nwonly outer-PFS assembler to consume.
#nullable enable
using LibProsperoPkg.Util;
using System;

namespace LibProsperoPkg.PFS;

/// <summary>
/// Classification of an outer-PFS block for AES-XTS sector numbering.
/// </summary>
public enum ProsperoOuterBlockKind : byte
{
    /// <summary>Plain file-data block: XTS sector = block index.</summary>
    Data = 0,

    /// <summary>
    /// Signed / metadata block: XTS sector = <see cref="ProsperoOuterPfsSignature.SignedBlockTweakFlag"/>
    /// | block index.
    /// </summary>
    Signed = 1,

    /// <summary>Superblock / metadata block stored plaintext (not encrypted).</summary>
    Plaintext = 2,
}

/// <summary>
/// AES-XTS encrypt/decrypt for the PS5 nwonly <em>outer</em> finalized-image PFS. Each whole
/// filesystem block is one XTS data unit numbered by its image block index; the metadata
/// (superblock) block is left plaintext. See the file header for how this differs from the
/// inner-image crypto in <see cref="ProsperoPfsImage"/> and how it was validated.
/// </summary>
public static class ProsperoOuterPfsImage
{
    /// <summary>The outer finalized-image PFS block size (one block = one AES-XTS data unit).</summary>
    public const int DefaultBlockSize = 0x10000;

    /// <summary>
    /// AES-XTS transforms <paramref name="image"/> in place using an explicit per-block
    /// classification: <see cref="ProsperoOuterBlockKind.Data"/> blocks use sector = block index,
    /// <see cref="ProsperoOuterBlockKind.Signed"/> blocks use sector =
    /// <see cref="ProsperoOuterPfsSignature.SignedBlockTweakFlag"/> | block index (PS5), and
    /// <see cref="ProsperoOuterBlockKind.Plaintext"/> blocks are left untouched. This is the full
    /// validated outer-image scheme (data blocks 0-4 plain, superblock (block 6) plaintext, signed
    /// blocks 5,7-10 with bit 47 set). Returns the number of blocks transformed.
    /// </summary>
    public static int Transform(
        Span<byte> image, ReadOnlySpan<byte> tweakKey, ReadOnlySpan<byte> dataKey,
        int blockSize, ReadOnlySpan<ProsperoOuterBlockKind> blockKinds, bool encrypt)
    {
        if (tweakKey.Length != 16)
            throw new ArgumentException($"Tweak key must be 16 bytes (was {tweakKey.Length}).", nameof(tweakKey));
        if (dataKey.Length != 16)
            throw new ArgumentException($"Data key must be 16 bytes (was {dataKey.Length}).", nameof(dataKey));
        if (blockSize <= 0 || (blockSize & 15) != 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be a positive multiple of 16.");

        int total = (image.Length + blockSize - 1) / blockSize;
        if (blockKinds.Length != total)
            throw new ArgumentException(
                $"blockKinds length ({blockKinds.Length}) must equal the block count ({total}).", nameof(blockKinds));

        var xts = new XtsBlockTransform(dataKey.ToArray(), tweakKey.ToArray());
        int transformed = 0;

        for (int i = 0; i < total; i++)
        {
            ProsperoOuterBlockKind kind = blockKinds[i];
            if (kind == ProsperoOuterBlockKind.Plaintext)
                continue;

            int offset = i * blockSize;
            int len = Math.Min(blockSize, image.Length - offset);
            if ((len & 15) != 0)
                throw new ArgumentException(
                    $"Block {i} length {len} is not a multiple of the AES block size (16).", nameof(image));

            ulong sector = ProsperoOuterPfsSignature.BlockSector(
                i, kind == ProsperoOuterBlockKind.Signed);

            byte[] block = image.Slice(offset, len).ToArray();
            xts.CryptSector(block, sector, encrypt);
            block.CopyTo(image.Slice(offset, len));
            transformed++;
        }

        return transformed;
    }
}
