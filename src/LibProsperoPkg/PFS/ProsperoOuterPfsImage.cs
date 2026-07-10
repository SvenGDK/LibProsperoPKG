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
    /// Computes the index of the plaintext metadata (superblock) block from the package-absolute
    /// image and metadata offsets recorded in the FIH / <c>pfsimage.xml</c>
    /// (e.g. image <c>0x10000</c>, metadata <c>0x70000</c>, block <c>0x10000</c> ⇒ block 6).
    /// </summary>
    public static int MetadataBlockIndex(long imageOffset, long metadataOffset, int blockSize = DefaultBlockSize)
    {
        if (blockSize <= 0 || (blockSize & 15) != 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be a positive multiple of 16.");
        if (metadataOffset < imageOffset)
            throw new ArgumentOutOfRangeException(nameof(metadataOffset), "Metadata offset must not precede the image offset.");
        long rel = metadataOffset - imageOffset;
        if ((rel % blockSize) != 0)
            throw new ArgumentException("Metadata offset is not block-aligned within the image.", nameof(metadataOffset));
        return checked((int)(rel / blockSize));
    }

    /// <summary>
    /// AES-XTS transforms <paramref name="image"/> in place: every whole block is encrypted (or
    /// decrypted) as a single XTS data unit with the sector number equal to its block index,
    /// except <paramref name="plaintextBlockIndex"/> which is left untouched. Returns the number
    /// of blocks transformed.
    /// </summary>
    /// <param name="image">The full outer-PFS image (mutated in place).</param>
    /// <param name="tweakKey">16-byte AES-XTS tweak key.</param>
    /// <param name="dataKey">16-byte AES-XTS data key.</param>
    /// <param name="blockSize">Block size in bytes (default 0x10000); must be a multiple of 16.</param>
    /// <param name="plaintextBlockIndex">Index of the metadata/superblock block to leave plaintext, or a negative value to encrypt every block.</param>
    /// <param name="encrypt"><c>true</c> to encrypt, <c>false</c> to decrypt.</param>
    public static int Transform(
        Span<byte> image, ReadOnlySpan<byte> tweakKey, ReadOnlySpan<byte> dataKey,
        int blockSize, int plaintextBlockIndex, bool encrypt)
    {
        if (tweakKey.Length != 16)
            throw new ArgumentException($"Tweak key must be 16 bytes (was {tweakKey.Length}).", nameof(tweakKey));
        if (dataKey.Length != 16)
            throw new ArgumentException($"Data key must be 16 bytes (was {dataKey.Length}).", nameof(dataKey));
        if (blockSize <= 0 || (blockSize & 15) != 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be a positive multiple of 16.");

        var xts = new XtsBlockTransform(dataKey.ToArray(), tweakKey.ToArray());
        int total = (image.Length + blockSize - 1) / blockSize;
        int transformed = 0;

        for (int i = 0; i < total; i++)
        {
            if (i == plaintextBlockIndex)
                continue;

            int offset = i * blockSize;
            int len = Math.Min(blockSize, image.Length - offset);
            if ((len & 15) != 0)
                throw new ArgumentException(
                    $"Block {i} length {len} is not a multiple of the AES block size (16).", nameof(image));

            // CryptSector treats the whole buffer as one XTS data unit (GF-doubling the tweak
            // per 16 bytes), which is exactly the validated outer-image scheme.
            byte[] block = image.Slice(offset, len).ToArray();
            xts.CryptSector(block, (ulong)i, encrypt);
            block.CopyTo(image.Slice(offset, len));
            transformed++;
        }

        return transformed;
    }

    /// <summary>
    /// AES-XTS transforms <paramref name="image"/> in place using an explicit per-block
    /// classification: <see cref="ProsperoOuterBlockKind.Data"/> blocks use sector = block index,
    /// <see cref="ProsperoOuterBlockKind.Signed"/> blocks use sector =
    /// <see cref="ProsperoOuterPfsSignature.SignedBlockTweakFlag"/> | block index (PS5), and
    /// <see cref="ProsperoOuterBlockKind.Plaintext"/> blocks are left untouched. This is the full
    /// validated PS5 nwonly outer-image scheme (data blocks 0-5 plain, superblock plaintext, signed
    /// metadata blocks 7-10 with bit 47 set). Returns the number of blocks transformed.
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
    public static int EncryptInPlace(
        Span<byte> image, byte[] ekpfs, byte[] seed, int plaintextBlockIndex,
        int blockSize = DefaultBlockSize)
    {
        var (tweak, data) = ProsperoPfsKeys.DeriveImageEncryptionKeys(ekpfs, seed);
        return Transform(image, tweak, data, blockSize, plaintextBlockIndex, encrypt: true);
    }

    /// <summary>
    /// Decrypts the outer image in place (inverse of <see cref="EncryptInPlace(Span{byte}, byte[], byte[], int, int)"/>).
    /// </summary>
    public static int DecryptInPlace(
        Span<byte> image, byte[] ekpfs, byte[] seed, int plaintextBlockIndex,
        int blockSize = DefaultBlockSize)
    {
        var (tweak, data) = ProsperoPfsKeys.DeriveImageEncryptionKeys(ekpfs, seed);
        return Transform(image, tweak, data, blockSize, plaintextBlockIndex, encrypt: false);
    }

    /// <summary>
    /// Encrypts the outer image in place, deriving the EKPFS (and then the AES-XTS keys) from the
    /// package <paramref name="contentId"/> + <paramref name="passcode"/> and the 16-byte
    /// <paramref name="seed"/> in one step.
    /// </summary>
    public static int EncryptInPlace(
        Span<byte> image, string contentId, string passcode, byte[] seed, int plaintextBlockIndex,
        int blockSize = DefaultBlockSize)
        => EncryptInPlace(image, ProsperoPfsKeys.DeriveEkpfs(contentId, passcode), seed,
            plaintextBlockIndex, blockSize);

    /// <summary>
    /// Decrypts the outer image in place, deriving the keys from the package
    /// <paramref name="contentId"/> + <paramref name="passcode"/> and the <paramref name="seed"/>.
    /// </summary>
    public static int DecryptInPlace(
        Span<byte> image, string contentId, string passcode, byte[] seed, int plaintextBlockIndex,
        int blockSize = DefaultBlockSize)
        => DecryptInPlace(image, ProsperoPfsKeys.DeriveEkpfs(contentId, passcode), seed,
            plaintextBlockIndex, blockSize);

}
