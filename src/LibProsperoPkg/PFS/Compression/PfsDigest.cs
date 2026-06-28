// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// SHA3-256 digest helpers for the PS5 PFSv3 compression file format.
//
// The PFS compression container hashes every block (and the whole file) with SHA3-256, NOT SHA-256.
// Validated against reference output: each block hash in the container's id=4 section equals
// SHA3-256(uncompressed block bytes), and the header's "File Digest (SHA3)" at offset 0x28
// is a SHA3-256 value.
#nullable enable
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace LibProsperoPkg.PFS.Compression;

/// <summary>
/// Computes the SHA3-256 digests the PS5 PFSv3 compression container uses for its
/// per-block hashes (the <c>id=4</c> metadata section) and its file-level digest (header
/// offset <c>0x28</c>).
/// </summary>
/// <remarks>
/// SHA3-256 is the hash primitive used throughout the PFS compression format. Per-block
/// hashes are taken over the <i>uncompressed</i> block bytes, which is what
/// <see cref="ComputeBlockDigest(System.ReadOnlySpan{byte})"/> returns. The host runtime must
/// support SHA3-256; query <see cref="IsSupported"/> before use. (.NET 10 on a supported OS
/// satisfies this; it maps to the platform SHA-3 implementation.)
/// </remarks>
public static class PfsDigest
{
    /// <summary>The length, in bytes, of a SHA3-256 digest (256 bits).</summary>
    public const int DigestLength = 32;

    /// <summary>
    /// Gets a value indicating whether the host runtime and operating system provide SHA3-256.
    /// </summary>
    public static bool IsSupported => SHA3_256.IsSupported;

    /// <summary>
    /// Computes the SHA3-256 digest of a single PFS block's <b>uncompressed</b> bytes, matching the
    /// per-block hash stored in the container's <c>id=4</c> metadata section.
    /// </summary>
    /// <param name="uncompressedBlock">The raw (pre-compression, post-deshuffle) block bytes.</param>
    /// <returns>The 32-byte SHA3-256 digest.</returns>
    /// <exception cref="PlatformNotSupportedException">SHA3-256 is unavailable on this host.</exception>
    public static byte[] ComputeBlockDigest(ReadOnlySpan<byte> uncompressedBlock)
    {
        EnsureSupported();
        return SHA3_256.HashData(uncompressedBlock);
    }

    /// <summary>
    /// Computes the SHA3-256 digest of <paramref name="data"/> into <paramref name="destination"/>.
    /// </summary>
    /// <param name="data">The bytes to hash.</param>
    /// <param name="destination">A span of at least <see cref="DigestLength"/> bytes.</param>
    /// <returns>The number of bytes written (always <see cref="DigestLength"/>).</returns>
    /// <exception cref="PlatformNotSupportedException">SHA3-256 is unavailable on this host.</exception>
    public static int ComputeBlockDigest(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        EnsureSupported();
        return SHA3_256.HashData(data, destination);
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="expected"/> equals the SHA3-256 digest of
    /// <paramref name="uncompressedBlock"/>, using a fixed-time comparison.
    /// </summary>
    /// <param name="uncompressedBlock">The raw (pre-compression) block bytes.</param>
    /// <param name="expected">The 32-byte digest read from the container metadata.</param>
    public static bool VerifyBlockDigest(ReadOnlySpan<byte> uncompressedBlock, ReadOnlySpan<byte> expected)
    {
        if (expected.Length != DigestLength)
            return false;
        EnsureSupported();
        Span<byte> actual = stackalloc byte[DigestLength];
        SHA3_256.HashData(uncompressedBlock, actual);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static void EnsureSupported()
    {
        if (!SHA3_256.IsSupported)
            throw new PlatformNotSupportedException(
                "SHA3-256 is required for the PS5 PFSv3 compression format but is not available on this host.");
    }

    /// <summary>The length, in bytes, of the header parameter slice (<c>container[0x08..0x20]</c>) the file digest hashes.</summary>
    public const int FileDigestHeaderParamsLength = 0x18;

    /// <summary>
    /// Computes the container's file-level SHA3-256 digest (stored at header offset <c>0x28</c>),
    /// using the target format's file-digest algorithm.
    /// </summary>
    /// <param name="headerParams">
    /// Exactly <see cref="FileDigestHeaderParamsLength"/> (24) bytes copied verbatim from the container
    /// header at offsets <c>0x08..0x20</c> (block size, encode parameters, and uncompressed size).
    /// </param>
    /// <param name="shuffleSection">The shuffle-pattern metadata section bytes (directory id=2).</param>
    /// <param name="boundarySection">The block-boundary table bytes (directory id=3).</param>
    /// <param name="blockHashSection">The per-block hash table bytes (directory id=4).</param>
    /// <returns>The 32-byte SHA3-256 file digest.</returns>
    /// <remarks>
    /// The preimage is <c>header32 || shuffleSection || boundarySection || blockHashSection</c>, where
    /// <c>header32</c> is a 32-byte, 8-byte-aligned little-endian struct:
    /// <c>{u32 1; u32 blockSize; u32 encodeParam0C; u32 0 (pad); u64 encodeParam10; u64 uncompressedSize}</c>.
    /// This layout was validated byte-exact against independent encoder outputs
    /// (compressed and stored blocks).
    /// </remarks>
    /// <exception cref="ArgumentException"><paramref name="headerParams"/> is not 24 bytes.</exception>
    /// <exception cref="PlatformNotSupportedException">SHA3-256 is unavailable on this host.</exception>
    public static byte[] ComputeFileDigest(
        ReadOnlySpan<byte> headerParams,
        ReadOnlySpan<byte> shuffleSection,
        ReadOnlySpan<byte> boundarySection,
        ReadOnlySpan<byte> blockHashSection)
    {
        if (headerParams.Length != FileDigestHeaderParamsLength)
            throw new ArgumentException(
                $"headerParams must be exactly {FileDigestHeaderParamsLength} bytes (container[0x08..0x20]).",
                nameof(headerParams));
        EnsureSupported();

        // header32: {u32 1, u32 blockSize, u32 param0C, u32 0(pad), u64 param10, u64 uncompressedSize}.
        Span<byte> header32 = stackalloc byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(header32, 1u);
        headerParams[..8].CopyTo(header32[4..]);   // blockSize (0x08) + param0C (0x0C)
        // header32[12..16] stays zero (alignment padding).
        headerParams[8..].CopyTo(header32[16..]);  // param10 (0x10) + uncompressedSize (0x18)

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA3_256);
        hash.AppendData(header32);
        hash.AppendData(shuffleSection);
        hash.AppendData(boundarySection);
        hash.AppendData(blockHashSection);
        return hash.GetHashAndReset();
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="expected"/> equals the file digest computed by
    /// <see cref="ComputeFileDigest"/>, using a fixed-time comparison.
    /// </summary>
    public static bool VerifyFileDigest(
        ReadOnlySpan<byte> headerParams,
        ReadOnlySpan<byte> shuffleSection,
        ReadOnlySpan<byte> boundarySection,
        ReadOnlySpan<byte> blockHashSection,
        ReadOnlySpan<byte> expected)
    {
        if (expected.Length != DigestLength)
            return false;
        byte[] actual = ComputeFileDigest(headerParams, shuffleSection, boundarySection, blockHashSection);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
