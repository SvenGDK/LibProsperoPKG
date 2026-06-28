// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PS5 PKG signing primitives. This makes the wired-in PS5 key material
// (RSA-3072 PKG-metadata key, passcode blob, mount-image blob) actually used by the package
// pipeline.
//
// Checks and derivations:
// * The PKG-metadata signature primitive the system software checks: RSA-3072 PKCS#1 v1.5
// over a SHA-256 digest, using the embedded PKG-metadata private key. On a console that
// accepts non-retail packages this metadata-signature check is the gate a package must
// pass, so signing it with the published key satisfies that check.
// * EKPFS / PFS key derivation from content id + passcode
// (LibProsperoPkg.Util.Crypto.ComputeKeys / PfsGenEncKey) for the PS5 inner image.
// * Self-consistency checks: the public modulus recovered from the embedded private key is
// compared against the published modulus, and a sign -> verify round-trip proves the key
// is usable.
//
// What is not done here: a fully accepted retail image additionally depends on
// reference-only secrets that cannot be reproduced here. This class supplies the signing/key
// primitives the write path consumes, and is fully self-validated in isolation.

using LibProsperoPkg.Keys;
using System;
using System.Security.Cryptography;
using System.Text;

namespace LibProsperoPkg.PKG;

/// <summary>
/// PS5 PKG-metadata signing and PFS key-derivation primitives backed by the embedded
/// PS5 key material. See the file header for the boundary between what is
/// verifiable here and what additionally depends on reference-only secrets.
/// </summary>
public static class ProsperoPkgSigner
{
    /// <summary>Size in bytes of an RSA-3072 signature (the PKG-metadata key width).</summary>
    public const int SignatureSize = 384;

    /// <summary>
    /// The first 16 bytes of the published PKG-metadata RSA-3072 modulus. Used only as a
    /// fingerprint to confirm the embedded private key is the documented PKG-metadata key.
    /// </summary>
    private static readonly byte[] PublishedModulusPrefix =
    [
        0xAB, 0x1D, 0xBD, 0x43, 0x39, 0x49, 0x33, 0x16,
        0xA3, 0x5C, 0x40, 0x4E, 0x2C, 0x22, 0x97, 0xB8,
    ];

    /// <summary>True when the PS5 publishing key material required for signing is available.</summary>
    public static bool IsAvailable => ProsperoKeys.IsAvailable;

    /// <summary>
    /// Signs an arbitrary metadata blob with the PKG-metadata RSA-3072 key using PKCS#1 v1.5
    /// over SHA-256 — the signature scheme the system software verifies for a package's metadata.
    /// </summary>
    /// <param name="data">The metadata bytes to sign.</param>
    /// <returns>A 384-byte big-endian RSA-3072 signature.</returns>
    /// <exception cref="InvalidOperationException">The PKG-metadata key is unavailable.</exception>
    public static byte[] SignMetadata(ReadOnlySpan<byte> data)
    {
        using var rsa = ProsperoKeys.CreateMetadataRsa();
        return rsa.SignData(data.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>Verifies a metadata signature produced by <see cref="SignMetadata"/>.</summary>
    public static bool VerifyMetadata(ReadOnlySpan<byte> data, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        using var rsa = ProsperoKeys.CreateMetadataRsa();
        return rsa.VerifyData(data.ToArray(), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Signs a pre-computed 32-byte SHA-256 digest with the PKG-metadata RSA-3072 key
    /// (PKCS#1 v1.5). Use this when the digest is calculated incrementally over a large image.
    /// </summary>
    /// <param name="sha256Digest">A 32-byte SHA-256 digest.</param>
    /// <returns>A 384-byte big-endian RSA-3072 signature.</returns>
    public static byte[] SignDigest(byte[] sha256Digest)
    {
        ArgumentNullException.ThrowIfNull(sha256Digest);
        if (sha256Digest.Length != 32)
            throw new ArgumentException("A SHA-256 digest is exactly 32 bytes.", nameof(sha256Digest));

        using var rsa = ProsperoKeys.CreateMetadataRsa();
        return rsa.SignHash(sha256Digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>Verifies a digest signature produced by <see cref="SignDigest"/>.</summary>
    public static bool VerifyDigest(byte[] sha256Digest, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(sha256Digest);
        ArgumentNullException.ThrowIfNull(signature);
        using var rsa = ProsperoKeys.CreateMetadataRsa();
        return rsa.VerifyHash(sha256Digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Returns the big-endian modulus (n) of the embedded PKG-metadata RSA-3072 key (384 bytes).
    /// </summary>
    public static byte[] MetadataModulus()
    {
        using var rsa = ProsperoKeys.CreateMetadataRsa();
        var modulus = rsa.ExportParameters(false).Modulus
            ?? throw new InvalidOperationException("The PKG-metadata key exposes no modulus.");
        return modulus;
    }

    /// <summary>
    /// Confirms the embedded private key is the documented PKG-metadata key, by matching the
    /// published modulus fingerprint and proving the
    /// key signs and verifies. This is the self-check that replaces on-hardware testing
    /// for the key material itself.
    /// </summary>
    public static bool VerifyKeyMaterial()
    {
        if (!IsAvailable)
            return false;

        var modulus = MetadataModulus();
        if (modulus.Length != SignatureSize)
            return false;
        for (int i = 0; i < PublishedModulusPrefix.Length; i++)
        {
            if (modulus[i] != PublishedModulusPrefix[i])
                return false;
        }

        // Sign -> verify round-trip over a fixed probe digest.
        var probe = SHA256.HashData(Encoding.ASCII.GetBytes("PSMT-PS5-PKG-SIGNER"));
        var signature = SignDigest(probe);
        return signature.Length == SignatureSize && VerifyDigest(probe, signature);
    }

    /// <summary>
    /// Derives the package EKPFS (encryption key for the PFS) from a content id and passcode,
    /// following the package key scheme (index 1).
    /// </summary>
    /// <param name="contentId">The 36-character content id.</param>
    /// <param name="passcode">The 32-character passcode.</param>
    public static byte[] ComputeEkpfs(string contentId, string passcode) =>
        ComputeKeys(contentId, passcode, 1);

    /// <summary>
    /// Computes a package key for the given index. The key is
    /// <c>SHA256( SHA256(index_be) || SHA256(content_id padded to 48) || passcode )</c>.
    /// Index 1 is the EKPFS.
    /// </summary>
    public static byte[] ComputeKeys(string contentId, string passcode, uint index)
    {
        ArgumentNullException.ThrowIfNull(contentId);
        ArgumentNullException.ThrowIfNull(passcode);
        if (contentId.Length != 36)
            throw new ArgumentException($"Content id must be exactly 36 characters (was {contentId.Length}).", nameof(contentId));
        if (passcode.Length != 32)
            throw new ArgumentException($"Passcode must be exactly 32 characters (was {passcode.Length}).", nameof(passcode));

        Span<byte> indexBe = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(indexBe, index);

        byte[] data = new byte[96];
        SHA256.HashData(indexBe).CopyTo(data.AsSpan(0));
        SHA256.HashData(Encoding.ASCII.GetBytes(contentId.PadRight(48, '\0'))).CopyTo(data.AsSpan(32));
        Encoding.ASCII.GetBytes(passcode).CopyTo(data.AsSpan(64));

        return SHA256.HashData(data);
    }

    /// <summary>
    /// Derives the (tweak, data) AES-XTS key pair used to encrypt a PFS image from the EKPFS
    /// and the PFS header seed, following the published key derivation.
    /// </summary>
    /// <param name="ekpfs">The 32-byte EKPFS from <see cref="ComputeEkpfs"/>.</param>
    /// <param name="seed">The 16-byte PFS header crypto seed.</param>
    /// <param name="newCrypt">
    /// When true, derive the encryption key from <c>HMAC(EKPFS, seed)</c> first — the
    /// <c>new_crypt</c> path (the <c>newCrypt</c> scheme). Defaults to the classic path.
    /// </param>
    /// <returns>A tuple of (tweakKey, dataKey), each 16 bytes.</returns>
    public static (byte[] TweakKey, byte[] DataKey) DerivePfsEncryptionKeys(byte[] ekpfs, byte[] seed, bool newCrypt = false)
    {
        ArgumentNullException.ThrowIfNull(ekpfs);
        ArgumentNullException.ThrowIfNull(seed);

        // new_crypt: run the EKPFS through HMAC(EKPFS, seed) before the standard derivation.
        byte[] baseKey = newCrypt ? HMACSHA256.HashData(ekpfs, seed) : ekpfs;
        byte[] enc = PfsGenCryptoKey(baseKey, seed, 1);
        // HMAC-SHA256 always yields 32 bytes; guard the invariant before slicing.
        if (enc.Length < 32)
            throw new InvalidOperationException("PFS key derivation returned an undersized key.");
        byte[] tweak = enc[..16];
        byte[] dataKey = enc[16..32];
        return (tweak, dataKey);
    }

    /// <summary>
    /// Derives the PFS signing key (index 2) from the EKPFS and PFS header seed, following the
    /// published <c>PfsGenSignKey</c> derivation.
    /// </summary>
    public static byte[] DerivePfsSignKey(byte[] ekpfs, byte[] seed) => PfsGenCryptoKey(ekpfs, seed, 2);

    /// <summary>
    /// The common PFS key generator: <c>HMAC-SHA256(ekpfs, index_le || seed)</c>.
    /// </summary>
    private static byte[] PfsGenCryptoKey(byte[] ekpfs, byte[] seed, uint index)
    {
        ArgumentNullException.ThrowIfNull(ekpfs);
        ArgumentNullException.ThrowIfNull(seed);

        byte[] message = new byte[4 + seed.Length];
        // The index is appended little-endian.
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(0, 4), index);
        seed.CopyTo(message.AsSpan(4));
        return HMACSHA256.HashData(ekpfs, message);
    }
}
