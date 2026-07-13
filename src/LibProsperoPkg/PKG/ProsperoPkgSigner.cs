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
// console-held secrets that cannot be reproduced here. This class supplies the signing/key
// primitives the write path consumes, and is fully self-validated in isolation.

using LibProsperoPkg.Keys;
using System;
using System.Security.Cryptography;
using System.Text;

namespace LibProsperoPkg.PKG;

/// <summary>
/// PS5 PKG-metadata signing and PFS key-derivation primitives backed by the embedded
/// PS5 key material. See the file header for the boundary between what is
/// verifiable here and what additionally depends on console-held secrets.
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
    /// Produces the 384-byte CNT header-signature value: the 32-byte SHA3-256 header digest is
    /// PKCS#1 v1.5 (type 2) padded and raised to the public exponent of the PKG-metadata RSA-3072
    /// key. A verifier recovers the padded block with the private exponent, strips the padding and
    /// compares the trailing 32 bytes to its own SHA3-256 of the header region.
    /// </summary>
    /// <param name="sha3Digest">The 32-byte SHA3-256 digest of the CNT header region.</param>
    /// <returns>A 384-byte big-endian value.</returns>
    /// <exception cref="InvalidOperationException">The PKG-metadata key is unavailable.</exception>
    public static byte[] EncryptHeaderDigest(byte[] sha3Digest)
    {
        ArgumentNullException.ThrowIfNull(sha3Digest);
        if (sha3Digest.Length != 32)
            throw new ArgumentException("A SHA3-256 digest is exactly 32 bytes.", nameof(sha3Digest));

        using var rsa = ProsperoKeys.CreateMetadataRsa();
        return rsa.Encrypt(sha3Digest, RSAEncryptionPadding.Pkcs1);
    }

    /// <summary>Recovers the 32-byte digest sealed by <see cref="EncryptHeaderDigest"/>.</summary>
    public static byte[] DecryptHeaderDigest(byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        using var rsa = ProsperoKeys.CreateMetadataRsa();
        return rsa.Decrypt(signature, RSAEncryptionPadding.Pkcs1);
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
    /// Computes a package key for the given index using the PS5 key ladder:
    /// <c>SHA3-256( SHA3-256(index_be) || SHA3-256(content_id padded to 48) || passcode )</c>.
    /// Index 1 is the EKPFS. Delegates to the canonical
    /// <see cref="Util.Crypto.ComputeKeys(string, string, uint, bool)"/> (SHA3-256) so the derivation
    /// matches the outer-PFS mount-key path.
    /// </summary>
    public static byte[] ComputeKeys(string contentId, string passcode, uint index)
    {
        ArgumentNullException.ThrowIfNull(contentId);
        ArgumentNullException.ThrowIfNull(passcode);
        return Util.Crypto.ComputeKeys(contentId, passcode, index, useSha3: true);
    }

}
