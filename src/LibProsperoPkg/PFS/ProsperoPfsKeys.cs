// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// PFS image key derivation. A package's outer PFS image is AES-XTS encrypted with a (tweak, data)
// key pair derived from the EKPFS ("encrypted key for PFS") and the 16-byte superblock seed; the
// EKPFS itself is derived from the content-id + passcode. The EKPFS digest primitive is SHA3-256,
// and the image keys are produced by the keyed crypto ladder over (EKPFS, seed). These map onto the
// Crypto primitives via the SHA3 / keyed-crypto switches.
#nullable enable
using System;
using LibProsperoPkg.Util;

namespace LibProsperoPkg.PFS;

/// <summary>
/// Derivation of the PFS image keys: EKPFS, the AES-XTS tweak/data pair, and the block sign key.
/// </summary>
public static class ProsperoPfsKeys
{
    /// <summary>The key-ladder index that yields the EKPFS / encryption key material.</summary>
    public const uint EkpfsIndex = 1;

    /// <summary>
    /// Derives the 32-byte EKPFS from the package <paramref name="contentId"/> (36 chars) and the
    /// 32-char <paramref name="passcode"/> using SHA3-256.
    /// </summary>
    public static byte[] DeriveEkpfs(string contentId, string passcode)
    {
        ArgumentNullException.ThrowIfNull(contentId);
        ArgumentNullException.ThrowIfNull(passcode);
        return Crypto.ComputeKeys(contentId, passcode, EkpfsIndex, useSha3: true);
    }

    /// <summary>
    /// Derives the AES-XTS (tweak, data) key pair for the outer PFS image from the
    /// <paramref name="ekpfs"/> and the 16-byte superblock <paramref name="seed"/>.
    /// </summary>
    public static (byte[] TweakKey, byte[] DataKey) DeriveImageEncryptionKeys(byte[] ekpfs, byte[] seed)
    {
        ValidateEkpfs(ekpfs);
        ValidateSeed(seed);
        var pair = Crypto.PfsGenEncKey(ekpfs, seed, newCrypt: true);
        return (pair.Item1, pair.Item2);
    }

    /// <summary>
    /// Convenience overload: derives the EKPFS from <paramref name="contentId"/>/<paramref name="passcode"/>
    /// and then the AES-XTS (tweak, data) key pair in one step.
    /// </summary>
    public static (byte[] TweakKey, byte[] DataKey) DeriveImageEncryptionKeys(
        string contentId, string passcode, byte[] seed)
        => DeriveImageEncryptionKeys(DeriveEkpfs(contentId, passcode), seed);

    /// <summary>
    /// Derives the 32-byte sign key for the outer PFS image's signed metadata blocks from the
    /// <paramref name="ekpfs"/> and the 16-byte superblock <paramref name="seed"/>.
    /// </summary>
    public static byte[] DeriveImageSignKey(byte[] ekpfs, byte[] seed)
    {
        ValidateEkpfs(ekpfs);
        ValidateSeed(seed);
        return Crypto.PfsGenSignKey(ekpfs, seed, newCrypt: true);
    }

    private static void ValidateEkpfs(byte[] ekpfs)
    {
        ArgumentNullException.ThrowIfNull(ekpfs);
        if (ekpfs.Length != 32)
            throw new ArgumentException($"EKPFS must be exactly 32 bytes (was {ekpfs.Length}).", nameof(ekpfs));
    }

    private static void ValidateSeed(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        if (seed.Length != 16)
            throw new ArgumentException($"PFS seed must be exactly 16 bytes (was {seed.Length}).", nameof(seed));
    }
}
