// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// The debug grant for a content id + passcode. A debug image derives its mount key from public
// inputs only (the content id and the passcode), so the mount path consumes no license record.
// This type computes that derived key set and states the "no rif required" decision in one place.
// It never holds or fabricates a per-device secret: an all-zero content key is not a grant, and the
// structural rif it can emit carries a zero blob. The derived debug key stays distinct from the
// sealed retail key; this type only produces the former.

#nullable enable
using LibProsperoPkg.PFS;
using System;
using System.Text;

namespace LibProsperoPkg.License;

/// <summary>
/// The full derived key set for one debug image: the EKPFS and the AES-XTS (tweak, data) pair and
/// sign key it yields for a specific superblock seed. Every value is a function of public inputs.
/// </summary>
/// <param name="Ekpfs">The 32-byte image key derived from the content id and passcode.</param>
/// <param name="TweakKey">The 16-byte AES-XTS tweak key for the image data.</param>
/// <param name="DataKey">The 16-byte AES-XTS data key for the image data.</param>
/// <param name="SignKey">The 32-byte key for the image's signed metadata blocks.</param>
public sealed record ProsperoDebugKeySet(byte[] Ekpfs, byte[] TweakKey, byte[] DataKey, byte[] SignKey);

/// <summary>
/// Expresses the debug grant for a package: the content id and passcode whose EKPFS the mount path
/// recomputes. A debug image needs no <see cref="ProsperoRif"/>, because its key is derived, not
/// granted. Use <see cref="DeriveEkpfs"/> / <see cref="DeriveKeySet"/> to obtain the key material,
/// and <see cref="ToStructuralRif"/> only when a pipeline expects a license file to be present.
/// </summary>
public sealed class ProsperoDebugLicense
{
    /// <summary>Length in bytes of the derived EKPFS.</summary>
    public const int EkpfsSize = 32;

    /// <summary>Length in bytes of the superblock seed the image keys are bound to.</summary>
    public const int SeedSize = 16;

    /// <summary>Required passcode length.</summary>
    public const int PasscodeLength = 32;

    /// <summary>Maximum content-id length in bytes.</summary>
    public const int ContentIdMaxLength = 0x24;

    /// <summary>The all-zero passcode, the debug default.</summary>
    public static string DefaultPasscode => new('0', PasscodeLength);

    /// <summary>The package content id the derived key binds to. Also the id a structural rif carries.</summary>
    public required string ContentId { get; init; }

    /// <summary>The 32-character passcode. The all-zero passcode is the debug default.</summary>
    public required string Passcode { get; init; }

    /// <summary>
    /// A debug grant never requires a license record. The mount path recomputes the EKPFS from the
    /// content id and passcode, so no rif is consumed.
    /// </summary>
    public bool RequiresRif => false;

    /// <summary>
    /// Builds a debug grant for <paramref name="contentId"/>. The passcode defaults to the all-zero
    /// debug passcode when omitted.
    /// </summary>
    /// <exception cref="ArgumentException">The content id or passcode is malformed.</exception>
    public static ProsperoDebugLicense Create(string contentId, string? passcode = null)
    {
        string pass = passcode ?? DefaultPasscode;
        var license = new ProsperoDebugLicense { ContentId = contentId, Passcode = pass };
        if (!license.Validate(out string? error))
            throw new ArgumentException(error, nameof(contentId));
        return license;
    }

    /// <summary>Derives the 32-byte EKPFS from the content id and passcode.</summary>
    public byte[] DeriveEkpfs() => ProsperoPfsKeys.DeriveEkpfs(ContentId, Passcode);

    /// <summary>
    /// Derives the AES-XTS (tweak, data) key pair for the image data from the given 16-byte
    /// superblock <paramref name="seed"/>.
    /// </summary>
    public (byte[] TweakKey, byte[] DataKey) DeriveImageEncryptionKeys(byte[] seed) =>
        ProsperoPfsKeys.DeriveImageEncryptionKeys(DeriveEkpfs(), seed);

    /// <summary>Derives the 32-byte sign key for the image's signed metadata from the given seed.</summary>
    public byte[] DeriveImageSignKey(byte[] seed) =>
        ProsperoPfsKeys.DeriveImageSignKey(DeriveEkpfs(), seed);

    /// <summary>
    /// Derives the complete key set (EKPFS, tweak, data and sign keys) for an image built with the
    /// given 16-byte superblock <paramref name="seed"/> in one call.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="seed"/> is not exactly <see cref="SeedSize"/> bytes.</exception>
    public ProsperoDebugKeySet DeriveKeySet(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        if (seed.Length != SeedSize)
            throw new ArgumentException($"A superblock seed is exactly {SeedSize} bytes (got {seed.Length}).", nameof(seed));

        byte[] ekpfs = DeriveEkpfs();
        var (tweak, data) = ProsperoPfsKeys.DeriveImageEncryptionKeys(ekpfs, seed);
        byte[] sign = ProsperoPfsKeys.DeriveImageSignKey(ekpfs, seed);
        return new ProsperoDebugKeySet(ekpfs, tweak, data, sign);
    }

    /// <summary>
    /// Emits a structural rif bound to this content id, with a zero key blob. The debug mount path
    /// does not consume it; it exists only for pipelines that expect a license file to be present.
    /// </summary>
    public ProsperoRif ToStructuralRif(long expiry = ProsperoRif.NeverExpires) =>
        ProsperoRif.Create(ContentId, keyBlob: null, expiry);

    /// <summary>
    /// Checks that the content id and passcode are well-formed. Returns <see langword="true"/> when
    /// usable; otherwise <paramref name="error"/> describes the first problem.
    /// </summary>
    public bool Validate(out string? error)
    {
        if (string.IsNullOrEmpty(ContentId) || Encoding.ASCII.GetByteCount(ContentId) > ContentIdMaxLength)
        {
            error = $"A content id is 1..{ContentIdMaxLength} ASCII bytes.";
            return false;
        }
        if (string.IsNullOrEmpty(Passcode) || Passcode.Length != PasscodeLength)
        {
            error = $"A passcode is exactly {PasscodeLength} characters.";
            return false;
        }
        error = null;
        return true;
    }

    /// <summary>Returns the content id and rif requirement for diagnostics.</summary>
    public override string ToString() => $"DebugLicense({ContentId}, rif required={RequiresRif})";
}
