// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Key material for package extraction. A finalized image's outer PFS is AES-XTS
// encrypted under the package EKPFS; the EKPFS is either derived from the content id + passcode
// (the fake/debug key schedule, whose inputs are public) or supplied directly (e.g. an image key a
// provisioned console produced for a finalized/keyed package). This type captures the caller's
// choice and materialises the ordered list of candidate EKPFS values the extractor tries.
#nullable enable
using LibProsperoPkg.PFS;
using LibProsperoPkg.Util;
using System;
using System.Collections.Generic;

namespace LibProsperoPkg.PKG;

/// <summary>How the extraction key is obtained.</summary>
public enum ProsperoExtractionKeyKind
{
    /// <summary>No key: attempt extraction assuming the filesystem is not encrypted.</summary>
    None,

    /// <summary>Derive the EKPFS from a content id + passcode (public-input key schedule).</summary>
    Passcode,

    /// <summary>Use a supplied 32-byte EKPFS directly.</summary>
    Ekpfs,
}

/// <summary>
/// Describes how to obtain the EKPFS used to decrypt a package's outer PFS. See the file header.
/// </summary>
public sealed class ProsperoExtractionKey
{
    private readonly byte[]? _ekpfs;

    private ProsperoExtractionKey(ProsperoExtractionKeyKind kind, string? contentId, string? passcode, byte[]? ekpfs)
    {
        Kind = kind;
        ContentId = contentId;
        Passcode = passcode;
        _ekpfs = ekpfs;
    }

    /// <summary>How this key is obtained.</summary>
    public ProsperoExtractionKeyKind Kind { get; }

    /// <summary>The 36-character content id, when the key was built with one; otherwise <see langword="null"/>.</summary>
    public string? ContentId { get; }

    /// <summary>The 32-character passcode, when the key derives from one; otherwise <see langword="null"/>.</summary>
    public string? Passcode { get; }

    /// <summary>A copy of the supplied EKPFS, or <see langword="null"/> when not an <see cref="ProsperoExtractionKeyKind.Ekpfs"/> key.</summary>
    public byte[]? Ekpfs => _ekpfs is null ? null : (byte[])_ekpfs.Clone();

    /// <summary>
    /// The key that attempts extraction with no decryption material. Works only when the outer
    /// filesystem is not encrypted.
    /// </summary>
    public static ProsperoExtractionKey None { get; } =
        new(ProsperoExtractionKeyKind.None, null, null, null);

    /// <summary>
    /// Derives the EKPFS from a passcode, reading the content id from the package at extraction time.
    /// </summary>
    /// <param name="passcode">The 32-character passcode.</param>
    public static ProsperoExtractionKey FromPasscode(string passcode)
    {
        ValidatePasscode(passcode);
        return new ProsperoExtractionKey(ProsperoExtractionKeyKind.Passcode, null, passcode, null);
    }

    /// <summary>
    /// Derives the EKPFS from an explicit content id + passcode (used when the package carries no
    /// readable embedded content id, e.g. a split finalized image).
    /// </summary>
    /// <param name="contentId">The 36-character content id.</param>
    /// <param name="passcode">The 32-character passcode.</param>
    public static ProsperoExtractionKey FromPasscode(string contentId, string passcode)
    {
        ValidateContentId(contentId);
        ValidatePasscode(passcode);
        return new ProsperoExtractionKey(ProsperoExtractionKeyKind.Passcode, contentId, passcode, null);
    }

    /// <summary>
    /// Uses a supplied 32-byte EKPFS directly (e.g. an image key a provisioned console produced for
    /// a finalized/keyed package). The value is never derived or forged by this library.
    /// </summary>
    /// <param name="ekpfs">The 32-byte EKPFS.</param>
    public static ProsperoExtractionKey FromEkpfs(ReadOnlySpan<byte> ekpfs)
    {
        if (ekpfs.Length != 32)
            throw new ArgumentException($"EKPFS must be exactly 32 bytes (was {ekpfs.Length}).", nameof(ekpfs));
        return new ProsperoExtractionKey(ProsperoExtractionKeyKind.Ekpfs, null, null, ekpfs.ToArray());
    }

    /// <summary>
    /// Materialises the ordered list of candidate 32-byte EKPFS values to try against the outer PFS.
    /// For a passcode key both the SHA-256 and SHA3-256 EKPFS schedules are returned so the correct
    /// one is selected automatically. For an explicit EKPFS the single value is returned. For
    /// <see cref="None"/> the list is empty (no encryption expected).
    /// </summary>
    /// <param name="packageContentId">The content id read from the package, used when the key
    /// was built from a passcode without an explicit content id.</param>
    public IReadOnlyList<byte[]> ResolveEkpfsCandidates(string? packageContentId)
    {
        switch (Kind)
        {
            case ProsperoExtractionKeyKind.Ekpfs:
                return new[] { (byte[])_ekpfs!.Clone() };

            case ProsperoExtractionKeyKind.Passcode:
                string? contentId = ContentId ?? packageContentId;
                if (string.IsNullOrEmpty(contentId) || contentId.Length != 36)
                    throw new ProsperoExtractionException(
                        "A 36-character content id is required to derive the key from a passcode. " +
                        "Supply it via ProsperoExtractionKey.FromPasscode(contentId, passcode).");
                return new[]
                {
                    Crypto.ComputeKeys(contentId, Passcode!, 1, useSha3: false),
                    Crypto.ComputeKeys(contentId, Passcode!, 1, useSha3: true),
                };

            default:
                return Array.Empty<byte[]>();
        }
    }

    private static void ValidatePasscode(string passcode)
    {
        ArgumentNullException.ThrowIfNull(passcode);
        if (passcode.Length != 32)
            throw new ArgumentException("Passcode must be exactly 32 characters.", nameof(passcode));
    }

    private static void ValidateContentId(string contentId)
    {
        ArgumentNullException.ThrowIfNull(contentId);
        if (contentId.Length != 36)
            throw new ArgumentException("Content id must be exactly 36 characters.", nameof(contentId));
    }
}
