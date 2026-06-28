// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// Wired-in PS5 publishing key material, embedded as resources so the build is
// self-contained. None of these are secret retail keys: they are the published PKG-metadata
// RSA-3072 private key (used by the system software to verify a package's metadata) and the
// Prospero publishing passcode / mount-image keys.

using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace LibProsperoPkg.Keys;

/// <summary>
/// Provides access to the published PS5 publishing key material required by the package
/// pipeline. Keys are embedded resources; <see cref="IsAvailable"/> reports whether they could
/// be loaded.
/// </summary>
public static class ProsperoKeys
{
    private const string RsaPemResource = "LibProsperoPkg.Keys.Data.pkg_meta_rsa_key.pem";
    private const string PasscodeResource = "LibProsperoPkg.Keys.Data.passcode.bin";
    private const string MountImageResource = "LibProsperoPkg.Keys.Data.mount_image.bin";

    private static readonly Lazy<RSAParameters?> _metadataRsa = new(LoadMetadataRsaParameters);
    private static readonly Lazy<byte[]?> _passcodeKey = new(() => TryLoadBytes(PasscodeResource));
    private static readonly Lazy<byte[]?> _mountImageKey = new(() => TryLoadBytes(MountImageResource));

    /// <summary>True when every required PS5 publishing key was loaded successfully.</summary>
    public static bool IsAvailable =>
        _metadataRsa.Value is not null
        && _passcodeKey.Value is { Length: > 0 }
        && _mountImageKey.Value is { Length: > 0 };

    /// <summary>
    /// The PKG-metadata RSA-3072 private key. Returns a fresh
    /// <see cref="RSA"/> instance the caller owns and must dispose.
    /// </summary>
    /// <exception cref="InvalidOperationException">The embedded key could not be loaded.</exception>
    public static RSA CreateMetadataRsa()
    {
        if (_metadataRsa.Value is not { } parameters)
            throw new InvalidOperationException("The PS5 PKG-metadata RSA-3072 key is unavailable.");

        var rsa = RSA.Create();
        rsa.ImportParameters(parameters);
        return rsa;
    }

    /// <summary>The Prospero publishing-tool passcode key blob (from Prospero Publishing Tools).</summary>
    /// <exception cref="InvalidOperationException">The embedded key could not be loaded.</exception>
    public static ReadOnlySpan<byte> PasscodeKey =>
        _passcodeKey.Value ?? throw new InvalidOperationException("The PS5 passcode key is unavailable.");

    /// <summary>The Prospero publishing-tool mount-image key blob.</summary>
    /// <exception cref="InvalidOperationException">The embedded key could not be loaded.</exception>
    public static ReadOnlySpan<byte> MountImageKey =>
        _mountImageKey.Value ?? throw new InvalidOperationException("The PS5 mount-image key is unavailable.");

    private static RSAParameters? LoadMetadataRsaParameters()
    {
        try
        {
            var pem = LoadText(RsaPemResource);
            if (pem is null) return null;

            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            // Export including private parameters so we can re-import on demand without
            // keeping a single shared (and disposable) instance alive.
            return rsa.ExportParameters(true);
        }
        catch
        {
            return null;
        }
    }

    private static string? LoadText(string resourceName)
    {
        using var stream = OpenResource(resourceName);
        if (stream is null) return null;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static byte[]? TryLoadBytes(string resourceName)
    {
        try
        {
            using var stream = OpenResource(resourceName);
            if (stream is null) return null;
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            return ms.ToArray();
        }
        catch
        {
            return null;
        }
    }

    private static Stream? OpenResource(string resourceName) =>
        typeof(ProsperoKeys).GetTypeInfo().Assembly.GetManifestResourceStream(resourceName);
}
