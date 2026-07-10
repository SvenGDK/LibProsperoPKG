// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Model for the 128-bit content key ("entitlement_key") the package builder carries alongside
// a title. The builder accepts a content key as the finalized/keyed alternative to a passcode:
// the two are mutually exclusive (a passcode drives the fake/debug key schedule, an entitlement
// key drives the finalized/keyed one). The key is referenced as "pkg/entitlement_key" and is the
// value the license record's 448-byte blob is built to deliver to the mount path.
//
// The blob-wrap that binds an entitlement key into a license record is produced with per-device
// material, so this type is a validated carrier for supplied material only: it never fabricates
// the record blob.

#nullable enable
using System;

namespace LibProsperoPkg.License;

/// <summary>
/// Selects which key schedule a package is built for. The builder rejects supplying both a
/// passcode and an entitlement key at once ("entitlement_key must not be specified"), and rejects
/// supplying neither when one is required ("The passcode should be specified").
/// </summary>
public enum ProsperoKeyMode
{
    /// <summary>The fake/debug schedule: the image key is derived from a 32-character passcode.</summary>
    Passcode = 0,

    /// <summary>The finalized/keyed schedule: the image key is delivered by a supplied entitlement key.</summary>
    EntitlementKey = 1,
}

/// <summary>
/// A 128-bit content key ("entitlement_key"). Parses, validates and formats the raw 16-byte value
/// and expresses the builder's passcode/entitlement mutual-exclusivity rule. Binding this key into
/// a <see cref="ProsperoRif"/> record requires per-device material absent from host tooling, so this
/// type only ever carries supplied material — it does not forge a license blob.
/// </summary>
public sealed class ProsperoEntitlementKey
{
    /// <summary>Size in bytes of a content key (128-bit).</summary>
    public const int Size = 16;

    /// <summary>The raw 16-byte content key.</summary>
    public required byte[] Value { get; init; }

    /// <summary>True when every byte of <see cref="Value"/> is zero (an absent / placeholder key).</summary>
    public bool IsZero
    {
        get
        {
            foreach (byte b in Value)
            {
                if (b != 0) return false;
            }
            return true;
        }
    }

    /// <summary>Wraps a raw 16-byte content key. The bytes are copied.</summary>
    /// <exception cref="ArgumentException"><paramref name="value"/> is not exactly <see cref="Size"/> bytes.</exception>
    public static ProsperoEntitlementKey FromBytes(ReadOnlySpan<byte> value)
    {
        if (value.Length != Size)
            throw new ArgumentException($"A content key is exactly {Size} bytes (got {value.Length}).", nameof(value));
        return new ProsperoEntitlementKey { Value = value.ToArray() };
    }

    /// <summary>
    /// Parses a content key from a 32-character hex string. Surrounding whitespace and an optional
    /// <c>0x</c> prefix are ignored; the digits are case-insensitive.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="hex"/> is null.</exception>
    /// <exception cref="FormatException"><paramref name="hex"/> is not 32 hex digits.</exception>
    public static ProsperoEntitlementKey ParseHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        string s = hex.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s[2..];

        if (s.Length != Size * 2)
            throw new FormatException($"A content key is {Size * 2} hex digits (got {s.Length}).");

        byte[] value = new byte[Size];
        for (int i = 0; i < Size; i++)
            value[i] = (byte)((HexNibble(s[i * 2]) << 4) | HexNibble(s[(i * 2) + 1]));

        return new ProsperoEntitlementKey { Value = value };
    }

    /// <summary>Formats the key as a lower-case 32-character hex string (no prefix).</summary>
    public string ToHex() => Convert.ToHexStringLower(Value);

    /// <summary>
    /// Validates that the value is a well-formed, non-zero content key. Returns <see langword="true"/>
    /// when usable; otherwise <paramref name="error"/> describes the problem.
    /// </summary>
    public bool Validate(out string? error)
    {
        if (Value is null || Value.Length != Size)
        {
            error = $"A content key must be exactly {Size} bytes.";
            return false;
        }
        if (IsZero)
        {
            error = "A content key must not be all-zero.";
            return false;
        }
        error = null;
        return true;
    }

    /// <summary>
    /// Resolves which key schedule a build targets from the two mutually-exclusive inputs, applying
    /// the same rule the builder enforces. Exactly one of <paramref name="passcode"/> /
    /// <paramref name="entitlementKey"/> must be present.
    /// </summary>
    /// <param name="passcode">The 32-character passcode, or <see langword="null"/>.</param>
    /// <param name="entitlementKey">The content key, or <see langword="null"/>.</param>
    /// <param name="mode">The resolved key schedule on success.</param>
    /// <param name="error">The reason resolution failed, or <see langword="null"/> on success.</param>
    /// <returns><see langword="true"/> when exactly one input is present and valid.</returns>
    public static bool ResolveMode(
        string? passcode,
        ProsperoEntitlementKey? entitlementKey,
        out ProsperoKeyMode mode,
        out string? error)
    {
        bool hasPasscode = !string.IsNullOrEmpty(passcode);
        bool hasKey = entitlementKey is not null && !entitlementKey.IsZero;

        if (hasPasscode && hasKey)
        {
            mode = default;
            error = "entitlement_key must not be specified when a passcode is used.";
            return false;
        }
        if (!hasPasscode && !hasKey)
        {
            mode = default;
            error = "A passcode or an entitlement_key must be specified.";
            return false;
        }
        if (hasPasscode && passcode!.Length != 32)
        {
            mode = default;
            error = "A passcode must be 32 characters long.";
            return false;
        }
        if (hasKey && !entitlementKey!.Validate(out error))
        {
            mode = default;
            return false;
        }

        mode = hasPasscode ? ProsperoKeyMode.Passcode : ProsperoKeyMode.EntitlementKey;
        error = null;
        return true;
    }

    private static int HexNibble(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => throw new FormatException($"'{c}' is not a hex digit."),
    };

    /// <summary>Returns the hex form for diagnostics.</summary>
    public override string ToString() => $"EntitlementKey({ToHex()})";
}
