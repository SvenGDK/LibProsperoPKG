// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Structural validators for the backend-authored sce_sys system files carried in a package. These
// files are signed by a publishing backend and cannot be regenerated off-console, so the library
// packs them verbatim. The validators reject a structurally malformed input before it is added to
// the container and surface the identifiers embedded in each header.

#nullable enable
using System;
using System.Buffers.Binary;
using System.Text;

namespace LibProsperoPkg.PKG;

/// <summary>
/// Structural checks for the signed sce_sys system files (<c>npbind.dat</c>, <c>nptitle.dat</c>,
/// <c>license.dat</c>, <c>license.info</c>). Each checker validates the fixed header fields and
/// reports a specific reason when the input is not well formed.
/// </summary>
public static class ProsperoSystemFiles
{
    /// <summary>Network-platform binding header magic (big-endian) at offset 0x00 of <c>npbind.dat</c>.</summary>
    public const uint NpbindMagic = 0xD294A018;

    /// <summary>Fixed size of a <c>npbind.dat</c> file, in bytes.</summary>
    public const int NpbindSize = 532;

    /// <summary>Fixed size of a <c>nptitle.dat</c> file, in bytes.</summary>
    public const int NptitleSize = 160;

    // "NPTD" title-descriptor magic at offset 0x00 of nptitle.dat.
    private static ReadOnlySpan<byte> NptitleMagic => "NPTD"u8;

    // TLV tag that carries the network-platform communication id inside npbind.dat.
    private const ushort NpbindCommIdTag = 0x0010;
    private const int NpbindTlvStart = 0x80;
    private const int NpbindTlvEnd = 0x200; // trailing authentication code starts here

    /// <summary>
    /// Validates a <c>npbind.dat</c> blob and extracts its network-platform communication id.
    /// </summary>
    /// <param name="data">The file bytes.</param>
    /// <param name="commId">The communication id (e.g. <c>NPWR23725_00</c>) on success; otherwise <c>null</c>.</param>
    /// <param name="error">A description of the first structural problem, or <c>null</c> on success.</param>
    public static bool ValidateNpbind(ReadOnlySpan<byte> data, out string? commId, out string? error)
    {
        commId = null;
        if (data.Length != NpbindSize) { error = $"npbind.dat must be {NpbindSize} bytes (got {data.Length})."; return false; }
        if (BinaryPrimitives.ReadUInt32BigEndian(data) != NpbindMagic) { error = "npbind.dat has a bad magic."; return false; }
        if (BinaryPrimitives.ReadUInt32BigEndian(data[4..]) != 1) { error = "npbind.dat has an unsupported version."; return false; }
        uint sizeField = BinaryPrimitives.ReadUInt32BigEndian(data[0x0C..]);
        if (sizeField != NpbindSize) { error = $"npbind.dat size field ({sizeField}) does not match its length."; return false; }

        // Walk the tag/length/value chain for the communication id record.
        int p = NpbindTlvStart;
        while (p + 4 <= NpbindTlvEnd)
        {
            ushort tag = BinaryPrimitives.ReadUInt16BigEndian(data[p..]);
            ushort len = BinaryPrimitives.ReadUInt16BigEndian(data[(p + 2)..]);
            if (tag == 0) break;
            if (p + 4 + len > data.Length) { error = "npbind.dat has a truncated record."; return false; }
            if (tag == NpbindCommIdTag)
            {
                commId = Encoding.ASCII.GetString(data.Slice(p + 4, len)).TrimEnd('\0');
                break;
            }
            p += 4 + len;
        }
        if (string.IsNullOrEmpty(commId)) { error = "npbind.dat is missing the communication id record."; return false; }
        error = null;
        return true;
    }

    /// <summary>
    /// Validates a <c>nptitle.dat</c> blob and extracts its title id.
    /// </summary>
    /// <param name="data">The file bytes.</param>
    /// <param name="titleId">The title id (e.g. <c>PPSA00000_00</c>) on success; otherwise <c>null</c>.</param>
    /// <param name="error">A description of the first structural problem, or <c>null</c> on success.</param>
    public static bool ValidateNptitle(ReadOnlySpan<byte> data, out string? titleId, out string? error)
    {
        titleId = null;
        if (data.Length != NptitleSize) { error = $"nptitle.dat must be {NptitleSize} bytes (got {data.Length})."; return false; }
        if (!data[..4].SequenceEqual(NptitleMagic)) { error = "nptitle.dat has a bad magic."; return false; }
        uint sigOffset = BinaryPrimitives.ReadUInt32BigEndian(data[4..]);
        if (sigOffset != 0x80) { error = $"nptitle.dat has an unexpected signature offset (0x{sigOffset:x})."; return false; }

        titleId = Encoding.ASCII.GetString(data.Slice(0x10, 16)).TrimEnd('\0');
        if (titleId.Length == 0) { error = "nptitle.dat is missing its title id."; return false; }
        error = null;
        return true;
    }

    /// <summary>
    /// Validates a <c>license.dat</c> blob. The license container is backend-signed and
    /// content-key material; validation confirms only that a non-empty blob is present.
    /// </summary>
    public static bool ValidateLicenseDat(ReadOnlySpan<byte> data, out string? error) =>
        RequireNonEmpty(data, "license.dat", out error);

    /// <summary>
    /// Validates a <c>license.info</c> blob. Like <c>license.dat</c>, it is backend-signed;
    /// validation confirms only that a non-empty blob is present.
    /// </summary>
    public static bool ValidateLicenseInfo(ReadOnlySpan<byte> data, out string? error) =>
        RequireNonEmpty(data, "license.info", out error);

    /// <summary>
    /// Runs the checker that matches an sce_sys-relative file name, if one exists. File names with no
    /// dedicated checker return <c>true</c> (nothing to verify).
    /// </summary>
    /// <param name="relativeName">The file path relative to <c>sce_sys/</c> (forward slashes).</param>
    /// <param name="data">The file bytes.</param>
    /// <param name="error">A description of the first structural problem, or <c>null</c> on success.</param>
    public static bool Validate(string relativeName, ReadOnlySpan<byte> data, out string? error)
    {
        switch (relativeName)
        {
            case "npbind.dat":
                return ValidateNpbind(data, out _, out error);
            case "nptitle.dat":
                return ValidateNptitle(data, out _, out error);
            case "license.dat":
                return ValidateLicenseDat(data, out error);
            case "license.info":
                return ValidateLicenseInfo(data, out error);
            default:
                error = null;
                return true;
        }
    }

    private static bool RequireNonEmpty(ReadOnlySpan<byte> data, string name, out string? error)
    {
        if (data.Length == 0) { error = $"{name} is empty."; return false; }
        error = null;
        return true;
    }
}
