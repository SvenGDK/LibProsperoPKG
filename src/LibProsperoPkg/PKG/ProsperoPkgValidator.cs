// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Validates a parsed package against the console-side acceptance gate: the structural
// preconditions the mount path checks before it will read the key entry and mount a title.
// Each check maps to a step documented in Reversed/acceptance-gate.md and
// Reversed/AppSubcontainerGetEEKpfs.md. This does not (and cannot) reproduce the console's
// cryptographic checks; it verifies the structural gate a package must pass to be mountable.

using LibProsperoPkg.NpDrm;
using System;
using System.Collections.Generic;

namespace LibProsperoPkg.PKG;

/// <summary>The outcome of a single acceptance-gate check.</summary>
public enum ProsperoCheckStatus
{
    /// <summary>The precondition is met.</summary>
    Pass,

    /// <summary>Non-blocking: unusual but not necessarily fatal to mounting.</summary>
    Warning,

    /// <summary>The precondition is not met; the mount path would reject the package.</summary>
    Fail,
}

/// <summary>A single named acceptance-gate check and its result.</summary>
public sealed class ProsperoAcceptanceCheck
{
    /// <summary>The short check name.</summary>
    public required string Name { get; init; }

    /// <summary>The check outcome.</summary>
    public required ProsperoCheckStatus Status { get; init; }

    /// <summary>A human-readable explanation of the outcome.</summary>
    public required string Detail { get; init; }
}

/// <summary>The full acceptance-gate report for a package.</summary>
public sealed class ProsperoAcceptanceReport
{
    /// <summary>The individual checks, in evaluation order.</summary>
    public required IReadOnlyList<ProsperoAcceptanceCheck> Checks { get; init; }

    /// <summary>True when no check failed (warnings are allowed).</summary>
    public bool Accepted
    {
        get
        {
            foreach (ProsperoAcceptanceCheck c in Checks)
            {
                if (c.Status == ProsperoCheckStatus.Fail) return false;
            }
            return true;
        }
    }

    /// <summary>True when at least one check produced a warning.</summary>
    public bool HasWarnings
    {
        get
        {
            foreach (ProsperoAcceptanceCheck c in Checks)
            {
                if (c.Status == ProsperoCheckStatus.Warning) return true;
            }
            return false;
        }
    }
}

/// <summary>
/// Checks a parsed <see cref="ProsperoPkg"/> against the structural acceptance gate the console
/// mount path enforces (see Reversed/acceptance-gate.md).
/// </summary>
public static class ProsperoPkgValidator
{
    /// <summary>Reads and validates a package file.</summary>
    public static ProsperoAcceptanceReport Validate(string path, string? expectedContentId = null) =>
        Validate(ProsperoPkgReader.Read(path), expectedContentId);

    /// <summary>
    /// Validates a parsed package. When <paramref name="expectedContentId"/> is supplied (for
    /// example a RIF or <c>param.json</c> content-id) the embedded content-id must match it.
    /// </summary>
    public static ProsperoAcceptanceReport Validate(ProsperoPkg package, string? expectedContentId = null)
    {
        ArgumentNullException.ThrowIfNull(package);
        var checks = new List<ProsperoAcceptanceCheck>();

        // 1. A bare metadata container (CNT) is not an installable image; a finalized (FIH) image is required.
        ProsperoFihHeader? fih = package.Fih;
        if (fih is null)
        {
            checks.Add(Fail("Finalized image", "Package is a metadata (CNT) container, not a finalized (FIH) image; it cannot be mounted."));
        }
        else
        {
            checks.Add(Pass("Finalized image", $"Finalized {(fih.IsOfficial ? "retail" : "debug")} image (signed byte 0x{fih.SignedByte:X2})."));

            // 2. FIH format version must be 3 (the value getEEKc requires).
            checks.Add(fih.IsSupportedFormatVersion
                ? Pass("FIH format version", $"Version {fih.FormatVersion} (required: {ProsperoPkgLayout.FihRequiredFormatVersion}).")
                : Fail("FIH format version", $"Version {fih.FormatVersion}; the mount path requires {ProsperoPkgLayout.FihRequiredFormatVersion}."));

            // 3. The shared PFS image starts immediately after the FIH header region (0x10000).
            checks.Add(fih.PfsImageOffset == (ulong)ProsperoPkgLayout.FihHeaderRegionSize
                ? Pass("PFS image offset", $"0x{fih.PfsImageOffset:X}.")
                : Warning("PFS image offset", $"0x{fih.PfsImageOffset:X} (expected 0x{ProsperoPkgLayout.FihHeaderRegionSize:X})."));

            // 4. A nested PFS image must be present for the mount path to have anything to mount.
            checks.Add(fih.PfsImageSize > 0
                ? Pass("PFS image present", $"0x{fih.PfsImageSize:X} bytes.")
                : Fail("PFS image present", "The shared PFS image size is zero."));
        }

        // 5. The embedded CNT must be parseable.
        ProsperoPkgHeader? header = package.Header;
        if (header is null)
        {
            checks.Add(Fail("Embedded CNT", "The embedded CNT metadata container could not be parsed."));
        }
        else
        {
            checks.Add(Pass("Embedded CNT", $"{package.Entries.Count} entries, {header.ScEntryCount} system entries."));

            // 6. The EEKPFS key entry (id 0x20) must be present for the mount path to derive PFS keys.
            bool hasImageKey = false;
            foreach (ProsperoPkgEntry entry in package.Entries)
            {
                if (entry.Id == ProsperoEntryId.ImageKey) { hasImageKey = true; break; }
            }
            checks.Add(hasImageKey
                ? Pass("EEKPFS key entry", "Image-key entry (0x20) present.")
                : Fail("EEKPFS key entry", "No image-key entry (0x20); the mount path cannot derive PFS keys."));

            // 7. Content-id must be present and, when an expected value is supplied, must match.
            if (string.IsNullOrEmpty(header.ContentId))
            {
                checks.Add(Fail("Content-id", "The embedded CNT carries no content-id."));
            }
            else if (expectedContentId is { Length: > 0 } expected &&
                     !string.Equals(header.ContentId, expected, StringComparison.Ordinal))
            {
                checks.Add(Fail("Content-id", $"Content-id '{header.ContentId}' does not match the expected '{expected}'."));
            }
            else
            {
                checks.Add(Pass("Content-id", header.ContentId));
            }

            // 8. Project the NpDrm content-info the mount gate consumes and report the derived
            //    classification (title-id, drm/content type, patch kind, nested-image flag).
            var info = ProsperoNpDrmContentInfo.FromPackage(package);
            checks.Add(Pass("Content-info",
                $"title-id={info.TitleId}, drm_type=0x{info.DrmType:X}, content_type=0x{info.ContentType:X}, " +
                $"content_flags=0x{info.ContentFlags:X8}, patch={info.PatchKind}, nested={info.IsNestedImage}."));
        }

        return new ProsperoAcceptanceReport { Checks = checks };
    }

    private static ProsperoAcceptanceCheck Pass(string name, string detail) =>
        new() { Name = name, Status = ProsperoCheckStatus.Pass, Detail = detail };

    private static ProsperoAcceptanceCheck Warning(string name, string detail) =>
        new() { Name = name, Status = ProsperoCheckStatus.Warning, Detail = detail };

    private static ProsperoAcceptanceCheck Fail(string name, string detail) =>
        new() { Name = name, Status = ProsperoCheckStatus.Fail, Detail = detail };
}
