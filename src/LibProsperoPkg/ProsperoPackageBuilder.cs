// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// High-level PS5 package builder. Turns a prepared application
// folder into a complete, signed PS5 package entirely in-process: there is no external tool to
// install and no platform-specific shell-out. The GP5 project model, the inner/outer PFS image,
// the AES-XTS encryption, the RSA-3072 metadata signature and the finalized debug image are all
// produced by this library. The PS5 publishing key material is wired in through
// <see cref="LibProsperoPkg.Keys.ProsperoKeys"/> and the signing path through
// <see cref="LibProsperoPkg.PKG.ProsperoPkgSigner"/>.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using LibProsperoPkg.GP5;
using LibProsperoPkg.Keys;
using LibProsperoPkg.PKG;

namespace LibProsperoPkg;

/// <summary>The kind of PS5 package to produce.</summary>
public enum ProsperoPackageMode
{
    /// <summary>A generic PS5 application/game (already-prepared <c>sce_sys</c> + eboot folder).</summary>
    Application,

    /// <summary>A PS5 homebrew application.</summary>
    Homebrew,

    /// <summary>Additional content (DLC) that ships data.</summary>
    AdditionalContentData,

    /// <summary>Additional content (DLC) entitlement only, no data.</summary>
    AdditionalContentNoData,
}

/// <summary>The representation a built inner-PFS image is rendered in.</summary>
public enum InnerImageForm
{
    /// <summary>An unsigned, unencrypted PFS image (raw layout).</summary>
    Plaintext,

    /// <summary>An AES-XTS-encrypted PFS image (plaintext superblock + encrypted filesystem).</summary>
    Encrypted,

    /// <summary>A PFSC-compressed PFS image (the <c>pfs_image.dat</c> form).</summary>
    Compressed,

    /// <summary>
    /// A PS5 PFSv3 Kraken-compressed PFS image — the codec the
    /// <c>--oformat nwonly</c> path uses for the inner image. The container is self-describing
    /// (magic <c>PFSC</c>, format version 3, 0x40000 blocks, SHA3-256 digests) and is round-trip
    /// validated in-process with the managed Kraken decoder. Distinct from <see cref="Compressed"/>,
    /// which is the zlib PFSC used for the installable inner image.
    /// </summary>
    KrakenCompressed,
}

/// <summary>The container format the builder emits.</summary>
public enum ProsperoOutputFormat
{
    /// <summary>
    /// A metadata container (<c>\x7FCNT</c>) only. This holds nothing but the package metadata and
    /// is <b>not</b> a full, installable package — it cannot be installed on a console. Use it for
    /// inspection / tooling; produce <see cref="DebugImage"/> for an installable package.
    /// </summary>
    MetadataContainer,

    /// <summary>
    /// A finalized <i>debug</i> image (<c>\x7FFIH</c>, signed byte 0x00) — a full package, and the only
    /// form installable on a PS5 with debug mode enabled. The structure and embedded CNT are exact;
    /// the finalization digest table is debug-key gated and filled best-effort (see
    /// <see cref="LibProsperoPkg.PKG.ProsperoFihBuilder"/>). This is the default output.
    /// </summary>
    DebugImage,
}

/// <summary>Options describing the PS5 package to build.</summary>
public sealed class ProsperoBuildOptions
{
    /// <summary>The build preset.</summary>
    public ProsperoPackageMode Mode { get; set; } = ProsperoPackageMode.Application;

    /// <summary>
    /// The container format the builder emits. Defaults to the finalized debug
    /// <see cref="ProsperoOutputFormat.DebugImage"/>, since only a \x7FFIH image is a full,
    /// installable package; a bare \x7FCNT is metadata only.
    /// </summary>
    public ProsperoOutputFormat OutputFormat { get; set; } = ProsperoOutputFormat.DebugImage;

    /// <summary>Folder whose contents become the package image (must contain <c>sce_sys/</c>).</summary>
    public string SourceFolder { get; set; } = "";

    /// <summary>Folder the finished <c>*.pkg</c> is written to.</summary>
    public string OutputFolder { get; set; } = "";

    /// <summary>36-character content id (e.g. <c>UP9000-PPSA00000_00-PROSPERO00000000</c>).</summary>
    public string ContentId { get; set; } = "";

    /// <summary>32-character passcode. Defaults to all zeroes.</summary>
    public string Passcode { get; set; } = new string('0', 32);

    /// <summary>Human-readable title written into <c>param.json</c> when one is generated.</summary>
    public string Title { get; set; } = "";

    /// <summary>9-character title id (e.g. <c>PPSA00000</c>).</summary>
    public string TitleId { get; set; } = "";

    /// <summary>Content/master version, formatted <c>NN.NN</c>.</summary>
    public string Version { get; set; } = "01.00";

    /// <summary>When true a minimal <c>param.json</c> is generated if the source folder lacks one.</summary>
    public bool GenerateParamJsonIfMissing { get; set; } = true;

    /// <summary>
    /// When true the inner <c>pfs_image.dat</c> is stored PFSC-compressed (shrinking the package,
    /// the dominant size driver) instead of raw. Incompressible images fall back to the raw wrapper
    /// automatically. Off by default to preserve the size-stable path. This is the zlib
    /// PFSC used for the installable inner image; for the <c>--oformat nwonly</c> Kraken codec
    /// set <see cref="InnerCompression"/> to <see cref="ProsperoInnerCompression.Kraken"/> instead.
    /// </summary>
    public bool CompressInnerImage { get; set; }

    /// <summary>
    /// Selects the inner-image codec explicitly. When left at <see cref="ProsperoInnerCompression.None"/>
    /// the legacy <see cref="CompressInnerImage"/> flag decides (true =&gt; <see cref="ProsperoInnerCompression.Zlib"/>).
    /// When set to a non-<c>None</c> value this takes precedence over <see cref="CompressInnerImage"/>:
    /// <list type="bullet">
    /// <item><see cref="ProsperoInnerCompression.Zlib"/> — zlib PFSC (installable inner image).</item>
    /// <item><see cref="ProsperoInnerCompression.Kraken"/> — PS5 PFSv3 Kraken (the
    /// <c>--oformat nwonly</c> inner-image codec), validated against reference output.
    /// Incompressible images fall back to the raw wrapper automatically.</item>
    /// </list>
    /// </summary>
    public ProsperoInnerCompression InnerCompression { get; set; } = ProsperoInnerCompression.None;
}

/// <summary>The result of a build: the output path plus any non-fatal warnings.</summary>
public sealed class ProsperoBuildResult
{
    public required string OutputPath { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
}

/// <summary>
/// Folder -&gt; PS5 package builder. See the file header for the architecture.
/// </summary>
public static class ProsperoPackageBuilder
{
    // PS5 content ids use the 36-char shape; PS5 title ids are typically PPSAxxxxx.
    private static readonly Regex ContentIdRegex =
        new("^[A-Z]{2}[0-9]{4}-[A-Z]{4}[0-9]{5}_00-[A-Z0-9]{16}$", RegexOptions.Compiled);

    private static readonly Regex TitleIdRegex =
        new("^[A-Z]{4}[0-9]{5}$", RegexOptions.Compiled);

    /// <summary>True when the wired-in PS5 publishing key material is available.</summary>
    public static bool KeysAvailable => ProsperoKeys.IsAvailable;

    /// <summary>
    /// Encrypts a prepared (plaintext) inner PFS image with AES-XTS, deriving the
    /// EKPFS from the package content id + passcode, then the (tweak, data) keys from the EKPFS
    /// plus the image header seed. Offered as a standalone, round-trip-checked primitive.
    /// </summary>
    /// <param name="pfsImagePath">A prepared plaintext PFS image (in place).</param>
    /// <param name="contentId">The 36-character content id.</param>
    /// <param name="passcode">The 32-character passcode.</param>
    /// <param name="seed">Optional 16-byte header seed; <c>null</c> uses the image's own seed or generates one.</param>
    /// <param name="logger">Optional progress sink.</param>
    public static LibProsperoPkg.PFS.ProsperoPfsImageResult EncryptPfsImage(
        string pfsImagePath, string contentId, string passcode, byte[]? seed = null, Action<string>? logger = null)
    {
        var ekpfs = ProsperoPkgSigner.ComputeEkpfs(contentId, passcode);
        var options = new LibProsperoPkg.PFS.ProsperoPfsImageOptions { Ekpfs = ekpfs, Seed = seed };
        return LibProsperoPkg.PFS.ProsperoPfsImage.EncryptInPlace(pfsImagePath, options, logger);
    }

    /// <summary>
    /// Lays out a prepared folder into a plaintext PS5 inner-PFS image. The
    /// produced image is unsigned/unencrypted; pair it with <see cref="EncryptPfsImage"/>
    /// for the encrypted form, or with <see cref="BuildInnerImage"/> for the full pipeline.
    /// </summary>
    /// <param name="sourceFolder">A prepared application folder (its tree becomes the image's uroot).</param>
    /// <param name="outputPath">Destination plaintext inner-PFS image path.</param>
    /// <param name="logger">Optional progress sink.</param>
    public static LibProsperoPkg.PFS.ProsperoPfsLayoutResult BuildInnerPfsLayout(
        string sourceFolder, string outputPath, Action<string>? logger = null)
    {
        var options = new LibProsperoPkg.PFS.ProsperoPfsLayoutOptions();
        return LibProsperoPkg.PFS.ProsperoPfsLayout.BuildFromFolder(sourceFolder, outputPath, options, logger);
    }

    /// <summary>
    /// Runs the full inner-PFS pipeline end to end: lays out the folder into a plaintext
    /// inner-PFS image (<see cref="BuildInnerPfsLayout"/>), then renders it in the requested
    /// <paramref name="form"/> — left plaintext, AES-XTS-encrypted with the EKPFS derived from the
    /// content id + passcode (<see cref="EncryptPfsImage"/>), or PFSC-compressed
    /// (<see cref="LibProsperoPkg.PFS.ProsperoPfsc"/>). The forms are mutually exclusive: an encrypted
    /// image carries the plaintext PFS superblock the kernel needs, while a compressed image is a
    /// PFSC container — composing both is handled by the outer-PFS layer.
    /// </summary>
    /// <param name="sourceFolder">A prepared application folder.</param>
    /// <param name="outputPath">Destination inner-PFS image path.</param>
    /// <param name="contentId">The 36-character content id (used to derive the EKPFS when encrypting).</param>
    /// <param name="passcode">The 32-character passcode (used to derive the EKPFS when encrypting).</param>
    /// <param name="form">The inner-image representation to produce. Default <see cref="InnerImageForm.Encrypted"/>.</param>
    /// <param name="logger">Optional progress sink.</param>
    /// <returns>The final inner-PFS image path.</returns>
    public static string BuildInnerImage(
        string sourceFolder, string outputPath, string contentId, string passcode,
        InnerImageForm form = InnerImageForm.Encrypted, Action<string>? logger = null)
    {
        var log = logger ?? (_ => { });

        BuildInnerPfsLayout(sourceFolder, outputPath, log);

        switch (form)
        {
            case InnerImageForm.Plaintext:
                break;

            case InnerImageForm.Encrypted:
                log("AES-XTS-encrypting the laid-out inner PFS image...");
                EncryptPfsImage(outputPath, contentId, passcode, seed: null, log);
                break;

            case InnerImageForm.Compressed:
                log("Compressing the inner PFS image (PFSC)...");
                var tmp = outputPath + ".pfsc.tmp";
                var pfscOptions = new LibProsperoPkg.PFS.ProsperoPfscOptions
                {
                    BlockSize = 0x10000,
                };
                LibProsperoPkg.PFS.ProsperoPfsc.PackFile(outputPath, tmp, pfscOptions, log);
                File.Delete(outputPath);
                File.Move(tmp, outputPath);
                break;

            case InnerImageForm.KrakenCompressed:
                log("Compressing the inner PFS image (PFSv3)...");
                var krakenTmp = outputPath + ".pfsc.tmp";
                LibProsperoPkg.PFS.Compression.ProsperoCompressedPfsImage.PackFile(outputPath, krakenTmp, logger: log);
                File.Delete(outputPath);
                File.Move(krakenTmp, outputPath);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(form), form, "Unknown inner-image form.");
        }

        return outputPath;
    }

    /// <summary>Returns true when <paramref name="contentId"/> is a well-formed 36-char content id.</summary>
    public static bool IsValidContentId(string? contentId) =>
        !string.IsNullOrEmpty(contentId) && ContentIdRegex.IsMatch(contentId);

    /// <summary>Returns true when <paramref name="titleId"/> looks like <c>PPSAxxxxx</c>.</summary>
    public static bool IsValidTitleId(string? titleId) =>
        !string.IsNullOrEmpty(titleId) && TitleIdRegex.IsMatch(titleId);

    /// <summary>
    /// Builds a content id from a publisher prefix, a title id and a 16-char label.
    /// Missing pieces are padded so the result is always 36 characters.
    /// </summary>
    public static string ComposeContentId(string? publisher, string? titleId, string? label)
    {
        publisher = (publisher ?? "UP9000").ToUpperInvariant();
        if (publisher.Length < 6) publisher = publisher.PadRight(6, '0');
        publisher = publisher[..6];

        titleId = (titleId ?? "PPSA00000").ToUpperInvariant();
        if (titleId.Length < 9) titleId = titleId.PadRight(9, '0');
        titleId = titleId[..9];

        label = (label ?? "").ToUpperInvariant();
        label = new string(label.Where(c => (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')).ToArray());
        if (label.Length < 16) label = label.PadRight(16, '0');
        label = label[..16];

        return $"{publisher}-{titleId}_00-{label}";
    }

    /// <summary>The Prospero volume type used for a given mode.</summary>
    public static Gp5VolumeType VolumeTypeForMode(ProsperoPackageMode mode) => mode switch
    {
        ProsperoPackageMode.AdditionalContentData => Gp5VolumeType.prospero_ac,
        ProsperoPackageMode.AdditionalContentNoData => Gp5VolumeType.prospero_ac_nodata,
        _ => Gp5VolumeType.prospero_app,
    };

    /// <summary>The PS5 PKG builder volume kind used for a given mode.</summary>
    public static LibProsperoPkg.PKG.ProsperoVolumeType ProsperoVolumeTypeForMode(ProsperoPackageMode mode) => mode switch
    {
        ProsperoPackageMode.AdditionalContentData => LibProsperoPkg.PKG.ProsperoVolumeType.AdditionalContentData,
        ProsperoPackageMode.AdditionalContentNoData => LibProsperoPkg.PKG.ProsperoVolumeType.AdditionalContentNoData,
        _ => LibProsperoPkg.PKG.ProsperoVolumeType.Application,
    };

    /// <summary>True when the mode produces additional-content (DLC) packages.</summary>
    public static bool IsDlcMode(ProsperoPackageMode mode) =>
        mode is ProsperoPackageMode.AdditionalContentData or ProsperoPackageMode.AdditionalContentNoData;

    /// <summary>The PS5 application category type written into a generated param.json for a mode.</summary>
    private static int CategoryTypeForMode(ProsperoPackageMode mode) => mode switch
    {
        // 0 = PS5 Game/App. DLC packages carry no applicationCategoryType in their param.json.
        _ => 0,
    };

    /// <summary>
    /// Builds the PS5 package described by <paramref name="options"/>.
    /// </summary>
    /// <param name="options">The build description.</param>
    /// <param name="logger">Optional sink for progress messages.</param>
    /// <returns>The finished package path and any non-fatal warnings.</returns>
    /// <exception cref="ArgumentException">A required option is missing or malformed.</exception>
    /// <exception cref="InvalidOperationException">The build failed.</exception>
    public static ProsperoBuildResult Build(ProsperoBuildOptions options, Action<string>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var log = logger ?? (_ => { });
        var warnings = new List<string>();

        if (string.IsNullOrWhiteSpace(options.SourceFolder) || !Directory.Exists(options.SourceFolder))
            throw new ArgumentException("Source folder does not exist.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.OutputFolder))
            throw new ArgumentException("Output folder was not specified.", nameof(options));
        if (string.IsNullOrEmpty(options.Passcode) || options.Passcode.Length != 32)
            throw new ArgumentException("Passcode must be exactly 32 characters.", nameof(options));
        if (!IsValidContentId(options.ContentId))
            throw new ArgumentException("Content ID is not in the format XXYYYY-XXXXYYYYY_00-ZZZZZZZZZZZZZZZZ.", nameof(options));

        Directory.CreateDirectory(options.OutputFolder);
        var sourceFolder = Path.GetFullPath(options.SourceFolder);

        log(KeysAvailable
            ? "PS5 publishing keys (RSA-3072 metadata + passcode + mount-image) loaded."
            : "Warning: PS5 publishing keys are unavailable; signing is disabled.");
        if (!KeysAvailable)
            warnings.Add("PS5 publishing keys are unavailable.");

        // Ensure the package has a param.json.
        EnsureParamJson(options, sourceFolder, log, warnings);

        return BuildCore(options, sourceFolder, log, warnings);
    }

    /// <summary>
    /// Produces the final PS5 package via <see cref="LibProsperoPkg.PKG.ProsperoPkgBuilder"/>.
    /// The output is a complete <c>\x7FCNT</c> package with the inner + AES-XTS-encrypted outer PFS,
    /// all entries, every metadata digest and the header signature. The result is checked in-process
    /// with the reader and an outer-PFS decrypt round-trip; the detached metadata signature
    /// pass then exercises the wired-in publishing key material too. On-console acceptance is
    /// hardware-gated.
    /// </summary>
    private static ProsperoBuildResult BuildCore(
        ProsperoBuildOptions options, string sourceFolder, Action<string> log, List<string> warnings)
    {
        string finalPath = Path.Combine(options.OutputFolder, ComposePkgFileName(options.ContentId, options.Version));
        bool wantsFih = options.OutputFormat == ProsperoOutputFormat.DebugImage;

        // A CNT package holds only metadata and is NOT a full, installable package: only a finalized
        // \x7FFIH image is. So for the debug-image path the CNT is an intermediate that must NOT survive
        // next to the final package — the user asked for the final FIH image only. Build it (and its
        // detached .metasig) under a temporary name and delete both once the FIH is finalized.
        string cntPath = wantsFih
            ? Path.Combine(options.OutputFolder, "." + Path.GetFileName(finalPath) + ".cnt.tmp")
            : finalPath;

        var buildProps = new LibProsperoPkg.PKG.ProsperoPkgBuildProperties
        {
            SourceFolder = sourceFolder,
            ContentId = options.ContentId,
            Passcode = options.Passcode,
            VolumeType = ProsperoVolumeTypeForMode(options.Mode),
            CompressInnerImage = options.CompressInnerImage,
            InnerCompression = options.InnerCompression,
        };

        log("Building the PS5 package...");
        LibProsperoPkg.PKG.ProsperoPkgBuilder.Build(buildProps, cntPath, out byte[]? nestedImageDigest, log);

        if (!File.Exists(cntPath))
            throw new InvalidOperationException("The PS5 PKG builder did not produce an output package.");

        // Verify the produced container with the reader.
        try
        {
            var type = ProsperoPkgReader.DetectType(cntPath);
            if (type is null)
                warnings.Add("The produced package is not a recognisable PS5 PKG.");
            else
                log($"Validated intermediate container: {type} PS5 CNT (metadata only).");
        }
        catch (Exception ex)
        {
            warnings.Add("Output container validation failed: " + ex.Message);
        }

        // PKG-metadata signing pass using the wired-in publishing key material.
        SignPackage(cntPath, options, log, warnings);

        // A CNT alone is metadata only, so unless the caller explicitly asked for the metadata
        // container we finalize it into a debug (FIH) image — the only form a debug-mode console
        // can install — and keep ONLY that final package.
        if (!wantsFih)
        {
            log("Done (CNT metadata container).");
            return new ProsperoBuildResult { OutputPath = cntPath, Warnings = warnings };
        }

        try
        {
            log("Finalizing the CNT into a debug (FIH) image...");
            var fihWarnings = LibProsperoPkg.PKG.ProsperoFihBuilder.BuildFromCnt(
                cntPath, finalPath, LibProsperoPkg.PKG.ProsperoFihVariant.Debug, log,
                nestedImageDigest: nestedImageDigest);
            warnings.AddRange(fihWarnings);

            var fihType = ProsperoPkgReader.DetectType(finalPath);
            if (fihType != LibProsperoPkg.PKG.ProsperoPkgType.FullDebug)
                warnings.Add($"Produced FIH image was detected as {fihType}, expected FullDebug.");
            else
                log("Validated output container: FullDebug PS5 FIH image.");
        }
        finally
        {
            // Remove the intermediate CNT and its detached signature so only the final FIH remains.
            TryDelete(cntPath);
            TryDelete(cntPath + ".metasig");
        }

        log("Done (debug FIH).");
        return new ProsperoBuildResult { OutputPath = finalPath, Warnings = warnings };
    }

    /// <summary>Best-effort deletion of an intermediate build artifact.</summary>
    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* best-effort cleanup of intermediate artifacts */ }
    }

    /// <summary>
    /// Produces a detached PKG-metadata signature for the finished package using the
    /// embedded PKG-metadata RSA-3072 key (and consumes the content id + passcode to derive the
    /// package EKPFS). The signature is RSA-3072 PKCS#1 v1.5 over the SHA-256 of the container's
    /// metadata region (header + entry table) and is written next to the package as
    /// <c>&lt;pkg&gt;.metasig</c>.
    /// </summary>
    /// <remarks>
    /// The detached signature and the checked key material are self-validated; a fully accepted
    /// retail image additionally requires reference-controlled secrets.
    /// </remarks>
    private static void SignPackage(
        string pkgPath, ProsperoBuildOptions options, Action<string> log, List<string> warnings)
    {
        if (!ProsperoPkgSigner.IsAvailable)
        {
            warnings.Add("PS5 PKG-metadata key unavailable; signature skipped.");
            return;
        }

        try
        {
            if (!ProsperoPkgSigner.VerifyKeyMaterial())
            {
                warnings.Add("PS5 PKG-metadata key self-check failed; signature skipped.");
                return;
            }

            // Consume the content id + passcode to derive the package EKPFS (index 1).
            var ekpfs = ProsperoPkgSigner.ComputeEkpfs(options.ContentId, options.Passcode);
            log($"Derived package EKPFS (fingerprint {Convert.ToHexString(ekpfs.AsSpan(0, 4))}).");

            // Hash the container's metadata region (everything before the body) and sign it.
            var pkg = ProsperoPkgReader.Read(pkgPath);
            long fileLength = new FileInfo(pkgPath).Length;
            long metadataLength = (long)(pkg.Header?.BodyOffset ?? 0);
            if (metadataLength <= 0 || metadataLength > fileLength)
                metadataLength = Math.Min(0x1000, fileLength);

            byte[] digest;
            using (var fs = new FileStream(pkgPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var sha = SHA256.Create())
            {
                var region = new byte[metadataLength];
                int read = 0;
                while (read < region.Length)
                {
                    int n = fs.Read(region, read, region.Length - read);
                    if (n == 0) break;
                    read += n;
                }
                digest = sha.ComputeHash(region, 0, read);
            }

            byte[] signature = ProsperoPkgSigner.SignDigest(digest);
            bool verified = ProsperoPkgSigner.VerifyDigest(digest, signature);

            string sigPath = pkgPath + ".metasig";
            File.WriteAllBytes(sigPath, signature);
            log($"PKG-metadata signature written to {Path.GetFileName(sigPath)} " +
                $"({signature.Length} bytes, RSA-3072 PKCS#1 SHA-256), valid={verified}.");
            if (!verified)
                warnings.Add("PKG-metadata signature failed self-verification.");
        }
        catch (Exception ex)
        {
            warnings.Add("PKG-metadata signing failed: " + ex.Message);
        }
    }

    /// <summary>
    /// Compares two PS5 containers field-by-field (parsed header and entry table). Useful to verify
    /// that a candidate package matches a known-good reference container.
    /// </summary>
    /// <returns>An empty list when the containers match; otherwise the differences found.</returns>
    public static IReadOnlyList<string> CompareContainers(string referencePkg, string candidatePkg)
    {
        var diffs = new List<string>();
        var a = ProsperoPkgReader.Read(referencePkg);
        var b = ProsperoPkgReader.Read(candidatePkg);

        if (a.Type != b.Type) diffs.Add($"Type: {a.Type} != {b.Type}");
        if (a.Header is { } ha && b.Header is { } hb)
        {
            if (ha.EntryCount != hb.EntryCount) diffs.Add($"EntryCount: {ha.EntryCount} != {hb.EntryCount}");
            if (ha.EntryTableOffset != hb.EntryTableOffset) diffs.Add($"EntryTableOffset: {ha.EntryTableOffset:X} != {hb.EntryTableOffset:X}");
            if (ha.ContentId != hb.ContentId) diffs.Add($"ContentId: {ha.ContentId} != {hb.ContentId}");
            if (ha.ContentType != hb.ContentType) diffs.Add($"ContentType: {ha.ContentType} != {hb.ContentType}");
        }

        int n = Math.Min(a.Entries.Count, b.Entries.Count);
        for (int i = 0; i < n; i++)
        {
            var ea = a.Entries[i];
            var eb = b.Entries[i];
            if (ea.RawId != eb.RawId || ea.DataSize != eb.DataSize || ea.Flags1 != eb.Flags1)
                diffs.Add($"Entry[{i}] {ea.Id}/{eb.Id}: id={ea.RawId:X}/{eb.RawId:X} size={ea.DataSize}/{eb.DataSize} flags={ea.Flags1:X}/{eb.Flags1:X}");
        }
        if (a.Entries.Count != b.Entries.Count)
            diffs.Add($"Entry count differs: {a.Entries.Count} vs {b.Entries.Count}");

        return diffs;
    }

    private static void EnsureParamJson(
        ProsperoBuildOptions options, string sourceFolder, Action<string> log, List<string> warnings)
    {
        var sceSys = Path.Combine(sourceFolder, "sce_sys");
        var paramPath = Path.Combine(sceSys, "param.json");
        if (File.Exists(paramPath))
        {
            log("Using existing sce_sys/param.json.");
            return;
        }

        if (!options.GenerateParamJsonIfMissing)
            throw new InvalidOperationException("sce_sys/param.json is missing and auto-generation is disabled.");

        Directory.CreateDirectory(sceSys);
        log("sce_sys/param.json not found - generating a minimal one from the supplied metadata.");
        File.WriteAllText(paramPath, BuildMinimalParamJson(options), new UTF8Encoding(false));
        warnings.Add("A minimal param.json was generated; review it for store-grade packages.");
    }

    private static string BuildMinimalParamJson(ProsperoBuildOptions options)
    {
        var titleId = IsValidTitleId(options.TitleId) ? options.TitleId : options.ContentId.Substring(7, 9);
        var title = string.IsNullOrWhiteSpace(options.Title) ? titleId : options.Title;
        var version = NormalizeVersion(options.Version);

        var root = new JsonObject
        {
            ["applicationCategoryType"] = CategoryTypeForMode(options.Mode),
            ["contentId"] = options.ContentId,
            ["contentVersion"] = version,
            ["masterVersion"] = version,
            ["requiredSystemSoftwareVersion"] = "00.00.00.00",
            ["titleId"] = titleId,
            ["localizedParameters"] = new JsonObject
            {
                ["defaultLanguage"] = "en-US",
                ["en-US"] = new JsonObject { ["titleName"] = title },
            },
        };

        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    private static string ComposePkgFileName(string contentId, string version)
    {
        var v = NormalizeVersion(version).Replace(".", "");
        if (v.Length < 4) v = v.PadLeft(4, '0');
        return $"{contentId}-A{v[..4]}-V{v[..4]}.pkg";
    }

    private static string NormalizeVersion(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return "01.00";
        version = version.Trim();
        return Regex.IsMatch(version, "^[0-9]{2}\\.[0-9]{2}$") ? version : "01.00";
    }
}
