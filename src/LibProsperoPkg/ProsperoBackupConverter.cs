// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Turns a decrypted application backup into an installable debug package (fPKG). A decrypted backup
// carries the application's data and metadata in the clear alongside its executable modules in two
// forms: the on-disk signed/encrypted modules at their normal paths, and raw ELF copies of the same
// modules under a "decrypted" subtree. This converter assembles a single source tree that keeps the
// plaintext data and metadata, substitutes each raw ELF for its signed/encrypted counterpart, then
// hands the tree to <see cref="ProsperoPackageBuilder"/> with fake-signing enabled. The result is a
// finalized debug image whose mount key is derived from the content id and passcode, so it installs
// and runs on a debug-mode console with no license record.

using LibProsperoPkg.Content;
using LibProsperoPkg.License;
using LibProsperoPkg.PKG;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LibProsperoPkg;

/// <summary>
/// Options for <see cref="ProsperoBackupConverter.Convert"/>. Only <see cref="BackupFolder"/> and
/// <see cref="OutputFolder"/> are required; the content id, passcode and version default from the
/// backup's <c>sce_sys/param.json</c>.
/// </summary>
public sealed class ProsperoBackupConversionOptions
{
    /// <summary>Root folder of the decrypted backup (the folder that holds <c>sce_sys/</c>).</summary>
    public string BackupFolder { get; set; } = "";

    /// <summary>Folder the finished <c>*.pkg</c> is written to.</summary>
    public string OutputFolder { get; set; } = "";

    /// <summary>
    /// Name of the subtree that holds the raw ELF copies of the executable modules, relative to
    /// <see cref="BackupFolder"/>. Defaults to <c>decrypted</c>.
    /// </summary>
    public string DecryptedSubfolder { get; set; } = "decrypted";

    /// <summary>
    /// 36-character content id. When left empty it is read from the backup's
    /// <c>sce_sys/param.json</c> <c>contentId</c> field.
    /// </summary>
    public string ContentId { get; set; } = "";

    /// <summary>32-character passcode. Defaults to the all-zero debug passcode.</summary>
    public string Passcode { get; set; } = new string('0', 32);

    /// <summary>
    /// Content/master version formatted <c>NN.NN</c>. When left empty it is derived from the backup's
    /// <c>param.json</c>, falling back to <c>01.00</c>.
    /// </summary>
    public string Version { get; set; } = "";

    /// <summary>
    /// Folder used to assemble the merged source tree. When left empty a temporary folder is created
    /// under <see cref="OutputFolder"/> and removed after the build unless <see cref="KeepStaging"/>
    /// is set.
    /// </summary>
    public string StagingFolder { get; set; } = "";

    /// <summary>When true the assembled source tree is kept after the build. Off by default.</summary>
    public bool KeepStaging { get; set; }

    /// <summary>
    /// When true the backup's <c>sce_sys/about/right.sprx</c> is dropped so the builder injects its
    /// embedded debug module instead of fake-signing the backup's own module. Off by default (the
    /// backup's module is substituted and fake-signed like every other executable).
    /// </summary>
    public bool UseEmbeddedRightSprx { get; set; }

    /// <summary>
    /// When true the inner <c>pfs_image.dat</c> is stored PFSC-compressed. Off by default. See
    /// <see cref="ProsperoBuildOptions.CompressInnerImage"/>.
    /// </summary>
    public bool CompressInnerImage { get; set; }

    /// <summary>Inner-image codec selection. See <see cref="ProsperoBuildOptions.InnerCompression"/>.</summary>
    public ProsperoInnerCompression InnerCompression { get; set; } = ProsperoInnerCompression.None;

    /// <summary>
    /// Fake-self options (app/firmware version, authority-id override) applied to every module. When
    /// <see langword="null"/> the defaults are used.
    /// </summary>
    public FselfOptions? FselfOptions { get; set; }
}

/// <summary>The result of a backup conversion.</summary>
public sealed class ProsperoBackupConversionResult
{
    /// <summary>Path to the finished debug package.</summary>
    public required string OutputPath { get; init; }

    /// <summary>
    /// The debug grant for the package: the content id and passcode whose EKPFS the mount path
    /// recomputes. <see cref="ProsperoDebugLicense.RequiresRif"/> is always false.
    /// </summary>
    public required ProsperoDebugLicense DebugLicense { get; init; }

    /// <summary>
    /// Relative paths of the executable modules that were substituted with their raw ELF copy from the
    /// decrypted subtree (and then fake-signed).
    /// </summary>
    public required IReadOnlyList<string> SubstitutedModules { get; init; }

    /// <summary>
    /// Relative paths of executable modules that were already raw ELF at their normal path and were
    /// fake-signed in place.
    /// </summary>
    public required IReadOnlyList<string> PlaintextModules { get; init; }

    /// <summary>
    /// Relative paths of signed/encrypted executable modules with no raw ELF copy in the decrypted
    /// subtree. They are packed unchanged and will not run on a debug-mode console; each also raises a
    /// warning.
    /// </summary>
    public required IReadOnlyList<string> UnresolvedModules { get; init; }

    /// <summary>Non-fatal warnings from the assembly and the underlying build.</summary>
    public required IReadOnlyList<string> Warnings { get; init; }

    /// <summary>
    /// Launch-readiness of the assembled source tree: how each executable module classifies and whether
    /// the tree meets the debug-mode console launch conditions.
    /// </summary>
    public required ProsperoLaunchReadinessReport LaunchReadiness { get; init; }

    /// <summary>The assembled source tree, when <see cref="ProsperoBackupConversionOptions.KeepStaging"/> is set; otherwise empty.</summary>
    public required string StagingFolder { get; init; }
}

/// <summary>
/// Converts a decrypted application backup into an installable debug package. See the file header for
/// the assembly model.
/// </summary>
public static class ProsperoBackupConverter
{
    private const uint ElfMagic = 0x464C457FU;       // 0x7F 'E' 'L' 'F'
    private const uint SelfMagicFake = 0x1D3D154FU;  // on-disk fake-self
    private const uint SelfMagicSigned = 0xEEF51454U; // signed/encrypted on-disk module

    /// <summary>
    /// Assembles a merged source tree from <paramref name="options"/>' backup and builds a finalized
    /// debug package.
    /// </summary>
    /// <param name="options">The conversion inputs. See <see cref="ProsperoBackupConversionOptions"/>.</param>
    /// <param name="logger">Optional progress callback.</param>
    /// <returns>The output path plus the module classification and any warnings.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">The backup folder or a required field is invalid.</exception>
    public static ProsperoBackupConversionResult Convert(
        ProsperoBackupConversionOptions options, Action<string>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var log = logger ?? (_ => { });
        var warnings = new List<string>();

        if (string.IsNullOrWhiteSpace(options.BackupFolder) || !Directory.Exists(options.BackupFolder))
            throw new ArgumentException("Backup folder does not exist.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.OutputFolder))
            throw new ArgumentException("Output folder was not specified.", nameof(options));

        string backup = Path.GetFullPath(options.BackupFolder);
        if (!Directory.Exists(Path.Combine(backup, "sce_sys")))
            throw new ArgumentException("Backup folder does not contain a sce_sys directory.", nameof(options));

        string decryptedRoot = Path.Combine(backup, options.DecryptedSubfolder);
        bool hasDecrypted = Directory.Exists(decryptedRoot);
        if (!hasDecrypted)
            warnings.Add($"No '{options.DecryptedSubfolder}' subtree was found; signed modules cannot be substituted and the package will not run.");

        var paramMeta = ReadParamMeta(Path.Combine(backup, "sce_sys", "param.json"));
        string contentId = !string.IsNullOrWhiteSpace(options.ContentId) ? options.ContentId.Trim() : paramMeta.ContentId;
        if (string.IsNullOrWhiteSpace(contentId))
            throw new ArgumentException("Content id was not supplied and could not be read from param.json.", nameof(options));

        string passcode = string.IsNullOrEmpty(options.Passcode) ? ProsperoDebugLicense.DefaultPasscode : options.Passcode;
        string version = !string.IsNullOrWhiteSpace(options.Version) ? options.Version
            : (!string.IsNullOrWhiteSpace(paramMeta.Version) ? paramMeta.Version : "01.00");

        // Construct the grant up front so a malformed content id or passcode fails before any file work.
        var debugLicense = ProsperoDebugLicense.Create(contentId, passcode);

        string staging = string.IsNullOrWhiteSpace(options.StagingFolder)
            ? Path.Combine(options.OutputFolder, "." + SafeName(contentId) + ".convert.tmp")
            : Path.GetFullPath(options.StagingFolder);

        var substituted = new List<string>();
        var plaintext = new List<string>();
        var unresolved = new List<string>();

        try
        {
            if (Directory.Exists(staging))
                Directory.Delete(staging, recursive: true);
            Directory.CreateDirectory(staging);

            AssembleTree(backup, decryptedRoot, hasDecrypted, staging, options, log, warnings,
                substituted, plaintext, unresolved);

            foreach (var rel in unresolved)
                warnings.Add($"Module '{rel}' is signed with no decrypted copy; it is packed unchanged and will not run.");

            var buildOptions = new ProsperoBuildOptions
            {
                Mode = ProsperoPackageMode.Application,
                OutputFormat = ProsperoOutputFormat.DebugImage,
                SourceFolder = staging,
                OutputFolder = options.OutputFolder,
                ContentId = contentId,
                Passcode = passcode,
                Version = version,
                FakeSignSelfModules = true,
                FselfOptions = options.FselfOptions,
                CompressInnerImage = options.CompressInnerImage,
                InnerCompression = options.InnerCompression,
                GenerateParamJsonIfMissing = true,
            };

            log($"Building debug package for {contentId} from the assembled tree.");
            var buildResult = ProsperoPackageBuilder.Build(buildOptions, log);
            warnings.AddRange(buildResult.Warnings);

            // Read the assembled tree back against the launch conditions while it is still present.
            var readiness = ProsperoLaunchReadiness.InspectAppRoot(staging);

            return new ProsperoBackupConversionResult
            {
                OutputPath = buildResult.OutputPath,
                DebugLicense = debugLicense,
                SubstitutedModules = substituted,
                PlaintextModules = plaintext,
                UnresolvedModules = unresolved,
                Warnings = warnings,
                LaunchReadiness = readiness,
                StagingFolder = options.KeepStaging ? staging : "",
            };
        }
        finally
        {
            if (!options.KeepStaging)
            {
                try { if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true); }
                catch (IOException) { log($"Warning: could not remove the temporary tree '{staging}'."); }
            }
        }
    }

    // Copies the backup into the staging tree, excluding the decrypted subtree, substituting each
    // signed executable module with its raw ELF copy where one exists.
    private static void AssembleTree(
        string backup, string decryptedRoot, bool hasDecrypted, string staging,
        ProsperoBackupConversionOptions options, Action<string> log, List<string> warnings,
        List<string> substituted, List<string> plaintext, List<string> unresolved)
    {
        string decryptedFull = hasDecrypted ? Path.GetFullPath(decryptedRoot) : "";

        foreach (var file in Directory.EnumerateFiles(backup, "*", SearchOption.AllDirectories))
        {
            string full = Path.GetFullPath(file);
            // Skip the decrypted subtree itself; it is a source of substitutions, not a tree member.
            if (hasDecrypted && IsUnder(full, decryptedFull))
                continue;

            string rel = Path.GetRelativePath(backup, full);
            string relNorm = rel.Replace('\\', '/');

            // Drop the backup's own right.sprx so the builder injects its embedded debug module.
            if (options.UseEmbeddedRightSprx
                && relNorm.Equals("sce_sys/about/right.sprx", StringComparison.OrdinalIgnoreCase))
            {
                log("Dropping the backup right.sprx; the embedded debug module will be used.");
                continue;
            }

            string target = Path.Combine(staging, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);

            if (IsModuleCandidate(Path.GetFileName(rel)))
            {
                uint magic = ReadMagic(full);
                if (magic == ElfMagic)
                {
                    // Already a raw ELF at its normal path; the build's fake-sign step converts it.
                    File.Copy(full, target, overwrite: true);
                    plaintext.Add(relNorm);
                    continue;
                }

                if (magic == SelfMagicSigned || magic == SelfMagicFake)
                {
                    string? decrypted = hasDecrypted ? Path.Combine(decryptedRoot, rel) : null;
                    if (decrypted is not null && File.Exists(decrypted) && ReadMagic(decrypted) == ElfMagic)
                    {
                        File.Copy(decrypted, target, overwrite: true);
                        substituted.Add(relNorm);
                        log($"Substituted decrypted module for {relNorm}.");
                        continue;
                    }

                    // Signed module with no decrypted copy: pack it unchanged and flag it.
                    File.Copy(full, target, overwrite: true);
                    unresolved.Add(relNorm);
                    continue;
                }
            }

            // Data or metadata: copy verbatim.
            File.Copy(full, target, overwrite: true);
        }
    }

    // Executable-module file names/extensions that participate in substitution + fake-signing.
    private static bool IsModuleCandidate(string fileName) =>
        fileName.Equals("eboot.bin", StringComparison.OrdinalIgnoreCase)
        || fileName.EndsWith(".elf", StringComparison.OrdinalIgnoreCase)
        || fileName.EndsWith(".prx", StringComparison.OrdinalIgnoreCase)
        || fileName.EndsWith(".sprx", StringComparison.OrdinalIgnoreCase);

    private static uint ReadMagic(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            Span<byte> head = stackalloc byte[4];
            if (fs.Read(head) < 4)
                return 0;
            return (uint)(head[0] | (head[1] << 8) | (head[2] << 16) | (head[3] << 24));
        }
        catch (IOException) { return 0; }
    }

    private static bool IsUnder(string path, string root)
    {
        string p = path.TrimEnd(Path.DirectorySeparatorChar);
        string r = root.TrimEnd(Path.DirectorySeparatorChar);
        return p.Equals(r, StringComparison.OrdinalIgnoreCase)
            || p.StartsWith(r + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string SafeName(string contentId)
    {
        Span<char> buffer = stackalloc char[contentId.Length];
        for (int i = 0; i < contentId.Length; i++)
        {
            char c = contentId[i];
            buffer[i] = char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_';
        }
        return new string(buffer);
    }

    private readonly record struct ParamMeta(string ContentId, string Version);

    private static ParamMeta ReadParamMeta(string paramPath)
    {
        if (!File.Exists(paramPath))
            return new ParamMeta("", "");
        try
        {
            var root = JsonNode.Parse(File.ReadAllText(paramPath)) as JsonObject;
            if (root is null)
                return new ParamMeta("", "");
            string cid = root.TryGetPropertyValue("contentId", out var c) && c is JsonValue cv && cv.TryGetValue(out string? cs) ? cs ?? "" : "";
            string ver = root.TryGetPropertyValue("masterVersion", out var m) && m is JsonValue mv && mv.TryGetValue(out string? ms) ? ms ?? "" : "";
            return new ParamMeta(cid, ver);
        }
        catch (JsonException) { return new ParamMeta("", ""); }
        catch (IOException) { return new ParamMeta("", ""); }
    }
}
