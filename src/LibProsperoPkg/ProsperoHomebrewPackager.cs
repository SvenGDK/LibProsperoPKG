// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Packages a compiled homebrew module into an installable debug package (fPKG). The homebrew folder
// carries a raw ELF module (eboot.bin) and an optional sce_sys metadata tree. This packager assembles
// a clean source tree from those inputs and hands it to <see cref="ProsperoPackageBuilder"/> with the
// license-free path enabled: every module is fake-signed and the mount key is derived from the content
// id and passcode, so the result installs and runs on a debug-mode console with no license record.

using LibProsperoPkg.Content;
using LibProsperoPkg.License;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LibProsperoPkg;

/// <summary>
/// Options for <see cref="ProsperoHomebrewPackager.Package"/>. Only <see cref="HomebrewFolder"/> and
/// <see cref="OutputFolder"/> are required; the content id, title and version default from the
/// homebrew's <c>sce_sys/param.json</c> when present.
/// </summary>
public sealed class ProsperoHomebrewPackageOptions
{
    /// <summary>Root folder of the homebrew (the folder that holds the module and, optionally, <c>sce_sys/</c>).</summary>
    public string HomebrewFolder { get; set; } = "";

    /// <summary>Folder the finished <c>*.pkg</c> is written to.</summary>
    public string OutputFolder { get; set; } = "";

    /// <summary>Name of the compiled module inside <see cref="HomebrewFolder"/>. Defaults to <c>eboot.bin</c>.</summary>
    public string ModuleName { get; set; } = "eboot.bin";

    /// <summary>
    /// 36-character content id in the format <c>XXYYYY-XXXXYYYYY_00-ZZZZZZZZZZZZZZZZ</c>. When left
    /// empty it is read from the homebrew's <c>sce_sys/param.json</c> <c>contentId</c> field.
    /// </summary>
    public string ContentId { get; set; } = "";

    /// <summary>32-character passcode. Defaults to the all-zero debug passcode.</summary>
    public string Passcode { get; set; } = new string('0', 32);

    /// <summary>Display title. When left empty the title from <c>param.json</c> or the title id is used.</summary>
    public string Title { get; set; } = "";

    /// <summary>
    /// Content/master version formatted <c>NN.NN</c>. When left empty it is derived from the homebrew's
    /// <c>param.json</c>, falling back to <c>01.00</c>.
    /// </summary>
    public string Version { get; set; } = "";

    /// <summary>
    /// Folder used to assemble the source tree. When left empty a temporary folder is created under
    /// <see cref="OutputFolder"/> and removed after the build unless <see cref="KeepStaging"/> is set.
    /// </summary>
    public string StagingFolder { get; set; } = "";

    /// <summary>When true the assembled source tree is kept after the build. Off by default.</summary>
    public bool KeepStaging { get; set; }

    /// <summary>
    /// Fake-self options (app/firmware version, authority-id override) applied to the module. When
    /// <see langword="null"/> the defaults are used.
    /// </summary>
    public FselfOptions? FselfOptions { get; set; }
}

/// <summary>The result of a homebrew packaging run.</summary>
public sealed class ProsperoHomebrewPackageResult
{
    /// <summary>Path to the finished debug package.</summary>
    public required string OutputPath { get; init; }

    /// <summary>
    /// The debug grant for the package: the content id and passcode whose EKPFS the mount path
    /// recomputes. <see cref="ProsperoDebugLicense.RequiresRif"/> is always false.
    /// </summary>
    public required ProsperoDebugLicense DebugLicense { get; init; }

    /// <summary>Relative path of the module that was packed (always the assembled <c>eboot.bin</c>).</summary>
    public required string ModulePath { get; init; }

    /// <summary>
    /// Launch-readiness of the assembled source tree: how the module classifies and whether the tree
    /// meets the debug-mode console launch conditions.
    /// </summary>
    public required ProsperoLaunchReadinessReport LaunchReadiness { get; init; }

    /// <summary>Non-fatal warnings from the assembly and the underlying build.</summary>
    public required IReadOnlyList<string> Warnings { get; init; }

    /// <summary>The assembled source tree, when <see cref="ProsperoHomebrewPackageOptions.KeepStaging"/> is set; otherwise empty.</summary>
    public required string StagingFolder { get; init; }
}

/// <summary>
/// Packages a compiled homebrew module into an installable debug package. See the file header for the
/// assembly model.
/// </summary>
public static class ProsperoHomebrewPackager
{
    private const uint ElfMagic = 0x464C457FU; // 0x7F 'E' 'L' 'F'

    /// <summary>
    /// Assembles a source tree from <paramref name="options"/>' homebrew folder and builds a finalized
    /// debug package whose module is fake-signed and whose mount key is derived from the content id and
    /// passcode.
    /// </summary>
    /// <param name="options">The packaging inputs. See <see cref="ProsperoHomebrewPackageOptions"/>.</param>
    /// <param name="logger">Optional progress callback.</param>
    /// <returns>The output path plus the debug grant, module path, launch-readiness and any warnings.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">The homebrew folder or a required field is invalid.</exception>
    public static ProsperoHomebrewPackageResult Package(
        ProsperoHomebrewPackageOptions options, Action<string>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var log = logger ?? (_ => { });
        var warnings = new List<string>();

        if (string.IsNullOrWhiteSpace(options.HomebrewFolder) || !Directory.Exists(options.HomebrewFolder))
            throw new ArgumentException("Homebrew folder does not exist.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.OutputFolder))
            throw new ArgumentException("Output folder was not specified.", nameof(options));

        string homebrew = Path.GetFullPath(options.HomebrewFolder);
        string moduleName = string.IsNullOrWhiteSpace(options.ModuleName) ? "eboot.bin" : options.ModuleName.Trim();
        string modulePath = Path.Combine(homebrew, moduleName);
        if (!File.Exists(modulePath))
            throw new ArgumentException($"Compiled module '{moduleName}' was not found in the homebrew folder.", nameof(options));
        if (ReadMagic(modulePath) != ElfMagic)
            warnings.Add($"Module '{moduleName}' is not a raw ELF; the build's fake-sign step expects an ELF module.");

        string sceSys = Path.Combine(homebrew, "sce_sys");
        var paramMeta = ReadParamMeta(Path.Combine(sceSys, "param.json"));

        string contentId = !string.IsNullOrWhiteSpace(options.ContentId) ? options.ContentId.Trim() : paramMeta.ContentId;
        if (string.IsNullOrWhiteSpace(contentId))
            throw new ArgumentException("Content id was not supplied and could not be read from param.json.", nameof(options));

        string passcode = string.IsNullOrEmpty(options.Passcode) ? ProsperoDebugLicense.DefaultPasscode : options.Passcode;
        string version = !string.IsNullOrWhiteSpace(options.Version) ? options.Version
            : (!string.IsNullOrWhiteSpace(paramMeta.Version) ? paramMeta.Version : "01.00");

        // Construct the grant up front so a malformed content id or passcode fails before any file work.
        var debugLicense = ProsperoDebugLicense.Create(contentId, passcode);

        string staging = string.IsNullOrWhiteSpace(options.StagingFolder)
            ? Path.Combine(options.OutputFolder, "." + SafeName(contentId) + ".homebrew.tmp")
            : Path.GetFullPath(options.StagingFolder);

        try
        {
            if (Directory.Exists(staging))
                Directory.Delete(staging, recursive: true);
            Directory.CreateDirectory(staging);

            // The module always lands as eboot.bin so the launcher finds the application entry.
            File.Copy(modulePath, Path.Combine(staging, "eboot.bin"), overwrite: true);
            log($"Staged module {moduleName} as eboot.bin.");

            if (Directory.Exists(sceSys))
            {
                CopyTree(sceSys, Path.Combine(staging, "sce_sys"));
                log("Copied sce_sys metadata tree.");
            }

            // Library modules the application loads at run time live under sce_module and are packed
            // alongside the application module.
            string sceModule = Path.Combine(homebrew, "sce_module");
            if (Directory.Exists(sceModule))
            {
                CopyTree(sceModule, Path.Combine(staging, "sce_module"));
                log("Copied sce_module tree.");
            }

            var buildOptions = new ProsperoBuildOptions
            {
                Mode = ProsperoPackageMode.Homebrew,
                OutputFormat = ProsperoOutputFormat.DebugImage,
                SourceFolder = staging,
                OutputFolder = options.OutputFolder,
                ContentId = contentId,
                Passcode = passcode,
                Title = options.Title,
                Version = version,
                LicenseFree = true,
                FselfOptions = options.FselfOptions,
                GenerateParamJsonIfMissing = true,
            };

            log($"Building debug package for {contentId} from the assembled tree.");
            var buildResult = ProsperoPackageBuilder.Build(buildOptions, log);
            warnings.AddRange(buildResult.Warnings);

            // Read the assembled tree back against the launch conditions while it is still present.
            var readiness = ProsperoLaunchReadiness.InspectAppRoot(staging);

            return new ProsperoHomebrewPackageResult
            {
                OutputPath = buildResult.OutputPath,
                DebugLicense = debugLicense,
                ModulePath = "eboot.bin",
                LaunchReadiness = readiness,
                Warnings = warnings,
                StagingFolder = options.KeepStaging ? staging : "",
            };
        }
        finally
        {
            if (!options.KeepStaging)
            {
                try { if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { log($"Warning: could not remove the temporary tree '{staging}': {ex.Message}"); }
            }
        }
    }

    private static void CopyTree(string sourceDir, string targetDir)
    {
        Directory.CreateDirectory(targetDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            string rel = Path.GetRelativePath(sourceDir, file);
            string target = Path.Combine(targetDir, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }

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
