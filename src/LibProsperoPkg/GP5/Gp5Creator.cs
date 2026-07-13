// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Folder -> GP5 project generation. Walks a prepared folder and emits the Prospero GP5
// project descriptor.

using System;
using System.IO;

namespace LibProsperoPkg.GP5;

/// <summary>
/// Turns a prepared application folder into a <see cref="Gp5Project"/>.
/// </summary>
public static class Gp5Creator
{
    /// <summary>
    /// The default directory-exclude mask: directories (e.g. <c>about</c>) that hold project
    /// scaffolding rather than image content, so they never end up inside the image.
    /// </summary>
    public const string DefaultDirExclude = "about";

    /// <summary>The default file-exclude mask (semicolon separated).</summary>
    public const string DefaultFileExclude =
        "*.gp5;*.esbak;keystone;*.dds;disc_info.dat;pfs-version.dat;ext_info.dat";

    /// <summary>
    /// Builds a GP5 project that references <paramref name="sourceFolder"/> as a single
    /// recursively-walked <c>rootdir</c>. The path is emitted verbatim; callers that need a
    /// different on-disk root can pass an override.
    /// </summary>
    /// <param name="sourceFolder">The prepared folder (must contain <c>sce_sys/param.json</c>).</param>
    /// <param name="type">The Prospero volume type.</param>
    /// <param name="passcode">The 32-character package passcode (defaults to all zeroes).</param>
    /// <param name="rootDirPathOverride">
    /// When supplied, written as the <c>rootdir</c> <c>src_path</c> instead of
    /// <paramref name="sourceFolder"/>.
    /// </param>
    public static Gp5Project FromFolder(
        string sourceFolder,
        Gp5VolumeType type = Gp5VolumeType.prospero_app,
        string passcode = "00000000000000000000000000000000",
        string? rootDirPathOverride = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceFolder);
        if (!Directory.Exists(sourceFolder))
            throw new DirectoryNotFoundException($"Source folder does not exist: {sourceFolder}");

        var project = Gp5Project.Create(type, passcode);
        project.RootDir = new Gp5RootDir
        {
            SourcePath = rootDirPathOverride ?? sourceFolder,
            DirExclude = DefaultDirExclude,
            FileExclude = DefaultFileExclude,
        };
        return project;
    }

    /// <summary>
    /// Builds a GP5 project in the <see cref="Gp5Layout.Flat"/> style: every file under
    /// <paramref name="sourceFolder"/> is listed as an explicit top-level <c>&lt;file&gt;</c> entry
    /// (inside <c>&lt;files&gt;</c>), with no <c>&lt;rootdir&gt;</c> / <c>&lt;global_exclude&gt;</c>. This
    /// produces a fully-resolved project that does not rely on directory walking at pack time,
    /// which is convenient for a direct packaging pipeline.
    /// </summary>
    public static Gp5Project FromFolderExplicit(
        string sourceFolder,
        Gp5VolumeType type = Gp5VolumeType.prospero_app,
        string passcode = "00000000000000000000000000000000")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceFolder);
        if (!Directory.Exists(sourceFolder))
            throw new DirectoryNotFoundException($"Source folder does not exist: {sourceFolder}");

        var root = Path.GetFullPath(sourceFolder);
        var project = Gp5Project.Create(type, passcode);

        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(root, file);
            // Prospero destination paths use backslash separators (e.g. sce_sys\param.json).
            var dst = relative
                .Replace(Path.DirectorySeparatorChar, '\\')
                .Replace(Path.AltDirectorySeparatorChar, '\\');

            project.Files.Add(new Gp5File
            {
                SourcePath = file,
                DestinationPath = dst,
            });
        }

        return project;
    }
}
