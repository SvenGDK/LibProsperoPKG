// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PS5 inner-PFS layout generation: a prepared folder is turned
// into a plaintext inner-PFS image with the superblock, inode table, super-root,
// flat-path-table, dirents and file data laid out exactly as the kernel expects.
//
// The layout is produced by LibProsperoPkg.PFS.PfsBuilder with the superblock version stamped to 2,
// so this stays a single, round-trip-validated code path — the same way
// ProsperoPfsImage reuses XtsBlockTransform for image encryption and ProsperoPfsc reuses
// PfscEncoder for compression. The produced plaintext image is what the ProsperoPfsc
// (compression) and ProsperoPfsImage (AES-XTS encryption) primitives then consume, giving a
// folder-to-compressed/encrypted inner-PFS pipeline.
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;

namespace LibProsperoPkg.PFS;

/// <summary>Options controlling an inner-PFS layout build.</summary>
public sealed class ProsperoPfsLayoutOptions
{
    /// <summary>Filesystem block size in bytes. Default 64 KiB (the PS5 inner-PFS block size).</summary>
    public uint BlockSize { get; set; } = 0x10000;

    /// <summary>
    /// Timestamp written into the inode table. Defaults to the Unix epoch for reproducible output.
    /// </summary>
    public DateTime TimeStamp { get; set; } = DateTime.UnixEpoch;

    /// <summary>
    /// Case-insensitive file names that are skipped (project scaffolding that must never end up
    /// inside the image). Matches the default exclude masks the publishing tools use.
    /// </summary>
    public IReadOnlyCollection<string> ExcludeFileNames { get; set; } = DefaultExcludeFileNames;

    /// <summary>The default file-name exclude set (project files, intermediate caches, …).</summary>
    public static IReadOnlyCollection<string> DefaultExcludeFileNames { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "keystone", "disc_info.dat", "pfs-version.dat", "ext_info.dat",
        };

    /// <summary>File-name suffixes that are skipped (e.g. the project file itself).</summary>
    public IReadOnlyCollection<string> ExcludeFileSuffixes { get; set; } = DefaultExcludeFileSuffixes;

    /// <summary>The default file-suffix exclude set.</summary>
    public static IReadOnlyCollection<string> DefaultExcludeFileSuffixes { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".gp4", ".gp5", ".esbak", ".dds" };
}

/// <summary>The outcome of an inner-PFS layout build.</summary>
public sealed class ProsperoPfsLayoutResult
{
    /// <summary>The path the plaintext inner-PFS image was written to.</summary>
    public required string OutputPath { get; init; }

    /// <summary>Total image size in bytes.</summary>
    public required long ImageSize { get; init; }

    /// <summary>Filesystem block size used (bytes).</summary>
    public required uint BlockSize { get; init; }

    /// <summary>The PFS superblock version stamped (2 = PS5).</summary>
    public required long Version { get; init; }

    /// <summary>Number of files placed into the image.</summary>
    public required int FileCount { get; init; }

    /// <summary>Number of directories placed into the image.</summary>
    public required int DirectoryCount { get; init; }
}

/// <summary>
/// Inner-PFS layout generator for PS5. See the file header for the scheme.
/// </summary>
public static class ProsperoPfsLayout
{
    /// <summary>
    /// Builds a plaintext inner-PFS image from <paramref name="sourceFolder"/> and writes it to
    /// <paramref name="outputPath"/>. The result is unsigned and unencrypted; apply
    /// <see cref="ProsperoPfsImage"/> (AES-XTS) and/or <see cref="ProsperoPfsc"/> (compression)
    /// afterwards for the encrypted/compressed forms.
    /// </summary>
    /// <param name="sourceFolder">A prepared application folder (its tree becomes the image's uroot).</param>
    /// <param name="outputPath">Destination plaintext PFS image path.</param>
    /// <param name="options">Layout options. <c>null</c> uses the PS5 defaults.</param>
    /// <param name="logger">Optional progress sink.</param>
    public static ProsperoPfsLayoutResult BuildFromFolder(
        string sourceFolder, string outputPath, ProsperoPfsLayoutOptions? options = null, Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceFolder);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        if (!Directory.Exists(sourceFolder))
            throw new DirectoryNotFoundException($"Source folder does not exist: {sourceFolder}");

        options ??= new ProsperoPfsLayoutOptions();
        var log = logger ?? (_ => { });

        var dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        long version = ProsperoPfsHeader.VersionPs5;
        log($"Laying out the inner-PFS image (superblock version {version}, block size 0x{options.BlockSize:X})...");

        var root = BuildTree(Path.GetFullPath(sourceFolder), options, out int fileCount, out int dirCount);
        log($"Filesystem tree: {dirCount} directories, {fileCount} files.");

        var props = new ProsperoPfsProperties
        {
            root = root,
            BlockSize = options.BlockSize,
            Version = version,
            Encrypt = false,
            Sign = false,
            FileTime = ToUnixSeconds(options.TimeStamp),
        };

        var builder = new ProsperoPfsBuilder(props, s => log(s));
        long canonicalSize = builder.CalculatePfsSize();
        using (var output = new FileStream(outputPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
        {
            builder.WriteImage(output);
            // The stream writer fills blocks lazily, so the tail of the final block can be left
            // unwritten. The canonical image size is the data-block count (Ndblock) * BlockSize —
            // a whole number of 0x10000 blocks; pad to it so the image is block-aligned, which the
            // AES-XTS image crypto (operating on 0x1000-byte sectors) requires.
            if (output.Length < canonicalSize)
                output.SetLength(canonicalSize);
        }

        long size = new FileInfo(outputPath).Length;
        log($"Done: {Path.GetFileName(outputPath)} ({size:N0} bytes).");

        return new ProsperoPfsLayoutResult
        {
            OutputPath = outputPath,
            ImageSize = size,
            BlockSize = options.BlockSize,
            Version = version,
            FileCount = fileCount,
            DirectoryCount = dirCount,
        };
    }

    /// <summary>
    /// Proves a freshly built plaintext layout is self-consistent: builds the image from
    /// <paramref name="sourceFolder"/>, reads it back with <see cref="ProsperoPfsReader"/> and verifies
    /// every source file is present with byte-identical content (and the superblock version
    /// matches the requested profile). This is the self-check that replaces on-hardware
    /// testing for the layout step.
    /// </summary>
    public static bool VerifyRoundTrip(string sourceFolder, ProsperoPfsLayoutOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceFolder);
        options ??= new ProsperoPfsLayoutOptions();
        string image = Path.GetTempFileName();
        try
        {
            var result = BuildFromFolder(sourceFolder, image, options);

            using var mmf = MemoryMappedFile.CreateFromFile(image, FileMode.Open, mapName: null, capacity: 0, MemoryMappedFileAccess.Read);
            using var view = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
            var reader = new ProsperoPfsReader(view);
            if (reader.Header.Version != result.Version)
                return false;

            // Every non-excluded source file must round-trip byte-for-byte.
            var expected = EnumerateSourceFiles(Path.GetFullPath(sourceFolder), options);
            foreach (var (relativePath, fullPath) in expected)
            {
                var node = reader.GetFile(relativePath);
                if (node is null)
                    return false;
                if (!FileMatchesNode(fullPath, node))
                    return false;
            }
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            TryDelete(image);
        }
    }

    // Recursively builds an FSDir tree from a source folder, applying the exclude masks. Names are
    // sorted for deterministic, reproducible output.
    private static ProsperoFsDir BuildTree(string sourceFolder, ProsperoPfsLayoutOptions options, out int fileCount, out int dirCount)
    {
        int files = 0, dirs = 0;
        var root = new ProsperoFsDir();
        Populate(root, sourceFolder);
        fileCount = files;
        dirCount = dirs;
        return root;

        void Populate(ProsperoFsDir node, string path)
        {
            foreach (var sub in Directory.EnumerateDirectories(path).OrderBy(Path.GetFileName, StringComparer.Ordinal))
            {
                var child = new ProsperoFsDir { name = Path.GetFileName(sub), Parent = node };
                node.Dirs.Add(child);
                dirs++;
                Populate(child, sub);
            }
            foreach (var file in Directory.EnumerateFiles(path).OrderBy(Path.GetFileName, StringComparer.Ordinal))
            {
                var name = Path.GetFileName(file);
                if (IsExcluded(name, options))
                    continue;
                node.Files.Add(new ProsperoFsFile(file) { name = name, Parent = node });
                files++;
            }
        }
    }

    // Enumerates (image-relative path, full path) for every source file that ends up in the image.
    private static IEnumerable<(string Relative, string Full)> EnumerateSourceFiles(string sourceFolder, ProsperoPfsLayoutOptions options)
    {
        foreach (var file in Directory.EnumerateFiles(sourceFolder, "*", SearchOption.AllDirectories))
        {
            var name = Path.GetFileName(file);
            if (IsExcluded(name, options))
                continue;
            var rel = Path.GetRelativePath(sourceFolder, file)
                .Replace(Path.DirectorySeparatorChar, '/')
                .Replace(Path.AltDirectorySeparatorChar, '/');
            yield return (rel, file);
        }
    }

    private static bool IsExcluded(string name, ProsperoPfsLayoutOptions options)
    {
        if (options.ExcludeFileNames.Contains(name))
            return true;
        foreach (var suffix in options.ExcludeFileSuffixes)
            if (name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static bool FileMatchesNode(string fullPath, ProsperoPfsReader.File node)
    {
        var info = new FileInfo(fullPath);
        if (info.Length != node.size)
            return false;

        var actual = node.GetView();
        using var expected = File.OpenRead(fullPath);
        var ba = new byte[1 << 16];
        var bb = new byte[1 << 16];
        long remaining = info.Length;
        long pos = 0;
        while (remaining > 0)
        {
            int toRead = (int)Math.Min(ba.Length, remaining);
            ReadExact(expected, ba, toRead);
            actual.Read(pos, bb, 0, toRead);
            if (!ba.AsSpan(0, toRead).SequenceEqual(bb.AsSpan(0, toRead)))
                return false;
            pos += toRead;
            remaining -= toRead;
        }
        return true;
    }

    private static void ReadExact(Stream s, byte[] buffer, int count)
    {
        int read = 0;
        while (read < count)
        {
            int n = s.Read(buffer, read, count - read);
            if (n == 0) throw new EndOfStreamException("Unexpected end of stream while comparing PFS file data.");
            read += n;
        }
    }

    private static long ToUnixSeconds(DateTime time) =>
        (long)time.ToUniversalTime().Subtract(DateTime.UnixEpoch).TotalSeconds;

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* best-effort cleanup */ }
    }
}
