// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// End-to-end filesystem extraction over the proven ProsperoPfsReader: given an
// already-opened (decrypted) PFS image reader, walk its uroot tree and write every file to an
// output directory, PFSC-decompressing per-file where the inode marks it compressed. This is the
// single-image half of the package extractor; the two-layer orchestration (finalized image ->
// outer PFS -> pfs_image.dat -> inner PFS) lives in LibProsperoPkg.PKG.ProsperoPackageExtractor.
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LibProsperoPkg.PFS;

/// <summary>Raised when a package/filesystem cannot be extracted (bad key, malformed image, unsafe path).</summary>
public sealed class ProsperoExtractionException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    public ProsperoExtractionException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and inner cause.</summary>
    public ProsperoExtractionException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>One file written by an extraction pass.</summary>
public sealed class ProsperoExtractedEntry
{
    /// <summary>Forward-slash relative path of the file under the output directory.</summary>
    public required string RelativePath { get; init; }

    /// <summary>Number of bytes written to disk.</summary>
    public required long Size { get; init; }

    /// <summary>True when the source inode was PFSC-compressed (and was decompressed on write).</summary>
    public required bool IsCompressed { get; init; }
}

/// <summary>
/// Extracts the files of an opened <see cref="ProsperoPfsReader"/> to a directory. See the file
/// header for what this covers. All writes are confined to the output directory (path-traversal safe).
/// </summary>
public static class ProsperoPfsExtractor
{
    /// <summary>
    /// Writes every file in <paramref name="reader"/>'s uroot tree to <paramref name="outputDirectory"/>,
    /// preserving the relative directory structure and PFSC-decompressing per-file where flagged.
    /// </summary>
    /// <param name="reader">An opened (and, if encrypted, decrypted) PFS image reader.</param>
    /// <param name="outputDirectory">Destination directory (created if missing).</param>
    /// <param name="logger">Optional progress sink.</param>
    /// <returns>The list of files written.</returns>
    public static IReadOnlyList<ProsperoExtractedEntry> Extract(
        ProsperoPfsReader reader, string outputDirectory, Action<string>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        var log = logger ?? (_ => { });

        Directory.CreateDirectory(outputDirectory);
        string rootFull = Path.GetFullPath(outputDirectory);

        var written = new List<ProsperoExtractedEntry>();
        foreach (var file in reader.GetAllFiles())
        {
            string rel = ToRelativePath(file.FullName);
            if (rel.Length == 0)
                continue;

            string dest = Path.GetFullPath(Path.Combine(rootFull, rel));
            EnsureInside(rootFull, dest);
            string destDir = Path.GetDirectoryName(dest)!;
            Directory.CreateDirectory(destDir);

            bool compressed = file.flags.HasFlag(ProsperoInodeFlags.compressed);
            file.Save(dest, decompress: true);
            long size = new FileInfo(dest).Length;

            written.Add(new ProsperoExtractedEntry
            {
                RelativePath = rel.Replace('\\', '/'),
                Size = size,
                IsCompressed = compressed,
            });
            log($"  {rel} ({size:N0} bytes{(compressed ? ", decompressed" : "")})");
        }

        return written;
    }

    /// <summary>
    /// Lists the files in <paramref name="reader"/>'s uroot tree without writing them.
    /// </summary>
    /// <param name="reader">An opened (and, if encrypted, decrypted) PFS image reader.</param>
    /// <returns>The relative paths and inode sizes of every file.</returns>
    public static IReadOnlyList<ProsperoExtractedEntry> ListEntries(ProsperoPfsReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return reader.GetAllFiles()
            .Select(f => new { f, rel = ToRelativePath(f.FullName) })
            .Where(x => x.rel.Length != 0)
            .Select(x => new ProsperoExtractedEntry
            {
                RelativePath = x.rel.Replace('\\', '/'),
                Size = x.f.flags.HasFlag(ProsperoInodeFlags.compressed) ? x.f.compressed_size : x.f.size,
                IsCompressed = x.f.flags.HasFlag(ProsperoInodeFlags.compressed),
            })
            .ToList();
    }

    // A PFS file's FullName is "/uroot/<path>"; project it to a clean, forward-slash relative path.
    private static string ToRelativePath(string fullName)
    {
        string s = (fullName ?? string.Empty).Replace('\\', '/');
        int i = 0;
        while (i < s.Length && s[i] == '/') i++;
        s = s[i..];
        if (s.Equals("uroot", StringComparison.Ordinal))
            return string.Empty;
        if (s.StartsWith("uroot/", StringComparison.Ordinal))
            s = s["uroot/".Length..];
        return s;
    }

    // Confine every write to the output directory: reject any resolved path that escapes it.
    private static void EnsureInside(string rootFull, string destFull)
    {
        string root = rootFull.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        string dest = Path.GetFullPath(destFull);
        if (!dest.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new ProsperoExtractionException($"Refusing to write outside the output directory: {destFull}");
    }
}
