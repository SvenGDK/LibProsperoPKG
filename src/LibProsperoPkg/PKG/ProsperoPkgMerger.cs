// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Reassembles a split package into a single finalized image. Distribution splits a finalized
// image into a set of numbered pieces (<base>_0.pkg .. <base>_N.pkg) plus a metadata subcontainer
// (<base>_sc.pkg). The numbered pieces hold the finalized header and the encrypted image body; the
// metadata piece holds the embedded subcontainer that the header locates at a fixed offset.
// The merged file is the byte concatenation of the numbered pieces in ascending order followed by
// the metadata piece.

using LibProsperoPkg.DiscBackup;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace LibProsperoPkg.PKG;

/// <summary>The structural check performed on a split set before it is merged.</summary>
public sealed class ProsperoPkgMergeValidation
{
    /// <summary>True when no structural error was found.</summary>
    public required bool IsValid { get; init; }

    /// <summary>The image kind read from the finalized header signed byte.</summary>
    public required ProsperoPkgType PackageType { get; init; }

    /// <summary>The finalized-image format version read from the header.</summary>
    public required ushort FormatVersion { get; init; }

    /// <summary>The encrypted image body offset recorded in the header.</summary>
    public required long PfsImageOffset { get; init; }

    /// <summary>The encrypted image body size recorded in the header.</summary>
    public required long PfsImageSize { get; init; }

    /// <summary>The embedded subcontainer offset recorded in the header.</summary>
    public required long EmbeddedCntOffset { get; init; }

    /// <summary>The summed size of the numbered pieces.</summary>
    public required long NumberedSize { get; init; }

    /// <summary>The size of the metadata piece, or 0 when absent.</summary>
    public long MetaSize { get; init; }

    /// <summary>The problems found; empty when <see cref="IsValid"/> is true.</summary>
    public required IReadOnlyList<string> Errors { get; init; }
}

/// <summary>The outcome of a completed merge.</summary>
public sealed class ProsperoPkgMergeResult
{
    /// <summary>The path of the written file.</summary>
    public required string OutputPath { get; init; }

    /// <summary>The shared base name of the split set (the content id / title base).</summary>
    public required string BaseName { get; init; }

    /// <summary>The numbered pieces, in the ascending order they were written.</summary>
    public required IReadOnlyList<string> NumberedPieces { get; init; }

    /// <summary>The metadata piece appended last, or <see langword="null"/> when the set had none.</summary>
    public string? MetaPiece { get; init; }

    /// <summary>The size in bytes of the written file.</summary>
    public required long TotalSize { get; init; }

    /// <summary>The image kind read from the finalized header.</summary>
    public required ProsperoPkgType PackageType { get; init; }

    /// <summary>The lowercase hex SHA-256 of the written file, when a digest was requested.</summary>
    public string? Sha256 { get; init; }
}

/// <summary>
/// Reassembles split packages. A split set shares a base name and is made of numbered pieces
/// (<c>&lt;base&gt;_0.pkg</c> .. <c>&lt;base&gt;_N.pkg</c>) and an optional metadata piece
/// (<c>&lt;base&gt;_sc.pkg</c>). The merged file is the concatenation of the numbered pieces in
/// ascending order followed by the metadata piece.
/// </summary>
public static class ProsperoPkgMerger
{
    private const int CopyBufferSize = 1024 * 1024;
    private const string MetaToken = "sc";
    private const string MergedSuffix = "-merged.pkg";

    /// <summary>A split set grouped by shared base name.</summary>
    private sealed class SplitSet
    {
        public required string BaseName { get; init; }
        public readonly SortedDictionary<int, string> Numbered = [];
        public string? Meta { get; set; }

        public IReadOnlyList<string> OrderedNumbered => [.. Numbered.Values];
        public bool HasRoot => Numbered.ContainsKey(0);
    }

    /// <summary>
    /// Reads every <c>.pkg</c> in <paramref name="inputDir"/>, groups them into split sets by base
    /// name and merges each set that has a root piece. Output files are written to
    /// <paramref name="outputDir"/> (defaults to the input directory) as
    /// <c>&lt;base&gt;-merged.pkg</c>.
    /// </summary>
    public static IReadOnlyList<ProsperoPkgMergeResult> MergeDirectory(
        string inputDir,
        string? outputDir = null,
        bool computeDigest = false,
        Action<string>? log = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputDir);
        if (!Directory.Exists(inputDir))
            throw new DirectoryNotFoundException($"'{inputDir}' is not a directory.");

        outputDir = string.IsNullOrEmpty(outputDir) ? inputDir : outputDir;
        Directory.CreateDirectory(outputDir);

        IReadOnlyList<SplitSet> sets = Discover(inputDir, log, cancellationToken);
        var results = new List<ProsperoPkgMergeResult>();

        foreach (SplitSet set in sets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!set.HasRoot)
            {
                log?.Invoke($"[warn] no root piece (_0) for '{set.BaseName}'; skipping.");
                continue;
            }

            string outputPath = Path.Combine(outputDir, set.BaseName + MergedSuffix);
            log?.Invoke($"[work] merging '{set.BaseName}' ({set.Numbered.Count} numbered piece(s)" +
                        (set.Meta is null ? ", no metadata piece)..." : " + metadata piece)..."));
            results.Add(Merge(set.OrderedNumbered, set.Meta, outputPath, computeDigest, log, cancellationToken));
        }

        log?.Invoke("[done] merge complete.");
        return results;
    }

    /// <summary>
    /// Merges one split set. <paramref name="numberedPieces"/> must be ordered ascending with the
    /// root piece first; <paramref name="metaPiece"/> is appended last when supplied. The set is
    /// validated before any bytes are written.
    /// </summary>
    /// <exception cref="InvalidDataException">The set failed structural validation.</exception>
    public static ProsperoPkgMergeResult Merge(
        IReadOnlyList<string> numberedPieces,
        string? metaPiece,
        string outputPath,
        bool computeDigest = false,
        Action<string>? log = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(numberedPieces);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);
        if (numberedPieces.Count == 0)
            throw new ArgumentException("At least the root piece is required.", nameof(numberedPieces));

        ProsperoPkgMergeValidation validation = Validate(numberedPieces, metaPiece);
        if (!validation.IsValid)
            throw new InvalidDataException("Split package validation failed: " + string.Join("; ", validation.Errors));

        var ordered = new List<string>(numberedPieces);
        if (metaPiece is not null)
            ordered.Add(metaPiece);

        string? outputDir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(outputDir))
            Directory.CreateDirectory(outputDir);

        long total;
        string? digest = null;

        var sources = new FileStream[ordered.Count];
        try
        {
            for (int i = 0; i < ordered.Count; i++)
                sources[i] = File.OpenRead(ordered[i]);

            var segments = sources.Select(fs => ((Stream)fs, 0L, fs.Length));
            using var concat = new ProsperoConcatStream(segments);
            total = concat.Length;

            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, CopyBufferSize);
            if (computeDigest)
            {
                using var sha = SHA256.Create();
                using (var crypto = new CryptoStream(output, sha, CryptoStreamMode.Write, leaveOpen: true))
                    CopyWithProgress(concat, crypto, total, log, cancellationToken);
                digest = Convert.ToHexStringLower(sha.Hash!);
            }
            else
            {
                CopyWithProgress(concat, output, total, log, cancellationToken);
            }
        }
        finally
        {
            foreach (var s in sources)
                s?.Dispose();
        }

        return new ProsperoPkgMergeResult
        {
            OutputPath = outputPath,
            BaseName = BaseNameOf(numberedPieces[0]),
            NumberedPieces = [.. numberedPieces],
            MetaPiece = metaPiece,
            TotalSize = total,
            PackageType = validation.PackageType,
            Sha256 = digest,
        };
    }

    /// <summary>
    /// Checks a split set against the finalized-image layout: the root piece carries the header,
    /// the numbered pieces fill the region before the embedded subcontainer, and the metadata piece
    /// (when present) is the subcontainer that begins exactly at the recorded offset.
    /// </summary>
    public static ProsperoPkgMergeValidation Validate(IReadOnlyList<string> numberedPieces, string? metaPiece)
    {
        ArgumentNullException.ThrowIfNull(numberedPieces);
        if (numberedPieces.Count == 0)
            throw new ArgumentException("At least the root piece is required.", nameof(numberedPieces));

        var errors = new List<string>();

        byte[] head = ReadHead(numberedPieces[0], 0x60);
        var type = ProsperoPkgType.FullRetail;
        ushort formatVersion = 0;
        long pfsOffset = 0, pfsSize = 0, cntOffset = 0;

        if (head.Length < 0x60 || !head.AsSpan(0, 4).SequenceEqual(ProsperoPkgLayout.FihMagic))
        {
            errors.Add("root piece does not start with the finalized-image header.");
        }
        else
        {
            byte signed = head[ProsperoPkgLayout.FihSignedByteOffset];
            type = signed == 0x80 ? ProsperoPkgType.FullRetail
                 : signed == 0x00 ? ProsperoPkgType.FullDebug
                 : ProsperoPkgType.FullRetail;
            if (signed is not (0x80 or 0x00))
                errors.Add($"unexpected signed byte 0x{signed:X2} in the finalized-image header.");

            formatVersion = BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(ProsperoPkgLayout.FihFormatVersionField));
            if (formatVersion != ProsperoPkgLayout.FihRequiredFormatVersion)
                errors.Add($"unexpected format version {formatVersion}.");

            pfsOffset = ReadInt64(head, ProsperoPkgLayout.FihPfsImageOffsetField);
            pfsSize = ReadInt64(head, ProsperoPkgLayout.FihPfsImageSizeField);
            cntOffset = ReadInt64(head, ProsperoPkgLayout.FihEmbeddedCntOffsetField);

            if (cntOffset != pfsOffset + pfsSize)
                errors.Add($"embedded subcontainer offset {cntOffset} does not equal image offset+size {pfsOffset + pfsSize}.");
        }

        long numberedSize = 0;
        foreach (string piece in numberedPieces)
        {
            var info = new FileInfo(piece);
            if (!info.Exists)
                errors.Add($"missing piece '{piece}'.");
            else
                numberedSize += info.Length;
        }

        if (errors.Count == 0 && cntOffset != numberedSize)
            errors.Add($"numbered pieces total {numberedSize} does not equal the embedded subcontainer offset {cntOffset}.");

        long metaSize = 0;
        if (metaPiece is not null)
        {
            var metaInfo = new FileInfo(metaPiece);
            if (!metaInfo.Exists)
            {
                errors.Add($"missing metadata piece '{metaPiece}'.");
            }
            else
            {
                metaSize = metaInfo.Length;
                byte[] metaHead = ReadHead(metaPiece, 4);
                if (metaHead.Length < 4 || !metaHead.AsSpan(0, 4).SequenceEqual(ProsperoPkgLayout.CntMagic))
                    errors.Add("metadata piece does not start with the subcontainer header.");
            }
        }

        return new ProsperoPkgMergeValidation
        {
            IsValid = errors.Count == 0,
            PackageType = type,
            FormatVersion = formatVersion,
            PfsImageOffset = pfsOffset,
            PfsImageSize = pfsSize,
            EmbeddedCntOffset = cntOffset,
            NumberedSize = numberedSize,
            MetaSize = metaSize,
            Errors = errors,
        };
    }

    // ---- Internals ----

    private static IReadOnlyList<SplitSet> Discover(string inputDir, Action<string>? log, CancellationToken cancellationToken)
    {
        var sets = new Dictionary<string, SplitSet>(StringComparer.Ordinal);

        foreach (string file in Directory.EnumerateFiles(inputDir))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string fileName = Path.GetFileName(file);

            if (!string.Equals(Path.GetExtension(fileName), ".pkg", StringComparison.OrdinalIgnoreCase))
                continue;
            if (fileName.Contains(MergedSuffix, StringComparison.Ordinal))
                continue;
            if (!TryParseName(fileName, out string baseName, out string token))
            {
                log?.Invoke($"[warn] '{fileName}' does not match the split naming scheme; skipping.");
                continue;
            }

            if (!sets.TryGetValue(baseName, out SplitSet? set))
            {
                set = new SplitSet { BaseName = baseName };
                sets[baseName] = set;
            }

            if (string.Equals(token, MetaToken, StringComparison.OrdinalIgnoreCase))
                set.Meta = file;
            else if (TryParseLeadingInt(token, out int number))
                set.Numbered[number] = file;
            else
                log?.Invoke($"[warn] '{fileName}' has an unrecognised piece token; skipping.");
        }

        return [.. sets.Values];
    }

    /// <summary>
    /// Splits a file name into its base (everything before the last <c>_</c>) and the piece token
    /// (between that <c>_</c> and the first <c>.</c>).
    /// </summary>
    private static bool TryParseName(string fileName, out string baseName, out string token)
    {
        baseName = string.Empty;
        token = string.Empty;

        int lastUnderscore = fileName.LastIndexOf('_');
        int firstDot = fileName.IndexOf('.');
        if (lastUnderscore < 0 || firstDot < 0 || firstDot <= lastUnderscore)
            return false;

        int begin = lastUnderscore + 1;
        token = fileName.Substring(begin, firstDot - begin);
        baseName = fileName[..lastUnderscore];
        return token.Length > 0;
    }

    private static string BaseNameOf(string path)
    {
        string fileName = Path.GetFileName(path);
        return TryParseName(fileName, out string baseName, out _) ? baseName : Path.GetFileNameWithoutExtension(fileName);
    }

    private static bool TryParseLeadingInt(string text, out int value)
    {
        int i = 0;
        while (i < text.Length && char.IsAsciiDigit(text[i]))
            i++;
        if (i == 0)
        {
            value = 0;
            return false;
        }
        value = int.Parse(text.AsSpan(0, i), NumberStyles.None, CultureInfo.InvariantCulture);
        return true;
    }

    private static byte[] ReadHead(string path, int count)
    {
        using FileStream fs = File.OpenRead(path);
        byte[] buffer = new byte[count];
        int total = 0;
        int read;
        while (total < count && (read = fs.Read(buffer, total, count - total)) > 0)
            total += read;
        return total == count ? buffer : buffer[..total];
    }

    private static long ReadInt64(byte[] buffer, int offset) =>
        (long)BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset));

    private static void CopyWithProgress(Stream source, Stream destination, long total, Action<string>? log, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[CopyBufferSize];
        long copied = 0;
        int nextPercent = 25;
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            destination.Write(buffer, 0, read);
            copied += read;

            if (log is not null && total > 0)
            {
                int percent = (int)(copied * 100 / total);
                while (nextPercent <= 100 && percent >= nextPercent)
                {
                    log($"\t[work] {copied}/{total} bytes ({nextPercent}%)...");
                    nextPercent += 25;
                }
            }
        }
    }
}
