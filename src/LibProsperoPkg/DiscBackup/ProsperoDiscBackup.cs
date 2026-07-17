// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Opens a split disc-backup package (app_0.pkg + app_sc.pkg + ... described by app.json),
// reassembles the pieces on the fly, verifies the SHA-256 package digest and PlayGo chunk CRCs,
// and reads/extracts the finalized (FIH) container and its embedded CNT entries.

using LibProsperoPkg.PKG;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace LibProsperoPkg.DiscBackup;

/// <summary>
/// A split disc-backup package described by an <c>app.json</c> manifest. Reassembles its pieces
/// into the single finalized image without materialising a temp file, and exposes verification
/// and container-extraction helpers.
/// </summary>
public sealed class ProsperoDiscBackup
{
    private const int CopyBufferSize = 1 << 20;

    private readonly (ProsperoDiscBackupPiece Piece, string Path)[] _pieces;

    private ProsperoDiscBackup(string directory, ProsperoDiscBackupManifest manifest, (ProsperoDiscBackupPiece, string)[] pieces)
    {
        Directory = directory;
        Manifest = manifest;
        _pieces = pieces;
    }

    /// <summary>The directory that contains the manifest and its piece files.</summary>
    public string Directory { get; }

    /// <summary>The parsed <c>app.json</c> manifest.</summary>
    public ProsperoDiscBackupManifest Manifest { get; }

    /// <summary>The size in bytes of the reassembled package (from the manifest).</summary>
    public long OriginalFileSize => Manifest.OriginalFileSize;

    /// <summary>
    /// Opens a disc backup from an <c>app.json</c> path or from a directory that contains one.
    /// Piece <c>url</c>s are resolved relative to the manifest directory and must all exist.
    /// </summary>
    /// <exception cref="FileNotFoundException">The manifest or a piece file is missing.</exception>
    /// <exception cref="InvalidDataException">The manifest lists no pieces.</exception>
    public static ProsperoDiscBackup Open(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        string manifestPath = System.IO.Directory.Exists(path) ? Path.Combine(path, "app.json") : path;
        if (!File.Exists(manifestPath))
            throw new FileNotFoundException("Disc-backup manifest (app.json) not found.", manifestPath);

        string directory = Path.GetDirectoryName(Path.GetFullPath(manifestPath)) ?? ".";
        ProsperoDiscBackupManifest manifest = ProsperoDiscBackupManifest.Read(manifestPath);
        if (manifest.Pieces.Count == 0)
            throw new InvalidDataException("Disc-backup manifest lists no pieces.");

        var ordered = new List<(ProsperoDiscBackupPiece, string)>(manifest.Pieces.Count);
        foreach (ProsperoDiscBackupPiece piece in manifest.Pieces)
            ordered.Add((piece, Path.Combine(directory, piece.Url)));

        ordered.Sort((a, b) => a.Item1.FileOffset.CompareTo(b.Item1.FileOffset));

        // Validate the split is complete: pieces must tile the image contiguously from offset 0 with no
        // gap or overlap, and (when the manifest declares it) sum to the original size. Otherwise the
        // reassembled stream would be silently misaligned.
        long expectedOffset = 0;
        foreach ((ProsperoDiscBackupPiece piece, string piecePath) in ordered)
        {
            if (!File.Exists(piecePath))
                throw new FileNotFoundException($"Disc-backup piece '{piece.Url}' not found.", piecePath);
            if (piece.FileOffset != expectedOffset)
                throw new InvalidDataException(
                    $"Disc-backup piece '{piece.Url}' starts at 0x{piece.FileOffset:X}, expected 0x{expectedOffset:X} (gapped or overlapping split).");
            expectedOffset += piece.FileSize;
        }
        if (manifest.OriginalFileSize > 0 && expectedOffset != manifest.OriginalFileSize)
            throw new InvalidDataException(
                $"Disc-backup pieces total {expectedOffset} bytes but the manifest declares {manifest.OriginalFileSize}.");

        return new ProsperoDiscBackup(directory, manifest, [.. ordered]);
    }

    /// <summary>The resolved absolute path of the PlayGo chunk-CRC file, or <see langword="null"/> when absent.</summary>
    public string? ChunkCrcPath
    {
        get
        {
            if (string.IsNullOrEmpty(Manifest.PlaygoChunkCrcUrl)) return null;
            string p = Path.Combine(Directory, Manifest.PlaygoChunkCrcUrl);
            return File.Exists(p) ? p : null;
        }
    }

    /// <summary>
    /// Opens the reassembled package as a single read-only, seekable stream. The pieces are read
    /// in place (no temp file); the returned stream owns the underlying piece handles.
    /// </summary>
    public ProsperoConcatStream OpenPackageStream()
    {
        var segments = new List<(Stream, long, long)>(_pieces.Length);
        var opened = new List<FileStream>(_pieces.Length);
        try
        {
            foreach ((ProsperoDiscBackupPiece piece, string piecePath) in _pieces)
            {
                var fs = new FileStream(piecePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                opened.Add(fs);
                long length = piece.FileSize > 0 ? Math.Min(piece.FileSize, fs.Length) : fs.Length;
                segments.Add((fs, 0, length));
            }
            return new ProsperoConcatStream(segments, ownsSources: true);
        }
        catch
        {
            foreach (FileStream fs in opened)
                fs.Dispose();
            throw;
        }
    }

    /// <summary>Reads and parses the reassembled finalized (FIH) container and its embedded CNT.</summary>
    public ProsperoPkg ReadPackage()
    {
        using ProsperoConcatStream stream = OpenPackageStream();
        return ProsperoPkgReader.Read(stream);
    }

    /// <summary>
    /// Projects the NpDrm content-info (title-id, drm/content type, content flags, patch kind,
    /// nested-image flag) from the reassembled finalized image. The CNT metadata is carried by the tail piece
    /// (<c>app_sc.pkg</c>), so this requires the full reassembled stream, not the head piece alone.
    /// </summary>
    public NpDrm.ProsperoNpDrmContentInfo ReadContentInfo() =>
        NpDrm.ProsperoNpDrmContentInfo.FromPackage(ReadPackage());

    /// <summary>Computes the uppercase-hex SHA-256 of the reassembled package.</summary>
    public string ComputePackageDigest(IProgress<long>? progress = null)
    {
        using ProsperoConcatStream stream = OpenPackageStream();
        return Sha256Hex(stream, progress);
    }

    /// <summary>
    /// Verifies the reassembled package against <see cref="ProsperoDiscBackupManifest.PackageDigest"/>.
    /// </summary>
    public bool VerifyPackageDigest(IProgress<long>? progress = null) =>
        !string.IsNullOrEmpty(Manifest.PackageDigest) &&
        string.Equals(ComputePackageDigest(progress), Manifest.PackageDigest, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Verifies the PlayGo chunk-CRC file against
    /// <see cref="ProsperoDiscBackupManifest.PlaygoChunkCrcHashValue"/> (SHA-256 of <c>app.crc</c>).
    /// </summary>
    public bool VerifyChunkCrcHash()
    {
        string? crcPath = ChunkCrcPath;
        if (crcPath is null || string.IsNullOrEmpty(Manifest.PlaygoChunkCrcHashValue))
            return false;

        using var fs = new FileStream(crcPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        return string.Equals(Sha256Hex(fs, null), Manifest.PlaygoChunkCrcHashValue, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Reads the parsed PlayGo chunk-CRC table.</summary>
    /// <exception cref="FileNotFoundException">The chunk-CRC file is absent.</exception>
    public ProsperoPlaygoChunkCrc ReadChunkCrc()
    {
        string crcPath = ChunkCrcPath
            ?? throw new FileNotFoundException("Disc-backup PlayGo chunk-CRC file not found.");
        return ProsperoPlaygoChunkCrc.Read(crcPath);
    }

    /// <summary>
    /// Recomputes every 64 KiB CRC-32C of the reassembled package and checks it against the
    /// chunk-CRC table. <paramref name="mismatchChunk"/> is the first bad chunk, or -1 on success.
    /// </summary>
    public bool VerifyChunkCrcs(out int mismatchChunk, IProgress<long>? progress = null)
    {
        ProsperoPlaygoChunkCrc table = ReadChunkCrc();
        using ProsperoConcatStream stream = OpenPackageStream();
        return table.VerifyPackage(stream, out mismatchChunk, progress);
    }

    /// <summary>Reassembles the pieces into <paramref name="output"/>; returns the byte count written.</summary>
    public long ReassembleTo(Stream output, IProgress<long>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(output);
        using ProsperoConcatStream stream = OpenPackageStream();
        return Copy(stream, output, progress);
    }

    /// <summary>Reassembles the pieces into a new file at <paramref name="path"/>.</summary>
    public long ReassembleTo(string path, IProgress<long>? progress = null)
    {
        using var output = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        return ReassembleTo(output, progress);
    }

    /// <summary>
    /// Finds the EEKPFS key entry (id <see cref="ProsperoEntryId.ImageKey"/>, 0x20) in the embedded
    /// CNT, or <see langword="null"/> when absent. This is the entry the console reads to derive the
    /// PFS keys; for a retail image it is encrypted.
    /// </summary>
    public static ProsperoPkgEntry? FindImageKeyEntry(ProsperoPkg package)
    {
        ArgumentNullException.ThrowIfNull(package);
        foreach (ProsperoPkgEntry entry in package.Entries)
        {
            if (entry.Id == ProsperoEntryId.ImageKey)
                return entry;
        }
        return null;
    }

    /// <summary>Extracts one CNT entry's raw bytes (as stored — encrypted entries stay encrypted).</summary>
    public byte[] ExtractEntryBytes(ProsperoPkg package, ProsperoPkgEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        using var output = new MemoryStream(checked((int)entry.DataSize));
        ExtractEntry(package, entry, output);
        return output.ToArray();
    }

    /// <summary>
    /// Copies one CNT entry's raw bytes into <paramref name="output"/>; returns the byte count.
    /// The offset is resolved relative to the embedded CNT base (FIH+0x58) for a finalized image.
    /// </summary>
    public long ExtractEntry(ProsperoPkg package, ProsperoPkgEntry entry, Stream output)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(output);

        long cntBase = package.Fih is { } fih ? (long)fih.EmbeddedCntOffset : 0;
        long start = cntBase + entry.DataOffset;

        using ProsperoConcatStream stream = OpenPackageStream();
        if (start + entry.DataSize > stream.Length)
            throw new InvalidDataException($"Entry '{entry.Name ?? entry.Id.ToString()}' extends past the package.");

        stream.Position = start;
        return CopyExact(stream, output, entry.DataSize);
    }

    private static long Copy(Stream source, Stream destination, IProgress<long>? progress)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            long total = 0;
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                destination.Write(buffer, 0, read);
                total += read;
                progress?.Report(total);
            }
            return total;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static long CopyExact(Stream source, Stream destination, long count)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            long remaining = count;
            while (remaining > 0)
            {
                int want = (int)Math.Min(buffer.Length, remaining);
                int read = source.Read(buffer, 0, want);
                if (read == 0)
                    throw new EndOfStreamException("Unexpected end of package while extracting an entry.");
                destination.Write(buffer, 0, read);
                remaining -= read;
            }
            return count;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static string Sha256Hex(Stream stream, IProgress<long>? progress)
    {
        using var sha = SHA256.Create();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            long total = 0;
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha.TransformBlock(buffer, 0, read, null, 0);
                total += read;
                progress?.Report(total);
            }
            sha.TransformFinalBlock([], 0, 0);
            return Convert.ToHexString(sha.Hash!);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
