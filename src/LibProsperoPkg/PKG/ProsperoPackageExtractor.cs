// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// End-to-end package extractor. A finalized image is a plaintext header/digest region
// followed by the shared outer PFS (AES-XTS encrypted under the package EKPFS). The outer PFS holds
// a single nested file, pfs_image.dat (a PFSC container whose logical content is the inner PFS
// image), plus optional metadata. This orchestrates the whole path:
//
//   finalized image --(FIH header: pfs offset/size)--> outer PFS
//   outer PFS --(EKPFS via ProsperoPfsReader)--> decrypt + walk --> pfs_image.dat
//   pfs_image.dat --(PFSC decode)--> inner PFS image
//   inner PFS image --(ProsperoPfsReader)--> the application files
//
// reusing the proven ProsperoPfsReader / ProsperoPfscReader primitives end to end. The outer EKPFS
// is either derived from the content id + passcode (public-input schedule) or supplied by the
// caller; nothing about the key material is forged here.
#nullable enable
using LibProsperoPkg.PFS;
using LibProsperoPkg.Util;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LibProsperoPkg.PKG;

/// <summary>Options controlling a package extraction.</summary>
public sealed class ProsperoExtractionOptions
{
    /// <summary>
    /// When true, also writes the outer PFS's non-<c>pfs_image.dat</c> files (metadata that lives
    /// beside the nested image) into <see cref="OuterMetadataSubdirectory"/>. Off by default.
    /// </summary>
    public bool ExtractOuterMetadata { get; set; }

    /// <summary>Subdirectory (under the output directory) for outer metadata files.</summary>
    public string OuterMetadataSubdirectory { get; set; } = "_outer";
}

/// <summary>What <see cref="ProsperoPackageExtractor.Inspect"/> reports about a package.</summary>
public sealed class ProsperoPackageExtractionInfo
{
    /// <summary>Detected package type.</summary>
    public required ProsperoPkgType PackageType { get; init; }

    /// <summary>True when the finalized image is signed for a retail console (signed byte 0x80).</summary>
    public required bool IsRetail { get; init; }

    /// <summary>The embedded content id, when the package carries a readable one.</summary>
    public required string? ContentId { get; init; }

    /// <summary>File offset of the shared outer PFS image.</summary>
    public required long PfsImageOffset { get; init; }

    /// <summary>Byte length of the shared outer PFS image.</summary>
    public required long PfsImageSize { get; init; }

    /// <summary>True when the outer PFS superblock marks the filesystem AES-XTS encrypted.</summary>
    public required bool OuterEncrypted { get; init; }

    /// <summary>
    /// True when extraction needs key material that cannot be derived from public inputs (a
    /// finalized retail image whose key comes from the console entitlement path).
    /// </summary>
    public required bool RequiresSuppliedKey { get; init; }
}

/// <summary>The outcome of an extraction.</summary>
public sealed class ProsperoPackageManifest
{
    /// <summary>Detected package type.</summary>
    public required ProsperoPkgType PackageType { get; init; }

    /// <summary>True when the finalized image is signed for a retail console (signed byte 0x80).</summary>
    public required bool IsRetail { get; init; }

    /// <summary>The content id used/resolved, when known.</summary>
    public required string? ContentId { get; init; }

    /// <summary>First 4 bytes (hex) of the EKPFS that decrypted the outer PFS, or <see langword="null"/> when plaintext.</summary>
    public required string? EkpfsFingerprint { get; init; }

    /// <summary>The output directory the files were written to.</summary>
    public required string OutputDirectory { get; init; }

    /// <summary>Number of files in the outer PFS.</summary>
    public required int OuterFileCount { get; init; }

    /// <summary>True when the nested <c>pfs_image.dat</c> was stored PFSC-compressed.</summary>
    public required bool InnerImageCompressed { get; init; }

    /// <summary>The files written from the inner (application) filesystem.</summary>
    public required IReadOnlyList<ProsperoExtractedEntry> Entries { get; init; }

    /// <summary>Total number of files written (inner plus any outer metadata).</summary>
    public required int ExtractedFileCount { get; init; }
}

/// <summary>
/// Extracts the application filesystem from a finalized PS5 package. See the file header for the
/// pipeline. Debug/keyed packages whose EKPFS is derivable or supplied extract fully; a finalized
/// retail image without a supplied key throws a clear <see cref="ProsperoExtractionException"/>.
/// </summary>
public static class ProsperoPackageExtractor
{
    private const int SuperblockPeekSize = 0x400;

    /// <summary>
    /// Reads a package's finalized-image header and outer PFS superblock and reports what
    /// extraction would require, without needing (or using) any key.
    /// </summary>
    /// <param name="packagePath">Path to the finalized package.</param>
    public static ProsperoPackageExtractionInfo Inspect(string packagePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);
        if (!File.Exists(packagePath))
            throw new FileNotFoundException("Package not found.", packagePath);

        var type = ProsperoPkgReader.DetectType(packagePath)
            ?? throw new ProsperoExtractionException("Not a recognisable PS5 package (unknown magic).");
        if (type == ProsperoPkgType.Meta)
            throw new ProsperoExtractionException(
                "This is a metadata-only container; a finalized image is required to extract its filesystem.");

        using var stream = new FileStream(packagePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        long fileLength = stream.Length;
        var (signedByte, pfsOffset, pfsSize) = ReadFihFields(stream, fileLength);

        var state = PeekOuterState(new LibProsperoPkg.Util.StreamReader(stream, pfsOffset));
        string? contentId = TryReadContentId(packagePath);
        bool isRetail = signedByte == 0x80;
        bool encrypted = state != OuterPfsState.Plaintext;

        return new ProsperoPackageExtractionInfo
        {
            PackageType = type,
            IsRetail = isRetail,
            ContentId = contentId,
            PfsImageOffset = pfsOffset,
            PfsImageSize = pfsSize,
            OuterEncrypted = encrypted,
            // A retail image with an encrypted outer PFS and no embedded/derivable key needs a
            // supplied image key; a debug image's key is derivable from its passcode.
            RequiresSuppliedKey = encrypted && isRetail,
        };
    }

    /// <summary>
    /// Extracts a package to <paramref name="outputDirectory"/>, deriving the outer EKPFS from
    /// <paramref name="passcode"/> (and the package's own content id).
    /// </summary>
    public static ProsperoPackageManifest Extract(
        string packagePath, string outputDirectory, string passcode, Action<string>? logger = null)
        => Extract(packagePath, outputDirectory, ProsperoExtractionKey.FromPasscode(passcode), null, logger);

    /// <summary>
    /// Extracts a package to <paramref name="outputDirectory"/> using the supplied key material.
    /// </summary>
    /// <param name="packagePath">Path to the finalized package.</param>
    /// <param name="outputDirectory">Destination directory (created if missing).</param>
    /// <param name="key">How to obtain the outer EKPFS.</param>
    /// <param name="options">Extraction options (optional).</param>
    /// <param name="logger">Optional progress sink.</param>
    public static ProsperoPackageManifest Extract(
        string packagePath, string outputDirectory, ProsperoExtractionKey key,
        ProsperoExtractionOptions? options = null, Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        ArgumentNullException.ThrowIfNull(key);
        options ??= new ProsperoExtractionOptions();
        var log = logger ?? (_ => { });

        if (!File.Exists(packagePath))
            throw new FileNotFoundException("Package not found.", packagePath);

        var type = ProsperoPkgReader.DetectType(packagePath)
            ?? throw new ProsperoExtractionException("Not a recognisable PS5 package (unknown magic).");
        if (type == ProsperoPkgType.Meta)
            throw new ProsperoExtractionException(
                "This is a metadata-only container; a finalized image is required to extract its filesystem.");

        bool isRetail = false;
        string? contentId = TryReadContentId(packagePath);
        Directory.CreateDirectory(outputDirectory);

        using var pkgStream = new FileStream(packagePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        long fileLength = pkgStream.Length;
        var (signedByte, pfsOffset, pfsSize) = ReadFihFields(pkgStream, fileLength);
        isRetail = signedByte == 0x80;

        var outerState = PeekOuterState(new LibProsperoPkg.Util.StreamReader(pkgStream, pfsOffset));
        var candidates = key.ResolveEkpfsCandidates(contentId);

        byte[]? usedEkpfs = null;
        ProsperoPfsReader outer;
        if (outerState == OuterPfsState.Plaintext)
        {
            log("Opening outer PFS (plaintext)...");
            outer = new ProsperoPfsReader(new LibProsperoPkg.Util.StreamReader(pkgStream, pfsOffset), 0);
        }
        else if (candidates.Count == 0)
        {
            throw new ProsperoExtractionException(isRetail
                ? "The outer filesystem is encrypted and this is a finalized retail image: its image key " +
                  "is delivered through the console entitlement path and cannot be derived from a passcode. " +
                  "Supply the image key with ProsperoExtractionKey.FromEkpfs(...) to extract."
                : "The outer filesystem is encrypted. Supply a passcode with " +
                  "ProsperoExtractionKey.FromPasscode(...) or an image key with FromEkpfs(...).");
        }
        else
        {
            log($"Opening outer PFS (encrypted; trying {candidates.Count} key candidate(s))...");
            outer = OpenOuterWithCandidates(pkgStream, pfsOffset, candidates, out usedEkpfs)
                ?? throw new ProsperoExtractionException(isRetail
                    ? "None of the supplied keys decrypted the outer filesystem. A finalized retail image " +
                      "requires the console-provisioned image key (ProsperoExtractionKey.FromEkpfs)."
                    : "None of the derived/supplied keys decrypted the outer filesystem. Confirm the content " +
                      "id and passcode, or supply the image key directly.");
        }

        int outerFileCount = outer.GetAllFiles().Count();
        var innerOuterFile = outer.GetFile("pfs_image.dat") ?? FindByName(outer, "pfs_image.dat");

        List<ProsperoExtractedEntry> entries;
        bool innerCompressed = false;
        int extractedCount;

        if (innerOuterFile is null)
        {
            // No nested image: the outer filesystem is the content. Extract it directly.
            log("No nested pfs_image.dat; extracting the outer filesystem directly...");
            entries = new List<ProsperoExtractedEntry>(ProsperoPfsExtractor.Extract(outer, outputDirectory, log));
            extractedCount = entries.Count;
        }
        else
        {
            innerCompressed = innerOuterFile.flags.HasFlag(ProsperoInodeFlags.compressed);
            log($"Opening nested pfs_image.dat ({(innerCompressed ? "PFSC container" : "raw")})...");

            IMemoryReader onDisk = innerOuterFile.GetView();
            IMemoryReader innerImage = innerCompressed ? new ProsperoPfscReader(onDisk) : onDisk;

            ProsperoPfsReader inner;
            try
            {
                // The inner image carries its own superblock; the reader auto-detects whether it is
                // encrypted and uses the EKPFS only if the inner superblock says so.
                inner = new ProsperoPfsReader(innerImage, 0, usedEkpfs);
            }
            catch (Exception ex)
            {
                throw new ProsperoExtractionException(
                    "Failed to open the nested filesystem image (pfs_image.dat).", ex);
            }

            log("Extracting the application filesystem...");
            entries = new List<ProsperoExtractedEntry>(ProsperoPfsExtractor.Extract(inner, outputDirectory, log));
            extractedCount = entries.Count;

            if (options.ExtractOuterMetadata)
                extractedCount += ExtractOuterMetadata(outer, outputDirectory, options.OuterMetadataSubdirectory, log);
        }

        string? fingerprint = usedEkpfs is null ? null : Convert.ToHexString(usedEkpfs.AsSpan(0, 4));
        log($"Done: extracted {extractedCount} file(s) to {outputDirectory}.");

        return new ProsperoPackageManifest
        {
            PackageType = type,
            IsRetail = isRetail,
            ContentId = contentId,
            EkpfsFingerprint = fingerprint,
            OutputDirectory = Path.GetFullPath(outputDirectory),
            OuterFileCount = outerFileCount,
            InnerImageCompressed = innerCompressed,
            Entries = entries,
            ExtractedFileCount = extractedCount,
        };
    }

    /// <summary>
    /// Lists the application files a package would extract, without writing them.
    /// </summary>
    public static IReadOnlyList<ProsperoExtractedEntry> ListFiles(
        string packagePath, ProsperoExtractionKey key, Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);
        ArgumentNullException.ThrowIfNull(key);
        var log = logger ?? (_ => { });

        var type = ProsperoPkgReader.DetectType(packagePath)
            ?? throw new ProsperoExtractionException("Not a recognisable PS5 package (unknown magic).");
        if (type == ProsperoPkgType.Meta)
            throw new ProsperoExtractionException(
                "This is a metadata-only container; a finalized image is required to list its filesystem.");

        string? contentId = TryReadContentId(packagePath);

        using var pkgStream = new FileStream(packagePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        long fileLength = pkgStream.Length;
        var (signedByte, pfsOffset, _) = ReadFihFields(pkgStream, fileLength);
        bool isRetail = signedByte == 0x80;

        var outerState = PeekOuterState(new LibProsperoPkg.Util.StreamReader(pkgStream, pfsOffset));
        var candidates = key.ResolveEkpfsCandidates(contentId);

        byte[]? usedEkpfs = null;
        ProsperoPfsReader outer = outerState == OuterPfsState.Plaintext
            ? new ProsperoPfsReader(new LibProsperoPkg.Util.StreamReader(pkgStream, pfsOffset), 0)
            : candidates.Count == 0
                ? throw new ProsperoExtractionException(isRetail
                    ? "The outer filesystem is encrypted (finalized retail image); supply the image key with FromEkpfs(...)."
                    : "The outer filesystem is encrypted; supply a passcode or image key.")
                : OpenOuterWithCandidates(pkgStream, pfsOffset, candidates, out usedEkpfs)
                    ?? throw new ProsperoExtractionException("None of the derived/supplied keys decrypted the outer filesystem.");

        var innerOuterFile = outer.GetFile("pfs_image.dat") ?? FindByName(outer, "pfs_image.dat");
        if (innerOuterFile is null)
            return ProsperoPfsExtractor.ListEntries(outer);

        IMemoryReader onDisk = innerOuterFile.GetView();
        IMemoryReader innerImage = innerOuterFile.flags.HasFlag(ProsperoInodeFlags.compressed)
            ? new ProsperoPfscReader(onDisk)
            : onDisk;
        var inner = new ProsperoPfsReader(innerImage, 0, usedEkpfs);
        return ProsperoPfsExtractor.ListEntries(inner);
    }

    private static ProsperoPfsReader? OpenOuterWithCandidates(
        Stream pkgStream, long pfsOffset, IReadOnlyList<byte[]> candidates, out byte[]? used)
    {
        foreach (var candidate in candidates)
        {
            try
            {
                var reader = new ProsperoPfsReader(new LibProsperoPkg.Util.StreamReader(pkgStream, pfsOffset), 0, candidate);
                used = candidate;
                return reader;
            }
            catch
            {
                // Wrong key: the decrypted superblock/dinodes fail to parse. Try the next candidate.
            }
        }

        used = null;
        return null;
    }

    private static int ExtractOuterMetadata(
        ProsperoPfsReader outer, string outputDirectory, string subdirectory, Action<string> log)
    {
        string outDir = Path.Combine(outputDirectory, subdirectory);
        int count = 0;
        foreach (var file in outer.GetAllFiles())
        {
            if (string.Equals(file.name, "pfs_image.dat", StringComparison.OrdinalIgnoreCase))
                continue;

            string rel = file.name;
            string dest = Path.GetFullPath(Path.Combine(outDir, rel));
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            file.Save(dest, decompress: true);
            count++;
            log($"  [outer] {rel}");
        }

        return count;
    }

    private static ProsperoPfsReader.File? FindByName(ProsperoPfsReader reader, string name)
        => reader.GetAllFiles().FirstOrDefault(f => string.Equals(f.name, name, StringComparison.OrdinalIgnoreCase));

    // Reads the finalized-image header fields the extractor needs (signed byte, PFS offset/size),
    // validating the magic and applying safe fallbacks for absent offset/size fields.
    private static (byte SignedByte, long PfsOffset, long PfsSize) ReadFihFields(Stream stream, long fileLength)
    {
        byte[] header = new byte[0x100];
        stream.Position = 0;
        ReadExactly(stream, header, header.Length);
        var span = header.AsSpan();

        if (!span[..4].SequenceEqual(ProsperoPkgLayout.FihMagic))
            throw new ProsperoExtractionException("Not a finalized image (missing FIH magic).");

        byte signedByte = header[ProsperoPkgLayout.FihSignedByteOffset];
        long pfsOffset = (long)BinaryPrimitives.ReadUInt64LittleEndian(span[ProsperoPkgLayout.FihPfsImageOffsetField..]);
        long pfsSize = (long)BinaryPrimitives.ReadUInt64LittleEndian(span[ProsperoPkgLayout.FihPfsImageSizeField..]);

        if (pfsOffset <= 0 || pfsOffset >= fileLength)
            pfsOffset = ProsperoPkgLayout.FihHeaderRegionSize; // 0x10000
        if (pfsSize <= 0 || pfsOffset + pfsSize > fileLength)
            pfsSize = fileLength - pfsOffset;

        return (signedByte, pfsOffset, pfsSize);
    }

    // Reads the outer PFS superblock (plaintext for debug/keyed images) and classifies it. A
    // finalized retail image encrypts the whole outer PFS including block 0, so its superblock does
    // not parse without the console image key; that case is reported as Unreadable (i.e. gated).
    private static OuterPfsState PeekOuterState(IMemoryReader reader)
    {
        byte[] buffer = new byte[SuperblockPeekSize];
        reader.Read(0, buffer, 0, buffer.Length);
        using var ms = new MemoryStream(buffer);
        try
        {
            var hdr = ProsperoPfsHeader.ReadFromStream(ms);
            return hdr.Mode.HasFlag(ProsperoPfsMode.Encrypted) ? OuterPfsState.Encrypted : OuterPfsState.Plaintext;
        }
        catch (Exception)
        {
            // The superblock is not a readable plaintext PFS header: the outer filesystem is
            // encrypted at block 0 (a finalized retail image) or is not a PFS. Either way it needs a
            // supplied key to proceed.
            return OuterPfsState.Unreadable;
        }
    }

    private enum OuterPfsState
    {
        Plaintext,
        Encrypted,
        Unreadable,
    }

    private static string? TryReadContentId(string packagePath)
    {
        try
        {
            return ProsperoPkgReader.Read(packagePath).Header?.ContentId;
        }
        catch
        {
            return null;
        }
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int count)
    {
        int read = 0;
        while (read < count)
        {
            int n = stream.Read(buffer, read, count - read);
            if (n == 0)
                throw new ProsperoExtractionException("Unexpected end of file while reading the finalized-image header.");
            read += n;
        }
    }
}
