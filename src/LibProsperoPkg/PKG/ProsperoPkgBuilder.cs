// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// End-to-end PS5 PKG/CNT writer: turns a prepared folder into a complete
// \x7FCNT package fully in-process. It assembles the outer container header, the system-container
// entries, the param.json + media entries and the inner+outer PFS image, then computes
// every digest and the header signature.
//
// Boundary: on-console acceptance is gated by the target console's configuration and is not
// validated here. The in-process validation covers the full
// structural correctness of the produced package: it round-trips through ProsperoPkgReader, its
// outer PFS decrypts back to the inner image, and every internal digest is self-consistent.

#nullable enable
using LibProsperoPkg.Content;
using LibProsperoPkg.PFS;
using LibProsperoPkg.PFS.Compression;
using LibProsperoPkg.Util;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace LibProsperoPkg.PKG;

/// <summary>
/// Reproducible inputs captured during a CNT build for producing the trailing debug SI segment
/// (<c>sce_suppl</c> ZIP). The package builder surfaces these out of
/// <see cref="ProsperoPkgBuilder.Build(ProsperoPkgBuildProperties,string,out byte[],out ProsperoSiBuildInputs,Action{string})"/>
/// so the finalizer (<see cref="ProsperoFihBuilder.BuildFromCnt"/>) can assemble the segment from the
/// finalized mount image via <see cref="ProsperoSiArchive.BuildDebugSiSegment"/>.
/// </summary>
internal sealed class ProsperoSiBuildInputs
{
    /// <summary>Fully-populated reproducible pfsimage.xml options (real self-consistent digests).</summary>
    public required ProsperoPfsImageXmlOptions Xml { get; init; }

    /// <summary>PlayGo chunk descriptor bytes (CNT entry 0x1001), copied verbatim into the SI, or null.</summary>
    public byte[]? PlayGoChunkDat { get; init; }

    /// <summary>
    /// Block-aligned stored size of the inner <c>pfs_image.dat</c> (<c>alignUp(storedSize, 0x10000)</c>) — the
    /// value the FIH records at <see cref="ProsperoPkgLayout.FihInnerImageSizeField"/> (0xA0) in the reference
    /// data-first layout. The SI's <c>naps_meta_300/301/302/308.dat</c> records derive from it as
    /// <c>R = InnerImageSize - 0x10000</c> via <see cref="ProsperoNapsMeta.BuildMeta300FromInnerImageSize"/>.
    /// It is captured here at build time because our superblock-first outer PFS leaves FIH[0xA0] at 0
    /// (that field is only populated for the data-first layout), so it cannot be read back from the mount image.
    /// </summary>
    public long InnerImageSize { get; init; }
}

/// <summary>The PS5 volume kind, which selects the content-type code stamped into the header.</summary>
public enum ProsperoVolumeType
{
    /// <summary>A PS5 application / game (gd, content_type 0x20).</summary>
    Application,

    /// <summary>Additional content that ships data (ac, content_type 0x21).</summary>
    AdditionalContentData,

    /// <summary>Additional content, entitlement only / no data (al, content_type 0x22).</summary>
    AdditionalContentNoData,
}

/// <summary>
/// Selects how the inner <c>pfs_image.dat</c> is stored inside the encrypted outer PFS.
/// </summary>
public enum ProsperoInnerCompression
{
    /// <summary>Stored raw inside a PFSC wrapper (the default).</summary>
    None,

    /// <summary>
    /// zlib PFSC dinode compression (<see cref="LibProsperoPkg.PFS.ProsperoPfsc"/>). This is the
    /// codec the <em>installable</em> debug package uses for its inner image.
    /// </summary>
    Zlib,

    /// <summary>
    /// PS5 PFSv3 Kraken compression (<see cref="LibProsperoPkg.PFS.Compression.ProsperoCompressedPfsImage"/>).
    /// This codec stores <c>pfs_image.dat</c> as a self-describing Kraken "PFSC" container
    /// inside a regular outer-PFS file. The container round-trips byte-exact through the decoder;
    /// on-console package acceptance depends on console mode and firmware.
    /// </summary>
    Kraken,
}

/// <summary>Everything required to build a PS5 CNT package.</summary>
public sealed class ProsperoPkgBuildProperties
{
    /// <summary>The prepared source folder (must contain <c>sce_sys/param.json</c>).</summary>
    public required string SourceFolder { get; init; }

    /// <summary>The 36-character content id.</summary>
    public required string ContentId { get; init; }

    /// <summary>The 32-character passcode (the EKPFS is derived from it; all-zero is the default).</summary>
    public string Passcode { get; init; } = new string('0', 32);

    /// <summary>The PS5 volume kind.</summary>
    public ProsperoVolumeType VolumeType { get; init; } = ProsperoVolumeType.Application;

    /// <summary>The volume timestamp written into the PFS inode table.</summary>
    public DateTime TimeStamp { get; init; } = DateTime.UnixEpoch;

    /// <summary>
    /// When true the inner <c>pfs_image.dat</c> is stored PFSC-compressed (the
    /// <see cref="LibProsperoPkg.PFS.ProsperoPfsc"/> / <c>LibProsperoPkg.PFS.PfscEncoder</c> path),
    /// shrinking the package (the dominant size driver). When false (the default) the
    /// inner image is stored raw inside a PFSC wrapper. Incompressible inner images fall back to the raw wrapper
    /// automatically. The compressed form is round-trip-validated in-process before use;
    /// on-console acceptance depends on console mode and firmware either way.
    /// </summary>
    /// <remarks>
    /// This is a convenience flag equivalent to <see cref="InnerCompression"/> =
    /// <see cref="ProsperoInnerCompression.Zlib"/>. When <see cref="InnerCompression"/> is set to a
    /// non-<see cref="ProsperoInnerCompression.None"/> value it takes precedence over this flag.
    /// </remarks>
    public bool CompressInnerImage { get; init; }

    /// <summary>
    /// Selects the inner-image codec. <see cref="ProsperoInnerCompression.None"/> (default) stores the
    /// inner image raw; <see cref="ProsperoInnerCompression.Zlib"/> uses the installable zlib
    /// PFSC path; <see cref="ProsperoInnerCompression.Kraken"/> produces the
    /// PS5 PFSv3 Kraken container. When left at
    /// <see cref="ProsperoInnerCompression.None"/>, the legacy <see cref="CompressInnerImage"/> flag is
    /// honoured (true ⇒ zlib) for backward compatibility.
    /// </summary>
    public ProsperoInnerCompression InnerCompression { get; init; } = ProsperoInnerCompression.None;
}

/// <summary>
/// Prepared folder to complete PS5 CNT package builder. See the file header for the
/// architecture and validation boundary.
/// </summary>
public static class ProsperoPkgBuilder
{
    // PS5 header constants confirmed against reference packages.
    private const uint DrmTypePs5 = 0x10;          // CNT header @0x70.
    private const uint ContentTypeGd = 0x20;       // CNT header @0x74 (game data).
    private const uint ContentTypeAc = 0x21;       // additional content, with data.
    private const uint ContentTypeAl = 0x22;       // additional content, no data.
    private const uint Unk0CPs5 = 0xC;             // CNT header @0x0C.
    private const uint FlagsPs5 = 0x02000001;      // VER_2 | Unknown (not finalized; the FIH finalize bit is set on-console).
    private const ulong PfsFlags = 0x80000000000003CC; // The encrypted+signed PFS flag word for a PfsBuilder image.

    private const ulong BodyOffset = 0x2000;
    private const ulong PfsImageOffset = 0x80000;  // Canonical PFS image offset.
    private const int BlockSize = 0x10000;

    // imagedigs.dat is the unnamed CNT entry id 0x040A (one after PSRESERVED_DAT 0x409). It is a CNT
    // body entry — NOT an inner-PFS file — so it does not digest its own storage: there is no fixpoint
    // and no multi-pass build. Its size (= outer block count x 32) is known up front from the image.
    private const uint ImagedigsEntryId = 0x040A;

    // playgo-chunk.dat is CNT entry id 0x1001. Its bytes are copied verbatim into the trailing debug SI
    // segment (common/etc/playgo-chunk.dat), so the SI capture reads them straight off the built entry.
    private const uint PlayGoChunkDatEntryId = 0x1001;

    /// <summary>The content-type code for a PS5 volume kind.</summary>
    public static uint ContentTypeFor(ProsperoVolumeType type) => type switch
    {
        ProsperoVolumeType.AdditionalContentData => ContentTypeAc,
        ProsperoVolumeType.AdditionalContentNoData => ContentTypeAl,
        _ => ContentTypeGd,
    };

    /// <summary>True for additional-content (DLC) volume kinds.</summary>
    public static bool IsAdditionalContent(ProsperoVolumeType type) =>
        type is ProsperoVolumeType.AdditionalContentData or ProsperoVolumeType.AdditionalContentNoData;

    private static ProsperoCntContentFlags ContentFlagsFor(ProsperoVolumeType type) => type switch
    {
        ProsperoVolumeType.AdditionalContentNoData => 0,
        _ => ProsperoCntContentFlags.Unk_x8000000 | ProsperoCntContentFlags.GD_AC,
    };

    /// <summary>
    /// Builds the PS5 CNT package described by <paramref name="props"/> and writes it to
    /// <paramref name="outputPath"/>.
    /// </summary>
    /// <returns>The output path.</returns>
    /// <exception cref="ArgumentException">A required property is missing or malformed.</exception>
    public static string Build(ProsperoPkgBuildProperties props, string outputPath, Action<string>? logger = null)
        => Build(props, outputPath, out _, out _, logger);

    /// <summary>
    /// CNT-build overload that also surfaces the FIH 0xB0 nested-image-content digest — SHA3-256 of the
    /// UNCOMPRESSED inner PFS image. The plaintext
    /// inner image exists only during this build pass, so the digest is threaded out here for the caller
    /// that finalizes the CNT into a debug (FIH) image (<see cref="ProsperoFihBuilder.BuildFromCnt"/>),
    /// which would otherwise only have the encrypted CNT and fall back to a best-effort outer-image hash.
    /// Also surfaces the reproducible <see cref="ProsperoSiBuildInputs"/> so the finalizer can assemble the
    /// trailing debug SI segment (<c>sce_suppl</c>) from the finalized mount image.
    /// </summary>
    internal static string Build(ProsperoPkgBuildProperties props, string outputPath, out byte[]? nestedImageDigest, out ProsperoSiBuildInputs? siInputs, Action<string>? logger = null)
    {
        nestedImageDigest = null;
        siInputs = null;
        ArgumentNullException.ThrowIfNull(props);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        var log = logger ?? (_ => { });

        if (string.IsNullOrWhiteSpace(props.SourceFolder) || !Directory.Exists(props.SourceFolder))
            throw new ArgumentException("Source folder does not exist.", nameof(props));
        if (props.ContentId is not { Length: 36 })
            throw new ArgumentException("Content id must be exactly 36 characters.", nameof(props));
        if (props.Passcode is not { Length: 32 })
            throw new ArgumentException("Passcode must be exactly 32 characters.", nameof(props));

        string sourceFolder = Path.GetFullPath(props.SourceFolder);

        // EKPFS (index 1) from content id + passcode.
        byte[] ekpfs = Crypto.ComputeKeys(props.ContentId, props.Passcode, 1);

        var directory = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

        // --- Inner + outer PFS (version 2 = PS5), built by the PFS builder. ---
        // imagedigs.dat is an OUTER CNT entry (id 0x040A) that holds one per-block descriptor
        // digest for every block of the OUTER image. Because it lives in the CNT body — NOT inside the
        // outer PFS image it describes — there is no self-reference and no fixpoint: the digest count
        // (= outer block count) is known up front from the image size, so the entry is laid out as a
        // correctly-sized placeholder and filled with the signer's captured per-block digests after the
        // image is written, before the container bodies/digests are finalized.
        long fileTime = ToUnixSeconds(props.TimeStamp);
        byte[]? capturedNestedDigest = null;
        ProsperoSiBuildInputs? capturedSi = null;
        BuildImageOnce();
        nestedImageDigest = capturedNestedDigest;
        siInputs = capturedSi;

        log($"Done: {Path.GetFileName(outputPath)} ({new FileInfo(outputPath).Length:N0} bytes).");
        return outputPath;

        // Builds (and writes to outputPath) one complete package.
        void BuildImageOnce()
        {
            log("Preparing PS5 inner PFS (superblock version 2)...");
            var innerRoot = BuildInnerTree(sourceFolder, props.Passcode);
            // PlayGo file/inode count of the inner image: drives playgo-ficm.dat (count) and
            // playgo-hash-table.dat (count / 2), matching reference samples. The total
            // inner content size drives the playgo-chunk.dat size words (self-consistent layout).
            var innerFiles = innerRoot.GetAllChildrenFiles();
            uint playgoFileCount = (uint)Math.Min(innerFiles.Count, 0x100000);
            ulong chunkDataSize = (ulong)Math.Max(0L, innerFiles.Sum(f => f.Size));
            var innerProps = new ProsperoPfsProperties
            {
                root = innerRoot,
                BlockSize = BlockSize,
                // PS5 packages size the inner PFS to their content; no artificial block floor is used.
                // Reference PS5 system/app packages are well under 1MiB (e.g. NPXS41139 has a
                // 0xB0000 / 704KiB shared PFS image).
                MinBlocks = 0,
                Version = ProsperoPfsHeader.VersionPs5,
                Encrypt = false,
                Sign = false,
                FileTime = fileTime,
            };
            var innerPfs = new ProsperoPfsBuilder(innerProps, s => log($" [inner] {s}"));

            // FIH 0xB0 nested-image-content digest:
            // the finalized-image 0xB0 slot is SHA3-256(map[0xD]) where map[0xD] is the UNCOMPRESSED inner
            // (nested) PFS image at its plain/logical size (*(ctx+0x14e0) bytes) — NOT the outer image and NOT
            // the stored/compressed pfs_image.dat. Render the inner image once into a zero-filled buffer (so
            // sparse blocks match the in-memory logical image) and take its SHA3-256.
            // Rendering is idempotent on disk (every node writes to its fixed inode StartBlock), so the inner
            // file path below re-renders the identical bytes. An inner image too large to buffer (>2 GiB, never
            // a typical nwonly system package) is left null so the FIH header falls back to its best-effort hash.
            byte[]? innerImageDigest = null;
            {
                long innerImageSize = innerPfs.CalculatePfsSize();
                if (innerImageSize > 0 && innerImageSize <= Array.MaxLength)
                {
                    using var innerImageBuf = new MemoryStream(checked((int)innerImageSize));
                    innerImageBuf.SetLength(innerImageSize);
                    innerPfs.WriteImage(innerImageBuf);
                    innerImageDigest = innerImageBuf.TryGetBuffer(out var seg)
                        ? ProsperoImageDigests.Sha3_256(seg.AsSpan(0, (int)innerImageSize))
                        : ProsperoImageDigests.Sha3_256(innerImageBuf.ToArray());
                }
            }
            capturedNestedDigest = innerImageDigest;

            log("Preparing PS5 outer PFS (encrypted + signed)...");
            var outerRoot = new ProsperoFsDir();
            // The inner image is either stored raw inside a PFSC wrapper (the default)
            // or genuinely PFSC-compressed (the compact form,
            // the dominant size driver). Genuine compression renders the inner image to a temp file and
            // PFSC-encodes it; the temp files live until the outer image has been written.
            string? tmpRawInner = null, tmpPfscInner = null;
            try
            {
                var innerFile = ResolveInnerCompression(props) switch
                {
                    ProsperoInnerCompression.Zlib => BuildCompressedInnerFile(innerPfs, log, out tmpRawInner, out tmpPfscInner),
                    ProsperoInnerCompression.Kraken => BuildKrakenInnerFile(innerPfs, log, out tmpRawInner, out tmpPfscInner),
                    _ => new ProsperoFsFile(innerPfs),
                };
                innerFile.Parent = outerRoot;
                outerRoot.Files.Add(innerFile);

                // The block-aligned stored size of pfs_image.dat is what the FIH records at 0xA0 in the
                // reference data-first layout and is the sole input to the SI's naps_meta_300 record
                // (R = alignUp(storedSize) - 0x10000). Our outer PFS is superblock-first, so FIH[0xA0] is
                // left 0; capture the value here where the stored inner-file size is known.
                long innerImageAlignedSize =
                    (innerFile.Size + BlockSize - 1) / BlockSize * BlockSize;
                var outerProps = new ProsperoPfsProperties
                {
                    root = outerRoot,
                    BlockSize = BlockSize,
                    Version = ProsperoPfsHeader.VersionPs5,
                    Encrypt = true,
                    Sign = true,
                    EKPFS = ekpfs,
                    Seed = new byte[16],
                    FileTime = fileTime,
                };
                var outerPfs = new ProsperoPfsBuilder(outerProps, s => log($" [outer] {s}")) { CaptureImageDigests = true, CaptureSuperblockIcv = true };
                long pfsSize = outerPfs.CalculatePfsSize();
                // imagedigs.dat (CNT entry 0x040A) = one 32-byte per-block descriptor digest
                // per outer-image block. The outer image size is independent of the CNT body, so this
                // count is known before the container is laid out.
                int imagedigsSize = checked((int)(pfsSize / BlockSize) * 32);

                // --- Outer container (header + entries). ---
                var pkg = BuildContainer(props, ekpfs, sourceFolder, (ulong)pfsSize, imagedigsSize, playgoFileCount, chunkDataSize);
                var imagedigsEntry = (ProsperoCntGenericEntry)pkg.Entries.First(e => (uint)e.Id == ImagedigsEntryId);

                long totalSize = (long)(pkg.Header.body_offset + pkg.Header.body_size + pkg.Header.pfs_image_size);
                using (var fs = new FileStream(outputPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
                {
                    fs.SetLength(totalSize);
                    log($"Writing outer PFS image at 0x{pkg.Header.pfs_image_offset:X} ({pfsSize:N0} bytes)...");
                    fs.Position = (long)pkg.Header.pfs_image_offset;
                    outerPfs.WriteImage(new OffsetStream(fs, (long)pkg.Header.pfs_image_offset));

                    // Fill the imagedigs placeholder with the signer's captured per-block digests (same
                    // length as the placeholder, so the container layout is unchanged) before the bodies
                    // and digest tables are written.
                    byte[]? captured = outerPfs.ImageDigests;
                    if (captured is { Length: > 0 } && captured.Length == imagedigsEntry.FileData.Length)
                        imagedigsEntry.FileData = captured;
                    ProsperoPfsImageXmlOptions siXml = FinishContainer(pkg, fs, props, innerImageDigest, log);

                    // Capture the reproducible SI inputs so the finalizer can build the sce_suppl segment:
                    // the pfsimage.xml options (with the now-computed self-consistent digests) plus a verbatim
                    // copy of the PlayGo chunk descriptor (CNT entry 0x1001).
                    byte[]? playGoChunkDat = (pkg.Entries.FirstOrDefault(e => (uint)e.Id == PlayGoChunkDatEntryId) as ProsperoCntGenericEntry)?.FileData;

                    // Inode-tree introspection (self-consistent): snapshot the outer + inner PFS
                    // inode trees and the PlayGo chunk map so pfsimage.xml describes the exact image
                    // that was produced.
                    long mountImageTotal = siXml.PfsImageOffset + siXml.PfsImageSize;
                    siXml.OuterPfsTree = outerPfs.CaptureImageTree();
                    siXml.NestedPfsTree = innerPfs.CaptureImageTree();
                    siXml.ChunkInfo = new ProsperoChunkInfoModel
                    {
                        PlayGoChunkDatSize = playGoChunkDat?.Length ?? 0,
                        TotalSize = mountImageTotal,
                        Outer0Size = innerImageAlignedSize,
                        Outer1Size = mountImageTotal - innerImageAlignedSize,
                    };
                    capturedSi = new ProsperoSiBuildInputs { Xml = siXml, PlayGoChunkDat = playGoChunkDat, InnerImageSize = innerImageAlignedSize };
                }
            }
            finally
            {
                TryDeleteTemp(tmpRawInner);
                TryDeleteTemp(tmpPfscInner);
            }
        }
    }

    // Resolves the effective inner-image codec, honouring the legacy CompressInnerImage flag when the
    // explicit InnerCompression property is left at its default.
    private static ProsperoInnerCompression ResolveInnerCompression(ProsperoPkgBuildProperties props)
        => props.InnerCompression != ProsperoInnerCompression.None
            ? props.InnerCompression
            : props.CompressInnerImage ? ProsperoInnerCompression.Zlib : ProsperoInnerCompression.None;

    /// <summary>
    /// Renders <paramref name="innerPfs"/> to a temp file and wraps it as a PS5 PFSv3 Kraken
    /// "PFSC" container, returning an <see cref="ProsperoFsFile"/>
    /// that stores the self-describing container as <c>pfs_image.dat</c> — a regular outer-PFS file (the
    /// Kraken compression lives inside the file, not in the outer inode). The produced container is
    /// round-trip-validated in-process with the Kraken decoder before use; if it does not shrink
    /// the image, or validation fails, the raw <see cref="ProsperoFsFile(ProsperoPfsBuilder)"/> wrapper is returned
    /// instead. On-console package acceptance depends on console mode and firmware.
    /// </summary>
    private static ProsperoFsFile BuildKrakenInnerFile(ProsperoPfsBuilder innerPfs, Action<string> log, out string? tmpRaw, out string? tmpKraken)
    {
        tmpRaw = null;
        tmpKraken = null;
        long rawSize = innerPfs.CalculatePfsSize();
        if (rawSize > Array.MaxLength)
        {
            log($"Inner image is {rawSize:N0} bytes; too large for the in-memory Kraken packer — storing it raw.");
            return new ProsperoFsFile(innerPfs);
        }

        string raw = Path.Combine(Path.GetTempPath(), "psmt_pfs_" + Guid.NewGuid().ToString("N") + ".raw");
        string kraken = Path.Combine(Path.GetTempPath(), "psmt_pfs_" + Guid.NewGuid().ToString("N") + ".kpfs");

        log($"Compressing inner pfs_image.dat ({rawSize:N0} bytes raw) with Kraken (PFSv3)...");
        byte[] rawBytes;
        using (var rawStream = new FileStream(raw, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
        {
            innerPfs.WriteImage(rawStream);
            tmpRaw = raw;
            rawStream.Flush();
            long actual = rawStream.Length;
            rawStream.Position = 0;
            rawBytes = new byte[actual];
            rawStream.ReadExactly(rawBytes, 0, rawBytes.Length);
        }

        byte[] container = ProsperoCompressedPfsImage.Pack(rawBytes);

        // In-process acceptance gate: the decoder must reconstruct the raw image byte-exact.
        byte[] restored = ProsperoCompressedPfsFile.Parse(container).Decompress();
        bool roundTripOk = restored.Length == rawBytes.Length && restored.AsSpan().SequenceEqual(rawBytes);
        if (!roundTripOk || container.Length >= rawBytes.Length)
        {
            log(roundTripOk
                ? "Inner image is incompressible with Kraken; storing it raw."
                : "Kraken round-trip validation failed; storing the inner image raw.");
            TryDeleteTemp(tmpRaw); tmpRaw = null;
            return new ProsperoFsFile(innerPfs);
        }

        File.WriteAllBytes(kraken, container);
        tmpKraken = kraken;
        TryDeleteTemp(tmpRaw); tmpRaw = null; // the raw image is no longer needed

        log($"Inner pfs_image.dat Kraken-compressed to {container.Length:N0} bytes "
            + $"({(double)container.Length / rawBytes.Length:P1} of raw).");

        long onDisk = container.Length;
        string krakenPath = kraken;
        return new ProsperoFsFile(
            s => { using var f = File.OpenRead(krakenPath); f.CopyTo(s); },
            "pfs_image.dat",
            size: onDisk);
    }

    /// <summary>
    /// Renders <paramref name="innerPfs"/> to a temp file, PFSC-compresses it (block size matched to
    /// the outer PFS) into a second temp file and returns an <see cref="ProsperoFsFile"/> that stores the
    /// genuinely compressed image as <c>pfs_image.dat</c>. If the image is incompressible (the encoder
    /// reports <c>StoredRaw</c> or yields no size benefit) the raw <see cref="ProsperoFsFile(ProsperoPfsBuilder)"/>
    /// wrapper is returned and the temp files are released immediately.
    /// </summary>
    private static ProsperoFsFile BuildCompressedInnerFile(ProsperoPfsBuilder innerPfs, Action<string> log, out string? tmpRaw, out string? tmpPfsc)
    {
        tmpRaw = null;
        tmpPfsc = null;
        long rawSize = innerPfs.CalculatePfsSize();

        string raw = Path.Combine(Path.GetTempPath(), "psmt_pfs_" + Guid.NewGuid().ToString("N") + ".raw");
        string pfsc = Path.Combine(Path.GetTempPath(), "psmt_pfs_" + Guid.NewGuid().ToString("N") + ".pfsc");

        log($"Compressing inner pfs_image.dat ({rawSize:N0} bytes raw)...");
        using (var rawStream = new FileStream(raw, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
        {
            innerPfs.WriteImage(rawStream);
            tmpRaw = raw;

            ProsperoPfscEncodeStats stats;
            using (var pfscStream = new FileStream(pfsc, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                rawStream.Position = 0;
                stats = ProsperoPfscEncoder.Encode(rawStream, rawSize, pfscStream, new ProsperoPfscEncoderOptions { BlockSize = BlockSize });
            }
            tmpPfsc = pfsc;

            long pfscSize = new FileInfo(pfsc).Length;
            if (stats.StoredRaw || pfscSize >= rawSize)
            {
                log("Inner image is incompressible; storing it raw (size-stable PFSC wrapper).");
                TryDeleteTemp(tmpRaw); tmpRaw = null;
                TryDeleteTemp(tmpPfsc); tmpPfsc = null;
                return new ProsperoFsFile(innerPfs);
            }

            log($"Inner pfs_image.dat compressed to {pfscSize:N0} bytes "
                + $"({(double)pfscSize / rawSize:P1} of raw, {stats.CompressedBlocks}/{stats.BlockCount} blocks).");
        }

        string pfscPath = pfsc;
        long onDisk = new FileInfo(pfscPath).Length;
        return new ProsperoFsFile(
            s => { using var f = File.OpenRead(pfscPath); f.CopyTo(s); },
            "pfs_image.dat",
            size: onDisk,
            compressedSize: rawSize,
            compress: true);
    }

    private static void TryDeleteTemp(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { /* best-effort temp cleanup */ }
        catch (UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }

    // Builds the FSDir tree from the source folder, injecting the inner-only auxiliary sce_sys files
    // that the publishing pipeline generates during PKG building (these are NOT part of the loose
    // input): sce_sys/keystone and sce_sys/about/right.sprx. imagedigs.dat and the PlayGo descriptors
    // are OUTER CNT entries (see BuildContainer), not inner-PFS files.
    private static ProsperoFsDir BuildInnerTree(string sourceFolder, string passcode)
    {
        var root = new ProsperoFsDir();
        Populate(root, sourceFolder);

        var sceSys = root.Dirs.FirstOrDefault(d => d.name == "sce_sys");
        if (sceSys != null)
        {
            // sce_sys/keystone — generated from the passcode if the project did not supply one.
            if (!sceSys.Files.Any(f => f.name == "keystone"))
            {
                var keystone = Crypto.CreateKeystone(passcode, 3); // PS5 keystone header version
                AddFile(sceSys, "keystone", keystone);
            }

            EnsureAboutRightSprx(sceSys);
            EnsureUcpArchives(sceSys);

            // NOTE: imagedigs.dat and the PlayGo descriptors (playgo-chunk.dat, playgo-hash-table.dat,
            // playgo-ficm.dat) are NOT inner-PFS files. They are OUTER CNT entries — ids 0x040A, 0x1001,
            // 0x2010, 0x2011 — and the inner-PFS builder deliberately filters any sce_sys file whose name
            // is a known CNT id out of the inner image. They are generated as CNT entries in
            // BuildContainer instead.
        }
        return root;

        static void AddFile(ProsperoFsDir dir, string name, byte[] data) =>
            dir.Files.Add(new ProsperoFsFile(s => s.Write(data, 0, data.Length), name, data.Length) { Parent = dir });

        static void Populate(ProsperoFsDir node, string path)
        {
            foreach (var sub in Directory.EnumerateDirectories(path).OrderBy(Path.GetFileName, StringComparer.Ordinal))
            {
                var child = new ProsperoFsDir { name = Path.GetFileName(sub), Parent = node };
                node.Dirs.Add(child);
                Populate(child, sub);
            }
            foreach (var file in Directory.EnumerateFiles(path).OrderBy(Path.GetFileName, StringComparer.Ordinal))
            {
                var name = Path.GetFileName(file);
                if (name.EndsWith(".gp4", StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith(".gp5", StringComparison.OrdinalIgnoreCase))
                    continue;
                node.Files.Add(new ProsperoFsFile(file) { name = name, Parent = node });
            }
        }
    }

    // sce_sys/about/right.sprx — the entitlement module the runtime loads from the package's about
    // directory. A supplied file always wins; when the project does not ship one, the embedded debug
    // module is injected so the package layout is complete. The publishing tool selects this module
    // by content type from a fixed embedded set; the library ships one debug default and never
    // rewrites a caller-supplied module.
    private static void EnsureAboutRightSprx(ProsperoFsDir sceSys)
    {
        var about = FindDir(sceSys, "about");
        if (about != null && about.Files.Any(f => f.name == "right.sprx"))
            return;

        byte[]? module = LibProsperoPkg.PlayGo.ProsperoPlayGo.GetRightSprx();
        if (module is not { Length: > 0 })
            return;

        if (about == null)
        {
            about = new ProsperoFsDir { name = "about", Parent = sceSys };
            sceSys.Dirs.Add(about);
        }
        AddInMemoryFile(about, "right.sprx", module);
    }

    // sce_sys/trophy2 and sce_sys/uds carry UCP archives (trophyNN.ucp / udsNN.ucp). A supplied
    // archive is packed as-is, but its whole-file digest is refreshed first so a re-assembled or
    // edited archive still validates on load. Fresh archives are produced from loose assets with
    // ProsperoUcp.BuildFromDirectory and placed here by the caller.
    private static void EnsureUcpArchives(ProsperoFsDir sceSys)
    {
        foreach (var dirName in new[] { "trophy2", "uds" })
        {
            var dir = FindDir(sceSys, dirName);
            if (dir == null) continue;
            for (int i = 0; i < dir.Files.Count; i++)
            {
                var file = dir.Files[i];
                if (!file.name.EndsWith(".ucp", StringComparison.OrdinalIgnoreCase)) continue;
                byte[] bytes = ReadNode(file);
                if (!ProsperoUcp.IsUcp(bytes) || ProsperoUcp.VerifyDigest(bytes)) continue;
                byte[] repaired = ProsperoUcp.WithRepairedDigest(bytes);
                dir.Files[i] = new ProsperoFsFile(s => s.Write(repaired, 0, repaired.Length), file.name, repaired.Length) { Parent = dir };
            }
        }
    }

    private static ProsperoFsDir? FindDir(ProsperoFsDir parent, string name) =>
        parent.Dirs.FirstOrDefault(d => d.name == name);

    private static void AddInMemoryFile(ProsperoFsDir dir, string name, byte[] data) =>
        dir.Files.Add(new ProsperoFsFile(s => s.Write(data, 0, data.Length), name, data.Length) { Parent = dir });

    private static byte[] ReadNode(ProsperoFsFile file)
    {
        using var ms = new MemoryStream();
        file.Write(ms);
        return ms.ToArray();
    }

    private static ProsperoCnt BuildContainer(
        ProsperoPkgBuildProperties props, byte[] ekpfs, string sourceFolder,
        ulong pfsSize, int imagedigsSize, uint playgoFileCount, ulong chunkDataSize)
    {
        uint contentType = ContentTypeFor(props.VolumeType);
        var pkg = new ProsperoCnt
        {
            Header = new ProsperoCntHeader
            {
                CNTMagic = "\u007fCNT",
                flags = (ProsperoCntFlags)FlagsPs5,
                unk_0x08 = 0,
                unk_0x0C = Unk0CPs5,
                entry_count = 0,
                sc_entry_count = 6,
                entry_count_2 = 0,
                entry_table_offset = 0,
                main_ent_data_size = 0,
                body_offset = BodyOffset,
                body_size = 0,
                content_id = props.ContentId,
                drm_type = DrmTypePs5,
                content_type = contentType,
                content_flags = ContentFlagsFor(props.VolumeType),
                promote_size = 0,
                version_date = 0x20260101,
                version_hash = 0,
                iro_tag = ProsperoCntIroTag.None,
                ekc_version = 1,
                sc_entries1_hash = new byte[32],
                sc_entries2_hash = new byte[32],
                digest_table_hash = new byte[32],
                body_digest = new byte[32],
                unk_0x400 = 1,
                pfs_image_count = 1,
                pfs_flags = PfsFlags,
                pfs_image_offset = PfsImageOffset,
                pfs_image_size = pfsSize,
                mount_image_offset = 0,
                mount_image_size = 0,
                package_size = PfsImageOffset + pfsSize,
                pfs_signed_size = BlockSize,
                pfs_cache_size = 0xD0000,
                pfs_image_digest = new byte[32],
                pfs_signed_digest = new byte[32],
                pfs_split_size_nth_0 = 0,
                pfs_split_size_nth_1 = 0,
            },
            HeaderDigest = new byte[32],
            HeaderSignature = new byte[0x100],
        };

        // System-container entries (the 6 SC entries), ids 0x1/0x10/0x20/0x80/0x100/0x200.
        pkg.EntryKeys = new ProsperoCntKeysEntry(props.ContentId, props.Passcode);
        pkg.ImageKey = new ProsperoCntGenericEntry(ProsperoCntEntryId.IMAGE_KEY)
        {
            FileData = Crypto.RSA2048EncryptKey(LibProsperoPkg.Util.RSAKeyset.FakeKeyset.Modulus, ekpfs),
        };
        pkg.GeneralDigests = new ProsperoCntGeneralDigestsEntry { type = ProsperoImageDigests.GeneralDigestsTypeFull };
        pkg.Metas = new ProsperoCntMetasEntry();
        pkg.Digests = new ProsperoCntGenericEntry(ProsperoCntEntryId.DIGESTS);
        pkg.EntryNames = new ProsperoCntNameTableEntry();

        // param.json (PS5 entry id 0x2000).
        byte[] paramJson = ReadParamJson(sourceFolder);
        var paramEntry = new ProsperoCntGenericEntry((ProsperoCntEntryId)0x2000, "param.json") { FileData = paramJson };

        pkg.Entries = new List<ProsperoCntEntry>
        {
            pkg.EntryKeys,
            pkg.ImageKey,
            pkg.GeneralDigests,
            pkg.Metas,
            pkg.Digests,
            pkg.EntryNames,
            paramEntry,
        };

        // sce_sys media entries (icon0.png, pic0.png, pic1.png, snd0.at9, ...) present in the folder.
        foreach (var media in CollectMediaEntries(sourceFolder))
            pkg.Entries.Add(media);

        // PS5 image-digest + PlayGo descriptor CNT entries. Reference package layout shows
        // these are OUTER CNT entries — imagedigs.dat
        // (id 0x040A, UNNAMED), playgo-chunk.dat (0x1001), playgo-hash-table.dat (0x2010) and
        // playgo-ficm.dat (0x2011) — NOT inner-PFS files. imagedigs is laid out as a placeholder sized
        // to the outer block count and filled with the captured per-block digests after the image is
        // written. The PlayGo file/inode count drives playgo-ficm.dat (count) and playgo-hash-table.dat
        // (count / 2), matching reference samples. Any entry the source folder already
        // supplied (e.g. a hand-authored playgo-chunk.dat) is respected and not regenerated.
        foreach (var (id, name, data) in new (uint Id, string? Name, byte[] Data)[]
        {
            (ImagedigsEntryId, null, new byte[imagedigsSize]),
            (0x1001u, "playgo-chunk.dat", LibProsperoPkg.PlayGo.ProsperoPlayGo.BuildChunkDat(props.ContentId, chunkDataSize)),
            (0x2010u, "playgo-hash-table.dat", LibProsperoPkg.PlayGo.ProsperoPlayGo.BuildHashTable(playgoFileCount / 2)),
            (0x2011u, "playgo-ficm.dat", LibProsperoPkg.PlayGo.ProsperoPlayGo.BuildFicm(playgoFileCount)),
        })
        {
            if (!pkg.Entries.Any(e => (uint)e.Id == id))
                pkg.Entries.Add(new ProsperoCntGenericEntry((ProsperoCntEntryId)id, name) { FileData = data });
        }

        pkg.Digests.FileData = new byte[pkg.Entries.Count * ProsperoCnt.HASH_SIZE];

        LayOutEntries(pkg, paramJson);
        return pkg;
    }

    // The PS5 Flags1 word for each entry id.
    private static uint Flags1For(uint id) => id switch
    {
        (uint)ProsperoCntEntryId.DIGESTS => 0x40000000,
        (uint)ProsperoCntEntryId.ENTRY_KEYS => 0x60000000,
        (uint)ProsperoCntEntryId.IMAGE_KEY => 0x60000000,        // image key is not entry-encrypted.
        (uint)ProsperoCntEntryId.GENERAL_DIGESTS => 0x60000000,
        (uint)ProsperoCntEntryId.METAS => 0x60000000,
        (uint)ProsperoCntEntryId.ENTRY_NAMES => 0x40000000,
        0x2000 => 0x00000000,                          // param.json
        _ => 0x08000000,                               // media / data entries
    };

    // No CNT entries in this package class are entry-encrypted, so Flags2 is always zero.
    private static uint Flags2For(uint id) => 0u;

    private static void LayOutEntries(ProsperoCnt pkg, byte[] paramJson)
    {
        // 1st pass: register every entry name so the name-table offsets are stable.
        foreach (var entry in pkg.Entries.OrderBy(e => e.Name, StringComparer.Ordinal))
            pkg.EntryNames.GetOffset(entry.Name);

        // 2nd pass: assign 16-byte-aligned data offsets and build the meta table.
        ulong dataOffset = pkg.Header.body_offset;
        foreach (var entry in pkg.Entries)
        {
            var meta = new ProsperoCntMetaEntry
            {
                id = entry.Id,
                NameTableOffset = pkg.EntryNames.GetOffset(entry.Name),
                DataOffset = (uint)dataOffset,
                DataSize = entry.Length,
                Flags1 = Flags1For((uint)entry.Id),
                Flags2 = Flags2For((uint)entry.Id),
            };
            pkg.Metas.Metas.Add(meta);
            if (entry == pkg.Metas)
                meta.DataSize = (uint)pkg.Entries.Count * 32;

            dataOffset = Align(dataOffset + meta.DataSize, 16);
            entry.meta = meta;
        }

        ulong bodySize = dataOffset - pkg.Header.body_offset;
        pkg.Metas.Metas.Sort((a, b) => a.id.CompareTo(b.id));
        pkg.Header.entry_count = (uint)pkg.Entries.Count;
        pkg.Header.entry_count_2 = (ushort)pkg.Entries.Count;
        pkg.Header.entry_table_offset = pkg.Metas.meta.DataOffset;
        pkg.Header.body_size = Align(pkg.Header.body_offset + bodySize, 0x80000) - pkg.Header.body_offset;
        pkg.Header.main_ent_data_size = (uint)(new ProsperoCntEntry[]
        {
            pkg.EntryKeys, pkg.ImageKey, pkg.GeneralDigests, pkg.Metas, pkg.Digests,
        }).Sum(x => x.Length);

        pkg.Header.pfs_image_offset = pkg.Header.body_offset + pkg.Header.body_size;
        pkg.Header.package_size = pkg.Header.mount_image_size =
            pkg.Header.body_offset + pkg.Header.body_size + pkg.Header.pfs_image_size;
    }

    private static ProsperoPfsImageXmlOptions FinishContainer(ProsperoCnt pkg, Stream s, ProsperoPkgBuildProperties props, byte[]? nestedImageDigest, Action<string> log)
    {
        // Read the outer PFS image (encrypted blocks + plaintext superblock) so the PS5 mount digests can be
        // computed for the mount image — both are SHA3-256, NOT SHA-256:
        //   game-digest  (pfs_image_digest @0x440) = SHA3-256(plaintext outer superblock block)
        //   fixed-info   (pfs_signed_digest @0x460) = SHA3-256(the FIH header block that wraps this CNT)
        // The FIH block is cycle-free here (it depends only on the image + sizes, never on the CNT digest
        // table) so it is identical to the one ProsperoFihBuilder.BuildFromCnt writes when finalizing.
        log("Calculating PFS image digests (SHA3-256)...");
        byte[] image = new byte[(int)pkg.Header.pfs_image_size];
        s.Position = (long)pkg.Header.pfs_image_offset;
        s.ReadExactly(image);

        var (sbOffset, sblockDigest) = ProsperoImageDigests.ComputeSblockDigestFromImage(image);
        pkg.Header.pfs_image_digest = sblockDigest ?? ProsperoImageDigests.Sha3_256(image);
        byte[] fihBlock = ProsperoFihBuilder.BuildFihHeaderBlock(
            ProsperoFihVariant.Debug, pkg.Header.pfs_image_size,
            ProsperoImageDigests.FihRelativeImageOffset + pkg.Header.pfs_image_size, image,
            warnings: null, nestedImageDigest: nestedImageDigest);
        pkg.Header.pfs_signed_digest = ProsperoImageDigests.ComputeFixedInfoDigest(fihBlock);

        // General digests (PS5 nwonly scheme: type 0x102 [set at creation so the layout reserves 0x1E0],
        // set_digests 0x10DE = content|game|header|system|param|playgo|target, all SHA3-256). game/fixed-info
        // above must already be set: the header-digest preimage (CNT[0x400:0x480]) includes both.
        foreach (var kv in ComputeGeneralDigests(pkg))
            pkg.GeneralDigests.Set(kv.Key, kv.Value);

        // Write the body (entries) now so the per-entry hashes can be computed from the stream.
        var writer = new ProsperoCntWriter(s);
        writer.WriteBody(pkg, props.ContentId, props.Passcode);
        CalcBodyDigests(pkg, s);

        // Header, header digest and the fake header signature.
        s.Position = 0;
        writer.WriteHeader(pkg.Header);
        // Package-digest (the CNT self-seal at +0xFE0): PS5 uses SHA3-256(CNT[0:0xFE0]), NOT SHA-256.
        // The preimage spans 0x410 (pfs_image_offset); BuildFromCnt rewrites that field to the FIH-relative
        // 0x10000 when it finalizes the image, so force 0x10000 here too — otherwise the stored seal would be
        // over the physical offset and would not match a verifier reading the finalized package. Validated
        // byte-exact against reference output (this is the value reported as "Package Digest").
        s.Position = 0;
        byte[] cntHead = new byte[ProsperoImageDigests.PackageDigestRegionSize];
        s.ReadExactly(cntHead);
        BinaryPrimitives.WriteUInt64BigEndian(
            cntHead.AsSpan(ProsperoImageDigests.CntPfsImageOffsetField, 8), ProsperoImageDigests.FihRelativeImageOffset);
        pkg.HeaderDigest = ProsperoImageDigests.ComputePackageDigest(cntHead);
        s.Position = ProsperoImageDigests.PackageDigestStoredOffset;
        s.Write(pkg.HeaderDigest, 0, pkg.HeaderDigest.Length);
        byte[] headerSha = Crypto.Sha256(s, 0, 0x1000);
        s.Position = 0x1000;
        pkg.HeaderSignature = Crypto.RSA2048EncryptKey(LibProsperoPkg.Util.CryptoKeys.PkgSignKey, headerSha);
        s.Write(pkg.HeaderSignature, 0, 256);

        // Every digest, the geometry and the entry table are now finalized on this CNT, so the reproducible
        // SI pfsimage.xml options can be assembled from the builder's own output. The inner-PFS seed is read
        // from the plaintext outer superblock at sbOffset+0x370.
        return BuildSiXmlOptions(pkg, image, sbOffset, Path.GetFullPath(props.SourceFolder!));
    }

    // ---- SI (sce_suppl) pfsimage.xml option assembly ----------------------------------------------

    /// <summary>
    /// Builds the reproducible <see cref="ProsperoPfsImageXmlOptions"/> for the trailing debug SI segment
    /// from the finalized CNT (<paramref name="pkg"/>) and outer image (<paramref name="image"/>). Every
    /// value maps to something the builder already produced — the general digests, the header/body/
    /// fixed-info digests, the container geometry and the CNT entry table — so the emitted pfsimage.xml is
    /// self-consistent with the produced package.
    /// </summary>
    private static ProsperoPfsImageXmlOptions BuildSiXmlOptions(ProsperoCnt pkg, byte[] image, int sbOffsetInImage, string sourceFolder)
    {
        // Inner-PFS superblock seed: 16 bytes at superblock+0x370 (zeros in our build — self-consistent).
        byte[] seed = new byte[16];
        if (sbOffsetInImage >= 0 && sbOffsetInImage + PfsSeedOffset + seed.Length <= image.Length)
            Array.Copy(image, sbOffsetInImage + PfsSeedOffset, seed, 0, seed.Length);

        ParamJsonInfo pj = ReadParamJsonInfo(sourceFolder);

        long pfsImageSize = (long)pkg.Header.pfs_image_size;
        long containerSize = (long)pkg.Header.pfs_image_offset;   // CNT-internal value = CNT body end = CNT size.
        long bodyOffset = (long)pkg.Header.body_offset;
        long mandatorySize = (long)pkg.Metas.Metas.First(m => (uint)m.id == ImagedigsEntryId).DataOffset;
        // Mount-image size = FIH (0x10000) + shared PFS image + container. pkg.Header.mount_image_size omits
        // the leading FIH block, so it is reconstructed here.
        long packageSize = (long)ProsperoImageDigests.FihRelativeImageOffset + pfsImageSize + containerSize;

        // The <entries> table = the file-class CNT entries (id >= 0x400), ordered by container offset.
        var entries = pkg.Metas.Metas
            .Where(m => (uint)m.id >= 0x400)
            .Select(m => new ProsperoPfsImageEntry(EntryDisplayName(pkg, m.id), (long)m.DataOffset, m.DataSize))
            .OrderBy(e => e.Offset)
            .ToList();

        byte[]? Dig(ProsperoCntGeneralDigest d) => pkg.GeneralDigests.Digests.TryGetValue(d, out byte[]? v) ? v : null;

        return new ProsperoPfsImageXmlOptions
        {
            ContentId = pkg.Header.content_id,
            TitleName = pj.TitleName,
            ContentVersion = pj.ContentVersion,
            DrmType = "none",
            ApplicationDrmType = pj.ApplicationDrmType,
            ContentType = ContentTypeString(pkg.Header.content_type),
            ApplicationType = "free",
            MasterVersion = pj.MasterVersion,
            RequiredSystemSoftwareVersion = pj.RequiredSystemSoftwareVersion,
            SdkVersion = pj.SdkVersion,
            PackageSize = packageSize,
            PfsImageOffset = (long)ProsperoImageDigests.FihRelativeImageOffset,
            PfsImageSize = pfsImageSize,
            PfsImageSeed = seed,
            ContainerSize = containerSize,
            MandatorySize = mandatorySize,
            BodyOffset = bodyOffset,
            SupplementalOffset = containerSize,
            Entries = entries,
            ContentDigest = Dig(ProsperoCntGeneralDigest.ContentDigest),
            GameDigest = pkg.Header.pfs_image_digest,
            HeaderDigest = Dig(ProsperoCntGeneralDigest.HeaderDigest),
            SystemDigest = Dig(ProsperoCntGeneralDigest.SystemDigest),
            ParamDigest = Dig(ProsperoCntGeneralDigest.ParamDigest),
            PackageDigest = pkg.HeaderDigest,
            BodyDigest = pkg.Header.body_digest,
            SblockDigest = pkg.Header.pfs_image_digest,
            FixedInfoDigest = pkg.Header.pfs_signed_digest,
        };
    }

    /// <summary>Plaintext superblock offset of the 16-byte inner-PFS seed (superblock+0x370).</summary>
    private const int PfsSeedOffset = 0x370;

    // pfsimage.xml content-type string, selected from the CNT header content-type code.
    private static string ContentTypeString(uint contentType) => contentType switch
    {
        ContentTypeAc => "PS5AC",
        ContentTypeAl => "PS5AL",
        _ => "PS5GD",
    };

    // Display name for one <entry> of the pfsimage.xml <entries> table. imagedigs (0x040A) is stored
    // UNNAMED in the CNT, so it is special-cased; every other file-class entry carries its CNT name (or a
    // canonical id->name fallback).
    private static string EntryDisplayName(ProsperoCnt pkg, ProsperoCntEntryId id)
    {
        if ((uint)id == ImagedigsEntryId) return "imagedigs.dat";
        var e = pkg.Entries.FirstOrDefault(x => x.Id == id);
        if (e?.Name is { Length: > 0 } named) return named;
        return ProsperoCntEntryNames.IdToName.TryGetValue(id, out string? nm) ? nm : $"0x{(uint)id:x4}.bin";
    }

    // Reproducible pfsimage.xml string fields sourced from param.json.
    private readonly record struct ParamJsonInfo(
        string ContentVersion, string MasterVersion, string SdkVersion,
        string RequiredSystemSoftwareVersion, string ApplicationDrmType, string TitleName);

    // Best-effort param.json reader for the pfsimage.xml string fields. Any parse failure falls back to
    // the neutral defaults (the produced XML stays structurally valid and self-consistent).
    private static ParamJsonInfo ReadParamJsonInfo(string sourceFolder)
    {
        string contentVersion = "01.000.000", masterVersion = "01.00",
               sdkVersion = "0x0000000000000000", reqSys = "0x0000000000000000",
               appDrm = "free", title = "";
        try
        {
            byte[] pj = ReadParamJson(sourceFolder);
            if (pj is { Length: > 0 })
            {
                using var doc = JsonDocument.Parse(pj);
                JsonElement root = doc.RootElement;
                if (root.ValueKind == JsonValueKind.Object)
                {
                    static string? Str(JsonElement o, string name) =>
                        o.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

                    contentVersion = Str(root, "contentVersion") ?? contentVersion;
                    masterVersion = Str(root, "masterVersion") ?? masterVersion;
                    sdkVersion = Str(root, "sdkVersion") ?? sdkVersion;
                    reqSys = Str(root, "requiredSystemSoftwareVersion") ?? reqSys;
                    appDrm = Str(root, "applicationDrmType") ?? appDrm;

                    if (root.TryGetProperty("localizedParameters", out JsonElement lp) && lp.ValueKind == JsonValueKind.Object)
                    {
                        string lang = Str(lp, "defaultLanguage") ?? "en-US";
                        if (lp.TryGetProperty(lang, out JsonElement le) && le.ValueKind == JsonValueKind.Object &&
                            Str(le, "titleName") is { Length: > 0 } tn)
                        {
                            title = tn;
                        }
                        else
                        {
                            foreach (JsonProperty prop in lp.EnumerateObject())
                            {
                                if (prop.Value.ValueKind == JsonValueKind.Object &&
                                    Str(prop.Value, "titleName") is { Length: > 0 } t2)
                                {
                                    title = t2;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or ArgumentException)
        {
            // Best-effort: keep the neutral defaults.
        }
        return new ParamJsonInfo(contentVersion, masterVersion, sdkVersion, reqSys, appDrm, title);
    }

    // Per-entry CNT ids that contribute to the system-digest (the sce_sys visual/audio media + their *.dds
    // re-encodes) and the playgo-digest (the PlayGo stream files). Validated against reference output:
    // system = SHA3-256( ed(icon0.png 0x1200) ‖ ed(icon0.dds 0x1280) );
    // playgo = SHA3-256( ed(playgo-chunk.dat 0x1001) ‖ ed(playgo-hash-table.dat 0x2010) ‖ ed(playgo-ficm.dat 0x2011) ).
    private static readonly uint[] SystemMediaIds =
        [0x1006, 0x100D, 0x1200, 0x1220, 0x1240, 0x1280, 0x12A0, 0x12C0, 0x2040, 0x2060];
    private static readonly uint[] PlaygoIds = [0x1001, 0x2010, 0x2011];

    private static Dictionary<ProsperoCntGeneralDigest, byte[]> ComputeGeneralDigests(ProsperoCnt pkg)
    {
        byte[] game = pkg.Header.pfs_image_digest;
        bool includeGame = pkg.Header.content_type != ContentTypeAl;

        var digests = new Dictionary<ProsperoCntGeneralDigest, byte[]>
        {
            { ProsperoCntGeneralDigest.HeaderDigest, ComputeHeaderDigest(pkg) },
            { ProsperoCntGeneralDigest.ContentDigest, ComputeContentDigest(pkg, game, includeGame) },
        };
        if (includeGame)
        {
            // game-digest (= pfs_image_digest) and its copy in the target slot (target == game for nwonly).
            digests[ProsperoCntGeneralDigest.GameDigest] = game;
            digests[ProsperoCntGeneralDigest.TargetDigest] = game;
        }

        // system-digest / playgo-digest = SHA3-256 over the concatenated per-entry SHA3 digests of the
        // relevant entries, in ascending id order. Computed over whatever such entries the package carries
        // (self-consistent); the byte-exact formula is validated against reference output.
        byte[]? system = ComputeConcatOverEntries(pkg, SystemMediaIds);
        if (system is not null) digests[ProsperoCntGeneralDigest.SystemDigest] = system;
        byte[]? playgo = ComputeConcatOverEntries(pkg, PlaygoIds);
        if (playgo is not null) digests[ProsperoCntGeneralDigest.PlaygoDigest] = playgo;

        // param.json drives the param-digest (SHA3-256 of the entry payload) on PS5.
        var paramEntry = pkg.Entries.FirstOrDefault(e => (uint)e.Id == 0x2000);
        if (paramEntry is ProsperoCntGenericEntry { FileData: { } pj })
            digests[ProsperoCntGeneralDigest.ParamDigest] = ProsperoImageDigests.ComputeEntryDigest(pj);

        return digests;
    }

    private static byte[]? ComputeConcatOverEntries(ProsperoCnt pkg, uint[] ids)
    {
        var set = new HashSet<uint>(ids);
        var perEntry = pkg.Entries
            .Where(e => set.Contains((uint)e.Id) && e is ProsperoCntGenericEntry { FileData: not null })
            .OrderBy(e => (uint)e.Id)
            .Select(e => ProsperoImageDigests.ComputeEntryDigest(((ProsperoCntGenericEntry)e).FileData!))
            .ToList();
        return perEntry.Count == 0 ? null : ProsperoImageDigests.ComputeConcatDigest(perEntry);
    }

    private static byte[] ComputeHeaderDigest(ProsperoCnt pkg)
    {
        // header-digest = SHA3-256( CNT[0x00:0x40] ‖ CNT[0x400:0x480] ). The mount descriptor must carry the
        // finalized FIH-relative pfs_image_offset (0x10000) at CNT+0x410 — BuildFromCnt rewrites it on disk
        // after this runs, so force it in the preimage so the stored digest matches the finalized image.
        using var ms = new MemoryStream();
        new ProsperoCntWriter(ms).WriteHeader(pkg.Header);
        byte[] prefix = new byte[ProsperoImageDigests.HeaderDigestPrefixSize];
        ms.Position = 0;
        ms.ReadExactly(prefix);
        byte[] mount = new byte[ProsperoImageDigests.HeaderDigestMountDescriptorSize];
        ms.Position = 0x400;
        ms.ReadExactly(mount);
        return ProsperoImageDigests.ComputeHeaderDigest(prefix, ProsperoImageDigests.ForceFihRelativeImageOffset(mount));
    }

    private static byte[] ComputeContentDigest(ProsperoCnt pkg, byte[] game, bool includeGame)
    {
        // content-digest = SHA3-256( CNT[0x40:0x78] ‖ game-digest(32, when present) ‖ major-param-digest(32) ).
        // CNT[0x40:0x78] = content_id(36) + 12 reserved + drm_type(BE32 @0x30) + content_type(BE32 @0x34).
        // The major-param-digest is all-zero for the nwonly package class, as validated against reference output.
        byte[] descriptor = new byte[ProsperoImageDigests.ContentDescriptorSize];
        byte[] cid = Encoding.ASCII.GetBytes(pkg.Header.content_id);
        Array.Copy(cid, 0, descriptor, 0, Math.Min(cid.Length, 36));
        BinaryPrimitives.WriteUInt32BigEndian(descriptor.AsSpan(0x30, 4), pkg.Header.drm_type);
        BinaryPrimitives.WriteUInt32BigEndian(descriptor.AsSpan(0x34, 4), pkg.Header.content_type);
        return ProsperoImageDigests.ComputeContentDigest(
            descriptor, includeGame ? game : default, new byte[ProsperoImageDigests.DigestSize], includeGame);
    }

    private static void CalcBodyDigests(ProsperoCnt pkg, Stream s)
    {
        // All CNT body digests are SHA3-256 on PS5 (the per-entry table, body-digest, digest-table hash and
        // the two sc-entry rollups). This is the same primitive the digest layer above uses.
        var digests = pkg.Digests;
        var digestsOffset = pkg.Metas.Metas.First(m => m.id == ProsperoCntEntryId.DIGESTS).DataOffset;
        for (int i = 1; i < pkg.Metas.Metas.Count; i++)
        {
            var meta = pkg.Metas.Metas[i];
            var hash = Crypto.Sha3_256(s, meta.DataOffset, meta.DataSize);
            Buffer.BlockCopy(hash, 0, digests.FileData, 32 * i, 32);
            s.Position = digestsOffset + 32 * i;
            s.Write(hash, 0, 32);
        }

        pkg.Header.body_digest = Crypto.Sha3_256(s, (long)pkg.Header.body_offset, (long)pkg.Header.body_size);
        pkg.Header.digest_table_hash = Crypto.Sha3_256(pkg.Digests.FileData);

        using var ms = new MemoryStream();
        foreach (var entry in new ProsperoCntEntry[] { pkg.EntryKeys, pkg.ImageKey, pkg.GeneralDigests, pkg.Metas, pkg.Digests })
            new SubStream(s, entry.meta.DataOffset, entry.meta.DataSize).CopyTo(ms);
        pkg.Header.sc_entries1_hash = Crypto.Sha3_256(ms);

        ms.SetLength(0);
        foreach (var entry in new ProsperoCntEntry[] { pkg.EntryKeys, pkg.ImageKey, pkg.GeneralDigests, pkg.Metas })
        {
            long size = entry.Id == ProsperoCntEntryId.METAS ? pkg.Header.sc_entry_count * 0x20 : entry.meta.DataSize;
            new SubStream(s, entry.meta.DataOffset, size).CopyTo(ms);
        }
        pkg.Header.sc_entries2_hash = Crypto.Sha3_256(ms);
    }

    private static byte[] ReadParamJson(string sourceFolder)
    {
        var path = Path.Combine(sourceFolder, "sce_sys", "param.json");
        if (!File.Exists(path))
            throw new FileNotFoundException("sce_sys/param.json is required to build a PS5 package.", path);
        return File.ReadAllBytes(path);
    }

    // Known sce_sys media files and their PS5 entry ids (the inspection-relevant subset).
    private static readonly (string Name, uint Id)[] MediaFiles =
    [
        ("icon0.png", 0x1200),
        ("pic0.png", 0x1220),
        ("pic1.png", 0x1006),
        ("pic2.png", 0x2040),
        ("snd0.at9", 0x1240),
        ("save_data.png", 0x100D),
        ("playgo-chunk.dat", 0x1001),
    ];

    // sce_sys images that are re-encoded as a same-named *.dds (BC7) sibling,
    // with the PS5 entry id of the generated *.dds. Decoded from reference
    // packages: icon0.png->icon0.dds (0x1280), pic0.png->pic0.dds (0x12A0), pic1.png->pic1.dds
    // (0x12C0), pic2.png->pic2.dds (0x2060).
    private static readonly (string Png, string Dds, uint Id)[] DdsMedia =
    [
        ("icon0.png", "icon0.dds", 0x1280),
        ("pic0.png", "pic0.dds", 0x12A0),
        ("pic1.png", "pic1.dds", 0x12C0),
        ("pic2.png", "pic2.dds", 0x2060),
    ];

    // Entry ids that are produced by dedicated builders and must not be re-emitted from a
    // supplied sce_sys file: param.sfo (PS4, unused on PS5) and the PlayGo chunk descriptor,
    // which is regenerated when absent.
    private static readonly HashSet<uint> GeneratedEntryIds = [0x1000];

    private static IEnumerable<ProsperoCntEntry> CollectMediaEntries(string sourceFolder)
    {
        var sceSys = Path.Combine(sourceFolder, "sce_sys");
        var emitted = new HashSet<uint>();

        foreach (var (name, id) in MediaFiles)
        {
            var path = Path.Combine(sceSys, name);
            if (!File.Exists(path)) continue;
            emitted.Add(id);
            var data = File.ReadAllBytes(path);
            yield return new ProsperoCntGenericEntry((ProsperoCntEntryId)id, name) { FileData = data };
        }

        // DDS re-encodes of the icon/pic images: use an on-disk *.dds if the caller already supplied
        // one (e.g. extracted from a package); otherwise generate it from the *.png.
        foreach (var (png, dds, id) in DdsMedia)
        {
            var ddsPath = Path.Combine(sceSys, dds);
            byte[]? data = null;
            if (File.Exists(ddsPath))
            {
                data = File.ReadAllBytes(ddsPath);
            }
            else
            {
                var pngPath = Path.Combine(sceSys, png);
                if (!File.Exists(pngPath)) continue;
                try
                {
                    data = ProsperoDdsEncoder.EncodePngToDds(File.ReadAllBytes(pngPath));
                }
                catch
                {
                    // Not a decodable image (e.g. a placeholder input); skip the DDS sibling.
                    continue;
                }
            }
            emitted.Add(id);
            yield return new ProsperoCntGenericEntry((ProsperoCntEntryId)id, dds) { FileData = data };
        }

        // System files: every remaining supplied sce_sys file whose relative path maps to a known
        // CNT id becomes an outer CNT entry. The inner-PFS builder deliberately keeps these named
        // system files out of the inner image (PFSBuilder skips known-id sce_sys files), so they
        // must be carried in the outer container instead. Covers the backend-authored license,
        // network-platform, self-info, delta-info, keymap_rp, changeinfo, pronunciation and trophy
        // files. These blobs are packed as supplied; the library never fabricates them.
        if (!Directory.Exists(sceSys)) yield break;
        foreach (var file in Directory.EnumerateFiles(sceSys, "*", SearchOption.AllDirectories)
                                      .OrderBy(p => p, StringComparer.Ordinal))
        {
            var rel = Path.GetRelativePath(sceSys, file).Replace('\\', '/');
            if (!ProsperoCntEntryNames.NameToId.TryGetValue(rel, out var id)) continue;
            var idv = (uint)id;
            if (rel.EndsWith(".dds", StringComparison.Ordinal)) continue; // handled by the DDS pass
            if (GeneratedEntryIds.Contains(idv)) continue;
            if (!emitted.Add(idv)) continue; // already emitted above
            var data = File.ReadAllBytes(file);
            if (!ProsperoSystemFiles.Validate(rel, data, out var error))
                throw new InvalidDataException($"sce_sys/{rel}: {error}");
            yield return new ProsperoCntGenericEntry(id, rel) { FileData = data };
        }
    }

    private static ulong Align(ulong value, ulong align)
    {
        var rem = value % align;
        return rem == 0 ? value : value + (align - rem);
    }

    private static long ToUnixSeconds(DateTime time) =>
        (long)time.ToUniversalTime().Subtract(DateTime.UnixEpoch).TotalSeconds;
}
