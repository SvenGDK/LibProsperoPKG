// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// PS5 PFSv3 inner-image packer/unpacker — the Kraken "PFSC" container used for
// inner images (pfs_image.dat). This is the Kraken counterpart of the zlib packer
// in LibProsperoPkg.PFS.ProsperoPfsc: same 'PFSC' magic, but format version 3, a
// 7-section directory, SHA3-256 digests and Kraken (level 7, window 18) per-block compression
// — NOT zlib. The two are kept as separate code paths because the installable debug .pkg inner
// image uses the zlib PFSC, while the "--oformat nwonly" inner image uses this Kraken PFSv3
// container (see ProsperoPkgBuildProperties.InnerCompression).
//
// Compression and decompression use the codec in PFS/Compression: CompressedPfsFileWriter
// (Kraken encoder) and CompressedPfsFile (Kraken decoder). Every byte the writer emits
// round-trips byte-exact through the in-process decoder for the supported container shapes.
#nullable enable
using System;
using System.Buffers.Binary;
using System.IO;

namespace LibProsperoPkg.PFS.Compression;

/// <summary>The outcome of a <see cref="ProsperoCompressedPfsImage"/> pack operation.</summary>
public sealed class ProsperoCompressedPfsImageResult
{
    /// <summary>The path the container was written to, or <c>null</c> for in-memory packs.</summary>
    public string? OutputPath { get; init; }

    /// <summary>Logical (uncompressed) source size in bytes.</summary>
    public required long RawSize { get; init; }

    /// <summary>Size of the produced container in bytes (including metadata).</summary>
    public required long EncodedSize { get; init; }

    /// <summary>The logical block size used, in bytes.</summary>
    public required int BlockSize { get; init; }

    /// <summary>Total number of logical blocks in the container.</summary>
    public required int BlockCount { get; init; }

    /// <summary>Number of blocks that were Kraken-compressed (the rest are stored uncompressed).</summary>
    public required int CompressedBlocks { get; init; }

    /// <summary>True when no block compressed below its stored size (the whole image is stored raw).</summary>
    public bool StoredRaw => CompressedBlocks == 0;

    /// <summary>Percentage saved relative to the source (negative if it grew).</summary>
    public double GainPercent => RawSize == 0 ? 0.0 : (RawSize - EncodedSize) / (double)RawSize * 100.0;
}

/// <summary>
/// Packer/unpacker for the PS5 PFSv3 compression container ("PFSC", Kraken). This is the codec used for the "--oformat nwonly" inner image
/// (<c>pfs_image.dat</c>); for the installable zlib PFSC image use
/// <see cref="LibProsperoPkg.PFS.ProsperoPfsc"/>.
/// </summary>
public static class ProsperoCompressedPfsImage
{
    /// <summary>The default PS5 v3 logical block size (256 KiB), matching "--oformat nwonly".</summary>
    public const int DefaultBlockSize = CompressedPfsFileWriter.DefaultBlockSize;

    /// <summary>The default Kraken level recorded in the header (7, matching "--oformat nwonly").</summary>
    public const int DefaultLevel = 7;

    private const uint PfscMagic = 0x43534650; // 'P','F','S','C'

    /// <summary>
    /// Compresses an already-prepared inner image into a PS5 Kraken PFSv3 container in memory. Each
    /// block is Kraken-compressed; blocks that do not shrink are stored uncompressed.
    /// </summary>
    /// <param name="image">The raw inner image (e.g. a nested pfs_image payload) to wrap.</param>
    /// <param name="level">The Kraken level recorded in the header. Default 7.</param>
    /// <param name="blockSize">The logical block size. Default 256 KiB. Must be positive.</param>
    /// <returns>The serialized PFSv3 'PFSC' container.</returns>
    public static byte[] Pack(ReadOnlySpan<byte> image, int level = DefaultLevel, int blockSize = DefaultBlockSize)
        => CompressedPfsFileWriter.WriteCompressed(image, level, blockSize);

    /// <summary>
    /// Wraps an already-prepared inner image into a PS5 Kraken PFSv3 container, storing every block
    /// uncompressed (isBlockCompressed = 0). Useful for incompressible images or deterministic output.
    /// </summary>
    /// <param name="image">The raw inner image to wrap.</param>
    /// <param name="level">The Kraken level recorded in the header. Default 7.</param>
    /// <param name="blockSize">The logical block size. Default 256 KiB. Must be positive.</param>
    /// <returns>The serialized PFSv3 'PFSC' container with stored blocks.</returns>
    public static byte[] PackStored(ReadOnlySpan<byte> image, int level = DefaultLevel, int blockSize = DefaultBlockSize)
        => CompressedPfsFileWriter.WriteStored(image, level, blockSize);

    /// <summary>
    /// Compresses a prepared inner image file at <paramref name="inputImagePath"/> into a PS5 Kraken
    /// PFSv3 container at <paramref name="outputPath"/>.
    /// </summary>
    /// <param name="inputImagePath">A prepared inner image file (e.g. a nested PFS image).</param>
    /// <param name="outputPath">Destination container path.</param>
    /// <param name="level">The Kraken level recorded in the header. Default 7.</param>
    /// <param name="blockSize">The logical block size. Default 256 KiB. Must be positive.</param>
    /// <param name="logger">Optional progress sink.</param>
    /// <returns>Statistics describing the produced container.</returns>
    public static ProsperoCompressedPfsImageResult PackFile(
        string inputImagePath,
        string outputPath,
        int level = DefaultLevel,
        int blockSize = DefaultBlockSize,
        Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputImagePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(blockSize);
        if (!File.Exists(inputImagePath))
            throw new FileNotFoundException("Input image was not found.", inputImagePath);

        var log = logger ?? (_ => { });
        long length = new FileInfo(inputImagePath).Length;
        if (length > Array.MaxLength)
            throw new NotSupportedException(
                $"The inner image is {length:N0} bytes; the in-memory Kraken packer supports up to {Array.MaxLength:N0} bytes.");

        var dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        log($"Packing {Path.GetFileName(inputImagePath)} ({length:N0} bytes) into a PS5 Kraken PFSv3 image...");

        byte[] raw = File.ReadAllBytes(inputImagePath);
        byte[] container = Pack(raw, level, blockSize);
        File.WriteAllBytes(outputPath, container);

        // Parse the produced container to report accurate block statistics.
        var parsed = CompressedPfsFile.Parse(container);
        int compressed = 0;
        foreach (var block in parsed.Blocks)
            if (!block.IsStored) compressed++;
        int blockCount = parsed.Blocks.Count;

        var result = new ProsperoCompressedPfsImageResult
        {
            OutputPath = outputPath,
            RawSize = length,
            EncodedSize = container.Length,
            BlockSize = parsed.BlockSize,
            BlockCount = blockCount,
            CompressedBlocks = compressed,
        };

        if (result.StoredRaw)
            log("Compression produced no benefit; every block was stored uncompressed.");
        else
            log($"Done: {result.EncodedSize:N0} bytes ({result.GainPercent:F1}% saved, {compressed}/{blockCount} blocks compressed).");

        return result;
    }

    /// <summary>
    /// Decompresses a PS5 Kraken PFSv3 container in memory back to the original image bytes, using the
    /// Kraken decoder.
    /// </summary>
    /// <param name="container">A container produced by <see cref="Pack"/> (or any valid PFSv3 compressed image).</param>
    /// <returns>The reconstructed image.</returns>
    public static byte[] Unpack(byte[] container)
    {
        ArgumentNullException.ThrowIfNull(container);
        return CompressedPfsFile.Parse(container).Decompress();
    }

    /// <summary>
    /// Reverses <see cref="PackFile"/>: decompresses a PS5 Kraken PFSv3 container back to a flat image.
    /// </summary>
    /// <param name="inputPath">A container produced by this API (or any valid PFSv3 compressed image).</param>
    /// <param name="outputPath">Destination flat image path.</param>
    /// <param name="logger">Optional progress sink.</param>
    /// <returns>The number of logical bytes written.</returns>
    public static long UnpackFile(string inputPath, string outputPath, Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        if (!File.Exists(inputPath))
            throw new FileNotFoundException("Container was not found.", inputPath);

        var log = logger ?? (_ => { });
        byte[] container = File.ReadAllBytes(inputPath);
        if (!IsScePfsImage(container))
            throw new InvalidDataException("The input file is not a PFSv3 compressed image (wrong magic/version).");

        byte[] raw = Unpack(container);

        var dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllBytes(outputPath, raw);

        log($"Unpacked {raw.Length:N0} bytes to {Path.GetFileName(outputPath)}.");
        return raw.LongLength;
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="data"/> begins with a PS5 PFSv3/PFSv2 'PFSC'
    /// header. This distinguishes the Kraken container from the zlib PFSC (which carries a
    /// zero word at offset 0x04 and no section count), so callers can pick the right unpacker.
    /// </summary>
    public static bool IsScePfsImage(ReadOnlySpan<byte> data)
    {
        if (data.Length < 0x08) return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(data) != PfscMagic) return false;
        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(data[0x04..]);
        ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(data[0x06..]);
        // PFSv2/PFSv3: version 2 or 3 with a 7-entry section directory. The zlib PFSC has 0 here.
        return (version == 2 || version == 3) && sectionCount == 7;
    }

    /// <summary>Returns <c>true</c> when the file at <paramref name="path"/> is a PS5 PFSv3 compressed image.</summary>
    public static bool IsScePfsImageFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using var s = File.OpenRead(path);
        Span<byte> head = stackalloc byte[8];
        int read = s.Read(head);
        return read == head.Length && IsScePfsImage(head);
    }

    /// <summary>
    /// In-process self-test: packs <paramref name="image"/> with the Kraken encoder, decodes it
    /// back with the Kraken decoder, and verifies the result is byte-exact. Returns <c>true</c>
    /// on success. This does not require external processes.
    /// </summary>
    /// <param name="image">The image to round-trip.</param>
    /// <param name="level">The Kraken level recorded in the header. Default 7.</param>
    /// <param name="blockSize">The logical block size. Default 256 KiB.</param>
    public static bool ValidateRoundTrip(ReadOnlySpan<byte> image, int level = DefaultLevel, int blockSize = DefaultBlockSize)
    {
        byte[] container = Pack(image, level, blockSize);
        if (!IsScePfsImage(container)) return false;
        byte[] restored = CompressedPfsFile.Parse(container).Decompress();
        return restored.AsSpan().SequenceEqual(image);
    }
}
