// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// PS5-facing PFSC image pack/unpack. It wraps a prepared image file
// (exFAT/UFS/inner pfs_image.dat) into a PFSC-compressed image and reverses the operation.
// Compression is performed
// by LibProsperoPkg.PFS.PfscEncoder.
#nullable enable
using System;
using System.IO;
using System.IO.Compression;
using System.IO.MemoryMappedFiles;
using LibProsperoPkg.PFS;

namespace LibProsperoPkg.PFS;

/// <summary>Options for <see cref="ProsperoPfsc"/> pack operations.</summary>
public sealed class ProsperoPfscOptions
{
    /// <summary>Logical PFSC block size (power of two, 4 KiB - 2 MiB). Default 64 KiB.</summary>
    public int BlockSize { get; set; } = 0x10000;

    /// <summary>zlib level used per block. Default: maximum.</summary>
    public CompressionLevel CompressionLevel { get; set; } = CompressionLevel.SmallestSize;

    /// <summary>Minimum per-block gain percent (0-100) to keep a compressed block. Default 0.</summary>
    public int ThresholdGain { get; set; } = 0;

    /// <summary>Files smaller than this are stored raw. Default 0.</summary>
    public long MinCompressSize { get; set; } = 0;

    internal PfscEncoderOptions ToEncoderOptions() => new()
    {
        BlockSize = BlockSize,
        CompressionLevel = CompressionLevel,
        ThresholdGain = ThresholdGain,
        MinCompressSize = MinCompressSize,
    };
}

/// <summary>The outcome of a pack operation.</summary>
public sealed class ProsperoPfscResult
{
    /// <summary>The path the PFSC image was written to.</summary>
    public required string OutputPath { get; init; }

    /// <summary>Logical (uncompressed) source size in bytes.</summary>
    public required long RawSize { get; init; }

    /// <summary>Size of the produced image in bytes.</summary>
    public required long EncodedSize { get; init; }

    /// <summary>True when the source was stored uncompressed because compression gave no benefit.</summary>
    public required bool StoredRaw { get; init; }

    /// <summary>Percentage saved relative to the source (negative if it grew).</summary>
    public double GainPercent => RawSize == 0 ? 0.0 : (RawSize - EncodedSize) / (double)RawSize * 100.0;
}

/// <summary>
/// PFSC image packer/unpacker for PS5 workflows.
/// </summary>
public static class ProsperoPfsc
{
    /// <summary>
    /// Wraps an already-prepared image <paramref name="inputImagePath"/> into a
    /// PFSC-compressed image at <paramref name="outputPath"/>.
    /// </summary>
    /// <param name="inputImagePath">A prepared image file (exFAT/UFS image, or an inner PFS image).</param>
    /// <param name="outputPath">Destination PFSC image path.</param>
    /// <param name="options">Compression options. <c>null</c> uses the PS5 defaults.</param>
    /// <param name="logger">Optional progress sink.</param>
    /// <returns>Statistics describing the produced image.</returns>
    public static ProsperoPfscResult PackFile(
        string inputImagePath, string outputPath, ProsperoPfscOptions? options = null, Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputImagePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        if (!File.Exists(inputImagePath))
            throw new FileNotFoundException("Input image was not found.", inputImagePath);

        options ??= new ProsperoPfscOptions();
        var log = logger ?? (_ => { });
        var length = new FileInfo(inputImagePath).Length;

        var dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        log($"Packing {Path.GetFileName(inputImagePath)} ({length:N0} bytes) into a PFSC image...");

        PfscEncodeStats stats;
        using (var input = File.OpenRead(inputImagePath))
        using (var output = new FileStream(outputPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
        {
            long reported = -1;
            stats = PfscEncoder.Encode(input, length, output, options.ToEncoderOptions(), produced =>
            {
                // Throttle progress to whole-percent updates.
                long pct = length == 0 ? 100 : produced * 100 / length;
                if (pct != reported) { reported = pct; log($"  {pct,3}%"); }
            });
        }

        if (stats.StoredRaw)
            log("Compression produced no benefit; the image was stored uncompressed.");
        else
            log($"Done: {stats.EncodedSize:N0} bytes ({stats.GainPercent:F1}% saved, {stats.CompressedBlocks}/{stats.BlockCount} blocks compressed).");

        return new ProsperoPfscResult
        {
            OutputPath = outputPath,
            RawSize = stats.RawSize,
            EncodedSize = stats.EncodedSize,
            StoredRaw = stats.StoredRaw,
        };
    }

    /// <summary>
    /// Reverses <see cref="PackFile"/>: decompresses a PFSC image back to a flat image file.
    /// </summary>
    /// <param name="pfscPath">A PFSC image produced by this tool (or any PFSC image).</param>
    /// <param name="outputPath">Destination flat image path.</param>
    /// <param name="logger">Optional progress sink.</param>
    /// <returns>The number of logical bytes written.</returns>
    public static long Unpack(string pfscPath, string outputPath, Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pfscPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        if (!File.Exists(pfscPath))
            throw new FileNotFoundException("PFSC image was not found.", pfscPath);
        if (!IsPfsc(pfscPath))
            throw new InvalidDataException("The input file is not a PFSC image (missing 'PFSC' magic).");

        var log = logger ?? (_ => { });
        var dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        long written = 0;
        using (var mmf = MemoryMappedFile.CreateFromFile(pfscPath, FileMode.Open, mapName: null, capacity: 0, MemoryMappedFileAccess.Read))
        using (var va = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
        using (var reader = new PFSCReader(va))
        using (var output = File.Create(outputPath))
        {
            long total = reader.DataLength;
            var buf = new byte[reader.SectorSize];
            long pos = 0;
            while (pos < total)
            {
                int toRead = (int)Math.Min(buf.Length, total - pos);
                reader.Read(pos, buf, 0, toRead);
                output.Write(buf, 0, toRead);
                pos += toRead;
                written += toRead;
            }
        }

        log($"Unpacked {written:N0} bytes to {Path.GetFileName(outputPath)}.");
        return written;
    }

    /// <summary>Returns true when the file at <paramref name="path"/> begins with the PFSC magic.</summary>
    public static bool IsPfsc(string path)
    {
        using var s = File.OpenRead(path);
        Span<byte> magic = stackalloc byte[4];
        if (s.Read(magic) != 4) return false;
        // 'P','F','S','C'
        return magic[0] == 0x50 && magic[1] == 0x46 && magic[2] == 0x53 && magic[3] == 0x43;
    }
}
