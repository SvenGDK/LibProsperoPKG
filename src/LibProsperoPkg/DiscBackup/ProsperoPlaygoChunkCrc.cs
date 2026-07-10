// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Parser and verifier for the disc-backup PlayGo chunk-CRC file (app.crc / playgo-chunk.crc).
// The file is a headerless array of little-endian CRC-32C (Castagnoli) values, one per 64 KiB
// (0x10000) chunk of the reassembled package.

using LibProsperoPkg.Util;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace LibProsperoPkg.DiscBackup;

/// <summary>
/// The parsed PlayGo chunk-CRC table: one <see cref="ProsperoCrc32C"/> value per 64 KiB chunk
/// of the reassembled package, in chunk order.
/// </summary>
public sealed class ProsperoPlaygoChunkCrc
{
    /// <summary>The chunk size each CRC covers (64 KiB).</summary>
    public const int ChunkSize = 0x10000;

    private readonly uint[] _crcs;

    private ProsperoPlaygoChunkCrc(uint[] crcs) => _crcs = crcs;

    /// <summary>The per-chunk CRC-32C values, in chunk order.</summary>
    public IReadOnlyList<uint> ChunkCrcs => _crcs;

    /// <summary>The number of chunks (CRC values) in the table.</summary>
    public int Count => _crcs.Length;

    /// <summary>The CRC-32C for chunk <paramref name="index"/>.</summary>
    public uint this[int index] => _crcs[index];

    /// <summary>Parses the headerless little-endian CRC-32C array.</summary>
    /// <exception cref="InvalidDataException">The length is not a multiple of 4.</exception>
    public static ProsperoPlaygoChunkCrc Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length % sizeof(uint) != 0)
            throw new InvalidDataException("A playgo-chunk.crc file must be a multiple of 4 bytes.");

        var crcs = new uint[data.Length / sizeof(uint)];
        for (int i = 0; i < crcs.Length; i++)
            crcs[i] = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(i * sizeof(uint), sizeof(uint)));
        return new ProsperoPlaygoChunkCrc(crcs);
    }

    /// <summary>Reads and parses an <c>app.crc</c> / <c>playgo-chunk.crc</c> file.</summary>
    public static ProsperoPlaygoChunkCrc Read(string path) => Parse(File.ReadAllBytes(path));

    /// <summary>
    /// Verifies every chunk of <paramref name="package"/> against this table by recomputing each
    /// 64 KiB CRC-32C from the current stream position. Returns <see langword="true"/> when all
    /// chunks match; otherwise <paramref name="mismatchChunk"/> is the index of the first bad
    /// (or missing) chunk.
    /// </summary>
    public bool VerifyPackage(Stream package, out int mismatchChunk, IProgress<long>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(package);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ChunkSize);
        try
        {
            long total = 0;
            for (int i = 0; i < _crcs.Length; i++)
            {
                int read = ReadChunk(package, buffer);
                if (read == 0)
                {
                    mismatchChunk = i;
                    return false;
                }
                if (ProsperoCrc32C.Compute(buffer.AsSpan(0, read)) != _crcs[i])
                {
                    mismatchChunk = i;
                    return false;
                }
                total += read;
                progress?.Report(total);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        mismatchChunk = -1;
        return true;
    }

    private static int ReadChunk(Stream stream, byte[] buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = stream.Read(buffer, total, buffer.Length - total);
            if (read == 0) break;
            total += read;
        }
        return total;
    }
}
