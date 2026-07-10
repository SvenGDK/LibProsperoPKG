// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Parser for the disc-backup reassembly manifest (app.json): the split-file list plus the
// SHA-256 digests used to verify the reassembled package and the PlayGo chunk-CRC file.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace LibProsperoPkg.DiscBackup;

/// <summary>One split piece of a disc-backup package.</summary>
public sealed class ProsperoDiscBackupPiece
{
    /// <summary>The disc number this piece belongs to.</summary>
    public int DiscNumber { get; init; }

    /// <summary>The byte offset of this piece within the reassembled package.</summary>
    public long FileOffset { get; init; }

    /// <summary>The size in bytes of this piece.</summary>
    public long FileSize { get; init; }

    /// <summary>The piece file name, relative to the manifest directory (e.g. <c>app_0.pkg</c>).</summary>
    public required string Url { get; init; }
}

/// <summary>
/// The parsed <c>app.json</c> manifest describing how a split disc-backup package is
/// reassembled and verified.
/// </summary>
public sealed class ProsperoDiscBackupManifest
{
    /// <summary>The number of split piece files.</summary>
    public int NumberOfSplitFiles { get; init; }

    /// <summary>The size in bytes of the reassembled package.</summary>
    public long OriginalFileSize { get; init; }

    /// <summary>Hex SHA-256 of the reassembled package.</summary>
    public string PackageDigest { get; init; } = "";

    /// <summary>The split pieces, in manifest order.</summary>
    public IReadOnlyList<ProsperoDiscBackupPiece> Pieces { get; init; } = Array.Empty<ProsperoDiscBackupPiece>();

    /// <summary>Hex SHA-256 of the PlayGo chunk-CRC file (<c>app.crc</c>).</summary>
    public string PlaygoChunkCrcHashValue { get; init; } = "";

    /// <summary>The PlayGo chunk-CRC file name, relative to the manifest directory.</summary>
    public string PlaygoChunkCrcUrl { get; init; } = "";

    /// <summary>Parses a manifest from a JSON string.</summary>
    /// <exception cref="InvalidDataException">The JSON root is not an object.</exception>
    public static ProsperoDiscBackupManifest Parse(string json)
    {
        ArgumentException.ThrowIfNullOrEmpty(json);
        using var doc = JsonDocument.Parse(json);
        return FromRoot(doc.RootElement);
    }

    /// <summary>Reads and parses an <c>app.json</c> manifest file.</summary>
    public static ProsperoDiscBackupManifest Read(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        using var doc = JsonDocument.Parse(bytes);
        return FromRoot(doc.RootElement);
    }

    private static ProsperoDiscBackupManifest FromRoot(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("app.json root is not a JSON object.");

        var pieces = new List<ProsperoDiscBackupPiece>();
        if (root.TryGetProperty("pieces", out JsonElement arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement e in arr.EnumerateArray())
            {
                if (e.ValueKind != JsonValueKind.Object) continue;
                pieces.Add(new ProsperoDiscBackupPiece
                {
                    DiscNumber = Int(e, "discNumber"),
                    FileOffset = Long(e, "fileOffset"),
                    FileSize = Long(e, "fileSize"),
                    Url = Str(e, "url"),
                });
            }
        }

        return new ProsperoDiscBackupManifest
        {
            NumberOfSplitFiles = Int(root, "numberOfSplitFiles"),
            OriginalFileSize = Long(root, "originalFileSize"),
            PackageDigest = Str(root, "packageDigest"),
            Pieces = pieces,
            PlaygoChunkCrcHashValue = Str(root, "playgoChunkCrcHashValue"),
            PlaygoChunkCrcUrl = Str(root, "playgoChunkCrcUrl"),
        };
    }

    private static int Int(JsonElement o, string name) =>
        o.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out int i) ? i : 0;

    private static long Long(JsonElement o, string name) =>
        o.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out long l) ? l : 0;

    private static string Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
}
