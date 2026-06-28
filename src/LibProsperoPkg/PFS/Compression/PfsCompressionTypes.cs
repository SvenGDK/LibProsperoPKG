// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Types for the PS5 PFS *compression file format*.
//
// These mirror the target format's numeric values byte-for-byte. They intentionally do NOT describe the PFS
// *filesystem* superblock version, which is a distinct, unrelated version number.
#nullable enable
namespace LibProsperoPkg.PFS.Compression;

/// <summary>
/// Compression algorithm recorded in the PFS compressed-file header.
/// Only <see cref="Kraken"/> is supported for compressed-file creation.
/// </summary>
public enum CompressionAlgorithm
{
    /// <summary>Fast Zlib. <b>Not</b> supported for PFS compressed-file creation.</summary>
    QuickZ = 0,

    /// <summary>High-quality Zlib. <b>Not</b> supported for PFS compressed-file creation.</summary>
    Zlib = 1,

    /// <summary>Kraken. The only supported algorithm for PFS compressed-file creation.</summary>
    Kraken = 2,
}

/// <summary>
/// PFS compression file-format version recorded in the container header.
/// </summary>
/// <remarks>
/// This is the version of the <i>compression container</i>, not the PFS filesystem superblock
/// version. Only <see cref="Version2"/> and <see cref="Version3"/> are valid for PS5.
/// </remarks>
public enum PfsCompressionFormat
{
    /// <summary>PFSv0. Deprecated.</summary>
    Version0 = 0,

    /// <summary>PFSv1. Deprecated.</summary>
    Version1 = 1,

    /// <summary>PFSv2. A PS5 compression file format.</summary>
    Version2 = 2,

    /// <summary>
    /// PFSv3. The <b>default</b> PS5 compression file format. Supports region hints and
    /// pre-compression shuffles for a greater compression ratio and includes metadata for
    /// efficient conversion to package format (i.e. <c>naps_pkg_layout.dat</c>).
    /// </summary>
    Version3 = 3,
}

/// <summary>
/// Pre-compression shuffle pattern recorded in the container metadata.
/// A shuffle groups bytes at given positions within fixed 8-byte or 16-byte vectors together
/// (a structure-of-arrays de-interleave) so that similar bytes become adjacent and compress better.
/// </summary>
public enum PfsShufflePattern
{
    /// <summary>An invalid shuffle pattern.</summary>
    Invalid = -1,

    /// <summary>No shuffle is applied.</summary>
    None = 0,

    /// <summary>Tap 2x 4 bytes with an 8 byte stride.</summary>
    Shuffle44 = 1,

    /// <summary>Tap 2x 2 bytes then 4 bytes with an 8 byte stride.</summary>
    Shuffle224 = 2,

    /// <summary>Tap 2x 1 bytes then 6 bytes with an 8 byte stride.</summary>
    Shuffle116 = 3,

    /// <summary>Tap 8x 1 bytes with an 8 byte stride.</summary>
    Shuffle11111111 = 4,

    /// <summary>Tap 8 bytes, 2x 2 bytes then 4 bytes with a 16 byte stride.</summary>
    Shuffle8224 = 5,

    /// <summary>Tap 2x 1 bytes, 6 bytes, 2x 2 bytes then 4 bytes with a 16 byte stride.</summary>
    Shuffle116224 = 6,

    /// <summary>Tap 2x 1 bytes, 6 bytes, 2x 1 bytes then 6 bytes with a 16 byte stride.</summary>
    Shuffle116116 = 7,

    /// <summary>Tap 4x 4 bytes with a 16 byte stride.</summary>
    Shuffle4444 = 8,

    /// <summary>Tap 2x 8 bytes with a 16 byte stride.</summary>
    Shuffle88 = 9,

    /// <summary>Tap 8 bytes then 2x 4 bytes with a 16 byte stride.</summary>
    Shuffle844 = 10,

    /// <summary>Tap 2 bytes then 6 bytes with an 8 byte stride.</summary>
    Shuffle26 = 11,

    /// <summary>Tap 2 bytes, 6 bytes, 2 bytes then 6 bytes with a 16 byte stride.</summary>
    Shuffle2626 = 12,
}

/// <summary>
/// Constants for PFS Kraken compression.
/// </summary>
public static class PfsCompressionConstants
{
    /// <summary>Number of sliding-window bits used for Kraken (the only valid value).</summary>
    public const uint KrakenWindowBits = 18;

    /// <summary>
    /// The default compression level used for PFSv3 containers (<c>"compression level": 7</c>).
    /// </summary>
    public const uint DefaultKrakenLevel = 7;

    /// <summary>Lowest (fastest) accepted Kraken level, encoded as an unsigned value.</summary>
    public const uint KrakenLevelFastest = unchecked((uint)-4);

    /// <summary>Highest accepted Kraken level.</summary>
    public const uint KrakenLevelMax = 9;

    /// <summary>Returns <c>true</c> when <paramref name="level"/> is an accepted Kraken level.</summary>
    public static bool IsValidKrakenLevel(uint level)
        => level <= KrakenLevelMax
           || level is KrakenLevelFastest
                    or unchecked((uint)-3)
                    or unchecked((uint)-2)
                    or unchecked((uint)-1);
}
