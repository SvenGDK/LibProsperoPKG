// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK

using System;
using System.Collections.Generic;

namespace LibProsperoPkg.PKG;

/// <summary>
/// The parsed outer-container header of a PS5 PKG. Only the fields relevant to
/// container inspection and validation are exposed; all multi-byte values are big-endian on disk.
/// </summary>
public sealed class ProsperoPkgHeader
{
    /// <summary>The 4-byte magic, either <c>\x7FCNT</c> or <c>\x7FFIH</c>.</summary>
    public required byte[] Magic { get; init; }

    /// <summary>Package flags (header offset 0x04).</summary>
    public uint Flags { get; init; }

    /// <summary>Total number of entries in the entry table (header offset 0x10).</summary>
    public uint EntryCount { get; init; }

    /// <summary>Number of system-container entries (header offset 0x14).</summary>
    public ushort ScEntryCount { get; init; }

    /// <summary>Byte offset of the entry-meta table (header offset 0x18).</summary>
    public uint EntryTableOffset { get; init; }

    /// <summary>Offset of the package body (header offset 0x20).</summary>
    public ulong BodyOffset { get; init; }

    /// <summary>Size of the package body (header offset 0x28).</summary>
    public ulong BodySize { get; init; }

    /// <summary>The 0x30-byte content id (header offset 0x40), NUL-trimmed.</summary>
    public string ContentId { get; init; } = "";

    /// <summary>The DRM type (header offset 0x70).</summary>
    public uint DrmType { get; init; }

    /// <summary>The content type (header offset 0x74).</summary>
    public uint ContentType { get; init; }
}

/// <summary>
/// A single entry-meta record from the PS5 PKG entry table (0x20 bytes on disk).
/// </summary>
public sealed class ProsperoPkgEntry
{
    /// <summary>The entry id.</summary>
    public ProsperoEntryId Id { get; init; }

    /// <summary>The raw 32-bit entry id (some packages use ids outside <see cref="ProsperoEntryId"/>).</summary>
    public uint RawId { get; init; }

    /// <summary>Offset of this entry's name within the name table.</summary>
    public uint NameTableOffset { get; init; }

    /// <summary>First flags word; bit 31 marks an encrypted entry.</summary>
    public uint Flags1 { get; init; }

    /// <summary>Second flags word; bits 12-15 hold the key index.</summary>
    public uint Flags2 { get; init; }

    /// <summary>Byte offset of this entry's data within the package.</summary>
    public uint DataOffset { get; init; }

    /// <summary>Size in bytes of this entry's data.</summary>
    public uint DataSize { get; init; }

    /// <summary>The resolved entry name (from the name table), when available.</summary>
    public string? Name { get; set; }

    /// <summary>The key index used to derive this entry's encryption key.</summary>
    public uint KeyIndex => (Flags2 & 0xF000) >> 12;

    /// <summary>True when this entry's data is encrypted.</summary>
    public bool Encrypted => (Flags1 & ProsperoPkgLayout.EntryFlagEncrypted) != 0;
}

/// <summary>
/// The parsed header of a finalized (FIH) image. Unlike the CNT header, every multi-byte
/// value here is <b>little-endian</b> on disk. A finalized image is laid out as
/// <c>[FIH header + digest table : 0x10000][encrypted PFS image : <see cref="PfsImageSize"/>]
/// [embedded CNT metadata : at <see cref="EmbeddedCntOffset"/>]</c>; the embedded CNT's own
/// <c>pfs_image_offset</c> points back to the shared image at <see cref="PfsImageOffset"/>.
/// </summary>
public sealed class ProsperoFihHeader
{
    /// <summary>The signed byte (FIH offset 0x05): <c>0x80</c> = official, <c>0x00</c> = debug.</summary>
    public byte SignedByte { get; init; }

    /// <summary>True when this is an official finalized image (signed byte 0x80).</summary>
    public bool IsOfficial => SignedByte == 0x80;

    /// <summary>Offset of the shared encrypted PFS image within the finalized file (FIH offset 0x10).</summary>
    public ulong PfsImageOffset { get; init; }

    /// <summary>Size in bytes of the shared encrypted PFS image (FIH offset 0x18).</summary>
    public ulong PfsImageSize { get; init; }

    /// <summary>Offset of the embedded CNT metadata container (FIH offset 0x58).</summary>
    public ulong EmbeddedCntOffset { get; init; }
}

/// <summary>The fully parsed outer container: header plus the resolved entry list.</summary>
public sealed class ProsperoPkg
{
    /// <summary>The detected package type.</summary>
    public required ProsperoPkgType Type { get; init; }

    /// <summary>
    /// The parsed CNT header. For a metadata (CNT) package this is the file header; for a
    /// finalized (FIH) image this is the header of the <b>embedded</b> CNT container.
    /// </summary>
    public ProsperoPkgHeader? Header { get; init; }

    /// <summary>
    /// The entry-meta table records. For a finalized (FIH) image these come from the embedded
    /// CNT container.
    /// </summary>
    public IReadOnlyList<ProsperoPkgEntry> Entries { get; init; } = Array.Empty<ProsperoPkgEntry>();

    /// <summary>The parsed finalized-image header, or <see langword="null"/> for a CNT package.</summary>
    public ProsperoFihHeader? Fih { get; init; }
}
