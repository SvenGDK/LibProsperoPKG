// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// reader for the PS5 outer PKG container. Parses the big-endian header
// and the 0x20-byte entry-meta table, resolving each entry's name from the name table.
// This is the structured, reusable parser a creator validates its own output against.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace LibProsperoPkg.PKG;

/// <summary>Reads the outer container of a PS5 PKG file.</summary>
public static class ProsperoPkgReader
{
    /// <summary>
    /// Detects the package type from its 4-byte magic (and, for finalized images, the signed byte).
    /// Returns <see langword="null"/> when the file is not a recognisable PS5 PKG.
    /// </summary>
    public static ProsperoPkgType? DetectType(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return DetectType(fs);
    }

    /// <summary>Detects the package type from an open stream positioned anywhere (it is rewound).</summary>
    public static ProsperoPkgType? DetectType(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (stream.Length < 6) return null;

        stream.Position = 0;
        Span<byte> magic = stackalloc byte[4];
        if (stream.Read(magic) != 4) return null;

        if (magic.SequenceEqual(ProsperoPkgLayout.CntMagic))
            return ProsperoPkgType.Meta;

        if (magic.SequenceEqual(ProsperoPkgLayout.FihMagic))
        {
            stream.Position = 5;
            int signedByte = stream.ReadByte();
            return signedByte switch
            {
                0x80 => ProsperoPkgType.FullRetail,
                0x00 => ProsperoPkgType.FullDebug,
                _ => null,
            };
        }

        return null;
    }

    /// <summary>
    /// Reads and parses the outer container. For metadata (CNT) packages the full header and
    /// entry table are returned; for finalized (FIH) images only the type is populated.
    /// </summary>
    /// <exception cref="InvalidDataException">The file is not a recognisable PS5 PKG.</exception>
    public static ProsperoPkg Read(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Read(fs);
    }

    /// <inheritdoc cref="Read(string)"/>
    public static ProsperoPkg Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var type = DetectType(stream)
            ?? throw new InvalidDataException("Not a recognisable PS5 PKG (unknown magic).");

        if (type == ProsperoPkgType.Meta)
        {
            var cntHeader = ReadHeader(stream, 0);
            var cntEntries = ReadEntryTable(stream, cntHeader, 0);
            ResolveNames(stream, cntEntries, 0);
            return new ProsperoPkg { Type = type, Header = cntHeader, Entries = cntEntries };
        }

        // Finalized image (FIH): parse the little-endian header, then the embedded CNT container.
        var fih = ReadFihHeader(stream);
        long cntBase = (long)fih.EmbeddedCntOffset;
        if (cntBase <= 0 || cntBase + ProsperoPkgLayout.HeaderSize > stream.Length)
            return new ProsperoPkg { Type = type, Fih = fih };

        var header = ReadHeader(stream, cntBase);
        var entries = ReadEntryTable(stream, header, cntBase);
        ResolveNames(stream, entries, cntBase);
        return new ProsperoPkg { Type = type, Fih = fih, Header = header, Entries = entries };
    }

    private static ProsperoFihHeader ReadFihHeader(Stream stream)
    {
        byte[] buffer = new byte[0x100];
        stream.Position = 0;
        ReadExactly(stream, buffer, 0, buffer.Length);
        var span = buffer.AsSpan();
        return new ProsperoFihHeader
        {
            SignedByte = buffer[ProsperoPkgLayout.FihSignedByteOffset],
            FormatVersion = BinaryPrimitives.ReadUInt16LittleEndian(span[ProsperoPkgLayout.FihFormatVersionField..]),
            PfsImageOffset = BinaryPrimitives.ReadUInt64LittleEndian(span[ProsperoPkgLayout.FihPfsImageOffsetField..]),
            PfsImageSize = BinaryPrimitives.ReadUInt64LittleEndian(span[ProsperoPkgLayout.FihPfsImageSizeField..]),
            EmbeddedCntOffset = BinaryPrimitives.ReadUInt64LittleEndian(span[ProsperoPkgLayout.FihEmbeddedCntOffsetField..]),
        };
    }

    private static ProsperoPkgHeader ReadHeader(Stream stream, long baseOffset)
    {
        byte[] buffer = new byte[ProsperoPkgLayout.HeaderSize];
        stream.Position = baseOffset;
        ReadExactly(stream, buffer, 0, buffer.Length);
        var span = buffer.AsSpan();

        return new ProsperoPkgHeader
        {
            Magic = buffer[..4],
            Flags = BinaryPrimitives.ReadUInt32BigEndian(span[0x04..]),
            EntryCount = BinaryPrimitives.ReadUInt32BigEndian(span[0x10..]),
            ScEntryCount = BinaryPrimitives.ReadUInt16BigEndian(span[0x14..]),
            EntryTableOffset = BinaryPrimitives.ReadUInt32BigEndian(span[0x18..]),
            BodyOffset = BinaryPrimitives.ReadUInt64BigEndian(span[0x20..]),
            BodySize = BinaryPrimitives.ReadUInt64BigEndian(span[0x28..]),
            ContentId = ReadNulTrimmedAscii(span.Slice(0x40, ProsperoPkgLayout.ContentIdSize)),
            DrmType = BinaryPrimitives.ReadUInt32BigEndian(span[0x70..]),
            ContentType = BinaryPrimitives.ReadUInt32BigEndian(span[0x74..]),
            ContentFlags = BinaryPrimitives.ReadUInt32BigEndian(span[0x78..]),
        };
    }

    private static List<ProsperoPkgEntry> ReadEntryTable(Stream stream, ProsperoPkgHeader header, long baseOffset)
    {
        // Guard against malformed headers claiming an absurd number of entries.
        long maxEntries = (stream.Length - (baseOffset + header.EntryTableOffset)) / ProsperoPkgLayout.EntryMetaSize;
        if (header.EntryCount > maxEntries || header.EntryCount > 0x10000)
            throw new InvalidDataException("PS5 PKG entry table is malformed (entry count out of range).");

        var entries = new List<ProsperoPkgEntry>((int)header.EntryCount);
        byte[] record = new byte[ProsperoPkgLayout.EntryMetaSize];
        stream.Position = baseOffset + header.EntryTableOffset;

        for (uint i = 0; i < header.EntryCount; i++)
        {
            ReadExactly(stream, record, 0, record.Length);
            var span = record.AsSpan();
            uint rawId = BinaryPrimitives.ReadUInt32BigEndian(span);
            entries.Add(new ProsperoPkgEntry
            {
                RawId = rawId,
                Id = Enum.IsDefined(typeof(ProsperoEntryId), rawId) ? (ProsperoEntryId)rawId : ProsperoEntryId.Unknown,
                NameTableOffset = BinaryPrimitives.ReadUInt32BigEndian(span[0x04..]),
                Flags1 = BinaryPrimitives.ReadUInt32BigEndian(span[0x08..]),
                Flags2 = BinaryPrimitives.ReadUInt32BigEndian(span[0x0C..]),
                DataOffset = BinaryPrimitives.ReadUInt32BigEndian(span[0x10..]),
                DataSize = BinaryPrimitives.ReadUInt32BigEndian(span[0x14..]),
            });
        }

        return entries;
    }

    private static void ResolveNames(Stream stream, List<ProsperoPkgEntry> entries, long baseOffset)
    {
        // The name table is the data of the ENTRY_NAMES entry (id 0x0200): a block of
        // NUL-terminated strings indexed by each entry's NameTableOffset.
        ProsperoPkgEntry? nameTable = null;
        foreach (var e in entries)
        {
            if (e.Id == ProsperoEntryId.EntryNames) { nameTable = e; break; }
        }
        if (nameTable is null || nameTable.DataSize == 0) return;

        byte[] names = new byte[nameTable.DataSize];
        stream.Position = baseOffset + nameTable.DataOffset;
        ReadExactly(stream, names, 0, names.Length);

        foreach (var e in entries)
        {
            if (e.NameTableOffset == 0 || e.NameTableOffset >= names.Length) continue;
            int start = (int)e.NameTableOffset;
            int end = start;
            while (end < names.Length && names[end] != 0) end++;
            e.Name = Encoding.ASCII.GetString(names, start, end - start);
        }
    }

    private static string ReadNulTrimmedAscii(ReadOnlySpan<byte> span)
    {
        int len = span.IndexOf((byte)0);
        if (len < 0) len = span.Length;
        return Encoding.ASCII.GetString(span[..len]);
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
    {
        int total = 0;
        while (total < count)
        {
            int read = stream.Read(buffer, offset + total, count - total);
            if (read == 0)
                throw new EndOfStreamException("Unexpected end of PS5 PKG while reading container.");
            total += read;
        }
    }
}
