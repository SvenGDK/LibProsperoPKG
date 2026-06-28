// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// writer for the PS5 outer PKG/CNT container: the exact inverse of
// ProsperoPkgReader. It assembles a big-endian CNT header, the 0x20-byte entry-meta table and
// the ENTRY_NAMES (0x0200) name table, so a container produced here round-trips through the
// reader field-for-field. This is the write side of the PS5 PKG library and the harness
// the signer/builder use to self-validate the container layout in-process.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace LibProsperoPkg.PKG;

/// <summary>A single entry to place in a PS5 CNT container, with its name and payload.</summary>
public sealed class ProsperoPkgWriterEntry
{
    /// <summary>The 32-bit entry id (see <see cref="ProsperoEntryId"/>).</summary>
    public required uint Id { get; init; }

    /// <summary>The entry name written into the ENTRY_NAMES table (empty for unnamed entries).</summary>
    public string Name { get; init; } = "";

    /// <summary>The entry payload.</summary>
    public byte[] Data { get; init; } = Array.Empty<byte>();

    /// <summary>First flags word; bit 31 marks an encrypted entry.</summary>
    public uint Flags1 { get; init; }

    /// <summary>Second flags word; bits 12-15 hold the key index.</summary>
    public uint Flags2 { get; init; }
}

/// <summary>Describes the CNT container to assemble.</summary>
public sealed class ProsperoPkgWriterOptions
{
    /// <summary>The 36-character content id written at header offset 0x40.</summary>
    public string ContentId { get; init; } = "";

    /// <summary>Package flags (header offset 0x04).</summary>
    public uint Flags { get; init; }

    /// <summary>The DRM type (header offset 0x70).</summary>
    public uint DrmType { get; init; }

    /// <summary>The content type (header offset 0x74).</summary>
    public uint ContentType { get; init; }

    /// <summary>Number of system-container entries (header offset 0x14).</summary>
    public ushort ScEntryCount { get; init; }

    /// <summary>The entries to write (the ENTRY_NAMES table is generated automatically).</summary>
    public IReadOnlyList<ProsperoPkgWriterEntry> Entries { get; init; } = Array.Empty<ProsperoPkgWriterEntry>();
}

/// <summary>Writes the outer container of a PS5 PKG file.</summary>
public static class ProsperoPkgWriter
{
    /// <summary>Assembles a CNT container into a byte array.</summary>
    /// <exception cref="ArgumentException">A required option is missing or malformed.</exception>
    public static byte[] Write(ProsperoPkgWriterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.ContentId) || options.ContentId.Length > ProsperoPkgLayout.ContentIdSize)
            throw new ArgumentException(
                $"Content id is missing or exceeds the {ProsperoPkgLayout.ContentIdSize}-byte field.", nameof(options));

        // Build the ordered entry list, inserting an ENTRY_NAMES entry if the caller did not.
        var entries = options.Entries.ToList();
        bool hasNameTable = entries.Any(e => e.Id == (uint)ProsperoEntryId.EntryNames);

        // Compose the name table: a leading NUL (so offset 0 means "unnamed") followed by the
        // NUL-terminated name of every named entry.
        var nameOffsets = new Dictionary<int, uint>();
        using var nameStream = new MemoryStream();
        nameStream.WriteByte(0);
        for (int i = 0; i < entries.Count; i++)
        {
            if (string.IsNullOrEmpty(entries[i].Name)) continue;
            nameOffsets[i] = (uint)nameStream.Position;
            var bytes = Encoding.ASCII.GetBytes(entries[i].Name);
            nameStream.Write(bytes, 0, bytes.Length);
            nameStream.WriteByte(0);
        }
        byte[] nameTable = nameStream.ToArray();

        if (!hasNameTable)
        {
            entries.Add(new ProsperoPkgWriterEntry
            {
                Id = (uint)ProsperoEntryId.EntryNames,
                Data = nameTable,
            });
        }
        else
        {
            // Replace the caller's placeholder ENTRY_NAMES payload with the generated table.
            int idx = entries.FindIndex(e => e.Id == (uint)ProsperoEntryId.EntryNames);
            var existing = entries[idx];
            entries[idx] = new ProsperoPkgWriterEntry
            {
                Id = existing.Id,
                Name = existing.Name,
                Flags1 = existing.Flags1,
                Flags2 = existing.Flags2,
                Data = nameTable,
            };
        }

        int entryCount = entries.Count;
        uint entryTableOffset = ProsperoPkgLayout.HeaderSize;
        uint dataStart = entryTableOffset + (uint)(entryCount * ProsperoPkgLayout.EntryMetaSize);

        // Lay out the entry data sequentially, 16-byte aligned.
        var dataOffsets = new uint[entryCount];
        uint cursor = dataStart;
        for (int i = 0; i < entryCount; i++)
        {
            cursor = Align(cursor, 16);
            dataOffsets[i] = cursor;
            cursor += (uint)entries[i].Data.Length;
        }
        uint bodyEnd = Align(cursor, 16);

        byte[] image = new byte[bodyEnd];

        // Header.
        var header = image.AsSpan(0, ProsperoPkgLayout.HeaderSize);
        ProsperoPkgLayout.CntMagic.CopyTo(header);
        BinaryPrimitives.WriteUInt32BigEndian(header[0x04..], options.Flags);
        BinaryPrimitives.WriteUInt32BigEndian(header[0x10..], (uint)entryCount);
        BinaryPrimitives.WriteUInt16BigEndian(header[0x14..], options.ScEntryCount);
        BinaryPrimitives.WriteUInt32BigEndian(header[0x18..], entryTableOffset);
        BinaryPrimitives.WriteUInt64BigEndian(header[0x20..], dataStart);
        BinaryPrimitives.WriteUInt64BigEndian(header[0x28..], bodyEnd - dataStart);
        Encoding.ASCII.GetBytes(options.ContentId).CopyTo(header[0x40..]);
        BinaryPrimitives.WriteUInt32BigEndian(header[0x70..], options.DrmType);
        BinaryPrimitives.WriteUInt32BigEndian(header[0x74..], options.ContentType);

        // Entry table + data.
        for (int i = 0; i < entryCount; i++)
        {
            var e = entries[i];
            int recOff = (int)entryTableOffset + i * ProsperoPkgLayout.EntryMetaSize;
            var rec = image.AsSpan(recOff, ProsperoPkgLayout.EntryMetaSize);
            BinaryPrimitives.WriteUInt32BigEndian(rec, e.Id);
            BinaryPrimitives.WriteUInt32BigEndian(rec[0x04..], nameOffsets.TryGetValue(i, out var no) ? no : 0);
            BinaryPrimitives.WriteUInt32BigEndian(rec[0x08..], e.Flags1);
            BinaryPrimitives.WriteUInt32BigEndian(rec[0x0C..], e.Flags2);
            BinaryPrimitives.WriteUInt32BigEndian(rec[0x10..], dataOffsets[i]);
            BinaryPrimitives.WriteUInt32BigEndian(rec[0x14..], (uint)e.Data.Length);

            if (e.Data.Length > 0)
                e.Data.CopyTo(image.AsSpan((int)dataOffsets[i]));
        }

        return image;
    }

    /// <summary>Assembles a CNT container and writes it to <paramref name="path"/>.</summary>
    public static void WriteToFile(ProsperoPkgWriterOptions options, string path) =>
        File.WriteAllBytes(path, Write(options));

    private static uint Align(uint value, uint alignment) =>
        (value + alignment - 1) / alignment * alignment;
}
