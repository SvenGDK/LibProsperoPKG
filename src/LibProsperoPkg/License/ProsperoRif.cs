// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Reader, writer and creator for the PS5 per-title license file (license/rif).
// A RIF (Rights Information File) is a fixed 0x400-byte record that binds a content-id
// to an encrypted 448-byte entitlement/key blob. The fixed header is big-endian on disk;
// multi-title discs concatenate one record per sub-title.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace LibProsperoPkg.License;

/// <summary>
/// A single PS5 <c>rif</c> license record (0x400 bytes). Parses and rebuilds every fixed
/// field (magic, version, flags, <c>QPaC</c> tag, expiry, content-id, format descriptor and
/// the raw 448-byte encrypted key blob). Use <see cref="Parse"/> / <see cref="Read"/> to read
/// one record, <see cref="ReadAll(Stream)"/> for a multi-title file, and <see cref="Create"/>
/// to build a structural record for a content-id.
/// </summary>
public sealed class ProsperoRif
{
    /// <summary>Size in bytes of a single RIF record.</summary>
    public const int RecordSize = 0x400;

    /// <summary>Size in bytes of the content-id field (offset 0x20).</summary>
    public const int ContentIdSize = 0x24;

    /// <summary>Offset of the encrypted key blob within the record.</summary>
    public const int KeyBlobOffset = 0x240;

    /// <summary>Size in bytes of the encrypted key blob (offset 0x240 to end of record).</summary>
    public const int KeyBlobSize = 0x1C0;

    /// <summary>The expected header version (0x0002).</summary>
    public const ushort CurrentVersion = 2;

    /// <summary>The non-expiring expiry sentinel (<see cref="long.MaxValue"/>).</summary>
    public const long NeverExpires = 0x7FFFFFFFFFFFFFFF;

    private const int VersionField = 0x04;
    private const int FlagsField = 0x06;
    private const int FormatTagField = 0x14;
    private const int ExpiryField = 0x18;
    private const int ContentIdField = 0x20;
    private const int FormatDescriptorField = 0x50;
    private const int FormatDescriptorSize = 0x08;
    private const int EntryCountField = 0x60;

    /// <summary>Record magic: <c>52 49 46 00</c> ("RIF\0").</summary>
    public static ReadOnlySpan<byte> Magic => [0x52, 0x49, 0x46, 0x00];

    /// <summary>The constant format tag at offset 0x14: <c>51 50 61 43</c> ("QPaC").</summary>
    public static ReadOnlySpan<byte> FormatTag => [0x51, 0x50, 0x61, 0x43];

    /// <summary>The constant format descriptor at offset 0x50.</summary>
    public static ReadOnlySpan<byte> DefaultFormatDescriptor => [0x01, 0x04, 0x00, 0x10, 0x00, 0x20, 0x00, 0x03];

    /// <summary>Header version (offset 0x04, big-endian). Expected to be <see cref="CurrentVersion"/>.</summary>
    public ushort Version { get; init; } = CurrentVersion;

    /// <summary>Header flags (offset 0x06, big-endian). <c>0xFFFF</c> observed.</summary>
    public ushort Flags { get; init; } = 0xFFFF;

    /// <summary>Expiry / timestamp (offset 0x18, big-endian). <see cref="NeverExpires"/> = non-expiring.</summary>
    public long Expiry { get; init; } = NeverExpires;

    /// <summary>The 36-char content-id (offset 0x20), NUL-trimmed.</summary>
    public required string ContentId { get; init; }

    /// <summary>The 8-byte format descriptor (offset 0x50).</summary>
    public byte[] FormatDescriptor { get; init; } = DefaultFormatDescriptor.ToArray();

    /// <summary>The entry-count / flag field (offset 0x60, big-endian). <c>1</c> observed.</summary>
    public ulong EntryCount { get; init; } = 1;

    /// <summary>The raw 448-byte encrypted key blob (offset 0x240). Encrypted with console secrets.</summary>
    public byte[] KeyBlob { get; init; } = new byte[KeyBlobSize];

    /// <summary>True when <see cref="Expiry"/> is the non-expiring sentinel.</summary>
    public bool IsNonExpiring => Expiry == NeverExpires;

    /// <summary>True when the key blob is non-zero (a real entitlement blob is present).</summary>
    public bool HasKeyBlob => !IsAllZero(KeyBlob);

    /// <summary>
    /// The title-id extracted from <see cref="ContentId"/> (the token between the label prefix
    /// and <c>_00</c>, e.g. <c>PPSA00000</c>), or <see langword="null"/> when it cannot be parsed.
    /// </summary>
    public string? TitleId
    {
        get
        {
            int dash = ContentId.IndexOf('-', StringComparison.Ordinal);
            if (dash < 0 || dash + 1 >= ContentId.Length) return null;
            int underscore = ContentId.IndexOf('_', dash + 1);
            if (underscore < 0) return null;
            return ContentId.Substring(dash + 1, underscore - dash - 1);
        }
    }

    /// <summary>
    /// The service label extracted from <see cref="ContentId"/> (the token before the first
    /// <c>-</c>, e.g. <c>EP0082</c> or <c>UP0001</c>), or <see langword="null"/> when it cannot be
    /// parsed. This is the identifier the verify path reports as the per-record <c>ServiceID</c>.
    /// </summary>
    public string? ServiceLabel
    {
        get
        {
            int dash = ContentId.IndexOf('-', StringComparison.Ordinal);
            return dash > 0 ? ContentId[..dash] : null;
        }
    }

    /// <summary>Parses a single RIF record from the first <see cref="RecordSize"/> bytes of <paramref name="record"/>.</summary>
    /// <exception cref="ArgumentException">The span is shorter than one record.</exception>
    /// <exception cref="InvalidDataException">The record magic is not "RIF\0".</exception>
    public static ProsperoRif Parse(ReadOnlySpan<byte> record)
    {
        if (record.Length < RecordSize)
            throw new ArgumentException($"A RIF record needs {RecordSize} bytes.", nameof(record));

        record = record[..RecordSize];
        if (!record[..4].SequenceEqual(Magic))
            throw new InvalidDataException("Not a RIF record (unexpected magic).");

        return new ProsperoRif
        {
            Version = BinaryPrimitives.ReadUInt16BigEndian(record[VersionField..]),
            Flags = BinaryPrimitives.ReadUInt16BigEndian(record[FlagsField..]),
            Expiry = BinaryPrimitives.ReadInt64BigEndian(record[ExpiryField..]),
            ContentId = ReadNulTrimmedAscii(record.Slice(ContentIdField, ContentIdSize)),
            FormatDescriptor = record.Slice(FormatDescriptorField, FormatDescriptorSize).ToArray(),
            EntryCount = BinaryPrimitives.ReadUInt64BigEndian(record[EntryCountField..]),
            KeyBlob = record.Slice(KeyBlobOffset, KeyBlobSize).ToArray(),
        };
    }

    /// <summary>Reads one RIF record from <paramref name="stream"/> at its current position.</summary>
    public static ProsperoRif Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        byte[] record = new byte[RecordSize];
        ReadExactly(stream, record);
        return Parse(record);
    }

    /// <summary>Reads every 0x400-byte record from a (single- or multi-title) RIF file.</summary>
    public static IReadOnlyList<ProsperoRif> ReadAll(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return ReadAll(fs);
    }

    /// <summary>Reads every 0x400-byte record from a (single- or multi-title) RIF stream.</summary>
    /// <exception cref="InvalidDataException">The stream length is not a whole number of records.</exception>
    public static IReadOnlyList<ProsperoRif> ReadAll(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        long remaining = stream.Length - stream.Position;
        if (remaining < RecordSize || remaining % RecordSize != 0)
            throw new InvalidDataException($"A RIF file must be a positive multiple of {RecordSize} bytes.");

        int count = (int)(remaining / RecordSize);
        var list = new List<ProsperoRif>(count);
        for (int i = 0; i < count; i++)
            list.Add(Read(stream));
        return list;
    }

    /// <summary>
    /// Builds a structural RIF for <paramref name="contentId"/>. The 448-byte
    /// <paramref name="keyBlob"/> (if supplied) is copied verbatim; when omitted the blob is
    /// left zero. A record built without a supplied blob is only valid for the fake/debug path or as a template
    /// whose blob comes from an existing license — a retail entitlement blob cannot be forged.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="contentId"/> is empty/too long or the blob is too large.</exception>
    public static ProsperoRif Create(string contentId, byte[]? keyBlob = null, long expiry = NeverExpires)
    {
        ArgumentException.ThrowIfNullOrEmpty(contentId);
        if (Encoding.ASCII.GetByteCount(contentId) > ContentIdSize)
            throw new ArgumentException($"A content-id is at most {ContentIdSize} bytes.", nameof(contentId));
        if (keyBlob is not null && keyBlob.Length > KeyBlobSize)
            throw new ArgumentException($"A RIF key blob is at most {KeyBlobSize} bytes.", nameof(keyBlob));

        byte[] blob = new byte[KeyBlobSize];
        keyBlob?.CopyTo(blob, 0);

        return new ProsperoRif
        {
            Version = CurrentVersion,
            Flags = 0xFFFF,
            Expiry = expiry,
            ContentId = contentId,
            FormatDescriptor = DefaultFormatDescriptor.ToArray(),
            EntryCount = 1,
            KeyBlob = blob,
        };
    }

    /// <summary>Serialises this record to a new <see cref="RecordSize"/>-byte array.</summary>
    public byte[] ToBytes()
    {
        byte[] record = new byte[RecordSize];
        var span = record.AsSpan();

        Magic.CopyTo(span);
        BinaryPrimitives.WriteUInt16BigEndian(span[VersionField..], Version);
        BinaryPrimitives.WriteUInt16BigEndian(span[FlagsField..], Flags);
        FormatTag.CopyTo(span[FormatTagField..]);
        BinaryPrimitives.WriteInt64BigEndian(span[ExpiryField..], Expiry);

        int idBytes = Math.Min(Encoding.ASCII.GetByteCount(ContentId), ContentIdSize);
        Encoding.ASCII.GetBytes(ContentId).AsSpan(0, idBytes).CopyTo(span[ContentIdField..]);

        FormatDescriptor.AsSpan(0, Math.Min(FormatDescriptor.Length, FormatDescriptorSize))
            .CopyTo(span[FormatDescriptorField..]);
        BinaryPrimitives.WriteUInt64BigEndian(span[EntryCountField..], EntryCount);
        KeyBlob.AsSpan(0, Math.Min(KeyBlob.Length, KeyBlobSize)).CopyTo(span[KeyBlobOffset..]);

        return record;
    }

    /// <summary>Writes this record to <paramref name="stream"/> at its current position.</summary>
    public void Write(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        stream.Write(ToBytes());
    }

    /// <summary>Writes one or more records to <paramref name="stream"/> as a multi-title RIF.</summary>
    public static void WriteAll(Stream stream, IEnumerable<ProsperoRif> records)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(records);
        foreach (ProsperoRif rif in records)
            rif.Write(stream);
    }

    /// <summary>Writes one or more records to <paramref name="path"/> as a multi-title RIF.</summary>
    public static void WriteAll(string path, IEnumerable<ProsperoRif> records)
    {
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        WriteAll(fs, records);
    }

    /// <summary>
    /// Validates the structural fields against the known-good layout. Returns <see langword="true"/>
    /// when consistent; otherwise <paramref name="error"/> describes the first problem found.
    /// </summary>
    public bool Validate(out string? error)
    {
        if (Version != CurrentVersion)
        {
            error = $"Unexpected RIF version 0x{Version:X4} (expected 0x{CurrentVersion:X4}).";
            return false;
        }
        if (string.IsNullOrEmpty(ContentId) || Encoding.ASCII.GetByteCount(ContentId) > ContentIdSize)
        {
            error = "Content-id is empty or longer than 36 bytes.";
            return false;
        }
        if (KeyBlob.Length != KeyBlobSize)
        {
            error = $"Key blob must be exactly {KeyBlobSize} bytes.";
            return false;
        }
        error = null;
        return true;
    }

    private static bool IsAllZero(ReadOnlySpan<byte> data)
    {
        foreach (byte b in data)
        {
            if (b != 0) return false;
        }
        return true;
    }

    private static string ReadNulTrimmedAscii(ReadOnlySpan<byte> span)
    {
        int len = span.IndexOf((byte)0);
        if (len < 0) len = span.Length;
        return Encoding.ASCII.GetString(span[..len]);
    }

    private static void ReadExactly(Stream stream, byte[] buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = stream.Read(buffer, total, buffer.Length - total);
            if (read == 0)
                throw new EndOfStreamException("Unexpected end of stream while reading a RIF record.");
            total += read;
        }
    }
}
