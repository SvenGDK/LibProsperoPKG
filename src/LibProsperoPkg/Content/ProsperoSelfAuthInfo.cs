// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// SELF authentication-info sidecar (*.auth_info): a fixed 0x88-byte record that pairs with a SELF
// module and carries the program authority id together with the capability and attribute words the
// runtime consults for the module. It is distinct from the in-SELF extended-info authority id
// (see ProsperoFself.SelfExtInfo): a fake-self carries a 0x31.. id in its extended info while its
// paired sidecar may carry a genuine 0x45.. authority for the original module. The runtime retrieves
// the same record for a running module through a kernel query that fills a 0x88-byte buffer; this
// type reads, validates, builds, and round-trips the on-disk sidecar form of that record.

#nullable enable
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace LibProsperoPkg.Content;

/// <summary>The authority-id category, taken from the top byte of the program authority id.</summary>
public enum ProsperoAuthorityCategory : byte
{
    /// <summary>An id whose category byte is none of the known values.</summary>
    Unknown = 0x00,

    /// <summary>Fake authority (debug / fake-self modules), category byte 0x31.</summary>
    Fake = 0x31,

    /// <summary>Genuine authority carried by an <c>auth_info</c> sidecar, category byte 0x45.</summary>
    Genuine = 0x45,

    /// <summary>Privileged system authority, category byte 0x48.</summary>
    PrivilegedSystem = 0x48,
}

/// <summary>
/// A parsed SELF authentication-info sidecar (<c>*.auth_info</c>), a fixed 0x88-byte record.
/// </summary>
/// <remarks>
/// Layout (little-endian scalars):
/// <list type="table">
/// <item><term>0x00</term><description>program authority id (<c>paid</c>), 8 bytes.</description></item>
/// <item><term>0x08</term><description>capability words, four 64-bit values (0x20 bytes).</description></item>
/// <item><term>0x28</term><description>attribute words, four 64-bit values (0x20 bytes).</description></item>
/// <item><term>0x48</term><description>reserved tail, 0x40 bytes.</description></item>
/// </list>
/// The record is structural: the capability and attribute words are grants issued for the original
/// module and are copied verbatim when a sidecar is carried alongside a module. This type never
/// synthesizes a grant; <see cref="Create"/> takes whatever material the caller supplies.
/// </remarks>
public sealed class ProsperoSelfAuthInfo
{
    /// <summary>The fixed size of an authentication-info record, in bytes.</summary>
    public const int Size = 0x88;

    /// <summary>The number of 64-bit capability words.</summary>
    public const int CapabilityWordCount = 4;

    /// <summary>The number of 64-bit attribute words.</summary>
    public const int AttributeWordCount = 4;

    /// <summary>The size of the reserved tail, in bytes.</summary>
    public const int ReservedSize = 0x40;

    private const int PaidOffset = 0x00;
    private const int CapabilitiesOffset = 0x08;
    private const int AttributesOffset = 0x28;
    private const int ReservedOffset = 0x48;

    private readonly ulong[] _capabilities;
    private readonly ulong[] _attributes;
    private readonly byte[] _reserved;

    private ProsperoSelfAuthInfo(ulong paid, ulong[] capabilities, ulong[] attributes, byte[] reserved)
    {
        Paid = paid;
        _capabilities = capabilities;
        _attributes = attributes;
        _reserved = reserved;
    }

    /// <summary>The program authority id (<c>paid</c>) at offset 0x00.</summary>
    public ulong Paid { get; }

    /// <summary>The program authority id, exposed under the name used by the SELF extended info.</summary>
    public ulong AuthorityId => Paid;

    /// <summary>The four 64-bit capability words at offset 0x08.</summary>
    public IReadOnlyList<ulong> Capabilities => _capabilities;

    /// <summary>The four 64-bit attribute words at offset 0x28.</summary>
    public IReadOnlyList<ulong> Attributes => _attributes;

    /// <summary>The 0x40-byte reserved tail at offset 0x48.</summary>
    public ReadOnlySpan<byte> Reserved => _reserved;

    /// <summary>The category taken from the top byte of <see cref="Paid"/>.</summary>
    public ProsperoAuthorityCategory Category
    {
        get
        {
            byte top = (byte)(Paid >> 56);
            return top is (byte)ProsperoAuthorityCategory.Fake
                or (byte)ProsperoAuthorityCategory.Genuine
                or (byte)ProsperoAuthorityCategory.PrivilegedSystem
                ? (ProsperoAuthorityCategory)top
                : ProsperoAuthorityCategory.Unknown;
        }
    }

    /// <summary>Whether the authority id carries the fake-authority category byte (0x31).</summary>
    public bool IsFakeAuthority => Category == ProsperoAuthorityCategory.Fake;

    /// <summary>Whether the authority id carries the genuine-authority category byte (0x45).</summary>
    public bool IsGenuineAuthority => Category == ProsperoAuthorityCategory.Genuine;

    /// <summary>Whether the authority id carries the privileged-system category byte (0x48).</summary>
    public bool IsPrivilegedSystem => Category == ProsperoAuthorityCategory.PrivilegedSystem;

    /// <summary>Returns whether the buffer is large enough to hold an authentication-info record.</summary>
    public static bool IsAuthInfo(ReadOnlySpan<byte> data) => data.Length >= Size;

    /// <summary>Parses an authentication-info record from the start of a buffer.</summary>
    /// <exception cref="InvalidDataException">The buffer is shorter than <see cref="Size"/>.</exception>
    public static ProsperoSelfAuthInfo Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < Size)
            throw new InvalidDataException($"Authentication-info record must be at least 0x{Size:X} bytes, got 0x{data.Length:X}.");

        ulong paid = BinaryPrimitives.ReadUInt64LittleEndian(data[PaidOffset..]);

        var capabilities = new ulong[CapabilityWordCount];
        for (int i = 0; i < CapabilityWordCount; i++)
            capabilities[i] = BinaryPrimitives.ReadUInt64LittleEndian(data[(CapabilitiesOffset + i * 8)..]);

        var attributes = new ulong[AttributeWordCount];
        for (int i = 0; i < AttributeWordCount; i++)
            attributes[i] = BinaryPrimitives.ReadUInt64LittleEndian(data[(AttributesOffset + i * 8)..]);

        var reserved = data.Slice(ReservedOffset, ReservedSize).ToArray();

        return new ProsperoSelfAuthInfo(paid, capabilities, attributes, reserved);
    }

    /// <summary>Reads an authentication-info record from the current position of a stream.</summary>
    /// <exception cref="InvalidDataException">The stream holds fewer than <see cref="Size"/> bytes.</exception>
    public static ProsperoSelfAuthInfo Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var buffer = new byte[Size];
        int read = 0;
        while (read < Size)
        {
            int n = stream.Read(buffer, read, Size - read);
            if (n == 0)
                throw new InvalidDataException($"Stream ended before a 0x{Size:X}-byte authentication-info record was read.");
            read += n;
        }
        return Parse(buffer);
    }

    /// <summary>Reads an authentication-info record from a <c>*.auth_info</c> file.</summary>
    public static ProsperoSelfAuthInfo ReadFile(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        using var fs = File.OpenRead(path);
        return Read(fs);
    }

    /// <summary>Builds an authentication-info record from supplied fields.</summary>
    /// <param name="paid">The program authority id.</param>
    /// <param name="capabilities">Up to four 64-bit capability words; fewer are zero-extended.</param>
    /// <param name="attributes">Up to four 64-bit attribute words; fewer are zero-extended.</param>
    /// <param name="reserved">Up to 0x40 reserved bytes; fewer are zero-extended.</param>
    /// <exception cref="ArgumentException">More words or reserved bytes are supplied than the record holds.</exception>
    public static ProsperoSelfAuthInfo Create(
        ulong paid,
        ReadOnlySpan<ulong> capabilities = default,
        ReadOnlySpan<ulong> attributes = default,
        ReadOnlySpan<byte> reserved = default)
    {
        if (capabilities.Length > CapabilityWordCount)
            throw new ArgumentException($"At most {CapabilityWordCount} capability words are allowed.", nameof(capabilities));
        if (attributes.Length > AttributeWordCount)
            throw new ArgumentException($"At most {AttributeWordCount} attribute words are allowed.", nameof(attributes));
        if (reserved.Length > ReservedSize)
            throw new ArgumentException($"At most 0x{ReservedSize:X} reserved bytes are allowed.", nameof(reserved));

        var caps = new ulong[CapabilityWordCount];
        capabilities.CopyTo(caps);
        var attrs = new ulong[AttributeWordCount];
        attributes.CopyTo(attrs);
        var rsv = new byte[ReservedSize];
        reserved.CopyTo(rsv);

        return new ProsperoSelfAuthInfo(paid, caps, attrs, rsv);
    }

    /// <summary>Serializes the record to a fresh 0x88-byte buffer.</summary>
    public byte[] ToBytes()
    {
        var buffer = new byte[Size];
        var span = buffer.AsSpan();

        BinaryPrimitives.WriteUInt64LittleEndian(span[PaidOffset..], Paid);
        for (int i = 0; i < CapabilityWordCount; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(span[(CapabilitiesOffset + i * 8)..], _capabilities[i]);
        for (int i = 0; i < AttributeWordCount; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(span[(AttributesOffset + i * 8)..], _attributes[i]);
        _reserved.CopyTo(span[ReservedOffset..]);

        return buffer;
    }

    /// <summary>Writes the record to the current position of a stream.</summary>
    public void Write(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        stream.Write(ToBytes(), 0, Size);
    }

    /// <summary>Writes the record to a <c>*.auth_info</c> file.</summary>
    public void WriteFile(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        using var fs = File.Create(path);
        Write(fs);
    }
}
