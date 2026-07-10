// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// PS5 "\x7fFLT" flat-path-table (inode_flat_path_table / apr_flat_path_table) builder and path
// hash. Uses a custom three-lane Keccak-ish sponge over the uppercased path (leading slash stripped,
// ASCII, no NUL) keyed with two hardcoded global 64-bit seeds, and a 0x40-byte header plus
// 16-byte {hash, packed} entries sorted ascending by hash.
//
// This is the PS5 nwonly inner-image flat path table; it is distinct from the legacy hashmap-style
// <see cref="ProsperoFlatPathTable"/> used by the older signed-image path.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace LibProsperoPkg.PFS;

/// <summary>
/// The PS5 <c>\x7fFLT</c> flat-path-table format (inode / apr variants) and its path hash for a
/// given inner-image file tree.
/// </summary>
public static class ProsperoPs5FlatPathTable
{
    // Hardcoded global seeds and round constant. The seeds are written before hashing and are not
    // per-image values.
    private const ulong Seed0 = 0x92ca8aab26a24f51UL;
    private const ulong Seed1 = 0x09bbb761a41bc44dUL;
    private const ulong RoundConst = 0x8000000080008081UL;

    /// <summary>The 0x40-byte FLT header size; entries begin here.</summary>
    public const int HeaderSize = 0x40;

    /// <summary>The fixed 16-byte "seed" stored in the header at +0x30 (the two global seeds, little-endian).</summary>
    public static readonly byte[] HeaderSeed =
    {
        0x51, 0x4f, 0xa2, 0x26, 0xab, 0x8a, 0xca, 0x92,
        0x4d, 0xc4, 0x1b, 0xa4, 0x61, 0xb7, 0xbb, 0x09,
    };

    private static ulong Rotl(ulong x, int n) => (x << n) | (x >> (64 - n));
    private static ulong Rotr(ulong x, int n) => (x >> n) | (x << (64 - n));

    /// <summary>
    /// Computes the PS5 flat-path-table 64-bit hash of a filesystem path. The path is uppercased and its
    /// leading <c>/</c> is stripped (e.g. <c>/sce_sys/keystone</c> → <c>SCE_SYS/KEYSTONE</c>) before hashing.
    /// </summary>
    public static ulong HashPath(string path)
    {
        if (path.Length > 0 && path[0] == '/')
            path = path.Substring(1);
        return HashBytes(Encoding.ASCII.GetBytes(path.ToUpperInvariant()));
    }

    /// <summary>The raw hash over exact bytes using the three-lane Keccak-ish sponge.</summary>
    public static ulong HashBytes(ReadOnlySpan<byte> str)
    {
        int len = str.Length;
        ulong s0 = Seed0, s1 = Rotl(Seed0, 11), s2 = Rotl(Seed0, 23);
        ulong tail = 0;
        if (len != 0)
        {
            int nwords = (len - 1) >> 3;
            ulong a0 = s0, a1 = s1, a2 = s2;
            int off = 0;
            for (int i = 0; i < nwords; i++)
            {
                ulong w = BinaryPrimitives.ReadUInt64LittleEndian(str.Slice(off, 8));
                off += 8;
                a0 ^= w;
                ulong t18 = Rotr(Rotl(a2 ^ a1, 5) ^ a0, 11);
                ulong t12 = Rotl(Rotl(a2 ^ a0, 17) ^ a1, 11);
                a2 = Rotr(Rotl(a1 ^ a0, 1) ^ a2, 5);
                a0 = (~t12 & a2) ^ t18 ^ RoundConst;
                a1 = (~a2 & t18) ^ t12;
                a2 = (~t18 & t12) ^ a2;
            }
            s0 = a0; s1 = a1; s2 = a2;
            int tlen = ((len - 1) & 7) + 1;
            for (int j = 0; j < tlen; j++)
                tail |= (ulong)str[off + j] << (8 * j);
        }
        ulong u16 = s1, u11 = s2, u6 = tail ^ s0 ^ Seed1;
        ulong u17 = Rotl(u11 ^ u16, 5) ^ u6;
        ulong u18 = Rotl(u11 ^ u6, 17) ^ u16;
        u11 = Rotl(u16 ^ u6, 1) ^ u11;
        return (~Rotl(u18, 11) & Rotr(u11, 5)) ^ Rotr(u17, 11) ^ RoundConst;
    }

    /// <summary>One flat-path-table entry: a path hash and the packed 64-bit payload.</summary>
    public readonly struct Entry
    {
        /// <summary>The path hash (table key; entries are sorted ascending by this value).</summary>
        public readonly ulong Hash;

        /// <summary>The packed payload (inode/size in the low bits, flag bits 30/31, value in bits 40+).</summary>
        public readonly ulong Packed;

        public Entry(ulong hash, ulong packed)
        {
            Hash = hash;
            Packed = packed;
        }
    }

    // Packed payload flag bits.
    private const ulong FlagDirectory = 0x40000000UL; // bit 30: node is a directory
    private const ulong FlagSubtree = 0x80000000UL;   // bit 31: node is outside the apr (top-level file) set
    private const ulong DirValue = 0xffffffUL;        // directories store 0xffffff in the value field (bits 40+)

    /// <summary>
    /// Packs an <c>inode_flat_path_table</c> payload: low 24 bits = inode number, bit 30 = directory,
    /// bit 31 = subtree (non-apr) node, bits 40+ = the node's afid (0xffffff for directories).
    /// </summary>
    public static ulong PackInodeEntry(uint inode, bool isDirectory, bool isSubtree, uint afid)
    {
        ulong packed = inode & 0xffffffUL;
        if (isDirectory) packed |= FlagDirectory;
        if (isSubtree) packed |= FlagSubtree;
        packed |= (isDirectory ? DirValue : afid) << 40;
        return packed;
    }

    /// <summary>
    /// Packs an <c>apr_flat_path_table</c> payload: low 40 bits = the file's uncompressed size, bits 40+ = afid.
    /// </summary>
    public static ulong PackAprEntry(long uncompressedSize, uint afid)
        => ((ulong)uncompressedSize & 0xffffffffffUL) | ((ulong)afid << 40);

    /// <summary>
    /// Serializes a flat-path-table (header + entries sorted ascending by hash) to <paramref name="s"/>.
    /// </summary>
    public static void Write(Stream s, IEnumerable<Entry> entries)
    {
        var list = new List<Entry>(entries);
        list.Sort((a, b) => a.Hash.CompareTo(b.Hash));

        Span<byte> hdr = stackalloc byte[HeaderSize];
        hdr.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(hdr, 1);              // +0x00 version
        hdr[0x04] = 0x10;                                             // +0x04 entry stride (16)
        BinaryPrimitives.WriteUInt32LittleEndian(hdr[0x08..], 0x40);  // +0x08 header size / data start
        Encoding.ASCII.GetBytes("FLT").CopyTo(hdr[0x21..]);         // +0x20 magic = 7F 'F' 'L' 'T'
        hdr[0x20] = 0x7f;
        BinaryPrimitives.WriteUInt32LittleEndian(hdr[0x2c..], (uint)list.Count); // +0x2c entry count
        HeaderSeed.CopyTo(hdr[0x30..]);                              // +0x30 seed (global constants)
        s.Write(hdr);

        Span<byte> ent = stackalloc byte[16];
        foreach (var e in list)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(ent, e.Hash);
            BinaryPrimitives.WriteUInt64LittleEndian(ent[8..], e.Packed);
            s.Write(ent);
        }
    }

    /// <summary>Serializes a flat-path-table to a new byte array.</summary>
    public static byte[] ToBytes(IEnumerable<Entry> entries)
    {
        using var ms = new MemoryStream();
        Write(ms, entries);
        return ms.ToArray();
    }
}
