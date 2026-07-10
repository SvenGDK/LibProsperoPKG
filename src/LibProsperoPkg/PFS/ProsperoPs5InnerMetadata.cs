// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// PS5 nwonly inner-image metadata region builder. Produces the uncompressed metadata plaintext: the
// superblock, unsigned inode table, per-directory dirent blocks, the two flat-path tables, and the
// afid_to_ino_table, each on its own 64 KiB block.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace LibProsperoPkg.PFS;

/// <summary>
/// Describes one node (file or directory) of the inner image for metadata reconstruction. All offsets are
/// resolved by the caller/builder from the image's data + metadata layout.
/// </summary>
public sealed class ProsperoPs5MetaNode
{
    /// <summary>Node name (leaf).</summary>
    public string Name = "";

    /// <summary>Full path from the user root (e.g. <c>/sce_sys/keystone</c>), used for the flat-path hash.</summary>
    public string FullPath = "";

    /// <summary>Assigned inode number.</summary>
    public uint Inode;

    /// <summary>True for a directory node.</summary>
    public bool IsDirectory;

    /// <summary>True when this node is a top-level uroot regular file that also appears in apr_flat_path_table.</summary>
    public bool IsApr;

    /// <summary>The node's afid (file id) or 0 for directories.</summary>
    public uint Afid;

    /// <summary>The node's logical byte offset within the inner image (data region for files, metadata region for dirs/tables).</summary>
    public ulong LogicalOffset;

    /// <summary>Uncompressed size in bytes.</summary>
    public long Size;

    /// <summary>Inode mode (e.g. 0x816d file, 0x4168 dir).</summary>
    public ushort Mode;

    /// <summary>Directory link count.</summary>
    public ushort Nlink = 1;

    /// <summary>Inode flags word.</summary>
    public uint Flags;

    /// <summary>Parent inode number, or -1 for the super-root's direct children.</summary>
    public int ParentInode = -1;

    /// <summary>Byte offset of this node's dirent within its parent dirent block, or -1.</summary>
    public int DirentOffset = -1;

    /// <summary>The dirents contained in this directory (in on-disk order), if it is a directory.</summary>
    public List<ProsperoPfsDirent> Dirents = new();
}

/// <summary>
/// Builds the PS5 nwonly inner-image metadata region as block-aligned plaintext. This plaintext is
/// Kraken-compressed into the inner image's metadata block.
/// </summary>
public sealed class ProsperoPs5InnerMetadata
{
    /// <summary>The inner-image block size (64 KiB).</summary>
    public const int BlockSize = 0x10000;

    private readonly long _timeSec;
    private readonly uint _timeNsec;

    /// <param name="buildTimeSec">Build timestamp seconds (the package c_date/c_time — a deterministic build input).</param>
    /// <param name="buildTimeNsec">Build timestamp nanoseconds fraction.</param>
    public ProsperoPs5InnerMetadata(long buildTimeSec, uint buildTimeNsec)
    {
        _timeSec = buildTimeSec;
        _timeNsec = buildTimeNsec;
    }

    /// <summary>Writes one 0xA8 unsigned inode for <paramref name="n"/> to <paramref name="dst"/>.</summary>
    private void WriteInode(Span<byte> dst, ProsperoPs5MetaNode n)
    {
        dst.Clear();
        BinaryPrimitives.WriteUInt16LittleEndian(dst, n.Mode);
        BinaryPrimitives.WriteUInt16LittleEndian(dst[2..], n.Nlink);
        BinaryPrimitives.WriteUInt32LittleEndian(dst[4..], n.Flags);
        BinaryPrimitives.WriteInt64LittleEndian(dst[8..], n.Size);
        BinaryPrimitives.WriteInt64LittleEndian(dst[0x10..], n.Size);
        for (int t = 0; t < 4; t++) BinaryPrimitives.WriteInt64LittleEndian(dst[(0x18 + t * 8)..], _timeSec);
        for (int t = 0; t < 4; t++) BinaryPrimitives.WriteUInt32LittleEndian(dst[(0x38 + t * 4)..], _timeNsec);
        BinaryPrimitives.WriteUInt64LittleEndian(dst[0x60..], n.LogicalOffset);
        // db[0] = 0; for the super-root and its direct children (ParentInode == -1) db[1..3] = -1;
        // otherwise db[1] = afid (files) / -1 (dirs), db[2] = parent inode, db[3] = dirent offset in parent.
        BinaryPrimitives.WriteInt32LittleEndian(dst[0x64..], 0);
        int db1 = n.ParentInode < 0 ? -1 : (n.IsDirectory ? -1 : (int)n.Afid);
        BinaryPrimitives.WriteInt32LittleEndian(dst[0x68..], db1);
        BinaryPrimitives.WriteInt32LittleEndian(dst[0x6c..], n.ParentInode);
        BinaryPrimitives.WriteInt32LittleEndian(dst[0x70..], n.DirentOffset);
    }

    /// <summary>Builds the superblock block (block 0).</summary>
    private byte[] BuildSuperblock(int inodeCount, long ndblock)
    {
        byte[] sb = new byte[0x369];
        BinaryPrimitives.WriteInt64LittleEndian(sb, 2);                           // version
        BinaryPrimitives.WriteInt64LittleEndian(sb.AsSpan(8), 20130315);          // magic
        sb[0x1a] = 1;                                                             // ReadOnly
        BinaryPrimitives.WriteUInt16LittleEndian(sb.AsSpan(0x1c), 0x18);          // Mode
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(0x20), BlockSize);     // BlockSize
        BinaryPrimitives.WriteInt64LittleEndian(sb.AsSpan(0x28), 1);              // NBlock
        BinaryPrimitives.WriteInt64LittleEndian(sb.AsSpan(0x30), inodeCount);     // DinodeCount
        BinaryPrimitives.WriteInt64LittleEndian(sb.AsSpan(0x38), ndblock);        // Ndblock
        BinaryPrimitives.WriteInt64LittleEndian(sb.AsSpan(0x40), 1);              // DinodeBlockCount
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(0x50), BlockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(0x54), 0x10);
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(0x58), BlockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(0x60), BlockSize);
        for (int t = 0; t < 4; t++) BinaryPrimitives.WriteInt64LittleEndian(sb.AsSpan(0x68 + t * 8), _timeSec);
        for (int t = 0; t < 4; t++) BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(0x88 + t * 4), _timeNsec);
        BinaryPrimitives.WriteInt64LittleEndian(sb.AsSpan(0xb0), 1);
        BinaryPrimitives.WriteInt64LittleEndian(sb.AsSpan(0xd8), 0x89);           // UnknownIndex
        sb[0x368] = 1;
        return sb;
    }

    private static byte[] Dirents(IEnumerable<ProsperoPfsDirent> dirents)
    {
        using var ms = new MemoryStream();
        foreach (var d in dirents) d.WriteToStream(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Assembles the full metadata plaintext. <paramref name="blocks"/> is the ordered list of metadata
    /// blocks to emit after the superblock (block 0) and inode table (block 1): each is either a dirent list,
    /// a flat-path table, or the afid table, at its own 64 KiB block. Returns a buffer whose length is a
    /// multiple of <see cref="BlockSize"/>.
    /// </summary>
    public byte[] Build(IReadOnlyList<ProsperoPs5MetaNode> inodes, long ndblock, IReadOnlyList<byte[]> blocks)
    {
        int totalBlocks = 2 + blocks.Count;
        // round the number of blocks up so the metadata region is a whole number of blocks
        byte[] outBuf = new byte[totalBlocks * BlockSize];

        BuildSuperblock(inodes.Count, ndblock).CopyTo(outBuf, 0);

        // inode table at block 1
        for (int i = 0; i < inodes.Count; i++)
            WriteInode(outBuf.AsSpan(BlockSize + i * 0xA8, 0xA8), inodes[i]);

        // remaining blocks
        for (int b = 0; b < blocks.Count; b++)
            blocks[b].CopyTo(outBuf, (2 + b) * BlockSize);

        return outBuf;
    }
}
