// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Self-consistent snapshot of a built PFS image's inode tree + geometry, captured after
// PfsBuilder.WriteImage for the supplemental pfsimage.xml introspection sections
// (<pfs-image> / <nested-image>). Every value is read straight from this image's own inode
// table and superblock, so the snapshot describes the exact bytes produced.
#nullable enable
using System.Collections.Generic;

namespace LibProsperoPkg.PFS;

/// <summary>
/// One node (inode) of a built PFS image as captured for the <c>pfsimage.xml</c>
/// introspection sections. Values come from this image's own inode table.
/// </summary>
public sealed class ProsperoPfsImageNode
{
    /// <summary>Node name (empty for the synthetic super-root).</summary>
    public string Name { get; init; } = "";

    /// <summary>True for a directory node.</summary>
    public bool IsDirectory { get; init; }

    /// <summary>Inode number (the <c>inode</c> attribute).</summary>
    public uint InodeNumber { get; init; }

    /// <summary>On-disk (stored) size — the smaller value for a PFSC-compressed file.</summary>
    public long StoredSize { get; init; }

    /// <summary>Logical (plain/decompressed) size — equals <see cref="StoredSize"/> for raw files.</summary>
    public long PlainSize { get; init; }

    /// <summary>Inode flags (the <c>imode</c> attribute).</summary>
    public uint Flags { get; init; }

    /// <summary>Inode mode bits (the <c>mode</c> attribute).</summary>
    public ushort Mode { get; init; }

    /// <summary>Hard-link count (the <c>links</c> attribute).</summary>
    public ushort Nlink { get; init; }

    /// <summary>First data block of this node (the <c>index</c> attribute base).</summary>
    public int StartBlock { get; init; }

    /// <summary>Number of data blocks this node occupies.</summary>
    public uint Blocks { get; init; }

    /// <summary>True when the inode carries the PFSC-compressed flag.</summary>
    public bool Compressed { get; init; }

    /// <summary>True for the PFS-internal pseudo files (flat path table / collision resolver).</summary>
    public bool Internal { get; init; }

    /// <summary>Child nodes (directories first, then files, both ordinal by name).</summary>
    public List<ProsperoPfsImageNode> Children { get; } = [];
}

/// <summary>
/// A self-consistent snapshot of a whole built PFS image (outer or nested), used to emit the
/// <c>pfsimage.xml</c> sections that describe this image's layout. Produced by
/// <see cref="ProsperoPfsBuilder.CaptureImageTree"/> after the image has been written.
/// </summary>
public sealed class ProsperoPfsImageTreeInfo
{
    /// <summary>PFS block size in bytes (superblock <c>BlockSize</c>).</summary>
    public int BlockSize { get; init; }

    /// <summary>Total data blocks in the image (superblock <c>Ndblock</c>).</summary>
    public long ImageBlocks { get; init; }

    /// <summary>Total inode count (superblock <c>DinodeCount</c>).</summary>
    public int InodeCount { get; init; }

    /// <summary>Blocks occupied by the dinode (inode) table (<c>DinodeBlockCount</c>).</summary>
    public int DinodeBlockCount { get; init; }

    /// <summary>Root inode number (0).</summary>
    public uint RootInodeNumber { get; init; }

    /// <summary>Start block of the dinode-table descriptor (superblock <c>InodeBlockSig</c>).</summary>
    public int DinodeBlock { get; init; }

    /// <summary>Size in bytes of the dinode-table descriptor (a single block).</summary>
    public long DinodeSize { get; init; }

    /// <summary>Flags of the dinode-table descriptor (the super-inode <c>imode</c>).</summary>
    public uint DinodeFlags { get; init; }

    /// <summary>Superblock seed (16 bytes; all-zero for our deterministic build).</summary>
    public byte[]? Seed { get; init; }

    /// <summary>
    /// Superblock integrity value: the 32-byte HMAC-SHA256 self-signature of this image's own
    /// superblock (final signature block 0 @ 0x380), captured during signing. Populated only for a
    /// signed image with <see cref="ProsperoPfsBuilder.CaptureSuperblockIcv"/> set; <see langword="null"/>
    /// otherwise.
    /// </summary>
    public byte[]? SuperblockIcv { get; init; }

    /// <summary>True when the image is signed (the outer PFS).</summary>
    public bool Signed { get; init; }

    /// <summary>True when the image is encrypted (the outer PFS).</summary>
    public bool Encrypted { get; init; }

    /// <summary>
    /// The synthetic super-root: the flat path table (+ optional collision resolver) and the
    /// user root (<c>uroot</c>) subtree, matching the PFS super-root layout.
    /// </summary>
    public ProsperoPfsImageNode Root { get; init; } = new();
}
