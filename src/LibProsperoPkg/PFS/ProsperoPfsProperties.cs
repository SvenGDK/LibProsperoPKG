// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PFS image structures, builder and reader primitives.
#nullable disable

namespace LibProsperoPkg.PFS;

/// <summary>
/// A data structure representing everything configurable in a PFS image.
/// Gets fed to a PfsBuilder.
/// </summary>
public class ProsperoPfsProperties
{
    public ProsperoFsDir root;
    public long FileTime;
    public uint BlockSize;
    public uint MinBlocks = 0;
    public bool Encrypt;
    public bool Sign;
    public byte[] EKPFS;
    public byte[] Seed;

    /// <summary>
    /// PFS superblock version stamped into the image header
    /// (<see cref="ProsperoPfsHeader.VersionPs5"/>, 2).
    /// </summary>
    public long Version = ProsperoPfsHeader.VersionPs5;
}