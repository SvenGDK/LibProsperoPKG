// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// CNT container structures, entries and writer primitives.
#nullable disable
using System.Collections.Generic;

namespace LibProsperoPkg.PKG;

public class ProsperoCnt
{
    // 0x0 - 0x5A0
    public ProsperoCntHeader Header;
    // 0xFE0 - 0xFFF
    public byte[] HeaderDigest;
    // 0x1000 - 0x10FF
    public byte[] HeaderSignature;
    // 0x2000 - 0x27FF
    public ProsperoCntKeysEntry EntryKeys;
    // 0x2800 - 0x28FF
    public ProsperoCntGenericEntry ImageKey;
    // 0x2900 - 0x2A7F
    public ProsperoCntGeneralDigestsEntry GeneralDigests;
    // 0x2A80 - variable
    public ProsperoCntMetasEntry Metas;
    // variable...
    public ProsperoCntGenericEntry Digests;
    public ProsperoCntNameTableEntry EntryNames;

    public List<ProsperoCntEntry> Entries;

    public const int HASH_SIZE = 0x20;
    public const string MAGIC = "\u007FCNT";

}



public struct ProsperoCntHeader
{
    public string CNTMagic;
    public ProsperoCntFlags flags;
    public uint unk_0x08;
    public uint unk_0x0C; /* 0xF */
    public uint entry_count;
    public ushort sc_entry_count;
    public ushort entry_count_2; /* same as entry_count */
    public uint entry_table_offset;
    public uint main_ent_data_size;
    public ulong body_offset;
    public ulong body_size;
    public ulong mandatory_size;
    public string content_id; // Length = PKG_CONTENT_ID_SIZE
    public uint drm_type;
    public uint content_type;
    public ProsperoCntContentFlags content_flags;
    public uint promote_size;
    public uint version_date;
    public uint version_hash;
    public uint unk_0x88;
    public uint unk_0x8C;
    public uint unk_0x90;
    public uint unk_0x94;
    public ProsperoCntIroTag iro_tag;
    public uint ekc_version; /* drm type version */
    public byte[] sc_entries1_hash;
    public byte[] sc_entries2_hash;
    public byte[] digest_table_hash;
    public byte[] body_digest;

    public uint unk_0x400;
    public uint pfs_image_count;
    public ulong pfs_flags;
    public ulong pfs_image_offset;
    public ulong pfs_image_size;
    public ulong mount_image_offset;
    public ulong mount_image_size;
    public ulong package_size;
    public uint pfs_signed_size;
    public uint pfs_cache_size;
    public byte[] pfs_image_digest;
    public byte[] pfs_signed_digest;
    public ulong pfs_split_size_nth_0;
    public ulong pfs_split_size_nth_1;

    // 0x4A0: outer-PFS AES-XTS crypt seed (16 bytes). Mirrors the seed stored in the outer superblock
    // at superblock+0x370 and used to derive the image encryption keys — so this locator descriptor
    // references the encrypted image with its actual seed.
    public byte[] image_seed;
    // 0x4B0 / 0x4B8: the CNT container's own locator inside the FINALIZED mount image (FIH-relative).
    // cnt_region_offset = FIH block (0x10000) + pfs_image_size; cnt_region_size = the CNT container size.
    // Their sum equals package_size. The on-console 0x80b21185 install geometry gate enumerates the
    // content region these descriptors locate; leaving them zero makes the enumeration total 0.
    public ulong cnt_region_offset;
    public ulong cnt_region_size;
    // 0x510: content-region descriptor — two (u32 offset, u32 size) big-endian pairs into the CNT content
    // region. Pair 1 = the IMAGE_KEY entry (id 0x0020); pair 2 = the mandatory entry (the entry whose
    // DataOffset == mandatory_size @0x30, i.e. the imagedigs entry, id 0x040A).
    public uint desc_image_key_offset;
    public uint desc_image_key_size;
    public uint desc_mandatory_offset;
    public uint desc_mandatory_size;
    // 0x520: the descriptor's region-digest table — two consecutive 32-byte SHA3-256 digests (64 bytes):
    //   0x520 = SHA3-256(IMAGE_KEY entry payload), 0x540 = SHA3-256(imagedigs entry payload).
    // Two 32-byte SHA3-256 slots over the IMAGE_KEY and imagedigs entry payloads. See ComputeDescriptorDigest.
    public byte[] desc_digest;
}
