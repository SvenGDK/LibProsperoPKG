// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// CNT container structures, entries and writer primitives.
#nullable disable
using LibProsperoPkg.Util;
using System;
using System.Collections.Generic;
using System.Linq;

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

    // Constants
    const uint PKG_FLAG_FINALIZED = 1u << 31;
    const ulong PKG_PFS_FLAG_NESTED_IMAGE = 0x8000000000000000UL;
    public const int PKG_TABLE_ENTRY_SIZE = 0x20;
    public const int PKG_ENTRY_KEYSET_SIZE = 0x20;
    public const int HASH_SIZE = 0x20;
    public const string MAGIC = "\u007FCNT";

    const int PKG_MAX_ENTRY_KEYS = 7;
    const int PKG_CONTENT_ID_HASH_SIZE = HASH_SIZE;
    const int PKG_ENTRY_KEYS_XHASHES_SIZE = (PKG_MAX_ENTRY_KEYS * HASH_SIZE);
    const int PKG_PASSCODE_KEY_SIZE = 0x100;
    const int PKG_IMAGE_KEY_SIZE = 0x100;
    const int PKG_ENTRY_KEY_SIZE = 0x100;

    const int PKG_PLAYGO_CHUNK_HASH_TABLE_OFFSET = 0x40;
    const int PKG_PLAYGO_CHUNK_HASH_SIZE = 0x4;
    const int PKG_PLAYGO_PFS_CHUNK_SIZE = 0x10000;

    const int PKG_SHAREPARAM_FILE_VERSION_MAJOR = 1;
    const int PKG_SHAREPARAM_FILE_VERSION_MINOR = 10;

    public const int PKG_CONTENT_ID_SIZE = 0x30;
    public const int PKG_HEADER_SIZE = 0x5A0;
    public const int PKG_ENTRY_KEYSET_ENC_SIZE = 0x100;

    /// <summary>
    /// Decrypts the EKPFS for a package. Will not work on retail-only packages.
    /// </summary>
    /// <returns>The EKPFS if successful; null otherwise</returns>
    public byte[] GetEkpfs()
    {
        try
        {
            var dk3 = Crypto.RSA2048Decrypt(EntryKeys.Keys[3].key, RSAKeyset.PkgDerivedKey3Keyset);
            var iv_key = Crypto.Sha256(ImageKey.meta.GetBytes().Concat(dk3).ToArray());
            var imageKeyDecrypted = ImageKey.FileData.Clone() as byte[];
            Crypto.AesCbcCfb128Decrypt(
              imageKeyDecrypted,
              imageKeyDecrypted,
              imageKeyDecrypted.Length,
              iv_key.Skip(16).Take(16).ToArray(),
              iv_key.Take(16).ToArray());
            return Crypto.RSA2048Decrypt(imageKeyDecrypted, RSAKeyset.FakeKeyset);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Checks if the given passcode is valid for this pkg
    /// </summary>
    /// <param name="passcode"></param>
    /// <returns>True if the passcode is correct</returns>
    public bool CheckPasscode(string passcode)
    {
        if (passcode == null || passcode.Length != 32) return false;
        var dk0 = Crypto.ComputeKeys(Header.content_id, passcode, 0);
        var digest0 = Crypto.Sha256(dk0).Xor(dk0);
        return digest0.SequenceEqual(EntryKeys.Keys[0].digest);
    }

    public bool CheckDerivedKey(byte[] dk, int index)
    {
        if (index < 0 || index > 6)
        {
            throw new ArgumentException("Invalid derived key index: " + index);
        }
        if (dk == null || dk.Length != 32)
            return false;
        var digest = Crypto.Sha256(dk).Xor(dk);
        return digest.SequenceEqual(EntryKeys.Keys[index].digest);

    }

    public bool CheckEkpfs(byte[] dk1) => CheckDerivedKey(dk1, 1);
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
}
