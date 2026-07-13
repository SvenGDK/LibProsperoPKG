// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Constants and enumerations for the PS5 outer PKG container. The outer
// container uses the "CNT" layout: a big-endian header followed by a 0x20-byte
// entry-meta table and an interleaved name table. PS5 packages additionally use a
// finalized-image "FIH" magic whose signed byte distinguishes retail from debug images.

namespace LibProsperoPkg.PKG;

/// <summary>The kind of PS5 package, distinguished by its 4-byte magic / signed byte.</summary>
public enum ProsperoPkgType
{
    /// <summary>
    /// Metadata container (<c>\x7FCNT</c>): carries only the package metadata (header, entry table,
    /// param.json / license / playgo info, digests). It is <b>not</b> a full, installable package —
    /// a CNT alone cannot be installed on any console. A full package is produced by finalizing the
    /// CNT into a <c>\x7FFIH</c> image (see <see cref="FullRetail"/> / <see cref="FullDebug"/>).
    /// </summary>
    Meta,

    /// <summary>
    /// Finalized retail image (<c>\x7FFIH</c>, signed byte 0x80): a full package as submitted with the
    /// finalized toolchain. The signed byte at offset 0x05 is what distinguishes it from a debug image.
    /// </summary>
    FullRetail,

    /// <summary>
    /// Finalized debug image (<c>\x7FFIH</c>, signed byte 0x00): a full, installable package. This is
    /// the <b>only</b> form that can be installed on PS5 consoles with debug mode enabled.
    /// </summary>
    FullDebug,
}

/// <summary>Well-known offsets and sizes of the outer CNT container.</summary>
public static class ProsperoPkgLayout
{
    /// <summary>Metadata-container magic: <c>0x7F 'C' 'N' 'T'</c>.</summary>
    public static readonly byte[] CntMagic = [0x7F, (byte)'C', (byte)'N', (byte)'T'];

    /// <summary>Finalized-image magic: <c>0x7F 'F' 'I' 'H'</c>.</summary>
    public static readonly byte[] FihMagic = [0x7F, (byte)'F', (byte)'I', (byte)'H'];

    /// <summary>Size in bytes of a single entry-meta record in the entry table.</summary>
    public const int EntryMetaSize = 0x20;

    /// <summary>Size in bytes of the outer container header.</summary>
    public const int HeaderSize = 0x5A0;

    /// <summary>Size in bytes of the content-id field.</summary>
    public const int ContentIdSize = 0x30;

    /// <summary>Encrypted-entry flag stored in <c>Flags1</c>.</summary>
    public const uint EntryFlagEncrypted = 0x80000000;

    // ---- Finalized-image (FIH) layout. All FIH header fields are little-endian on disk. ----

    /// <summary>Size in bytes of the finalized-image (FIH) header + digest table region.</summary>
    public const int FihHeaderRegionSize = 0x10000;

    /// <summary>FIH header offset of the signed byte (0x80 = official, 0x00 = debug).</summary>
    public const int FihSignedByteOffset = 0x05;

    /// <summary>FIH header offset of the format version (little-endian u16).</summary>
    public const int FihFormatVersionField = 0x06;

    /// <summary>The finalized-image format version the console mount path requires.</summary>
    public const ushort FihRequiredFormatVersion = 3;

    /// <summary>FIH header offset of the shared encrypted PFS image offset (little-endian u64).</summary>
    public const int FihPfsImageOffsetField = 0x10;

    /// <summary>FIH header offset of the shared encrypted PFS image size (little-endian u64).</summary>
    public const int FihPfsImageSizeField = 0x18;

    /// <summary>FIH header offset of the embedded CNT container offset (little-endian u64).</summary>
    public const int FihEmbeddedCntOffsetField = 0x58;

    /// <summary>
    /// FIH header offset of the inner mount's data-region block count (little-endian u64) — the metaBase
    /// block index = MetaBaseLogical / <see cref="FihHeaderRegionSize"/>. The installer's transfer reads
    /// this to size the inner mount's data region during pre-allocation; a zero value is rejected. This
    /// value must be nonzero for package types 0x14001 and 0x14004.
    /// </summary>
    public const int FihDataRegionBlockCountField = 0x50;

    // ---- Outer-PFS accounting fields (little-endian; derived from the FIH writer output
    // and cross-checked across debug packages). These describe
    // the inner pfs_image.dat / metadata block split of the shared outer-PFS image, not the
    // embedded CNT. Invariant: FihInnerImageBlockCountField + FihMetaBlockCountField ==
    // pfsImageSize / FihHeaderRegionSize. ----

    /// <summary>FIH header offset of the inner-image (pfs_image.dat) block count (little-endian u32).</summary>
    public const int FihInnerImageBlockCountField = 0x90;

    /// <summary>FIH header offset of the outer-PFS metadata block count (little-endian u32).</summary>
    public const int FihMetaBlockCountField = 0x94;

    /// <summary>FIH header offset of the mirrored outer-PFS metadata block count (little-endian u32).</summary>
    public const int FihMetaBlockCountMirrorField = 0x98;

    /// <summary>
    /// FIH header offset of the block-aligned inner-image (pfs_image.dat) size in bytes
    /// (little-endian u64) - equals <see cref="FihInnerImageBlockCountField"/> * <see cref="FihHeaderRegionSize"/>.
    /// </summary>
    public const int FihInnerImageSizeField = 0xA0;

    /// <summary>
    /// FIH header offset of the uncompressed inner-image logical size in bytes (little-endian u64).
    /// This is the plaintext size of the inner PFS image whose content digest is stored at 0xB0, and
    /// the size the mount pre-allocation reads; it must equal the 0xB0 digest preimage length.
    /// </summary>
    public const int FihInnerImageLogicalSizeField = 0xA8;

    /// <summary>FIH header offset of the content-version echo (little-endian u32) — high 32 bits of the
    /// content version u64 (major BCD in the top byte).</summary>
    public const int FihContentVersionField = 0x9C;

    /// <summary>FIH header offset of the outer-PFS regular file count (little-endian u32).</summary>
    public const int FihOuterFileCountField = 0xF0;

    /// <summary>FIH header offset of the outer-PFS flat-path-table block accounting value (little-endian u32).</summary>
    public const int FihFlatPathTableBlockCountField = 0xF8;

    /// <summary>
    /// Outer-PFS regular file count for the fixed data-first template. For the nwonly outer template
    /// (single pfs_image.dat data file; naps_pkg_layout.dat is a system file, not counted) this is 1.
    /// </summary>
    public const uint FihOuterFileCount = 1;

    /// <summary>Outer-PFS flat-path-table block accounting value for the fixed data-first template.
    /// For the nwonly outer template this is 2.</summary>
    public const uint FihFlatPathTableBlockCount = 2;
}

/// <summary>
/// Well-known entry ids found in the PS5 PKG entry table. Only the subset relevant to inspection / package creation is listed.
/// </summary>
public enum ProsperoEntryId : uint
{
    Unknown = 0x0000,
    Digests = 0x0001,
    EntryKeys = 0x0010,
    ImageKey = 0x0020,
    GeneralDigests = 0x0080,
    Metas = 0x0100,
    EntryNames = 0x0200,
    LicenseDat = 0x0400,
    LicenseInfo = 0x0401,
    Imagedigs = 0x040A,
    ParamSfo = 0x1000,
    PlaygoChunkDat = 0x1001,
    PlaygoChunkSha = 0x1002,
    PlaygoManifestXml = 0x1003,
    Icon0Png = 0x1200,
    Pic0Png = 0x1220,
    Snd0At9 = 0x1240,
    Icon0Dds = 0x1280,
    Pic0Dds = 0x12A0,
    Pic1Dds = 0x12C0,
    ParamJson = 0x2000,
    PlaygoHashTable = 0x2010,
    PlaygoFicm = 0x2011,
}
