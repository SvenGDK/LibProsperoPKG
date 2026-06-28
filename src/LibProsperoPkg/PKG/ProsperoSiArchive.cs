// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// Producer for the trailing SI (install-metadata) segment of a finalized image, in the
// DEBUG variant (FIH signed byte 0x00).
//
// Validated format. Decoded byte-for-byte from TestFiles/PS5/PKG/Debug/Downloads.pkg (cross-checked
// against InternetBrowser.pkg and DebugSettings.pkg): in a debug finalized image the SI segment is
// a plain ZIP (PK\x03\x04, every member STORED / uncompressed) with this exact member set:
//
// common/etc/naps_meta_18.dat 3440 B (per-package metric blob)
// common/etc/naps_meta_300/301/302/308.dat 48 B each, byte-identical
// common/etc/pfsimage.xml rich package-configuration descriptor
// common/etc/playgo-chunk.dat 416 B copied from the inner PFS
// config/<content-id>/playgo-chunk.crc 68 B
//
// Records and external inputs:
// * ZIP container framing, STORED entries and the exact member paths -> reproduced.
// * pfsimage.xml structure (the reference <package-configuration type="package-info"> tree with the
// "0xNN 0xNN" digest formatting, <config>/<digests>/<params>/<container>/<mount-image>) ->
// reproduced from values the caller/builder already knows.
// * playgo-chunk.dat -> reproduced (it is copied verbatim from the inner PFS the builder makes).
// * naps_meta_300/301/302/308.dat -> reproduced byte-exact by ProsperoNapsMeta.BuildMeta300 (a
// plaintext 48-byte descriptor derived from the inner-image geometry; validated against three reference
// debug packages).
// * Several pfsimage.xml <digests> are reproducible and should be supplied by the builder:
// game-digest (== inner sblock-digest, SHA3-256 of the plaintext outer superblock), param-digest
// (SHA3-256 of the param.json CNT entry), body-digest, fixed-info-digest, package-digest
// (== SHA3-256(CNT[0:0xFE0]), ProsperoImageDigests.ComputePackageDigest, identical to the value the
// produced CNT stores at +0xFE0), and the full GeneralDigests set — content-digest, header-digest,
// system-digest, playgo-digest and the target slot (all SHA3-256 of plaintext CNT regions / per-entry
// digests, ProsperoPkgBuilder.ComputeGeneralDigests, Validated byte-exact against the reference debug
// packages). When the produced CNT bytes are available, pass these via the corresponding options
// rather than leaving placeholders.
// * The remaining members are not reproducible off-console: the distinct FIH 0xB0 slot (a best-effort
// nested-image-content hash), the keyed/encrypted naps_meta_18.dat metric blob, and the 68-byte
// playgo-chunk.crc. They are accepted as inputs and emitted verbatim. When a caller does
// not have them, all-zero placeholders are written for the XML digests and the keyed standalone
// members are omitted - they are never fabricated.
// See LibProsperoPKG/docs/implementation-status.md.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;
using LibProsperoPkg.PlayGo;

namespace LibProsperoPkg.PKG;

/// <summary>A single member (one stored file) of the SI ZIP.</summary>
/// <param name="Path">ZIP entry path with forward slashes, e.g. <c>common/etc/pfsimage.xml</c>.</param>
/// <param name="Content">Raw, already-final bytes of the member.</param>
public readonly record struct ProsperoSiMember(string Path, byte[] Content);

/// <summary>
/// One <c>&lt;entry&gt;</c> of the <c>pfsimage.xml</c> <c>&lt;entries&gt;</c> table: a single CNT
/// (sce_sys) file with its byte offset and size inside the finalized container body. These values
/// are known to the builder once it has laid out the inner image, so the table is fully
/// reproducible (unlike the keyed digests).
/// </summary>
/// <param name="Name">CNT entry name, e.g. <c>imagedigs.dat</c>.</param>
/// <param name="Offset">Byte offset of the entry inside the container body.</param>
/// <param name="Size">Entry size in bytes.</param>
public readonly record struct ProsperoPfsImageEntry(string Name, long Offset, long Size);

/// <summary>
/// Structural inputs for the reproducible part of <c>common/etc/pfsimage.xml</c>. Every value here
/// is known to the builder (content id, sizes, the inner-PFS seed, the directory entries);
/// the keyed <see cref="ContentDigest"/>… fields and the inner-image digests are optional and are
/// emitted verbatim when supplied, or as all-zero placeholders (and reported) when not.
/// </summary>
public sealed class ProsperoPfsImageXmlOptions
{
    /// <summary>Content id, e.g. <c>IV9999-NPXS41139_00-XXXXXXXXXXXXXXXX</c>.</summary>
    public string ContentId { get; set; } = "";

    /// <summary>Human-readable title (<c>&lt;titleName&gt;</c> / <c>&lt;chunkinfo&gt;</c>).</summary>
    public string TitleName { get; set; } = "";

    /// <summary>Content version, e.g. <c>01.001.000</c>.</summary>
    public string ContentVersion { get; set; } = "01.000.000";

    /// <summary>DRM type (<c>&lt;drm-type&gt;</c>), e.g. <c>none</c> for debug packages.</summary>
    public string DrmType { get; set; } = "none";

    /// <summary>
    /// Application DRM type (<c>&lt;applicationDrmType&gt;</c> param). This is distinct from the
    /// config <see cref="DrmType"/>: ground-truth debug packages carry <c>none</c> for
    /// <c>drm-type</c> but <c>free</c> here. When <see langword="null"/> it falls back to
    /// <see cref="ApplicationType"/> (so it mirrors <c>application-type</c> by default).
    /// </summary>
    public string? ApplicationDrmType { get; set; }

    /// <summary>Content type (<c>&lt;content-type&gt;</c>), e.g. <c>PS5GD</c>.</summary>
    public string ContentType { get; set; } = "PS5GD";

    /// <summary>Application type (<c>&lt;application-type&gt;</c>), e.g. <c>free</c>.</summary>
    public string ApplicationType { get; set; } = "free";

    /// <summary>Total finalized package size in bytes (<c>&lt;package-size&gt;</c>).</summary>
    public long PackageSize { get; set; }

    /// <summary>Shared PFS image offset (always <c>0x10000</c> in a finalized image).</summary>
    public long PfsImageOffset { get; set; } = 0x10000;

    /// <summary>Shared PFS image size in bytes.</summary>
    public long PfsImageSize { get; set; }

    /// <summary>Inner-PFS superblock seed (16 bytes), stamped into the encrypted image header.</summary>
    public byte[]? PfsImageSeed { get; set; }

    // ---- Reproducible structural fields (builder-known; emitted verbatim). ----

    /// <summary>Master version (<c>&lt;masterVersion&gt;</c> and the longname <c>M</c> field).</summary>
    public string MasterVersion { get; set; } = "01.00";

    /// <summary>
    /// Explicit <c>&lt;longname&gt;</c> override. When <see langword="null"/> the value is derived as
    /// <c>{content-id}-C{version-digits}-M{master-16-hex}-{type-code}</c>.
    /// </summary>
    public string? LongName { get; set; }

    /// <summary>64-bit master value used for the <c>M</c> field of the derived longname (default 0).</summary>
    public ulong LongNameMasterValue { get; set; }

    /// <summary>Minimum required system version (<c>&lt;required-system-version&gt;</c>).</summary>
    public string RequiredSystemVersion { get; set; } = "00.000.000.00000000";

    /// <summary><c>&lt;requiredSystemSoftwareVersion&gt;</c> param (64-bit hex).</summary>
    public string RequiredSystemSoftwareVersion { get; set; } = "0x0000000000000000";

    /// <summary><c>&lt;sdkVersion&gt;</c> param (64-bit hex).</summary>
    public string SdkVersion { get; set; } = "0x0000000000000000";

    /// <summary>
    /// Toolchain <c>&lt;version-date&gt;</c> stamp. Defaults to the validated
    /// reference build constant <c>0x20200722</c>.
    /// </summary>
    public uint VersionDate { get; set; } = 0x20200722;

    /// <summary>
    /// Toolchain <c>&lt;version-hash&gt;</c> stamp. Defaults to the validated
    /// reference build constant <c>0x01fe52e9</c>.
    /// </summary>
    public uint VersionHash { get; set; } = 0x01fe52e9;

    /// <summary>Finalized container size in bytes (<c>&lt;container-size&gt;</c> / <c>&lt;promote-size&gt;</c>). Default <c>0x50000</c>.</summary>
    public long ContainerSize { get; set; } = 0x50000;

    /// <summary>Container <c>&lt;mandatory-size&gt;</c> (sum of mandatory CNT entries). Package-specific.</summary>
    public long MandatorySize { get; set; }

    /// <summary>Container <c>&lt;body-offset&gt;</c> (CNT body start inside the container). Default <c>0x2000</c>.</summary>
    public long BodyOffset { get; set; } = 0x2000;

    /// <summary>Supplemental segment offset (<c>&lt;supplemental-offset&gt;</c>). Default <c>0x50000</c>.</summary>
    public long SupplementalOffset { get; set; } = 0x50000;

    /// <summary>
    /// The CNT (sce_sys) entry table for the <c>&lt;entries&gt;</c> section. When non-empty the table
    /// is emitted exactly as the tool does (<c>num</c> attribute plus one <c>&lt;entry&gt;</c> per file);
    /// when empty the section is omitted.
    /// </summary>
    public IReadOnlyList<ProsperoPfsImageEntry> Entries { get; set; } = [];

    // ---- Keyed finalization products: supplied verbatim or left as zero placeholders. ----

    /// <summary>32-byte container <c>&lt;body-digest&gt;</c> (keyed).</summary>
    public byte[]? BodyDigest { get; set; }

    /// <summary>32-byte <c>&lt;content-digest&gt;</c> (keyed).</summary>
    public byte[]? ContentDigest { get; set; }
    /// <summary>32-byte <c>&lt;game-digest&gt;</c> (keyed; == inner <c>sblock-digest</c>).</summary>
    public byte[]? GameDigest { get; set; }
    /// <summary>32-byte <c>&lt;header-digest&gt;</c> (keyed).</summary>
    public byte[]? HeaderDigest { get; set; }
    /// <summary>32-byte <c>&lt;system-digest&gt;</c> (keyed).</summary>
    public byte[]? SystemDigest { get; set; }
    /// <summary>32-byte <c>&lt;param-digest&gt;</c> (keyed).</summary>
    public byte[]? ParamDigest { get; set; }
    /// <summary>
    /// 32-byte <c>&lt;package-digest&gt;</c>. Reproducible: equals
    /// <see cref="ProsperoImageDigests.ComputePackageDigest"/> (SHA3-256 of CNT[0:0xFE0]) and the value
    /// the produced CNT stores at +0xFE0. Pass it when the produced CNT bytes are available.
    /// </summary>
    public byte[]? PackageDigest { get; set; }
    /// <summary>32-byte inner <c>&lt;sblock-digest&gt;</c> (keyed; equals the game-digest).</summary>
    public byte[]? SblockDigest { get; set; }
    /// <summary>32-byte inner <c>&lt;fixed-info-digest&gt;</c> (keyed).</summary>
    public byte[]? FixedInfoDigest { get; set; }
}

/// <summary>
/// Writes the <b>debug</b>-variant SI install-metadata segment as the reference ZIP container decoded
/// from the reference debug packages. The container, member paths, the <c>pfsimage.xml</c> structure
/// (reproduced byte-for-byte through its config/digests/params/container/mount-image/entries
/// sections) and
/// the copied <c>playgo-chunk.dat</c> are reproduced exactly; keyed members are supplied by the
/// caller and emitted verbatim - never fabricated. The retail-variant SI is console-encrypted and
/// is not handled (see the file header).
/// </summary>
public static class ProsperoSiArchive
{
    /// <summary>Canonical member paths.</summary>
    public const string PfsImageXmlPath = "common/etc/pfsimage.xml";
    /// <summary>Canonical member path for the copied PlayGo chunk descriptor.</summary>
    public const string PlayGoChunkDatPath = "common/etc/playgo-chunk.dat";
    /// <summary>Canonical member path for the 3440-byte metric blob.</summary>
    public const string NapsMeta18Path = "common/etc/naps_meta_18.dat";

    /// <summary>The four byte-identical 48-byte <c>naps_meta_*</c> record ids, in file order.</summary>
    public static ReadOnlySpan<int> NapsMeta300Ids => [300, 301, 302, 308];

    /// <summary>
    /// Builds the canonical debug SI member set. The reproducible <paramref name="pfsImageXml"/> is
    /// always written; <paramref name="playGoChunkDat"/> is copied from the inner PFS when present;
    /// the keyed blobs (<paramref name="napsMeta18"/>, <paramref name="napsMeta300"/>) are included
    /// only when supplied and are never fabricated. The per-content-id <c>playgo-chunk.crc</c> is
    /// either supplied verbatim via <paramref name="playGoChunkCrc"/> or, when
    /// <paramref name="finalizedMountImage"/> is given instead, computed reproducibly from it with
    /// CRC-32C (see <see cref="ProsperoPlayGo.BuildChunkCrc"/>).
    /// </summary>
    public static IReadOnlyList<ProsperoSiMember> BuildMembers(
        string contentId,
        byte[] pfsImageXml,
        byte[]? playGoChunkDat = null,
        byte[]? napsMeta18 = null,
        byte[]? napsMeta300 = null,
        byte[]? playGoChunkCrc = null,
        byte[]? finalizedMountImage = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(contentId);
        ArgumentNullException.ThrowIfNull(pfsImageXml);

        // When the caller passes the finalized mount image but not an explicit CRC blob, compute
        // playgo-chunk.crc reproducibly (CRC-32C of each 64KiB block). An explicitly supplied blob
        // always wins so verbatim keyed/sample inputs are preserved.
        playGoChunkCrc ??= finalizedMountImage is { Length: > 0 }
            ? ProsperoPlayGo.BuildChunkCrc(finalizedMountImage)
            : null;

        var members = new List<ProsperoSiMember>();

        // The reference member order in Downloads.pkg is naps_meta_* first, then pfsimage.xml, then
        // playgo-chunk.dat, then the per-content-id playgo-chunk.crc.
        if (napsMeta18 is not null)
            members.Add(new(NapsMeta18Path, napsMeta18));
        if (napsMeta300 is not null)
        {
            foreach (int id in NapsMeta300Ids)
                members.Add(new($"common/etc/naps_meta_{id}.dat", napsMeta300));
        }

        members.Add(new(PfsImageXmlPath, pfsImageXml));

        if (playGoChunkDat is not null)
            members.Add(new(PlayGoChunkDatPath, playGoChunkDat));
        if (playGoChunkCrc is not null)
            members.Add(new($"config/{contentId}/playgo-chunk.crc", playGoChunkCrc));

        return members;
    }

    /// <summary>
    /// Serialises <paramref name="members"/> into a ZIP using <see cref="CompressionLevel.NoCompression"/>
    /// (the reference SI uses STORED entries) and returns the raw segment bytes.
    /// </summary>
    public static byte[] WriteZip(IReadOnlyList<ProsperoSiMember> members)
    {
        ArgumentNullException.ThrowIfNull(members);
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (ProsperoSiMember m in members)
            {
                ZipArchiveEntry entry = zip.CreateEntry(m.Path, CompressionLevel.NoCompression);
                using Stream es = entry.Open();
                es.Write(m.Content, 0, m.Content.Length);
            }
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Formats a 32-byte digest exactly the way <c>pfsimage.xml</c> does: lowercase
    /// <c>0xNN 0xNN …</c>, sixteen bytes per line. An empty span yields an all-zero block.
    /// </summary>
    public static string FormatDigest(ReadOnlySpan<byte> digest)
    {
        ReadOnlySpan<byte> src = digest.IsEmpty ? stackalloc byte[32] : digest;
        var sb = new StringBuilder(src.Length * 5);
        for (int i = 0; i < src.Length; i++)
        {
            if (i != 0) sb.Append(i % 16 == 0 ? '\n' : ' ');
            sb.Append("0x").Append(src[i].ToString("x2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    /// <summary>
    /// Builds <c>common/etc/pfsimage.xml</c> in the reference format, reproduced byte-for-byte through its
    /// <c>&lt;config&gt;</c>, <c>&lt;digests&gt;</c>, <c>&lt;params&gt;</c>, <c>&lt;container&gt;</c>,
    /// <c>&lt;mount-image&gt;</c> and <c>&lt;entries&gt;</c> sections. Keyed
    /// digest fields are emitted verbatim when present on <paramref name="options"/>, otherwise as
    /// all-zero placeholders; every placeholder is appended to <paramref name="warnings"/> so the
    /// caller can surface that the file is structurally valid but not finalization-exact.
    /// </summary>
    public static string BuildPfsImageXml(ProsperoPfsImageXmlOptions options, ICollection<string>? warnings = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(options.ContentId);

        void NoteIfPlaceholder(byte[]? value, string field, bool reproducible = false)
        {
            if (value is null || value.Length == 0)
                warnings?.Add(reproducible
                    ? $"pfsimage.xml <{field}> emitted as all-zero placeholder (reproducible — supply it from the builder/produced CNT)."
                    : $"pfsimage.xml <{field}> emitted as all-zero placeholder (keyed finalization product, not reproducible off-console).");
        }

        NoteIfPlaceholder(options.ContentDigest, "content-digest", reproducible: true);
        NoteIfPlaceholder(options.GameDigest, "game-digest", reproducible: true);
        NoteIfPlaceholder(options.HeaderDigest, "header-digest", reproducible: true);
        NoteIfPlaceholder(options.SystemDigest, "system-digest", reproducible: true);
        NoteIfPlaceholder(options.ParamDigest, "param-digest", reproducible: true);
        NoteIfPlaceholder(options.PackageDigest, "package-digest", reproducible: true);
        NoteIfPlaceholder(options.BodyDigest, "body-digest", reproducible: true);

        // The inner superblock seed is emitted as a 16-byte 0xNN block, exactly like the digests.
        string seedBlock = Indent(FormatDigest(options.PfsImageSeed is { Length: > 0 } s ? s : default), "      ");

        string Indent(string digest, string pad) => digest.Replace("\n", "\n" + pad);
        static string Hex16(long v) => "0x" + v.ToString("x16", CultureInfo.InvariantCulture);
        static string Hex8(long v) => "0x" + v.ToString("x8", CultureInfo.InvariantCulture);

        // Reproducible container/mount geometry (all derivable from the inner-image layout).
        long containerSize = options.ContainerSize;
        long bodyOffset = options.BodyOffset;
        long bodySize = containerSize - bodyOffset;
        long containerOffset = options.PfsImageOffset + options.PfsImageSize;
        long mountImageSize = containerOffset + containerSize;

        // longname = <content-id>-C<version-digits>-M<master16>-<type-code> (e.g. PS5GD -> GD).
        string longName = options.LongName ?? BuildLongName(options);

        var sb = new StringBuilder(8192);
        sb.Append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        sb.Append("<package-configuration version=\"1.0\" type=\"package-info\">\n");
        sb.Append($"  <config version=\"{options.ContentVersion}\" metadata=\"0\" primary=\"yes\">\n");
        sb.Append($"    <content-id>{options.ContentId}</content-id>\n");
        sb.Append($"    <primary-id>{options.ContentId}</primary-id>\n");
        sb.Append($"    <longname>{longName}</longname>\n");
        sb.Append($"    <required-system-version>{options.RequiredSystemVersion}</required-system-version>\n");
        sb.Append($"    <drm-type>{options.DrmType}</drm-type>\n");
        sb.Append($"    <content-type>{options.ContentType}</content-type>\n");
        sb.Append($"    <application-type>{options.ApplicationType}</application-type>\n");
        sb.Append("    <num-of-images>1</num-of-images>\n");
        sb.Append($"    <package-size>{options.PackageSize}</package-size>\n");
        sb.Append($"    <version-date>0x{options.VersionDate:x8}</version-date>\n");
        sb.Append($"    <version-hash>0x{options.VersionHash:x8}</version-hash>\n");
        sb.Append("  </config>\n");
        sb.Append("  <digests version=\"1.2\" major-param-version=\"0\">\n");
        sb.Append($"    <content-digest>\n      {Indent(FormatDigest(options.ContentDigest), "      ")}\n    </content-digest>\n");
        sb.Append($"    <game-digest>\n      {Indent(FormatDigest(options.GameDigest), "      ")}\n    </game-digest>\n");
        sb.Append($"    <header-digest>\n      {Indent(FormatDigest(options.HeaderDigest), "      ")}\n    </header-digest>\n");
        sb.Append($"    <system-digest>\n      {Indent(FormatDigest(options.SystemDigest), "      ")}\n    </system-digest>\n");
        sb.Append($"    <param-digest>\n      {Indent(FormatDigest(options.ParamDigest), "      ")}\n    </param-digest>\n");
        sb.Append($"    <package-digest>\n      {Indent(FormatDigest(options.PackageDigest), "      ")}\n    </package-digest>\n");
        sb.Append("  </digests>\n");
        sb.Append("  <params>\n");
        sb.Append($"    <applicationDrmType>{options.ApplicationDrmType ?? options.ApplicationType}</applicationDrmType>\n");
        sb.Append($"    <contentId>{options.ContentId}</contentId>\n");
        sb.Append($"    <contentVersion>{options.ContentVersion}</contentVersion>\n");
        sb.Append($"    <masterVersion>{options.MasterVersion}</masterVersion>\n");
        sb.Append($"    <requiredSystemSoftwareVersion>{options.RequiredSystemSoftwareVersion}</requiredSystemSoftwareVersion>\n");
        sb.Append($"    <sdkVersion>{options.SdkVersion}</sdkVersion>\n");
        sb.Append($"    <titleName>{options.TitleName}</titleName>\n");
        sb.Append("  </params>\n");
        sb.Append("  <container nth-of-image=\"1\">\n");
        sb.Append($"    <container-size>{Hex16(containerSize)}</container-size>\n");
        sb.Append($"    <mandatory-size>{Hex16(options.MandatorySize)}</mandatory-size>\n");
        sb.Append($"    <body-offset>{Hex16(bodyOffset)}</body-offset>\n");
        sb.Append($"    <body-size>{Hex16(bodySize)}</body-size>\n");
        sb.Append($"    <body-digest>\n      {Indent(FormatDigest(options.BodyDigest), "      ")}\n    </body-digest>\n");
        sb.Append($"    <promote-size>{Hex8(containerSize)}</promote-size>\n");
        sb.Append("  </container>\n");
        sb.Append("  <mount-image nth-of-image=\"1\" nested-image=\"yes\">\n");
        sb.Append("    <pfs-offset-align>0x0000000000010000</pfs-offset-align>\n");
        sb.Append("    <pfs-size-align>0x0000000000010000</pfs-size-align>\n");
        sb.Append($"    <pfs-image-offset>{Hex16(options.PfsImageOffset)}</pfs-image-offset>\n");
        sb.Append($"    <pfs-image-size>{Hex16(options.PfsImageSize)}</pfs-image-size>\n");
        sb.Append("    <fixed-info-size>0x00010000</fixed-info-size>\n");
        sb.Append($"    <pfs-image-seed>\n      {seedBlock}\n    </pfs-image-seed>\n");
        sb.Append($"    <sblock-digest>\n      {Indent(FormatDigest(options.SblockDigest ?? options.GameDigest), "      ")}\n    </sblock-digest>\n");
        sb.Append($"    <fixed-info-digest>\n      {Indent(FormatDigest(options.FixedInfoDigest), "      ")}\n    </fixed-info-digest>\n");
        sb.Append($"    <mount-image-offset>{Hex16(0)}</mount-image-offset>\n");
        sb.Append($"    <mount-image-size>{Hex16(mountImageSize)}</mount-image-size>\n");
        sb.Append($"    <container-offset>{Hex16(containerOffset)}</container-offset>\n");
        sb.Append($"    <supplemental-offset>{Hex16(options.SupplementalOffset)}</supplemental-offset>\n");
        sb.Append("  </mount-image>\n");
        if (options.Entries is { Count: > 0 } entries)
        {
            sb.Append($"  <entries nth-of-image=\"1\" num=\"{entries.Count}\">\n");
            foreach (ProsperoPfsImageEntry e in entries)
                sb.Append($"    <entry offset=\"{Hex8(e.Offset)}\" size=\"{Hex8(e.Size)}\" name=\"{e.Name}\"/>\n");
            sb.Append("  </entries>\n");
        }
        sb.Append("</package-configuration>\n");
        return sb.ToString();
    }

    /// <summary>
    /// Derives the <c>&lt;longname&gt;</c> the tool stamps:
    /// <c>{content-id}-C{version-digits}-M{master-16-hex}-{type-code}</c>, where the version digits
    /// are the dotted <see cref="ProsperoPfsImageXmlOptions.ContentVersion"/> with the dots removed
    /// and the type-code is the content type with any leading <c>PS5</c> dropped (so <c>PS5GD</c>
    /// becomes <c>GD</c>).
    /// </summary>
    private static string BuildLongName(ProsperoPfsImageXmlOptions o)
    {
        string versionDigits = o.ContentVersion.Replace(".", "", StringComparison.Ordinal);
        string typeCode = o.ContentType.StartsWith("PS5", StringComparison.OrdinalIgnoreCase)
            ? o.ContentType[3..]
            : o.ContentType;
        string master16 = o.LongNameMasterValue.ToString("x16", CultureInfo.InvariantCulture);
        return $"{o.ContentId}-C{versionDigits}-M{master16}-{typeCode}";
    }
}
