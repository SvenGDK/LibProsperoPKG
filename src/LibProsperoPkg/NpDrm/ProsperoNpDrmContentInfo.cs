// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// NpDrm content-info projection. This normalizes a package header into the compact
// classification the console's mount path consumes before it accepts an image:
// container offset, content id / title id, drm and content type, content flags, and the
// derived is-patch / is-nested-image / patch-kind signals.
//
// The projection reads the CNT header fields and feeds the mount acceptance checks.

using LibProsperoPkg.PKG;
using System;
using System.Buffers.Binary;
using System.IO;

namespace LibProsperoPkg.NpDrm;

/// <summary>
/// The kind of patch a package declares, decoded from the content-flags patch bits.
/// </summary>
public enum ProsperoPatchKind
{
    /// <summary>Not a patch (a base/application image).</summary>
    None = 0,

    /// <summary>The first patch over a base image (<c>FIRST_PATCH</c>, flag bit 0x00100000).</summary>
    First,

    /// <summary>A subsequent (non-delta) patch (<c>SUBSEQUENT_PATCH</c>, flag bit 0x40000000).</summary>
    Subsequent,

    /// <summary>A delta patch (<c>DELTA_PATCH</c>, flags 0x41000000).</summary>
    Delta,

    /// <summary>A cumulative patch (<c>CUMULATIVE_PATCH</c>, flags 0x60000000).</summary>
    Cumulative,
}

/// <summary>
/// The normalized NpDrm content-info for a package. This mirrors the
/// classification the console derives before mounting: it resolves the metadata container
/// offset, projects the header fields, and decodes the is-patch / is-nested-image / patch-kind
/// signals the mount gate checks.
/// </summary>
public sealed class ProsperoNpDrmContentInfo
{
    // ---- Content-flags patch bits (header offset 0x78), mirroring ProsperoCntContentFlags. ----
    private const uint FlagFirstPatch = 0x00100000;
    private const uint FlagSubsequentPatch = 0x40000000;
    private const uint FlagDeltaPatch = 0x41000000;
    private const uint FlagCumulativePatch = 0x60000000;
    // Finalized flag on the header Flags field (offset 0x04), not the 0x78 content-flags.
    private const uint FlagFinalized = 0x80000000;

    /// <summary>
    /// Byte offset of the metadata (CNT) container that carries the projected header. Zero for a
    /// bare metadata package; the embedded-CNT offset for a finalized image. This mirrors the
    /// console's container-offset switch (CNT / LIH / FIH magic).
    /// </summary>
    public required long ContainerOffset { get; init; }

    /// <summary>The content id (header offset 0x40), e.g. <c>UP0001-PPSA00001_00-XXXXXXXXXXXXXXXX</c>.</summary>
    public required string ContentId { get; init; }

    /// <summary>
    /// The title id derived from <see cref="ContentId"/> (the segment between the first <c>-</c> and
    /// the <c>_</c>), e.g. <c>PPSA00001</c>. Derived from the content id.
    /// </summary>
    public required string TitleId { get; init; }

    /// <summary>The drm type (header offset 0x70).</summary>
    public required uint DrmType { get; init; }

    /// <summary>The content type (header offset 0x74).</summary>
    public required uint ContentType { get; init; }

    /// <summary>The raw content flags (header offset 0x78).</summary>
    public required uint ContentFlags { get; init; }

    /// <summary>
    /// True when the metadata container is embedded in an outer finalized image (a nested image).
    /// The mount gate rejects a package that is not a nested image ("pkg is not nested image").
    /// </summary>
    public required bool IsNestedImage { get; init; }

    /// <summary>True when the CNT header carries the finalized flag (flags bit 31, offset 0x04).</summary>
    public required bool IsFinalized { get; init; }

    /// <summary>The decoded patch kind.</summary>
    public required ProsperoPatchKind PatchKind { get; init; }

    /// <summary>
    /// True when the package declares any patch kind. The mount gate requires this to match the
    /// slot it is mounting into (base vs patch); a mismatch is rejected ("patch type mismatch").
    /// </summary>
    public bool IsPatch => PatchKind != ProsperoPatchKind.None;

    /// <summary>Reads and projects the content-info for a package on disk.</summary>
    /// <exception cref="InvalidDataException">The file is not a recognisable PS5 PKG.</exception>
    public static ProsperoNpDrmContentInfo Read(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Read(fs);
    }

    /// <inheritdoc cref="Read(string)"/>
    public static ProsperoNpDrmContentInfo Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return FromPackage(ProsperoPkgReader.Read(stream));
    }

    /// <summary>Projects the content-info from an already-parsed package.</summary>
    /// <exception cref="InvalidDataException">The package has no readable CNT header.</exception>
    public static ProsperoNpDrmContentInfo FromPackage(ProsperoPkg pkg)
    {
        ArgumentNullException.ThrowIfNull(pkg);

        var header = pkg.Header
            ?? throw new InvalidDataException("Package has no readable CNT header to project content-info from.");

        bool nested = pkg.Fih is not null;
        long containerOffset = nested ? (long)pkg.Fih!.EmbeddedCntOffset : 0;

        return new ProsperoNpDrmContentInfo
        {
            ContainerOffset = containerOffset,
            ContentId = header.ContentId,
            TitleId = DeriveTitleId(header.ContentId),
            DrmType = header.DrmType,
            ContentType = header.ContentType,
            ContentFlags = header.ContentFlags,
            IsNestedImage = nested,
            IsFinalized = (header.Flags & FlagFinalized) != 0,
            PatchKind = ClassifyPatch(header.ContentFlags),
        };
    }

    /// <summary>
    /// Resolves the raw metadata-container offset from a package file exactly as the console's
    /// content-info switch does: it keys off the 4-byte magic and the version/format field.
    /// Returns the offset of the CNT header that carries the projectable fields.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item><c>\x7FCNT</c> (format &lt; 2): offset 0.</item>
    /// <item><c>\x7FLIH</c> (version 1): u64 at 0x30.</item>
    /// <item><c>\x7FFIH</c> (format 3): u64 at 0x58 (the embedded CNT).</item>
    /// </list>
    /// </remarks>
    /// <exception cref="InvalidDataException">The magic/version combination is not recognised.</exception>
    public static long ResolveContainerOffset(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (stream.Length < 0x60)
            throw new InvalidDataException("File is too small to carry a content-info container header.");

        Span<byte> head = stackalloc byte[0x60];
        stream.Position = 0;
        int read = stream.Read(head);
        if (read < 0x60)
            throw new InvalidDataException("Could not read the container header.");

        ushort version = BinaryPrimitives.ReadUInt16BigEndian(head[0x06..]);

        // \x7FCNT
        if (head[0] == 0x7F && head[1] == 0x43 && head[2] == 0x4E && head[3] == 0x54)
        {
            if (version < 2) return 0;
            throw new InvalidDataException($"Unsupported CNT format version {version}.");
        }

        // \x7FLIH
        if (head[0] == 0x7F && head[1] == 0x4C && head[2] == 0x49 && head[3] == 0x48)
        {
            if (version == 1) return (long)BinaryPrimitives.ReadUInt64LittleEndian(head[0x30..]);
            throw new InvalidDataException($"Unsupported LIH version {version}.");
        }

        // \x7FFIH
        if (head[0] == 0x7F && head[1] == 0x46 && head[2] == 0x49 && head[3] == 0x48)
        {
            if (version == ProsperoPkgLayout.FihRequiredFormatVersion)
                return (long)BinaryPrimitives.ReadUInt64LittleEndian(head[0x58..]);
            throw new InvalidDataException($"Unsupported FIH format version {version} (expected {ProsperoPkgLayout.FihRequiredFormatVersion}).");
        }

        throw new InvalidDataException("Unrecognised container magic for content-info.");
    }

    /// <summary>
    /// Derives the title id from a content id (the segment between the first <c>-</c> and the
    /// following <c>_</c>). Returns an empty string when the content id does not contain that shape.
    /// </summary>
    public static string DeriveTitleId(string contentId)
    {
        if (string.IsNullOrEmpty(contentId)) return string.Empty;

        int dash = contentId.IndexOf('-');
        if (dash < 0 || dash + 1 >= contentId.Length) return string.Empty;

        int start = dash + 1;
        int underscore = contentId.IndexOf('_', start);
        int end = underscore < 0 ? contentId.Length : underscore;
        return contentId[start..end];
    }

    private static ProsperoPatchKind ClassifyPatch(uint flags)
    {
        if ((flags & FlagCumulativePatch) == FlagCumulativePatch) return ProsperoPatchKind.Cumulative;
        if ((flags & FlagDeltaPatch) == FlagDeltaPatch) return ProsperoPatchKind.Delta;
        if ((flags & FlagSubsequentPatch) != 0) return ProsperoPatchKind.Subsequent;
        if ((flags & FlagFirstPatch) != 0) return ProsperoPatchKind.First;
        return ProsperoPatchKind.None;
    }
}
