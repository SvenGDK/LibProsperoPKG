// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// PS5 naps_pkg_layout.dat generator. Given the inner image's per-block compression plan, it
// produces a NapsLayoutDocument whose ProsperoNapsLayout.BuildLayout() serializes the CblockInfo,
// u2c, fidx, and header sections from the modeled fields.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;

namespace LibProsperoPkg.PKG;

/// <summary>
/// One logical PFS block in the naps generation plan. Each entry becomes one <c>STD</c> (per-block)
/// CblockInfo record, optionally preceded by a <c>RUN</c> base record when <see cref="StartRun"/> is set.
/// The fields mirror the compressor's per-block output; see <see cref="ProsperoNapsLayoutBuilder"/>.
/// </summary>
public sealed class NapsCblockPlanEntry
{
    /// <summary>Emit a RUN-base CblockInfo record before this block (re-bases the compressed-offset space).</summary>
    public bool StartRun { get; init; }

    /// <summary>The block's on-disk (compressed-image) byte offset. Only used when <see cref="StartRun"/> is set,
    /// where it drives the RUN base fields (<c>CoffsetStart256K</c>, <c>TweakIdxStart</c>) and the cursor reset.</summary>
    public long OnDiskOffset { get; init; }

    /// <summary>The block's uncompressed logical start offset (drives <c>UoffsetStart</c> and the u2c index map).</summary>
    public long LogicalOffset { get; init; }

    /// <summary>Compressed length of the block's even (or sole) chunk; drives <c>ClenEvenMinus1</c>.</summary>
    public long EvenChunkCompressedLength { get; init; }

    /// <summary>Bytes the compressed-offset cursor advances after this block (even + odd chunk stream length).</summary>
    public long StreamLength { get; init; }

    /// <summary>Even-chunk-present flag (1 for a full 256 KiB raw block, else 0).</summary>
    public byte Even { get; init; }

    /// <summary>Odd-chunk-present flag (1 for every real block, 0 only for the terminator).</summary>
    public byte Odd { get; init; }

    /// <summary>KDE predictor selector (raw-full=4, raw-partial=0, Kraken=2, padding=4).</summary>
    public byte KdePredictor { get; init; }

    /// <summary>Shuffle-pattern index (0 except the two Kraken metadata blocks which use 2).</summary>
    public byte ShuffleIndex { get; init; }

    /// <summary>True for the single trailing terminator block (special sentinel fields).</summary>
    public bool Terminator { get; init; }
}

/// <summary>
/// Inputs for generating a <c>naps_pkg_layout.dat</c> from a built inner image. The block plan
/// (<see cref="Blocks"/>) encodes the compressor's per-block output; <see cref="FileLogicalOffsets"/>
/// is the assembler's afid-order logical offset table (the fidx values). The remaining counts are
/// inner-image geometry.
/// </summary>
public sealed class NapsGenerationRequest
{
    /// <summary>Compression type (2 = Kraken for the nwonly format).</summary>
    public byte CompressionType { get; init; } = 2;

    /// <summary>Number of 256 KiB uncompressed blocks: <c>ceil(totalLogicalSize / 0x40000)</c>.</summary>
    public required int NumUBlocks { get; init; }

    /// <summary>Number of on-disk outer blocks in the built image (superblock block count).</summary>
    public required int NumOuterBlocks { get; init; }

    /// <summary>Number of distinct keys (1 for the debug format).</summary>
    public int NumKeys { get; init; } = 1;

    /// <summary>The afid-order uncompressed logical start offsets (the fidx offsets). The final entry is the
    /// total inner logical size and is emitted with <see cref="FinalFileOffsetType"/>.</summary>
    public required IReadOnlyList<long> FileLogicalOffsets { get; init; }

    /// <summary>Type byte for the final (total-size) fidx entry.</summary>
    public byte FinalFileOffsetType { get; init; } = 0x40;

    /// <summary>The 6-byte trailer sentinel appended after the per-file fidx entries. Defaults to the
    /// observed constant <c>01 00 00 05 06 07</c>.</summary>
    public IReadOnlyList<byte>? TrailerEntry { get; init; }

    /// <summary>The ordered block plan.</summary>
    public required IReadOnlyList<NapsCblockPlanEntry> Blocks { get; init; }

    /// <summary>Optional explicit 8-byte outer-block digest entries. Defaults to <see cref="NumOuterBlocks"/>
    /// all-zero entries (the debug format leaves them key-gated/zeroed).</summary>
    public IReadOnlyList<byte[]>? OuterBlockDigests { get; init; }

    /// <summary>Optional 8-byte shuffle-pattern entries (defaults to none).</summary>
    public IReadOnlyList<byte[]>? ShufflePatterns { get; init; }
}

/// <summary>
/// One placed DATA-region file, as laid out by <c>ProsperoPs5InnerImageAssembler</c>. The naps builder
/// derives this file's CblockInfo blocks from its geometry: a raw file becomes
/// <c>floor(UncompressedSize/0x40000)</c> full 256 KiB blocks plus a tail block; a compressed file
/// becomes a single block. Whether each block opens a new RUN base is decided by the flush schedule
/// (<c>runStartOnDiskOffsets</c>), which is a compressor artifact and is supplied separately.
/// </summary>
public sealed class NapsFilePlacement
{
    /// <summary>The file's on-disk (compressed-image) start offset.</summary>
    public required long OnDiskOffset { get; init; }

    /// <summary>The file's uncompressed logical start offset.</summary>
    public required long LogicalOffset { get; init; }

    /// <summary>The file's on-disk byte size (raw size when <see cref="StoreRaw"/>, else the Kraken payload size).</summary>
    public required long OnDiskSize { get; init; }

    /// <summary>The file's uncompressed byte size (drives the raw block split).</summary>
    public required long UncompressedSize { get; init; }

    /// <summary>True when the file is stored raw (block-split), false when Kraken-compressed (single block).</summary>
    public required bool StoreRaw { get; init; }

    /// <summary>KDE predictor for a compressed file's block (default 2 = Kraken).</summary>
    public byte CompressedKde { get; init; } = 2;
}

/// <summary>
/// Generator for the PS5 <c>naps_pkg_layout.dat</c> CblockInfo/u2c/fidx sections. Walks a
/// per-block compression plan with a compressed-offset cursor and emits a <see cref="NapsLayoutDocument"/>
/// that <see cref="ProsperoNapsLayout.BuildLayout"/> serializes from modeled fields.
/// </summary>
/// <remarks>
/// <para>Generation rules:</para>
/// <list type="bullet">
/// <item>A RUN-base record re-bases the compressed cursor: <c>coffEnd = cursor mod 0x40000</c> (captured
/// before the reset), <c>CoffsetStart256K = 2*floor(onDisk/0x40000)</c>, <c>TweakIdxStart = onDisk &gt;&gt; 15</c>
/// (0 for the terminator), then the cursor resets to <c>absC = 2*onDisk - (onDisk mod 0x40000)</c>.</item>
/// <item>A STD record: <c>CoffsetStartMod256K = cursor mod 0x40000</c>, <c>UoffsetStart = (2*(logical mod
/// 0x40000)) &amp; 0x3FFFF</c>, <c>ClenEvenMinus1 = min(2*(evenComp-1), 0x1FFFE)</c>, plus the even/odd/kde/shuf
/// flags. The cursor then advances by the block's stream length.</item>
/// <item>The terminator STD is a sentinel: <c>UoffsetStart = 1</c>, <c>ClenEvenMinus1 = 1</c>, all flags 0.</item>
/// <item>u2c packs a per-ublock "first CblockInfo index" table <c>I[u]</c> = the index of the first STD whose
/// logical start &gt;= <c>u*0x40000</c> (missing ublocks point at the terminator index), in a phase-shifted
/// 8-block grouping.</item>
/// </list>
/// </remarks>
public static class ProsperoNapsLayoutBuilder
{
    private const long UBlock = 0x40000;          // 256 KiB uncompressed block
    private const uint Mod256K = 0x3FFFF;         // 18-bit mod-0x40000 mask
    private const uint ClenEvenCap = 0x1FFFE;     // capped even clen (full 128 KiB chunk)

    private static readonly byte[] DefaultTrailer = { 0x01, 0x00, 0x00, 0x05, 0x06, 0x07 };

    /// <summary>
    /// Generate the full <see cref="NapsLayoutDocument"/> from an inner-image block plan. The result
    /// serializes via <see cref="ProsperoNapsLayout.BuildLayout"/>.
    /// </summary>
    public static NapsLayoutDocument BuildDocument(NapsGenerationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Blocks is null || request.Blocks.Count == 0)
            throw new ArgumentException("A naps generation request needs at least one block.", nameof(request));
        if (request.FileLogicalOffsets is null || request.FileLogicalOffsets.Count == 0)
            throw new ArgumentException("A naps generation request needs the afid logical offset table.", nameof(request));

        (List<NapsCblockInfoEntry> cblockInfos, List<(int Index, long Logical)> stdLogical) = WalkBlocks(request.Blocks);

        var counts = new NapsLayoutCounts(
            NumFiles: request.FileLogicalOffsets.Count,
            CompressionType: request.CompressionType,
            NumKeys: request.NumKeys,
            NumShufflePatterns: request.ShufflePatterns?.Count ?? 0,
            NumUBlocks: request.NumUBlocks,
            NumOuterBlocks: request.NumOuterBlocks,
            NumCblockInfo: cblockInfos.Count);

        List<NapsFileOffsetEntry> fileOffsets = BuildFileOffsets(request);
        List<NapsU2cEntry> u2c = BuildU2c(stdLogical, counts.NumUBlocks, counts.NumCblockInfo, counts.NumU2cEntries);

        IReadOnlyList<byte[]> outerDigests = request.OuterBlockDigests
            ?? Enumerable.Range(0, request.NumOuterBlocks)
                         .Select(_ => new byte[ProsperoNapsLayout.OuterBlockDigestStride])
                         .ToList();

        IReadOnlyList<byte[]> shuffles = request.ShufflePatterns ?? Array.Empty<byte[]>();

        return new NapsLayoutDocument
        {
            Counts = counts,
            Map = ProsperoNapsLayout.SectionMap(counts),
            OuterBlockDigests = outerDigests,
            ShufflePatterns = shuffles,
            FileOffsets = fileOffsets,
            CblockInfoOffsetByUblock = u2c,
            CblockInfos = cblockInfos,
        };
    }

    /// <summary>
    /// Generate and serialize a <c>naps_pkg_layout.dat</c> blob from an inner-image block plan.
    /// </summary>
    public static byte[] Build(NapsGenerationRequest request, int alignment = ProsperoNapsLayout.DefaultAlignment)
        => ProsperoNapsLayout.BuildLayout(BuildDocument(request), alignment);

    // ---- DATA-region derivation from file geometry ------------------------------------------------

    /// <summary>
    /// Derive the DATA-region CblockInfo block plan from placed files. Each raw file is split into
    /// <c>floor(UncompressedSize/0x40000)</c> full 256 KiB blocks (even/odd raw, kde 4) plus a tail block
    /// (kde 0); each compressed file becomes a single block (kde <see cref="NapsFilePlacement.CompressedKde"/>).
    /// A block opens a RUN base iff its on-disk offset is in <paramref name="runStartOnDiskOffsets"/> — the
    /// compressor's flush schedule, which is not statically derivable and must be supplied by the caller.
    /// </summary>
    public static List<NapsCblockPlanEntry> DeriveDataRegionBlocks(
        IReadOnlyList<NapsFilePlacement> files, IReadOnlyCollection<long> runStartOnDiskOffsets)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(runStartOnDiskOffsets);
        var runSet = new HashSet<long>(runStartOnDiskOffsets);
        var blocks = new List<NapsCblockPlanEntry>();

        foreach (NapsFilePlacement f in files)
        {
            if (f.StoreRaw)
            {
                long full = f.UncompressedSize / UBlock;
                long tail = f.UncompressedSize - full * UBlock;
                for (long k = 0; k < full; k++)
                {
                    long onDisk = f.OnDiskOffset + k * UBlock;
                    blocks.Add(new NapsCblockPlanEntry
                    {
                        StartRun = runSet.Contains(onDisk),
                        OnDiskOffset = onDisk,
                        LogicalOffset = f.LogicalOffset + k * UBlock,
                        EvenChunkCompressedLength = 0x10000,
                        StreamLength = 0x80000,
                        Even = 1,
                        Odd = 1,
                        KdePredictor = 4,
                        ShuffleIndex = 0,
                    });
                }
                if (tail > 0 || full == 0)
                {
                    long onDisk = f.OnDiskOffset + full * UBlock;
                    blocks.Add(new NapsCblockPlanEntry
                    {
                        StartRun = runSet.Contains(onDisk),
                        OnDiskOffset = onDisk,
                        LogicalOffset = f.LogicalOffset + full * UBlock,
                        EvenChunkCompressedLength = tail,
                        StreamLength = tail,
                        Even = 0,
                        Odd = 1,
                        KdePredictor = 0,
                        ShuffleIndex = 0,
                    });
                }
            }
            else
            {
                blocks.Add(new NapsCblockPlanEntry
                {
                    StartRun = runSet.Contains(f.OnDiskOffset),
                    OnDiskOffset = f.OnDiskOffset,
                    LogicalOffset = f.LogicalOffset,
                    EvenChunkCompressedLength = f.OnDiskSize,
                    StreamLength = f.OnDiskSize,
                    Even = 0,
                    Odd = 1,
                    KdePredictor = f.CompressedKde,
                    ShuffleIndex = 0,
                });
            }
        }

        return blocks;
    }

    /// <summary>
    /// Build a <c>naps_pkg_layout.dat</c> document from a built inner image: derive the DATA-region blocks
    /// from <paramref name="files"/> + the flush schedule, append the compressor-derived
    /// <paramref name="tailBlocks"/> (padding + metadata + terminator), then run the cursor generator.
    /// </summary>
    /// <param name="numUBlocks">ceil(total logical size / 0x40000).</param>
    /// <param name="numOuterBlocks">On-disk block count of the built image.</param>
    /// <param name="files">Placed DATA-region files, in afid order.</param>
    /// <param name="runStartOnDiskOffsets">On-disk offsets that open a RUN base (compressor flush schedule).</param>
    /// <param name="tailBlocks">The padding + metadata + terminator blocks (compressor-derived).</param>
    /// <param name="fileLogicalOffsets">The afid-order fidx offsets (incl. padding/metadata/total).</param>
    /// <param name="finalFileOffsetType">Type byte on the final (total-size) fidx entry.</param>
    /// <param name="trailerEntry">Optional fidx trailer sentinel (defaults to the observed constant).</param>
    public static NapsLayoutDocument BuildFromInnerImage(
        int numUBlocks,
        int numOuterBlocks,
        IReadOnlyList<NapsFilePlacement> files,
        IReadOnlyCollection<long> runStartOnDiskOffsets,
        IReadOnlyList<NapsCblockPlanEntry> tailBlocks,
        IReadOnlyList<long> fileLogicalOffsets,
        byte finalFileOffsetType = 0x40,
        IReadOnlyList<byte>? trailerEntry = null)
    {
        ArgumentNullException.ThrowIfNull(tailBlocks);
        var blocks = DeriveDataRegionBlocks(files, runStartOnDiskOffsets);
        blocks.AddRange(tailBlocks);

        return BuildDocument(new NapsGenerationRequest
        {
            NumUBlocks = numUBlocks,
            NumOuterBlocks = numOuterBlocks,
            FileLogicalOffsets = fileLogicalOffsets,
            FinalFileOffsetType = finalFileOffsetType,
            TrailerEntry = trailerEntry,
            Blocks = blocks,
        });
    }

    // ---- CblockInfo cursor walk -------------------------------------------------------------------

    private static (List<NapsCblockInfoEntry> Entries, List<(int Index, long Logical)> StdLogical) WalkBlocks(
        IReadOnlyList<NapsCblockPlanEntry> blocks)
    {
        var entries = new List<NapsCblockInfoEntry>(blocks.Count * 2);
        var stdLogical = new List<(int, long)>(blocks.Count);
        long cursor = 0;

        foreach (NapsCblockPlanEntry blk in blocks)
        {
            if (blk.StartRun)
            {
                uint coffEnd = (uint)(cursor & Mod256K);
                long baseC = 2 * (blk.OnDiskOffset / UBlock) * UBlock;
                long rem = blk.OnDiskOffset % UBlock;
                cursor = baseC + rem;                             // reset to absC = 2*onDisk - (onDisk mod 0x40000)
                uint tweak = blk.Terminator ? 0u : (uint)(blk.OnDiskOffset >> 15);
                uint c256K = (uint)(2 * (blk.OnDiskOffset / UBlock));
                entries.Add(new NapsCblockInfoEntry
                {
                    Raw = new byte[ProsperoNapsLayout.CblockInfoStride],
                    IsRunBase = true,
                    CoffsetEndMod256K = coffEnd,
                    TweakIdxStart = tweak,
                    KeyTableIdx = 0,
                    CoffsetStart256K = c256K,
                });
            }

            uint coffMod = (uint)(cursor & Mod256K);
            uint uoff = blk.Terminator ? 1u : (uint)(((blk.LogicalOffset & Mod256K) * 2) & Mod256K);
            uint clenEvenMinus1 = blk.Terminator
                ? 1u
                : (uint)Math.Min((blk.EvenChunkCompressedLength - 1) * 2, ClenEvenCap);

            int stdIndex = entries.Count;
            entries.Add(new NapsCblockInfoEntry
            {
                Raw = new byte[ProsperoNapsLayout.CblockInfoStride],
                IsRunBase = false,
                CoffsetStartMod256K = coffMod,
                UoffsetStart = uoff,
                ClenEvenMinus1 = clenEvenMinus1,
                Even = blk.Even,
                Odd = blk.Odd,
                KdePredictor = blk.KdePredictor,
                ShuffleIdx = blk.ShuffleIndex,
            });
            stdLogical.Add((stdIndex, blk.LogicalOffset));

            cursor += blk.StreamLength;
        }

        return (entries, stdLogical);
    }

    // ---- fidx --------------------------------------------------------------------------------------

    private static List<NapsFileOffsetEntry> BuildFileOffsets(NapsGenerationRequest request)
    {
        int fileCount = request.FileLogicalOffsets.Count;
        var list = new List<NapsFileOffsetEntry>(fileCount + 1);
        for (int i = 0; i < fileCount; i++)
        {
            byte type = (i == fileCount - 1) ? request.FinalFileOffsetType : (byte)0;
            list.Add(new NapsFileOffsetEntry(type, (ulong)request.FileLogicalOffsets[i]));
        }

        IReadOnlyList<byte> trailer = request.TrailerEntry ?? DefaultTrailer;
        if (trailer.Count != ProsperoNapsLayout.FileOffsetStride)
            throw new ArgumentException(
                $"fidx trailer must be {ProsperoNapsLayout.FileOffsetStride} bytes.", nameof(request));
        // Decode the 6-byte trailer back into (offset, type) so it re-encodes exactly.
        list.Add(ProsperoNapsLayout.DecodeFileOffsetEntry(trailer.ToArray()));
        return list;
    }

    // ---- u2c ---------------------------------------------------------------------------------------

    private static List<NapsU2cEntry> BuildU2c(
        List<(int Index, long Logical)> stdLogical, int numUBlocks, int numCblockInfo, int numGroups)
    {
        (int Index, long Logical)[] sorted = stdLogical.OrderBy(t => t.Logical).ToArray();

        // I[u] = index of the first STD whose logical start >= u*0x40000; missing => terminator index.
        int[] first = new int[numUBlocks];
        for (int u = 0; u < numUBlocks; u++)
        {
            long target = (long)u * UBlock;
            int found = numCblockInfo - 1;
            foreach ((int idx, long logical) in sorted)
            {
                if (logical >= target) { found = idx; break; }
            }
            first[u] = found;
        }

        int Delta(int ublock, int baseIndex)
        {
            if (ublock < numUBlocks) return first[ublock] - baseIndex;
            return (numCblockInfo - 1) - baseIndex;             // beyond last ublock -> terminator
        }

        var u2c = new List<NapsU2cEntry>(numGroups);
        for (int g = 0; g < numGroups; g++)
        {
            var entry = new byte[ProsperoNapsLayout.U2cStride];
            int baseG = first[8 * g];
            bool hasNext = 8 * g + 8 < numUBlocks;
            int nextBase = hasNext ? first[8 * g + 8] : 0;

            // bytes[0..3] = 2nd-half deltas of group g (ublocks 8g+4 .. 8g+7) from baseG.
            for (int j = 0; j < 4; j++)
                entry[j] = (byte)Delta(8 * g + 4 + j, baseG);

            entry[4] = (byte)nextBase;                          // base of the next group
            // bytes[5..6] are always zero.

            // bytes[7..9] = the next group's first-three deltas (ublocks 8g+9 .. 8g+11) from nextBase.
            for (int j = 0; j < 3; j++)
                entry[7 + j] = hasNext ? (byte)Delta(8 * g + 9 + j, nextBase) : (byte)0;

            u2c.Add(ProsperoNapsLayout.DecodeU2cEntry(entry));
        }

        return u2c;
    }
}
