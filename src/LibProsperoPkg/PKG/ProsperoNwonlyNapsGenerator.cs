// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// Generates a valid naps_pkg_layout.dat for a nwonly data-first inner image assembled by
// ProsperoPs5InnerImageAssembler. The run/flush schedule is derived statically from block-aligned
// file starts, the block after each Kraken-compressed file, and dedup padding/metadata re-anchors.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using LibProsperoPkg.PFS;
using LibProsperoPkg.PFS.Compression;
using System;
using System.Collections.Generic;
using System.Linq;

namespace LibProsperoPkg.PKG;

/// <summary>Generates a valid <c>naps_pkg_layout.dat</c> for an assembled nwonly inner image.</summary>
public static class ProsperoNwonlyNapsGenerator
{
    private const int Block64K = 0x10000;
    private const long Ublock256K = 0x40000;

    /// <summary>
    /// Builds the naps bytes for the inner image described by <paramref name="result"/>. The schedule is
    /// derived; pass <paramref name="runOverride"/> to supply explicit on-disk RUN offsets when the
    /// schedule is known.
    /// </summary>
    public static byte[] Generate(ProsperoPs5InnerImageResult result, IReadOnlyCollection<long>? runOverride = null)
    {
        ArgumentNullException.ThrowIfNull(result);
        var placements = result.Placements;
        long mountSize = result.Ndblock * Block64K;
        long metaBase = result.MetaBaseLogical;
        long dataEnd = result.DataEndLogical;

        // ---- DATA-region placements + derivable run schedule ----------------------------------------
        var files = placements.Select(p => new NapsFilePlacement
        {
            OnDiskOffset = p.OnDiskOffset,
            LogicalOffset = p.LogicalOffset,
            OnDiskSize = p.OnDiskSize,
            UncompressedSize = p.UncompressedSize,
            StoreRaw = p.StoreRaw,
            CompressedKde = 2,
        }).ToList();

        HashSet<long> runSet;
        if (runOverride is not null)
        {
            runSet = new HashSet<long>(runOverride);
        }
        else
        {
            // A RUN opens at each block-aligned file start (raw system files) and at the first file after a
            // Kraken-compressed file (the compressed cursor diverges from the on-disk offset there).
            runSet = new HashSet<long>();
            for (int i = 0; i < placements.Count; i++)
            {
                // A RUN opens only at a raw file that STARTS a fresh on-disk block. Raw modules that pack
                // contiguously after another raw file in the same block do NOT re-anchor — they continue
                // the current run, so
                // the reader decodes them linearly. (Before module packing every raw file was block-aligned,
                // so StoreRaw implied a fresh block; that is no longer true.)
                bool blockAligned = placements[i].StoreRaw && placements[i].OnDiskOffset % Block64K == 0;
                bool afterCompressed = i > 0 && !placements[i - 1].StoreRaw;
                if (blockAligned || afterCompressed)
                    runSet.Add(placements[i].OnDiskOffset);

                // The compressed offset space re-bases every 11 ublocks within a run. For a raw file this
                // is on-disk offset + 11*256K, 22*256K, and so on.
                if (placements[i].StoreRaw)
                {
                    long ublocks = (placements[i].UncompressedSize + Ublock256K - 1) / Ublock256K;
                    for (long m = 11; m < ublocks; m += 11)
                        runSet.Add(placements[i].OnDiskOffset + m * Ublock256K);
                }
            }
        }

        // ---- Tail: padding blocks + metadata blocks + terminator ------------------------------------
        var tail = new List<NapsCblockPlanEntry>();

        // Padding fills the logical gap [dataEnd, metaBase); each 256K block dedups to the block-info block.
        long paddingBytes = metaBase - dataEnd;
        int paddingBlocks = paddingBytes > 0 ? (int)((paddingBytes + Ublock256K - 1) / Ublock256K) : 0;
        for (int k = 0; k < paddingBlocks; k++)
            tail.Add(new NapsCblockPlanEntry
            {
                // Deduped padding blocks each re-anchor the on-disk cursor to the block-info block; the last
                // one is absorbed into the following metadata RUN, so only the first N-1 open a RUN.
                StartRun = k < paddingBlocks - 1,
                OnDiskOffset = result.BlockInfoOnDiskOffset,
                LogicalOffset = dataEnd + (long)k * Ublock256K,
                EvenChunkCompressedLength = 8,
                StreamLength = 0x10,
                Even = 0,
                Odd = 1,
                KdePredictor = 4,
                ShuffleIndex = 0,
            });

        // Metadata blocks: decode the compressed metadata's per-256K-block chunk sizes.
        var metaFile = ProsperoCompressedPfsFile.Parse(
            ProsperoCompressedPfsImage.Pack(result.MetadataPlaintext, 7, (int)Ublock256K));
        long metaOnDisk = result.MetadataOnDiskOffset;
        bool metaCompressed = result.CompressedMetadata.Length < result.MetadataPlaintext.Length;
        long metaCursor = metaOnDisk;
        int metaCount = metaFile.Blocks.Count;
        for (int i = 0; i < metaCount; i++)
        {
            var blk = metaFile.Blocks[i];
            int even = blk.IsMultiChunk ? blk.FirstChunkCompressedSize : blk.CompressedSize;
            tail.Add(new NapsCblockPlanEntry
            {
                // The metadata section opens a RUN on its first and last block; the middle blocks continue
                // the compressed cursor.
                StartRun = i == 0 || i == metaCount - 1,
                OnDiskOffset = metaCursor,
                LogicalOffset = metaBase + (long)i * Ublock256K,
                EvenChunkCompressedLength = metaCompressed ? even : blk.UncompressedSize,
                StreamLength = blk.CompressedSize,
                Even = 0,
                Odd = 1,
                KdePredictor = (byte)(metaCompressed ? 2 : 4),
                ShuffleIndex = (byte)(metaCompressed && i < metaCount - 1 ? 2 : 0),
            });
            metaCursor += blk.CompressedSize;
        }

        // Terminator marks the mount end.
        tail.Add(new NapsCblockPlanEntry { StartRun = true, OnDiskOffset = metaCursor, LogicalOffset = mountSize, Terminator = true });

        // ---- fidx: afid logical offsets + dataEnd + metaBase + mount --------------------------------
        var fidx = new List<long>(result.AfidLogicalOffsets);
        fidx.Add(dataEnd);
        fidx.Add(metaBase);
        fidx.Add(mountSize);

        int numUBlocks = (int)((mountSize + Ublock256K - 1) / Ublock256K);
        int numOuterBlocks = (result.Image.Length + Block64K - 1) / Block64K;

        var doc = ProsperoNapsLayoutBuilder.BuildFromInnerImage(
            numUBlocks: numUBlocks,
            numOuterBlocks: numOuterBlocks,
            files: files,
            runStartOnDiskOffsets: runSet,
            tailBlocks: tail,
            fileLogicalOffsets: fidx);

        return ProsperoNapsLayout.BuildLayout(doc);
    }
}
