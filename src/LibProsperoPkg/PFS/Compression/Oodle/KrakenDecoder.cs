// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// Kraken (newLZ) decoder for "nwonly" PFSv3 Kraken blocks: entropy-coded
// literals/commands/offsets/lengths, the post-seed 0x80 "excess" framing, and both literal models.
// It is an index-based translation of the Kraken *decompression* reference implementation in the
// project "ooz" (https://github.com/powzix/ooz, kraken.cpp, GNU GPL v3), extended with the
// excess-substream length escapes and continuation-byte excess-count parse emitted by the
// reference encoder.
//
// LibProsperoPkg as a whole is licensed under the GNU GPLv3; section 13 of the GPLv3 expressly
// permits conveying a work that links/combines GPLv3-covered code. This file carries the original
// ooz/GPL attribution. Uses byte[]/int indices only.
//
// Supported chunk-decode (DecodeBytes) array types: 0 (raw / memcpy-short) and 2/4 (Huffman, both
// code-length encodings + single/triple stream split). Types 1 (TANS), 3 (RLE) and 5 (recursive /
// multi-array) are reported as unsupported; reference level-7 nwonly blocks observed here use only
// raw + Huffman, but the dispatcher surfaces any unsupported type cleanly rather than silently failing.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System;
using System.Buffers.Binary;
using System.Numerics;

namespace LibProsperoPkg.PFS.Compression.Oodle;

/// <summary>The outcome of a Kraken decode attempt.</summary>
internal enum KrakenDecodeStatus
{
    /// <summary>The block decoded successfully into the destination buffer.</summary>
    Success = 0,

    /// <summary>The block's framing, sizes or arrays were inconsistent (corrupt or unexpected input).</summary>
    Malformed = 1,

    /// <summary>An entropy array used a coding the managed decoder does not implement (TANS/RLE/recursive).</summary>
    UnsupportedEntropy = 2,

    /// <summary>The chunk used an excess/control form the managed decoder does not implement.</summary>
    UnsupportedExcessMode = 3,
}

/// <summary>
/// A complete managed Kraken (newLZ) chunk decoder. Decodes one PFS block (one or two internal
/// newLZ chunks) into a caller-supplied destination buffer. This is the production decoder used by
/// <see cref="CompressedPfsFile"/> to read both this library's own output and reference-produced blocks.
/// </summary>
internal static class KrakenDecoder
{
    private const int ChunkMax = 0x20000; // a single newLZ chunk decodes at most 128 KiB
    private const int SeedSize = 8;

    /// <summary>
    /// Diagnostic seam: when non-null, invoked once per decoded LZ command with
    /// (litRunLen, matchLen, distance, offsIndex). offsIndex 0/1/2 = recent-offset reuse, 3 = new
    /// offset; the final literal tail is reported as (tailLen, 0, 0, -1). Used by diagnostics
    /// to extract the reference parse from a real chunk. Null in production (zero cost).
    /// </summary>
    internal static System.Action<int, int, int, int>? ParseTrace;

    // Boundary flag byte bits (the on-disk id=3 entry's per-chunk markers).
    // The low nibble describes the first sub-chunk, the high nibble the second: a 256 KiB block is two
    // 128 KiB sub-chunks whose types are INDEPENDENT (newLZ or bare-entropy), so each is decoded on its
    // own per these bits. Validated empirically across newLZ/entropy/mixed inputs and against the
    // frame rebuilder's bit-38 newLZ flag.
    private const int Chunk0SubLitBit = 0x01; // chunk0 literal model: set = sub/delta (mode 0), clear = raw (mode 1)
    private const int Chunk0NewLzBit = 0x02;  // chunk0 is newLZ; clear = bare-entropy array
    private const int Chunk1SubLitBit = 0x10; // chunk1 literal model (same encoding as chunk0)
    private const int Chunk1NewLzBit = 0x20;  // chunk1 is newLZ; clear (with 0x40) = bare-entropy array

    /// <summary>
    /// Decodes a whole PFS block (the section-7 payload) into <paramref name="dst"/> (sized to the
    /// block's exact uncompressed length). <paramref name="flags"/> is the block's on-disk boundary
    /// flag byte; <paramref name="firstChunkComp"/> is the first sub-chunk's compressed size (from the
    /// boundary size hint) and is only consulted when the block spans two sub-chunks (its uncompressed
    /// size exceeds one 128 KiB chunk). A two-chunk block's sub-chunks have INDEPENDENT types — each is
    /// newLZ or a bare-entropy <c>Kraken_DecodeBytes</c> array selected by <paramref name="flags"/>
    /// (chunk0: bit <c>0x02</c>; chunk1: bit <c>0x20</c>) — so they are decoded separately, the second
    /// seedless and able to back-reference the first. The literal model for each newLZ sub-chunk comes
    /// from its low bit (chunk0 <c>0x01</c>, chunk1 <c>0x10</c>): set = sub/delta, clear = raw.
    /// </summary>
    public static KrakenDecodeStatus DecodeBlock(
        ReadOnlySpan<byte> payload, int flags, int firstChunkComp, Span<byte> dst)
    {
        if (dst.Length <= 0)
            return payload.Length == 0 ? KrakenDecodeStatus.Success : KrakenDecodeStatus.Malformed;

        byte[] src = payload.ToArray();
        byte[] outBuf = new byte[dst.Length];

        bool chunk0NewLz = (flags & Chunk0NewLzBit) != 0;
        int litMode0 = (flags & Chunk0SubLitBit) != 0 ? 0 : 1;
        bool multiChunk = dst.Length > ChunkMax;

        KrakenDecodeStatus st;
        if (!multiChunk)
        {
            st = chunk0NewLz
                ? DecodeChunk(src, 0, src.Length, outBuf, 0, dst.Length, withSeed: true, litMode0)
                : DecodeBareEntropyBlock(src, 0, src.Length, outBuf, 0, dst.Length);
        }
        else
        {
            if (firstChunkComp <= 0 || firstChunkComp > src.Length || dst.Length <= ChunkMax)
                return KrakenDecodeStatus.Malformed;

            bool chunk1NewLz = (flags & Chunk1NewLzBit) != 0;
            int litMode1 = (flags & Chunk1SubLitBit) != 0 ? 0 : 1;
            int chunk1Comp = src.Length - firstChunkComp;
            int chunk1Dst = dst.Length - ChunkMax;

            // Sub-chunk 0 -> [0:ChunkMax].
            st = chunk0NewLz
                ? DecodeChunk(src, 0, firstChunkComp, outBuf, 0, ChunkMax, withSeed: true, litMode0)
                : DecodeBareEntropyBlock(src, 0, firstChunkComp, outBuf, 0, ChunkMax);
            if (st != KrakenDecodeStatus.Success)
                return st;

            // Sub-chunk 1 -> [ChunkMax:end], seedless; a newLZ chunk1 may back-reference chunk0's bytes
            // regardless of how chunk0 was decoded (they share the destination buffer).
            st = chunk1NewLz
                ? DecodeChunk(src, firstChunkComp, chunk1Comp, outBuf, ChunkMax, chunk1Dst, withSeed: false, litMode1)
                : DecodeBareEntropyBlock(src, firstChunkComp, chunk1Comp, outBuf, ChunkMax, chunk1Dst);
        }

        if (st == KrakenDecodeStatus.Success)
            outBuf.AsSpan(0, dst.Length).CopyTo(dst);
        return st;
    }

    /// <summary>
    /// Decodes one bare-entropy array: <paramref name="srcLen"/> bytes at <paramref name="srcStart"/>
    /// are a single <c>Kraken_DecodeBytes</c> array (raw type-0 or Huffman type-2/4) that expands to
    /// exactly <paramref name="dstLen"/> bytes written at <paramref name="dstStart"/> in
    /// <paramref name="outBuf"/> — no seed, no excess framing, no LZ table, no back-references. A block
    /// larger than one 128 KiB chunk is encoded as two such arrays back-to-back (each independent).
    /// The array must consume its whole source span.
    /// </summary>
    private static KrakenDecodeStatus DecodeBareEntropyBlock(
        byte[] src, int srcStart, int srcLen, byte[] outBuf, int dstStart, int dstLen)
    {
        if (srcLen < 0 || srcStart + srcLen > src.Length || dstLen < 0 || dstStart + dstLen > outBuf.Length)
            return KrakenDecodeStatus.Malformed;
        int n = DecodeBytes(src, srcStart, srcStart + srcLen, dstLen, out byte[] dec, out int decCount);
        if (n < 0)
            return n == -2 ? KrakenDecodeStatus.UnsupportedEntropy : KrakenDecodeStatus.Malformed;
        if (n != srcLen || decCount != dstLen)
            return KrakenDecodeStatus.Malformed;
        Array.Copy(dec, 0, outBuf, dstStart, dstLen);
        return KrakenDecodeStatus.Success;
    }

    /// <summary>Holds the four decoded streams for one newLZ chunk.</summary>
    private sealed class LzTable
    {
        public byte[] LitStream = Array.Empty<byte>();
        public int LitStreamSize;
        public byte[] CmdStream = Array.Empty<byte>();
        public int CmdStreamSize;
        public int[] OffsStream = Array.Empty<int>();
        public int OffsStreamSize;
        public int[] LenStream = Array.Empty<int>();
        public int LenStreamSize;
    }

    /// <summary>
    /// Decodes one newLZ chunk covering output range
    /// [<paramref name="dstStart"/>, dstStart + <paramref name="dstSize"/>) within the shared block
    /// buffer <paramref name="dst"/>. Matches may reference any earlier byte in <paramref name="dst"/>.
    /// </summary>
    private static KrakenDecodeStatus DecodeChunk(
        byte[] src, int srcStart, int srcLen, byte[] dst, int dstStart, int dstSize, bool withSeed, int literalMode)
    {
        if (dstSize <= 0 || dstStart + dstSize > dst.Length || srcLen < 0 || srcStart + srcLen > src.Length)
            return KrakenDecodeStatus.Malformed;

        int srcEnd = srcStart + srcLen;
        int sp = srcStart;
        int offset = withSeed ? 0 : dstStart; // ooz "offset" = dst - dst_start (0 only for the seeded chunk)

        var table = new LzTable();
        int rc = ReadLzTable(src, ref sp, srcEnd, dst, dstStart, dstSize, offset, table);
        if (rc < 0)
            return rc == -2 ? KrakenDecodeStatus.UnsupportedEntropy : KrakenDecodeStatus.Malformed;

        bool ok = ProcessLzRuns(literalMode, dst, dstStart, dstSize, offset, table);
        return ok ? KrakenDecodeStatus.Success : KrakenDecodeStatus.Malformed;
    }

    // ===========================================================================================
    //  Kraken_ReadLzTable  (+ the seed copy, the excess framing, and the multi-table offset mode)
    // ===========================================================================================
    private static int ReadLzTable(byte[] src, ref int sp, int srcEnd, byte[] dst, int dstStart, int dstSize, int offset, LzTable lzt)
    {
        // Seeded chunk: the first 8 output bytes are a raw COPY_64 seed.
        if (offset == 0)
        {
            if (srcEnd - sp < SeedSize)
                return -1;
            Array.Copy(src, sp, dst, dstStart, SeedSize);
            sp += SeedSize;
        }

        // Excess framing: reference chunks set the post-seed control byte's 0x80 bit.
        bool excessFlag = false;
        int excessCount = 0;
        if (sp < srcEnd && (src[sp] & 0x80) != 0)
        {
            byte flag = src[sp++];
            if ((flag & 0xC0) != 0x80)
                return -1; // reserved flag bit set
            excessFlag = true;
            excessCount = flag & 0x3F;
            if (excessCount > 0x1F)
            {
                if (sp >= srcEnd)
                    return -1; // truncated excess byte count
                excessCount += src[sp++] * 0x20; // continuation byte (newLZ_decode_chunk_phase1)
            }
            srcEnd -= excessCount; // trailing excess substream lives at [srcEnd, srcEnd+excessCount)
            if (srcEnd < sp)
                return -1;
        }

        // Lit stream (bounded by dst_size).
        int n = DecodeBytes(src, sp, srcEnd, dstSize, out byte[] lit, out int litCount);
        if (n < 0) return n;
        sp += n;
        lzt.LitStream = lit; lzt.LitStreamSize = litCount;

        // Command stream (bounded by dst_size).
        n = DecodeBytes(src, sp, srcEnd, dstSize, out byte[] cmd, out int cmdCount);
        if (n < 0) return n;
        sp += n;
        lzt.CmdStream = cmd; lzt.CmdStreamSize = cmdCount;

        if (srcEnd - sp < 3)
            return -1;

        int offsScaling = 0;
        byte[] packedOffsExtra = Array.Empty<byte>();
        byte[] packedOffs;
        int offsCount;

        if ((src[sp] & 0x80) != 0)
        {
            // Distances coded with two tables.
            offsScaling = src[sp] - 127;
            sp++;
            n = DecodeBytes(src, sp, srcEnd, cmdCount, out packedOffs, out offsCount);
            if (n < 0) return n;
            sp += n;
            if (offsScaling != 1)
            {
                n = DecodeBytes(src, sp, srcEnd, offsCount, out packedOffsExtra, out int extraCount);
                if (n < 0) return n;
                if (extraCount != offsCount) return -1;
                sp += n;
            }
        }
        else
        {
            n = DecodeBytes(src, sp, srcEnd, cmdCount, out packedOffs, out offsCount);
            if (n < 0) return n;
            sp += n;
        }
        lzt.OffsStreamSize = offsCount;

        // Packed litlen stream (bounded by dst_size / 4).
        n = DecodeBytes(src, sp, srcEnd, dstSize >> 2, out byte[] packedLitLen, out int lenCount);
        if (n < 0) return n;
        sp += n;
        lzt.LenStreamSize = lenCount;

        lzt.OffsStream = new int[offsCount];
        lzt.LenStream = new int[lenCount];

        return UnpackOffsets(src, sp, srcEnd, excessFlag, excessCount,
                             packedOffs, offsCount, offsScaling, packedOffsExtra,
                             packedLitLen, lenCount, lzt.OffsStream, lzt.LenStream)
            ? sp
            : -1;
    }

    // ===========================================================================================
    //  Kraken_UnpackOffsets  (dual meet-in-the-middle bit reader, traditional + scaled offsets,
    //                         in-band OR excess-substream length escapes)
    // ===========================================================================================
    private static bool UnpackOffsets(
        byte[] src, int bsBegin, int bsEnd, bool excessFlag, int excessCount,
        byte[] packedOffs, int offsCount, int offsScaling, byte[] packedOffsExtra,
        byte[] packedLitLen, int lenCount, int[] offsStream, int[] lenStream)
    {
        var a = OozBR.Forward(src, bsBegin, bsEnd);
        var b = OozBR.Backward(src, bsBegin, bsEnd);

        int u32LenStreamSize = 0;
        if (!excessFlag)
        {
            if (b.Bits < 0x2000) return false;
            int nn = 31 - Bsr(b.Bits);
            b.BitPos += nn; b.Bits <<= nn; b.RefillB();
            nn++;
            u32LenStreamSize = (int)((b.Bits >> (32 - nn)) - 1);
            b.BitPos += nn; b.Bits <<= nn; b.RefillB();
        }
        else
        {
            for (int q = 0; q < lenCount; q++)
                if (packedLitLen[q] == 255) u32LenStreamSize++;
        }

        if (offsScaling == 0)
        {
            int i = 0;
            while (i < offsCount)
            {
                offsStream[i] = -(int)a.ReadDistance(packedOffs[i]); i++;
                if (i >= offsCount) break;
                offsStream[i] = -(int)b.ReadDistanceB(packedOffs[i]); i++;
            }
        }
        else
        {
            int i = 0;
            while (i < offsCount)
            {
                uint cmd = packedOffs[i];
                if ((cmd >> 3) > 26) return false;
                uint off = ((8u + (cmd & 7)) << (int)(cmd >> 3)) | a.ReadMoreThan24Bits((int)(cmd >> 3));
                offsStream[i] = 8 - (int)off; i++;
                if (i >= offsCount) break;
                cmd = packedOffs[i];
                if ((cmd >> 3) > 26) return false;
                off = ((8u + (cmd & 7)) << (int)(cmd >> 3)) | b.ReadMoreThan24BitsB((int)(cmd >> 3));
                offsStream[i] = 8 - (int)off; i++;
            }
            if (offsScaling != 1)
                CombineScaledOffsets(offsStream, offsCount, offsScaling, packedOffsExtra);
        }

        if (u32LenStreamSize > 512)
            return false;
        var u32 = new uint[u32LenStreamSize];

        if (excessFlag)
        {
            // The length-escape u32 values live in a SEPARATE dual bitstream over the trailing
            // excess substream [bsEnd, bsEnd+excessCount), read with the same fwd/bwd alternation.
            var ea = OozBR.Forward(src, bsEnd, bsEnd + excessCount);
            var eb = OozBR.Backward(src, bsEnd, bsEnd + excessCount);
            int i = 0;
            for (; i + 1 < u32LenStreamSize; i += 2)
            {
                if (!ea.ReadLength(out u32[i])) return false;
                if (!eb.ReadLengthB(out u32[i + 1])) return false;
            }
            if (i < u32LenStreamSize)
            {
                if (!ea.ReadLength(out u32[i])) return false;
            }
            // (the excess seam is allowed to differ; ooz only asserts it for the main bitstream)
        }
        else
        {
            int i = 0;
            for (; i + 1 < u32LenStreamSize; i += 2)
            {
                if (!a.ReadLength(out u32[i])) return false;
                if (!b.ReadLengthB(out u32[i + 1])) return false;
            }
            if (i < u32LenStreamSize)
            {
                if (!a.ReadLength(out u32[i])) return false;
            }
        }

        int aSeam = a.P - ((24 - a.BitPos) >> 3);
        int bSeam = b.P + ((24 - b.BitPos) >> 3);
        if (aSeam != bSeam && !excessFlag)
            return false;

        int u = 0;
        for (int i = 0; i < lenCount; i++)
        {
            uint v = packedLitLen[i];
            if (v == 255)
            {
                if (u >= u32LenStreamSize) return false;
                v = u32[u++] + 255;
            }
            lenStream[i] = (int)v + 3;
        }
        return u == u32LenStreamSize;
    }

    private static void CombineScaledOffsets(int[] offs, int count, int scale, byte[] extra)
    {
        for (int i = 0; i < count; i++)
            offs[i] = (sbyte)extra[i] - offs[i] * scale;
    }

    // ===========================================================================================
    //  Kraken_DecodeBytes  (dispatcher) — returns srcUsed, or -1 malformed / -2 unsupported type
    // ===========================================================================================
    private static int DecodeBytes(byte[] src, int sp, int srcEnd, int outputCap, out byte[] output, out int decodedSize)
    {
        output = Array.Empty<byte>();
        decodedSize = 0;
        int srcOrg = sp;

        if (srcEnd - sp < 2)
            return -1;

        int chunkType = (src[sp] >> 4) & 0x7;
        int srcSize, dstSize;

        if (chunkType == 0)
        {
            if (src[sp] >= 0x80)
            {
                srcSize = ((src[sp] << 8) | src[sp + 1]) & 0xFFF; // memcpy-short, 12-bit length
                sp += 2;
            }
            else
            {
                if (srcEnd - sp < 3) return -1;
                srcSize = (src[sp] << 16) | (src[sp + 1] << 8) | src[sp + 2];
                if ((srcSize & ~0x3FFFF) != 0) return -1;
                sp += 3;
            }
            if (srcSize > outputCap || srcEnd - sp < srcSize) return -1;
            output = new byte[srcSize];
            Array.Copy(src, sp, output, 0, srcSize);
            decodedSize = srcSize;
            return sp + srcSize - srcOrg;
        }

        // Entropy modes: the first bytes carry src_size + dst_size.
        if (src[sp] >= 0x80)
        {
            if (srcEnd - sp < 3) return -1;
            uint bits = (uint)((src[sp] << 16) | (src[sp + 1] << 8) | src[sp + 2]);
            srcSize = (int)(bits & 0x3FF);
            dstSize = (int)(srcSize + ((bits >> 10) & 0x3FF) + 1);
            sp += 3;
        }
        else
        {
            if (srcEnd - sp < 5) return -1;
            uint bits = (uint)((src[sp + 1] << 24) | (src[sp + 2] << 16) | (src[sp + 3] << 8) | src[sp + 4]);
            srcSize = (int)(bits & 0x3FFFF);
            dstSize = (int)((((bits >> 18) | ((uint)src[sp] << 14)) & 0x3FFFF) + 1);
            if (srcSize >= dstSize) return -1;
            sp += 5;
        }
        if (srcEnd - sp < srcSize || dstSize > outputCap) return -1;

        output = new byte[dstSize];
        int used;
        switch (chunkType)
        {
            case 2:
            case 4:
                used = DecodeBytesType12(src, sp, srcSize, output, dstSize, chunkType >> 1);
                break;
            default:
                // 1 (TANS), 3 (RLE), 5 (recursive/multi-array): not emitted by reference nwonly lvl-7 here.
                return -2;
        }
        if (used != srcSize) return -1;
        decodedSize = dstSize;
        return sp + srcSize - srcOrg;
    }

    /// <summary>Diagnostic descriptor for one entropy/raw array inside a chunk.</summary>
    internal sealed class KrakenArrayInfo
    {
        public string Name = "";
        public int SrcOffset;          // absolute offset of the array's first byte in src
        public int SrcLen;             // bytes the array occupies (header + payload)
        public int ChunkType;          // (src[off] >> 4) & 7  — 0 raw, 2 single-3-stream, 4 two-core, 1 TANS, 3 RLE, 5 recursive
        public int Transmission = -1;  // entropy code-length transmission: 0 = simple, 1 = RLE; -1 = raw
        public byte[] Decoded = Array.Empty<byte>();
    }

    /// <summary>
    /// Walks a single newLZ chunk exactly like <see cref="ReadLzTable"/> but, instead of building the LZ
    /// table, records each entropy/raw array's exact byte span, chunk type and code-length transmission
    /// plus its decoded bytes. Used by diagnostics to compare this library's entropy encoding against
    /// reference arrays byte-for-byte. Returns 0 on success or a negative error.
    /// </summary>
    internal static int InspectChunkArrays(byte[] src, int sp, int srcEnd, int offset, int dstSize, out System.Collections.Generic.List<KrakenArrayInfo> arrays)
    {
        var list = new System.Collections.Generic.List<KrakenArrayInfo>();
        arrays = list;

        if (offset == 0)
        {
            if (srcEnd - sp < SeedSize) return -1;
            sp += SeedSize;
        }

        if (sp < srcEnd && (src[sp] & 0x80) != 0)
        {
            byte flag = src[sp++];
            if ((flag & 0xC0) != 0x80) return -1;
            int excessCount = flag & 0x3F;
            if (excessCount > 0x1F)
            {
                if (sp >= srcEnd) return -1;
                excessCount += src[sp++] * 0x20;
            }
            srcEnd -= excessCount;
            if (srcEnd < sp) return -1;
        }

        KrakenArrayInfo? Record(string name, int cap, out int err)
        {
            int arrStart = sp;
            int n = DecodeBytes(src, sp, srcEnd, cap, out byte[] dec, out int decCount);
            err = n;
            if (n < 0) return null;
            var info = new KrakenArrayInfo
            {
                Name = name,
                SrcOffset = arrStart,
                SrcLen = n,
                ChunkType = (src[arrStart] >> 4) & 0x7,
                Decoded = dec.Length == decCount ? dec : dec[..decCount],
            };
            info.Transmission = PeekTransmission(src, arrStart, arrStart + n, info.ChunkType);
            sp += n;
            list.Add(info);
            return info;
        }

        if (Record("lit", dstSize, out int eLit) is null) return eLit;
        int cmdCap = dstSize;
        var cmdInfo = Record("cmd", cmdCap, out int eCmd);
        if (cmdInfo is null) return eCmd;
        int cmdCount = cmdInfo.Decoded.Length;

        if (srcEnd - sp < 3) return -10;
        if ((src[sp] & 0x80) != 0)
        {
            int offsScaling = src[sp] - 127;
            sp++;
            var offsInfo = Record("offs", cmdCount, out int eOffs);
            if (offsInfo is null) return eOffs;
            if (offsScaling != 1)
            {
                if (Record("offsExtra", offsInfo.Decoded.Length, out int eEx) is null) return eEx;
            }
        }
        else
        {
            if (Record("offs", cmdCount, out int eOffs) is null) return eOffs;
        }

        if (Record("litlen", dstSize >> 2, out int eLen) is null) return eLen;
        return 0;
    }

    // Peeks the code-length transmission selector (first 1-2 stream bits) of an entropy array.
    private static int PeekTransmission(byte[] src, int sp, int arrEnd, int chunkType)
    {
        if (chunkType != 2 && chunkType != 4) return -1;
        int headerLen = src[sp] >= 0x80 ? 3 : 5;
        int payStart = sp + headerLen;
        if (payStart >= arrEnd) return -1;
        var bits = OozBR.Forward(src, payStart, arrEnd);
        if (bits.ReadBitNoRefill() == 0) return 0; // Old/simple
        if (bits.ReadBitNoRefill() == 0) return 1; // New/RLE
        return 2;                                   // reserved
    }

    // Diagnostic snapshot of a chunk-type-2/4 entropy array's Huffman header (M2 divergence probe).
    // Read-only: re-parses the header (length + code-length transmission + split sizes) and reconstructs
    // the per-symbol code-length table without decoding the 3-stream payload. Used to localize exactly
    // where this encoder diverges from the reference (tree shape vs transmission vs split vs bit-packing).
    internal sealed class Type12Info
    {
        public int ChunkType;            // 2 (single 3-stream) or 4 (two-core 6-stream)
        public int HeaderLen;            // 3 or 5
        public int SrcSize;              // array byte length after the header
        public int DstSize;              // decoded byte count
        public int Transmission = -1;    // 0 = Old/simple, 1 = New/RLE, 2 = reserved
        public int NumSyms;
        public int CodeLenEndOffset;     // byte offset (into src) right after the code-length transmission
        public int SplitMid = -1;        // type2: 2-byte mid split; type4: 3-byte outer split
        public int SplitLeft = -1;       // type4 only
        public int SplitRight = -1;      // type4 only
        public int PayloadOffset = -1;   // byte offset where the coded 3-stream payload begins
        public byte[] CodeLengths = new byte[256]; // per-symbol bit length, 0 = symbol absent
    }

    // Re-parses a type-2/4 entropy array starting at src[sp] (over [sp, srcEnd)). Returns false if the
    // bytes are not a well-formed type-2/4 Huffman header. Pure diagnostic; mutates nothing.
    internal static bool InspectType12(byte[] src, int sp, int srcEnd, out Type12Info info)
    {
        info = new Type12Info();
        if (src is null || sp < 0 || srcEnd > src.Length || srcEnd - sp < 2) return false;
        int chunkType = (src[sp] >> 4) & 7;
        if (chunkType != 2 && chunkType != 4) return false;
        info.ChunkType = chunkType;

        int srcSize, dstSize, headerLen;
        if (src[sp] >= 0x80)
        {
            if (srcEnd - sp < 3) return false;
            uint b = (uint)((src[sp] << 16) | (src[sp + 1] << 8) | src[sp + 2]);
            srcSize = (int)(b & 0x3FF);
            dstSize = (int)(srcSize + ((b >> 10) & 0x3FF) + 1);
            headerLen = 3;
        }
        else
        {
            if (srcEnd - sp < 5) return false;
            uint b = (uint)((src[sp + 1] << 24) | (src[sp + 2] << 16) | (src[sp + 3] << 8) | src[sp + 4]);
            srcSize = (int)(b & 0x3FFFF);
            dstSize = (int)(((((uint)src[sp] << 14) | (b >> 18)) & 0x3FFFF) + 1);
            headerLen = 5;
        }
        info.SrcSize = srcSize;
        info.DstSize = dstSize;
        info.HeaderLen = headerLen;

        int payStart = sp + headerLen;
        int arrEnd = payStart + srcSize;
        if (arrEnd > srcEnd || payStart >= arrEnd) return false;

        var bits = OozBR.Forward(src, payStart, arrEnd);
        uint[] codePrefix = (uint[])CodePrefixOrg.Clone();
        byte[] syms = new byte[1280];

        int numSyms;
        if (bits.ReadBitNoRefill() == 0)
        {
            info.Transmission = 0;
            numSyms = HuffReadCodeLengthsOld(ref bits, syms, codePrefix);
        }
        else if (bits.ReadBitNoRefill() == 0)
        {
            info.Transmission = 1;
            numSyms = HuffReadCodeLengthsNew(ref bits, syms, codePrefix);
        }
        else
        {
            info.Transmission = 2;
            return false;
        }
        if (numSyms < 1) return false;
        info.NumSyms = numSyms;

        // Reconstruct per-symbol code lengths: syms[prefixOrg[cl] .. codePrefix[cl]) all have length cl.
        for (int cl = 1; cl <= 11; cl++)
            for (uint k = CodePrefixOrg[cl]; k < codePrefix[cl]; k++)
                info.CodeLengths[syms[k]] = (byte)cl;

        int spAfter = bits.P - ((24 - bits.BitPos) / 8);
        info.CodeLenEndOffset = spAfter;

        if (numSyms == 1) { info.PayloadOffset = spAfter; return true; }

        int t = chunkType >> 1; // 2 -> single (1); 4 -> two-core (2)
        if (t == 1)
        {
            if (spAfter + 2 > arrEnd) return false;
            info.SplitMid = src[spAfter] | (src[spAfter + 1] << 8);
            info.PayloadOffset = spAfter + 2;
        }
        else
        {
            if (spAfter + 5 > arrEnd) return false;
            info.SplitMid = src[spAfter] | (src[spAfter + 1] << 8) | (src[spAfter + 2] << 16);
            info.SplitLeft = src[spAfter + 3] | (src[spAfter + 4] << 8);
            int srcMid = spAfter + 3 + info.SplitMid;
            if (srcMid + 2 <= arrEnd) info.SplitRight = src[srcMid] | (src[srcMid + 1] << 8);
            info.PayloadOffset = spAfter + 5;
        }
        return true;
    }

    // ===========================================================================================
    //  Huffman: Kraken_DecodeBytes_Type12 + code-length readers + LUT + 3-stream scalar core
    // ===========================================================================================
    private static readonly uint[] CodePrefixOrg =
        { 0x0, 0x0, 0x2, 0x6, 0xE, 0x1E, 0x3E, 0x7E, 0xFE, 0x1FE, 0x2FE, 0x3FE };

    private static int DecodeBytesType12(byte[] src, int srcStart, int srcSize, byte[] output, int outputSize, int type)
    {
        int srcEnd = srcStart + srcSize;
        var bits = OozBR.Forward(src, srcStart, srcEnd);

        uint[] codePrefix = (uint[])CodePrefixOrg.Clone();
        byte[] syms = new byte[1280];

        int numSyms;
        if (bits.ReadBitNoRefill() == 0)
            numSyms = HuffReadCodeLengthsOld(ref bits, syms, codePrefix);
        else if (bits.ReadBitNoRefill() == 0)
            numSyms = HuffReadCodeLengthsNew(ref bits, syms, codePrefix);
        else
            return -1;

        if (numSyms < 1)
            return -1;

        int sp = bits.P - ((24 - bits.BitPos) / 8);

        if (numSyms == 1)
        {
            byte fill = syms[0];
            for (int i = 0; i < outputSize; i++) output[i] = fill;
            return sp - srcEnd;
        }

        var lut = new NewHuffLut();
        if (!HuffMakeLut(CodePrefixOrg, codePrefix, lut, syms))
            return -1;

        var rev = new NewHuffLut();
        ReverseBitsArray2048(lut.Bits2Len, rev.Bits2Len);
        ReverseBitsArray2048(lut.Bits2Sym, rev.Bits2Sym);

        if (type == 1)
        {
            if (sp + 3 > srcEnd) return -1;
            int splitMid = src[sp] | (src[sp + 1] << 8);
            sp += 2;
            var hr = new HuffReader(src, output)
            {
                OutOff = 0,
                OutEnd = outputSize,
                Src = sp,
                SrcEnd = srcEnd,
                SrcMidOrg = sp + splitMid,
                SrcMid = sp + splitMid,
            };
            if (!DecodeBytesCore(ref hr, rev)) return -1;
        }
        else
        {
            if (sp + 6 > srcEnd) return -1;
            int halfOut = (outputSize + 1) >> 1;
            int splitMid = src[sp] | (src[sp + 1] << 8) | (src[sp + 2] << 16);
            sp += 3;
            if (splitMid > srcEnd - sp) return -1;
            int srcMid = sp + splitMid;
            int splitLeft = src[sp] | (src[sp + 1] << 8);
            sp += 2;
            if (srcMid - sp < splitLeft + 2 || srcEnd - srcMid < 3) return -1;
            int splitRight = src[srcMid] | (src[srcMid + 1] << 8);
            if (srcEnd - (srcMid + 2) < splitRight + 2) return -1;

            var hr1 = new HuffReader(src, output)
            {
                OutOff = 0,
                OutEnd = halfOut,
                Src = sp,
                SrcEnd = srcMid,
                SrcMidOrg = sp + splitLeft,
                SrcMid = sp + splitLeft,
            };
            if (!DecodeBytesCore(ref hr1, rev)) return -1;

            var hr2 = new HuffReader(src, output)
            {
                OutOff = halfOut,
                OutEnd = outputSize,
                Src = srcMid + 2,
                SrcEnd = srcEnd,
                SrcMidOrg = srcMid + 2 + splitRight,
                SrcMid = srcMid + 2 + splitRight,
            };
            if (!DecodeBytesCore(ref hr2, rev)) return -1;
        }
        return srcSize;
    }

    private sealed class NewHuffLut
    {
        public readonly byte[] Bits2Len = new byte[2048 + 16];
        public readonly byte[] Bits2Sym = new byte[2048 + 16];
    }

    private static bool HuffMakeLut(uint[] prefixOrg, uint[] prefixCur, NewHuffLut lut, byte[] syms)
    {
        uint currslot = 0;
        for (uint i = 1; i < 11; i++)
        {
            uint start = prefixOrg[i];
            uint count = prefixCur[i] - start;
            if (count != 0)
            {
                uint stepsize = 1u << (int)(11 - i);
                uint numToSet = count << (int)(11 - i);
                if (currslot + numToSet > 2048) return false;
                FillByte(lut.Bits2Len, (int)currslot, (byte)i, (int)numToSet);
                int p = (int)currslot;
                for (uint j = 0; j != count; j++, p += (int)stepsize)
                    FillByte(lut.Bits2Sym, p, syms[start + j], (int)stepsize);
                currslot += numToSet;
            }
        }
        if (prefixCur[11] - prefixOrg[11] != 0)
        {
            uint numToSet = prefixCur[11] - prefixOrg[11];
            if (currslot + numToSet > 2048) return false;
            FillByte(lut.Bits2Len, (int)currslot, 11, (int)numToSet);
            Array.Copy(syms, (int)prefixOrg[11], lut.Bits2Sym, (int)currslot, (int)numToSet);
            currslot += numToSet;
        }
        return currslot == 2048;
    }

    private static void FillByte(byte[] dst, int off, byte v, int n)
    {
        for (int i = 0; i < n; i++) dst[off + i] = v;
    }

    // output[i] = input[reverse-low-11-bits(i)]  (the SIMD ReverseBitsArray2048 is an 11-bit
    // index reversal converting the MSB-first LUT into the LSB-first form the 3-stream core reads).
    private static void ReverseBitsArray2048(byte[] input, byte[] output)
    {
        for (int i = 0; i < 2048; i++)
        {
            int j = Reverse11(i);
            output[i] = input[j];
        }
    }

    private static int Reverse11(int v)
    {
        int r = 0;
        for (int k = 0; k < 11; k++)
        {
            r = (r << 1) | (v & 1);
            v >>= 1;
        }
        return r;
    }

    private static int HuffReadCodeLengthsOld(ref OozBR bits, byte[] syms, uint[] codePrefix)
    {
        if (bits.ReadBitNoRefill() != 0)
        {
            int sym = 0, codelen, numSymbols = 0;
            int avgBitsX4 = 32;
            int forcedBits = (int)bits.ReadBitsNoRefill(2);
            uint thres = 1u << (31 - (int)(20u >> forcedBits));
            int n;
            bool skip = bits.ReadBit() != 0;

            while (true)
            {
                if (!skip)
                {
                    if ((bits.Bits & 0xFF000000) == 0) return -1;
                    sym += (int)bits.ReadBitsNoRefill(2 * (Clz(bits.Bits) + 1)) - 2 + 1;
                    if (sym >= 256) break;
                }
                skip = false;

                bits.Refill();
                if ((bits.Bits & 0xFF000000) == 0) return -1;
                n = (int)bits.ReadBitsNoRefill(2 * (Clz(bits.Bits) + 1)) - 2 + 1;
                if (sym + n > 256) return -1;
                bits.Refill();
                numSymbols += n;
                do
                {
                    if (bits.Bits < thres) return -1;
                    int lz = Clz(bits.Bits);
                    int v = (int)bits.ReadBitsNoRefill(lz + forcedBits + 1) + ((lz - 1) << forcedBits);
                    codelen = (-(v & 1) ^ (v >> 1)) + ((avgBitsX4 + 2) >> 2);
                    if (codelen < 1 || codelen > 11) return -1;
                    avgBitsX4 = codelen + ((3 * avgBitsX4 + 2) >> 2);
                    bits.Refill();
                    syms[codePrefix[codelen]++] = (byte)sym++;
                } while (--n != 0);

                if (sym == 256) break;
            }
            return (sym == 256 && numSymbols >= 2) ? numSymbols : -1;
        }
        else
        {
            int numSymbols = (int)bits.ReadBitsNoRefill(8);
            if (numSymbols == 0) return -1;
            if (numSymbols == 1)
            {
                syms[0] = (byte)bits.ReadBitsNoRefill(8);
            }
            else
            {
                int codelenBits = (int)bits.ReadBitsNoRefill(3);
                if (codelenBits > 4) return -1;
                for (int i = 0; i < numSymbols; i++)
                {
                    bits.Refill();
                    int sym = (int)bits.ReadBitsNoRefill(8);
                    int codelen = (int)bits.ReadBitsNoRefillZero(codelenBits) + 1;
                    if (codelen > 11) return -1;
                    syms[codePrefix[codelen]++] = (byte)sym;
                }
            }
            return numSymbols;
        }
    }

    private static int HuffReadCodeLengthsNew(ref OozBR bits, byte[] syms, uint[] codePrefix)
    {
        int forcedBits = (int)bits.ReadBitsNoRefill(2);
        int numSymbols = (int)bits.ReadBitsNoRefill(8) + 1;
        int fluff = bits.ReadFluff(numSymbols);

        byte[] codeLen = new byte[512 + 16];
        var br2 = new OozBR2
        {
            B = bits.B,
            BitPos = (bits.BitPos - 24) & 7,
            PEnd = bits.Bound,
            P = bits.P - ((24 - bits.BitPos + 7) >> 3),
        };

        if (!DecodeGolombRiceLengths(codeLen, numSymbols + fluff, ref br2)) return -1;
        for (int z = 0; z < 16; z++) codeLen[numSymbols + fluff + z] = 0;
        if (!DecodeGolombRiceBits(codeLen, numSymbols, forcedBits, ref br2)) return -1;

        // Reset the bit decoder onto br2's position.
        bits.BitPos = 24;
        bits.P = br2.P;
        bits.Bits = 0;
        bits.Refill();
        bits.Bits <<= br2.BitPos;
        bits.BitPos += br2.BitPos;

        uint runningSum = 0x1e;
        for (int i = 0; i < numSymbols; i++)
        {
            int v = codeLen[i];
            v = -(v & 1) ^ (v >> 1);
            int cl = v + (int)(runningSum >> 2) + 1;
            if (cl < 1 || cl > 11) return -1;
            codeLen[i] = (byte)cl;
            runningSum = (uint)((int)runningSum + v);
        }

        var range = new HuffRange[128];
        int ranges = HuffConvertToRanges(range, numSymbols, fluff, codeLen, numSymbols, ref bits);
        if (ranges <= 0) return -1;

        int cp = 0;
        for (int i = 0; i < ranges; i++)
        {
            int sym = range[i].Symbol;
            int nn = range[i].Num;
            do
            {
                syms[codePrefix[codeLen[cp++]]++] = (byte)sym++;
            } while (--nn != 0);
        }
        return numSymbols;
    }

    private struct HuffRange { public int Symbol; public int Num; }

    private static int HuffConvertToRanges(HuffRange[] range, int numSymbols, int p, byte[] symlen, int symlenOff, ref OozBR bits)
    {
        int numRanges = p >> 1, v, symIdx = 0;

        if ((p & 1) != 0)
        {
            bits.Refill();
            v = symlen[symlenOff++];
            if (v >= 8) return -1;
            symIdx = (int)bits.ReadBitsNoRefill(v + 1) + (1 << (v + 1)) - 1;
        }
        int symsUsed = 0;

        for (int i = 0; i < numRanges; i++)
        {
            bits.Refill();
            v = symlen[symlenOff];
            if (v >= 9) return -1;
            int num = (int)bits.ReadBitsNoRefillZero(v) + (1 << v);
            v = symlen[symlenOff + 1];
            if (v >= 8) return -1;
            int space = (int)bits.ReadBitsNoRefill(v + 1) + (1 << (v + 1)) - 1;
            range[i].Symbol = symIdx;
            range[i].Num = num;
            symsUsed += num;
            symIdx += num + space;
            symlenOff += 2;
        }

        if (symIdx >= 256 || symsUsed >= numSymbols || symIdx + numSymbols - symsUsed > 256)
            return -1;

        range[numRanges].Symbol = symIdx;
        range[numRanges].Num = numSymbols - symsUsed;
        return numRanges + 1;
    }

    // 3-stream scalar Huffman core (ooz Kraken_DecodeBytesCore, scalar tail only — no SIMD fast path).
    private static bool DecodeBytesCore(ref HuffReader hr, NewHuffLut lut)
    {
        byte[] B = hr.B;
        byte[] outp = hr.Out;
        byte[] b2len = lut.Bits2Len;
        byte[] b2sym = lut.Bits2Sym;

        int src = hr.Src;
        uint srcBits = hr.SrcBits;
        int srcBitpos = hr.SrcBitpos;
        int srcMid = hr.SrcMid;
        uint srcMidBits = hr.SrcMidBits;
        int srcMidBitpos = hr.SrcMidBitpos;
        int srcEnd = hr.SrcEnd;
        uint srcEndBits = hr.SrcEndBits;
        int srcEndBitpos = hr.SrcEndBitpos;

        int dst = hr.OutOff;
        int dstEnd = hr.OutEnd;

        if (src > srcMid)
            return false;

        int k, n;
        for (;;)
        {
            if (dst >= dstEnd) break;

            if (srcMid - src <= 1)
            {
                if (srcMid - src == 1) srcBits |= (uint)B[src] << srcBitpos;
            }
            else
            {
                srcBits |= (uint)(B[src] | (B[src + 1] << 8)) << srcBitpos;
            }
            k = (int)(srcBits & 0x7FF);
            n = b2len[k];
            srcBitpos -= n;
            srcBits >>= n;
            outp[dst++] = b2sym[k];
            src += (7 - srcBitpos) >> 3;
            srcBitpos &= 7;

            if (dst < dstEnd)
            {
                if (srcEnd - srcMid <= 1)
                {
                    if (srcEnd - srcMid == 1)
                    {
                        srcEndBits |= (uint)B[srcMid] << srcEndBitpos;
                        srcMidBits |= (uint)B[srcMid] << srcMidBitpos;
                    }
                }
                else
                {
                    uint vv = (uint)(B[srcEnd - 2] | (B[srcEnd - 1] << 8));
                    srcEndBits |= (((vv >> 8) | (vv << 8)) & 0xFFFF) << srcEndBitpos;
                    srcMidBits |= (uint)(B[srcMid] | (B[srcMid + 1] << 8)) << srcMidBitpos;
                }
                k = (int)(srcEndBits & 0x7FF);
                n = b2len[k];
                outp[dst++] = b2sym[k];
                srcEndBitpos -= n;
                srcEndBits >>= n;
                srcEnd -= (7 - srcEndBitpos) >> 3;
                srcEndBitpos &= 7;
                if (dst < dstEnd)
                {
                    k = (int)(srcMidBits & 0x7FF);
                    n = b2len[k];
                    outp[dst++] = b2sym[k];
                    srcMidBitpos -= n;
                    srcMidBits >>= n;
                    srcMid += (7 - srcMidBitpos) >> 3;
                    srcMidBitpos &= 7;
                }
            }
            if (src > srcMid || srcMid > srcEnd)
                return false;
        }
        if (src != hr.SrcMidOrg || srcEnd != srcMid)
            return false;
        return true;
    }

    private struct HuffReader
    {
        public byte[] B;
        public byte[] Out;
        public int Src, SrcEnd, SrcMid, SrcMidOrg;
        public uint SrcBits, SrcMidBits, SrcEndBits;
        public int SrcBitpos, SrcMidBitpos, SrcEndBitpos;
        public int OutOff, OutEnd;
        public HuffReader(byte[] b, byte[] o) : this()
        {
            B = b; Out = o;
        }
    }

    // ===========================================================================================
    //  Golomb-Rice (ooz BitReader2 / DecodeGolombRiceLengths / DecodeGolombRiceBits)
    // ===========================================================================================
    private struct OozBR2 { public byte[] B; public int P; public int PEnd; public int BitPos; }

    private static readonly uint[] RiceVal = BuildRiceVal();
    private static readonly byte[] RiceLen = BuildRiceLen();

    private static bool DecodeGolombRiceLengths(byte[] dst, int size, ref OozBR2 br)
    {
        int p = br.P, pEnd = br.PEnd;
        int dstPos = 0, dstEnd = size;
        if (p >= pEnd) return false;

        int count = -br.BitPos;
        uint v = (uint)(At(br.B, p++) & (255 >> br.BitPos));
        for (;;)
        {
            if (v == 0)
            {
                count += 8;
            }
            else
            {
                uint x = RiceVal[v];
                uint lo = (uint)count + (x & 0x0F0F0F0F);
                WriteLE32(dst, dstPos, lo);
                WriteLE32(dst, dstPos + 4, (x >> 4) & 0x0F0F0F0F);
                dstPos += RiceLen[v];
                if (dstPos >= dstEnd) break;
                count = (int)(x >> 28);
            }
            if (p >= pEnd) return false;
            v = At(br.B, p++);
        }
        if (dstPos > dstEnd)
        {
            int nn = dstPos - dstEnd;
            do { v &= v - 1; } while (--nn != 0);
        }
        int bitpos = 0;
        if ((v & 1) == 0)
        {
            p--;
            int q = Bsf(v);
            bitpos = 8 - q;
        }
        br.P = p;
        br.BitPos = bitpos;
        return true;
    }

    private static bool DecodeGolombRiceBits(byte[] dst, int size, int bitcount, ref OozBR2 br)
    {
        if (bitcount == 0) return true;
        int dstPos = 0, dstEnd = size;
        int p = br.P;
        int bitpos = br.BitPos;

        int bitsRequired = bitpos + bitcount * size;
        int bytesRequired = (bitsRequired + 7) >> 3;
        if (bytesRequired > br.PEnd - p) return false;

        br.P = p + (bitsRequired >> 3);
        br.BitPos = bitsRequired & 7;

        ulong bak = ReadLE64(dst, dstEnd);

        if (bitcount == 1)
        {
            do
            {
                ulong bits = (byte)(BSwap32(ReadLE32(br.B, p)) >> (24 - bitpos));
                p += 1;
                bits = (bits | (bits << 28)) & 0xF0000000Ful;
                bits = (bits | (bits << 14)) & 0x3000300030003ul;
                bits = (bits | (bits << 7)) & 0x0101010101010101ul;
                ulong cur = ReadLE64(dst, dstPos);
                WriteLE64(dst, dstPos, cur * 2 + BSwap64(bits));
                dstPos += 8;
            } while (dstPos < dstEnd);
        }
        else if (bitcount == 2)
        {
            do
            {
                ulong bits = (ushort)(BSwap32(ReadLE32(br.B, p)) >> (16 - bitpos));
                p += 2;
                bits = (bits | (bits << 24)) & 0xFF000000FFul;
                bits = (bits | (bits << 12)) & 0xF000F000F000Ful;
                bits = (bits | (bits << 6)) & 0x0303030303030303ul;
                ulong cur = ReadLE64(dst, dstPos);
                WriteLE64(dst, dstPos, cur * 4 + BSwap64(bits));
                dstPos += 8;
            } while (dstPos < dstEnd);
        }
        else // bitcount == 3
        {
            do
            {
                ulong bits = (ulong)((BSwap32(ReadLE32(br.B, p)) >> (8 - bitpos)) & 0xFFFFFF);
                p += 3;
                bits = (bits | (bits << 20)) & 0xFFF00000FFFul;
                bits = (bits | (bits << 10)) & 0x3F003F003F003Ful;
                bits = (bits | (bits << 5)) & 0x0707070707070707ul;
                ulong cur = ReadLE64(dst, dstPos);
                WriteLE64(dst, dstPos, cur * 8 + BSwap64(bits));
                dstPos += 8;
            } while (dstPos < dstEnd);
        }
        WriteLE64(dst, dstEnd, bak);
        return true;
    }

    // ===========================================================================================
    //  Kraken_ProcessLzRuns  (Type1 = raw literals, Type0 = sub/delta literals)
    // ===========================================================================================
    private static bool ProcessLzRuns(int mode, byte[] dst, int dstStart, int dstSize, int offset, LzTable lzt)
    {
        int dstEnd = dstStart + dstSize;
        int start = dstStart + (offset == 0 ? SeedSize : 0);
        int dstBaseStart = dstStart - offset; // ooz dst_start = dst - offset
        if (mode == 1)
            return ProcessLzRunsType1(lzt, dst, start, dstEnd, dstBaseStart);
        if (mode == 0)
            return ProcessLzRunsType0(lzt, dst, start, dstEnd, dstBaseStart);
        return false;
    }

    private static bool ProcessLzRunsType1(LzTable lzt, byte[] dst, int dstPos, int dstEnd, int dstStart)
    {
        byte[] cmd = lzt.CmdStream; int cmdPos = 0, cmdEnd = lzt.CmdStreamSize;
        int[] len = lzt.LenStream; int lenPos = 0, lenEnd = lzt.LenStreamSize;
        byte[] lit = lzt.LitStream; int litPos = 0, litEnd = lzt.LitStreamSize;
        int[] offs = lzt.OffsStream; int offsPos = 0, offsEnd = lzt.OffsStreamSize;

        Span<int> recent = stackalloc int[7];
        recent[3] = -8; recent[4] = -8; recent[5] = -8;

        while (cmdPos < cmdEnd)
        {
            uint f = cmd[cmdPos++];
            uint litlen = f & 3;
            int offsIndex = (int)(f >> 6);
            uint matchlen = (f >> 2) & 0xF;

            if (litlen == 3)
            {
                if (lenPos >= lenEnd) return false;
                litlen = (uint)len[lenPos++];
            }
            recent[6] = offsPos < offsEnd ? offs[offsPos] : 0;

            if (litlen != 0)
            {
                if (litPos + litlen > (uint)litEnd || dstPos + litlen > (uint)dstEnd) return false;
                for (uint c = 0; c < litlen; c++) dst[dstPos + c] = lit[litPos + c];
                dstPos += (int)litlen; litPos += (int)litlen;
            }

            int offset = recent[offsIndex + 3];
            recent[offsIndex + 3] = recent[offsIndex + 2];
            recent[offsIndex + 2] = recent[offsIndex + 1];
            recent[offsIndex + 1] = recent[offsIndex + 0];
            recent[3] = offset;

            offsPos += ((offsIndex + 1) & 4) >> 2;

            if (dstPos + offset < dstStart) return false;
            int copyFrom = dstPos + offset;

            uint actual;
            if (matchlen != 15)
            {
                actual = matchlen + 2;
            }
            else
            {
                if (lenPos >= lenEnd) return false;
                actual = 14 + (uint)len[lenPos++];
            }
            if (dstPos + actual > (uint)dstEnd) return false;
            ParseTrace?.Invoke((int)litlen, (int)actual, -offset, offsIndex);
            for (uint c = 0; c < actual; c++) dst[dstPos + c] = dst[copyFrom + c];
            dstPos += (int)actual;
        }

        if (offsPos != offsEnd || lenPos != lenEnd) return false;
        int finalLen = dstEnd - dstPos;
        if (finalLen != litEnd - litPos) return false;
        ParseTrace?.Invoke(finalLen, 0, 0, -1);
        for (int c = 0; c < finalLen; c++) dst[dstPos + c] = lit[litPos + c];
        return true;
    }

    private static bool ProcessLzRunsType0(LzTable lzt, byte[] dst, int dstPos, int dstEnd, int dstStart)
    {
        byte[] cmd = lzt.CmdStream; int cmdPos = 0, cmdEnd = lzt.CmdStreamSize;
        int[] len = lzt.LenStream; int lenPos = 0, lenEnd = lzt.LenStreamSize;
        byte[] lit = lzt.LitStream; int litPos = 0, litEnd = lzt.LitStreamSize;
        int[] offs = lzt.OffsStream; int offsPos = 0, offsEnd = lzt.OffsStreamSize;

        Span<int> recent = stackalloc int[7];
        recent[3] = -8; recent[4] = -8; recent[5] = -8;
        int lastOffset = -8;

        while (cmdPos < cmdEnd)
        {
            uint f = cmd[cmdPos++];
            uint litlen = f & 3;
            int offsIndex = (int)(f >> 6);
            uint matchlen = (f >> 2) & 0xF;

            if (litlen == 3)
            {
                if (lenPos >= lenEnd) return false;
                litlen = (uint)len[lenPos++];
            }
            recent[6] = offsPos < offsEnd ? offs[offsPos] : 0;

            if (litlen != 0)
            {
                if (litPos + litlen > (uint)litEnd || dstPos + litlen > (uint)dstEnd) return false;
                for (uint c = 0; c < litlen; c++)
                    dst[dstPos + c] = (byte)(lit[litPos + c] + dst[dstPos + (int)c + lastOffset]);
                dstPos += (int)litlen; litPos += (int)litlen;
            }

            int offset = recent[offsIndex + 3];
            recent[offsIndex + 3] = recent[offsIndex + 2];
            recent[offsIndex + 2] = recent[offsIndex + 1];
            recent[offsIndex + 1] = recent[offsIndex + 0];
            recent[3] = offset;
            lastOffset = offset;

            offsPos += ((offsIndex + 1) & 4) >> 2;

            if (dstPos + offset < dstStart) return false;
            int copyFrom = dstPos + offset;

            uint actual;
            if (matchlen != 15)
            {
                actual = matchlen + 2;
            }
            else
            {
                if (lenPos >= lenEnd) return false;
                actual = 14 + (uint)len[lenPos++];
            }
            if (dstPos + actual > (uint)dstEnd) return false;
            ParseTrace?.Invoke((int)litlen, (int)actual, -offset, offsIndex);
            for (uint c = 0; c < actual; c++) dst[dstPos + c] = dst[copyFrom + c];
            dstPos += (int)actual;
        }

        if (offsPos != offsEnd || lenPos != lenEnd) return false;
        int finalLen = dstEnd - dstPos;
        if (finalLen != litEnd - litPos) return false;
        ParseTrace?.Invoke(finalLen, 0, 0, -1);
        for (int c = 0; c < finalLen; c++)
            dst[dstPos + c] = (byte)(lit[litPos + c] + dst[dstPos + c + lastOffset]);
        return true;
    }

    // ===========================================================================================
    //  OozBR — faithful ooz BitReader (MSB-first, 24-bit refill window), forward & backward.
    // ===========================================================================================
    private struct OozBR
    {
        public byte[] B;
        public int P;       // current byte index
        public int Bound;   // forward: high bound (exclusive); backward: low bound (inclusive)
        public uint Bits;
        public int BitPos;
        private bool _bwd;

        public static OozBR Forward(byte[] b, int start, int end)
        {
            var r = new OozBR { B = b, P = start, Bound = end, Bits = 0, BitPos = 24, _bwd = false };
            r.RefillF();
            return r;
        }

        public static OozBR Backward(byte[] b, int low, int high)
        {
            var r = new OozBR { B = b, P = high, Bound = low, Bits = 0, BitPos = 24, _bwd = true };
            r.RefillB();
            return r;
        }

        public void Refill() { if (_bwd) RefillB(); else RefillF(); }

        public void RefillF()
        {
            while (BitPos > 0)
            {
                Bits |= (uint)(P < Bound ? B[P] : 0) << BitPos;
                BitPos -= 8;
                P++;
            }
        }

        public void RefillB()
        {
            while (BitPos > 0)
            {
                P--;
                Bits |= (uint)(P >= Bound ? B[P] : 0) << BitPos;
                BitPos -= 8;
            }
        }

        public int ReadBit()
        {
            Refill();
            int r = (int)(Bits >> 31);
            Bits <<= 1; BitPos += 1;
            return r;
        }

        public int ReadBitNoRefill()
        {
            int r = (int)(Bits >> 31);
            Bits <<= 1; BitPos += 1;
            return r;
        }

        public uint ReadBitsNoRefill(int n)
        {
            uint r = Bits >> (32 - n);
            Bits <<= n; BitPos += n;
            return r;
        }

        public uint ReadBitsNoRefillZero(int n)
        {
            uint r = Bits >> 1 >> (31 - n);
            Bits <<= n; BitPos += n;
            return r;
        }

        public int ReadFluff(int numSymbols)
        {
            if (numSymbols == 256) return 0;
            int x = 257 - numSymbols;
            if (x > numSymbols) x = numSymbols;
            x *= 2;
            int y = Bsr((uint)(x - 1)) + 1;
            uint v = Bits >> (32 - y);
            uint z = (uint)((1 << y) - x);
            if ((v >> 1) >= z)
            {
                Bits <<= y; BitPos += y;
                return (int)(v - z);
            }
            else
            {
                Bits <<= (y - 1); BitPos += (y - 1);
                return (int)(v >> 1);
            }
        }

        public uint ReadMoreThan24Bits(int n)
        {
            uint rv;
            if (n <= 24) rv = ReadBitsNoRefillZero(n);
            else { rv = ReadBitsNoRefill(24) << (n - 24); RefillF(); rv += ReadBitsNoRefill(n - 24); }
            RefillF();
            return rv;
        }

        public uint ReadMoreThan24BitsB(int n)
        {
            uint rv;
            if (n <= 24) rv = ReadBitsNoRefillZero(n);
            else { rv = ReadBitsNoRefill(24) << (n - 24); RefillB(); rv += ReadBitsNoRefill(n - 24); }
            RefillB();
            return rv;
        }

        public uint ReadDistance(uint v)
        {
            uint w, m, rv; int n;
            if (v < 0xF0)
            {
                n = (int)(v >> 4) + 4;
                w = BitOperations.RotateLeft(Bits | 1, n);
                BitPos += n;
                m = (2u << n) - 1;
                Bits = w & ~m;
                rv = ((w & m) << 4) + (v & 0xF) - 248;
            }
            else
            {
                n = (int)(v - 0xF0) + 4;
                w = BitOperations.RotateLeft(Bits | 1, n);
                BitPos += n;
                m = (2u << n) - 1;
                Bits = w & ~m;
                rv = 8322816 + ((w & m) << 12);
                RefillF();
                rv += Bits >> 20;
                BitPos += 12;
                Bits <<= 12;
            }
            RefillF();
            return rv;
        }

        public uint ReadDistanceB(uint v)
        {
            uint w, m, rv; int n;
            if (v < 0xF0)
            {
                n = (int)(v >> 4) + 4;
                w = BitOperations.RotateLeft(Bits | 1, n);
                BitPos += n;
                m = (2u << n) - 1;
                Bits = w & ~m;
                rv = ((w & m) << 4) + (v & 0xF) - 248;
            }
            else
            {
                n = (int)(v - 0xF0) + 4;
                w = BitOperations.RotateLeft(Bits | 1, n);
                BitPos += n;
                m = (2u << n) - 1;
                Bits = w & ~m;
                rv = 8322816 + ((w & m) << 12);
                RefillB();
                rv += Bits >> 20;
                BitPos += 12;
                Bits <<= 12;
            }
            RefillB();
            return rv;
        }

        public bool ReadLength(out uint v)
        {
            v = 0;
            int n = 31 - Bsr(Bits);
            if (n > 12) return false;
            BitPos += n; Bits <<= n; RefillF();
            n += 7;
            BitPos += n;
            v = (Bits >> (32 - n)) - 64;
            Bits <<= n; RefillF();
            return true;
        }

        public bool ReadLengthB(out uint v)
        {
            v = 0;
            int n = 31 - Bsr(Bits);
            if (n > 12) return false;
            BitPos += n; Bits <<= n; RefillB();
            n += 7;
            BitPos += n;
            v = (Bits >> (32 - n)) - 64;
            Bits <<= n; RefillB();
            return true;
        }
    }

    // ===========================================================================================
    //  Bit / byte helpers
    // ===========================================================================================
    private static int Bsr(uint x) => x == 0 ? 0 : 31 - BitOperations.LeadingZeroCount(x);
    private static int Bsf(uint x) => x == 0 ? 0 : BitOperations.TrailingZeroCount(x);
    private static int Clz(uint x) => x == 0 ? 31 : BitOperations.LeadingZeroCount(x);

    private static byte At(byte[] b, int i) => (uint)i < (uint)b.Length ? b[i] : (byte)0;

    private static uint ReadLE32(byte[] b, int off)
    {
        uint r = 0;
        for (int i = 0; i < 4; i++)
            if ((uint)(off + i) < (uint)b.Length) r |= (uint)b[off + i] << (8 * i);
        return r;
    }

    private static ulong ReadLE64(byte[] b, int off)
    {
        ulong r = 0;
        for (int i = 0; i < 8; i++)
            if ((uint)(off + i) < (uint)b.Length) r |= (ulong)b[off + i] << (8 * i);
        return r;
    }

    private static void WriteLE32(byte[] b, int off, uint v)
    {
        for (int i = 0; i < 4; i++)
            if ((uint)(off + i) < (uint)b.Length) b[off + i] = (byte)(v >> (8 * i));
    }

    private static void WriteLE64(byte[] b, int off, ulong v)
    {
        for (int i = 0; i < 8; i++)
            if ((uint)(off + i) < (uint)b.Length) b[off + i] = (byte)(v >> (8 * i));
    }

    private static uint BSwap32(uint v) => BinaryPrimitives.ReverseEndianness(v);
    private static ulong BSwap64(ulong v) => BinaryPrimitives.ReverseEndianness(v);

    private static uint[] BuildRiceVal()
    {
        return new uint[256]
        {
            0x80000000, 0x00000007, 0x10000006, 0x00000006, 0x20000005, 0x00000105, 0x10000005, 0x00000005,
            0x30000004, 0x00000204, 0x10000104, 0x00000104, 0x20000004, 0x00010004, 0x10000004, 0x00000004,
            0x40000003, 0x00000303, 0x10000203, 0x00000203, 0x20000103, 0x00010103, 0x10000103, 0x00000103,
            0x30000003, 0x00020003, 0x10010003, 0x00010003, 0x20000003, 0x01000003, 0x10000003, 0x00000003,
            0x50000002, 0x00000402, 0x10000302, 0x00000302, 0x20000202, 0x00010202, 0x10000202, 0x00000202,
            0x30000102, 0x00020102, 0x10010102, 0x00010102, 0x20000102, 0x01000102, 0x10000102, 0x00000102,
            0x40000002, 0x00030002, 0x10020002, 0x00020002, 0x20010002, 0x01010002, 0x10010002, 0x00010002,
            0x30000002, 0x02000002, 0x11000002, 0x01000002, 0x20000002, 0x00000012, 0x10000002, 0x00000002,
            0x60000001, 0x00000501, 0x10000401, 0x00000401, 0x20000301, 0x00010301, 0x10000301, 0x00000301,
            0x30000201, 0x00020201, 0x10010201, 0x00010201, 0x20000201, 0x01000201, 0x10000201, 0x00000201,
            0x40000101, 0x00030101, 0x10020101, 0x00020101, 0x20010101, 0x01010101, 0x10010101, 0x00010101,
            0x30000101, 0x02000101, 0x11000101, 0x01000101, 0x20000101, 0x00000111, 0x10000101, 0x00000101,
            0x50000001, 0x00040001, 0x10030001, 0x00030001, 0x20020001, 0x01020001, 0x10020001, 0x00020001,
            0x30010001, 0x02010001, 0x11010001, 0x01010001, 0x20010001, 0x00010011, 0x10010001, 0x00010001,
            0x40000001, 0x03000001, 0x12000001, 0x02000001, 0x21000001, 0x01000011, 0x11000001, 0x01000001,
            0x30000001, 0x00000021, 0x10000011, 0x00000011, 0x20000001, 0x00001001, 0x10000001, 0x00000001,
            0x70000000, 0x00000600, 0x10000500, 0x00000500, 0x20000400, 0x00010400, 0x10000400, 0x00000400,
            0x30000300, 0x00020300, 0x10010300, 0x00010300, 0x20000300, 0x01000300, 0x10000300, 0x00000300,
            0x40000200, 0x00030200, 0x10020200, 0x00020200, 0x20010200, 0x01010200, 0x10010200, 0x00010200,
            0x30000200, 0x02000200, 0x11000200, 0x01000200, 0x20000200, 0x00000210, 0x10000200, 0x00000200,
            0x50000100, 0x00040100, 0x10030100, 0x00030100, 0x20020100, 0x01020100, 0x10020100, 0x00020100,
            0x30010100, 0x02010100, 0x11010100, 0x01010100, 0x20010100, 0x00010110, 0x10010100, 0x00010100,
            0x40000100, 0x03000100, 0x12000100, 0x02000100, 0x21000100, 0x01000110, 0x11000100, 0x01000100,
            0x30000100, 0x00000120, 0x10000110, 0x00000110, 0x20000100, 0x00001100, 0x10000100, 0x00000100,
            0x60000000, 0x00050000, 0x10040000, 0x00040000, 0x20030000, 0x01030000, 0x10030000, 0x00030000,
            0x30020000, 0x02020000, 0x11020000, 0x01020000, 0x20020000, 0x00020010, 0x10020000, 0x00020000,
            0x40010000, 0x03010000, 0x12010000, 0x02010000, 0x21010000, 0x01010010, 0x11010000, 0x01010000,
            0x30010000, 0x00010020, 0x10010010, 0x00010010, 0x20010000, 0x00011000, 0x10010000, 0x00010000,
            0x50000000, 0x04000000, 0x13000000, 0x03000000, 0x22000000, 0x02000010, 0x12000000, 0x02000000,
            0x31000000, 0x01000020, 0x11000010, 0x01000010, 0x21000000, 0x01001000, 0x11000000, 0x01000000,
            0x40000000, 0x00000030, 0x10000020, 0x00000020, 0x20000010, 0x00001010, 0x10000010, 0x00000010,
            0x30000000, 0x00002000, 0x10001000, 0x00001000, 0x20000000, 0x00100000, 0x10000000, 0x00000000,
        };
    }

    private static byte[] BuildRiceLen()
    {
        return new byte[256]
        {
            0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
            1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
            1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
            2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
            1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
            2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
            2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
            3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
        };
    }
}
