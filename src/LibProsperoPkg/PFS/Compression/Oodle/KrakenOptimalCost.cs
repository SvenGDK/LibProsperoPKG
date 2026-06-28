// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// Kraken (newLZ) OPTIMAL parse cost model — the deterministic, byte-exact integer core of the
// reference level-7 "Optimal3" encoder. No bytes are copied from external source; only the
// integer formulas and the published fixed-point log2 mantissa table are encoded here. GPLv3.
//
// This file contains ONLY the cost quantizer (the guess-proof, float-free foundation):
//   * Log2Fix — fixed-point log2 of the
//                RECIPROCAL: Log2Fix(x) = round( log2(2^32 / x) * 8192 ). 65-entry u16 mantissa table.
//   * HistoToCodeCost — turns a symbol
//                histogram into a 256-entry per-symbol bit-cost table (cost units = bits * 32):
//                  total = Σhisto;  D = total*4 + alphabet;  log2D = Log2Fix(D)
//                  for s:  n = histo[s]*4 + 1;  raw = (Log2Fix(n) - log2D) * 32 >> 13;  cost[s] = raw + bias
//                  ENTROPY-FLATTEN: if (threshold * D < Σ raw*n)  →  all cost[s] = bias + 0x100
//                Because Log2Fix returns the reciprocal-log, Log2Fix(n) >= Log2Fix(D) (n <= D), so
//                raw = log2(D/n) * 32 >= 0 — the Shannon self-information of the symbol, in bits*32.
//
// The per-table biases and the entropy threshold are supplied by the caller. The forward trellis
// recurrence that consumes these tables lives in the encoder.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System;
using System.Numerics;

namespace LibProsperoPkg.PFS.Compression.Oodle;

/// <summary>
/// Byte-exact integer implementation of the reference newLZ optimal-parse cost model (the
/// fixed-point log2 quantizer behind histogram-to-code-cost conversion). Deterministic; no floating
/// point is used on any path that influences a cost. All costs are expressed in
/// <c>bits * 32</c> (the 1/32-bit fixed-point the parser compares).
/// </summary>
internal static class KrakenOptimalCost
{
    /// <summary>Alphabet size every newLZ entropy array is built over (asserted == 256 by the format).</summary>
    internal const int Alphabet = 256;

    /// <summary>
    /// 65-entry unsigned-16 mantissa table. Entry
    /// <c>k = round( log2(1 + k/64) * 8192 )</c>; <c>Table[0] = 0</c> (log2 1), <c>Table[64] = 0x2000</c>
    /// (log2 2 = one full bit, 8192). Interpolated by <see cref="Log2Fix"/>.
    /// </summary>
    private static readonly ushort[] Log2Mantissa =
    {
        0x0000, 0x00B7, 0x016C, 0x021D, 0x02CC, 0x0379, 0x0423, 0x04CB,
        0x0570, 0x0613, 0x06B4, 0x0752, 0x07EF, 0x088A, 0x0922, 0x09B9,
        0x0A4D, 0x0AE0, 0x0B71, 0x0C00, 0x0C8E, 0x0D1A, 0x0DA4, 0x0E2D,
        0x0EB4, 0x0F39, 0x0FBD, 0x1040, 0x10C1, 0x1141, 0x11BF, 0x123C,
        0x12B8, 0x1332, 0x13AC, 0x1424, 0x149A, 0x1510, 0x1585, 0x15F8,
        0x166A, 0x16DB, 0x174B, 0x17BA, 0x1828, 0x1895, 0x1901, 0x196C,
        0x19D6, 0x1A3F, 0x1AA7, 0x1B0E, 0x1B75, 0x1BDA, 0x1C3F, 0x1CA2,
        0x1D05, 0x1D67, 0x1DC9, 0x1E29, 0x1E89, 0x1EE8, 0x1F46, 0x1FA3,
        0x2000,
    };

    /// <summary>
    /// <c>bitlen(x)</c> = <c>x == 0 ? 0 : 32 - clz(x)</c>. The index of
    /// the most-significant set bit plus one.
    /// </summary>
    internal static int BitLen(uint x) => 32 - BitOperations.LeadingZeroCount(x);

    /// <summary>
    /// Fixed-point <c>log2</c> of the reciprocal, scaled by
    /// 2^13: returns <c>round( log2(2^32 / x) * 8192 )</c>. Exact for powers of two
    /// (<c>Log2Fix(2^k) = (32 - k) * 8192</c>); table-interpolated otherwise. <paramref name="x"/> must be
    /// non-zero (the caller always passes <c>count*4+1 &gt;= 1</c>).
    /// </summary>
    internal static int Log2Fix(uint x)
    {
        int e = BitLen(x) - 1;                       // MSB index 0..31
        uint norm = x << ((32 - e) & 31);            // shift the leading 1 out; mantissa bits move to the top
        int idx = (int)(norm >> 26);                 // top 6 fractional bits -> 0..63
        int t0 = Log2Mantissa[idx];
        int t1 = Log2Mantissa[idx + 1];
        int frac = (int)((norm & 0x3FFFFFFu) >> 10); // next 16 fractional bits
        int interp = (((t1 - t0) * frac) + 0x8000) >> 16;
        return ((32 - e) * 0x2000) - t0 - interp;
    }

    /// <summary>
    /// Builds a per-symbol bit-cost table (units = bits*32)
    /// from a symbol histogram, then applies the entropy-flatten clamp.
    /// </summary>
    /// <param name="histo">Symbol counts, length <see cref="Alphabet"/> (256).</param>
    /// <param name="cost">Destination cost table, length <see cref="Alphabet"/> (256); overwritten.</param>
    /// <param name="bias">Per-table additive bias (from <c>passinfo_to_codecost</c>).</param>
    /// <param name="threshold">Entropy-flatten threshold (expected in [7*32, 32*8] = [224, 256]).</param>
    internal static void HistoToCodeCost(ReadOnlySpan<int> histo, Span<int> cost, int bias, int threshold)
    {
        if (histo.Length < Alphabet || cost.Length < Alphabet)
            throw new ArgumentException("histo/cost must have length >= 256.");

        int total = 0;
        for (int i = 0; i < Alphabet; i++) total += histo[i];

        int dEnt = total * 4 + Alphabet;             // D = total*4 + alphabet
        int log2D = Log2Fix((uint)dEnt);
        long sumCost = 0;                            // Σ raw*n (pre-bias) — entropy estimate, 64-bit to avoid overflow

        for (int s = 0; s < Alphabet; s++)
        {
            int n = histo[s] * 4 + 1;
            int raw = (Log2Fix((uint)n) - log2D) * 0x20 >> 0xd;
            sumCost += (long)raw * n;
            cost[s] = raw + bias;
        }

        // Entropy-flatten: a near-uniform distribution (>~8 bits/symbol) is coded as flat 8-bit literals.
        if ((long)threshold * dEnt < sumCost)
        {
            int flat = bias + 0x100;
            for (int s = 0; s < Alphabet; s++) cost[s] = flat;
        }
    }

    // -----------------------------------------------------------------------------------------------
    // COST-HELPER LAYER — the five deterministic cost functions the forward trellis DP calls per
    // candidate, plus the per-pass table builder. The functions are byte-exact and cross-validated
    // against the shipping offset packer (KrakenBitWriter.WriteDistance).
    //   * BuildFromPassinfo — builds per-pass code costs
    //   * CostLiterals      — literal-run cost
    //   * CostOffset        — offset cost, mode-0 / standard newLZ window
    //   * CostLen           — length cost
    //   * CostLoMatch       — repeat-offset match cost
    //   * CostNormalMatch   — new-offset match packet/length cost; add CostOffset
    // -----------------------------------------------------------------------------------------------

    /// <summary>
    /// The per-pass quantized cost tables (<c>codecosts</c>, serialized size ~0x1808 bytes). Every
    /// table is a 256-entry <c>bits*32</c> cost array built by <see cref="BuildFromPassinfo"/>. Byte
    /// offsets of the serialized layout are noted for each field.
    /// </summary>
    internal sealed class CodeCosts
    {
        /// <summary>codecosts[0]: literal model — 1 = raw literals, otherwise "sub" (delta) literals.</summary>
        internal int LitMode;
        /// <summary>codecosts+0x04: literal-delta mask — 0 (raw) or 0xff (sub).</summary>
        internal int LitSubMask;
        /// <summary>codecosts+0x08: literal-byte cost table, indexed by <c>(byte - (ref &amp; mask)) &amp; 0xff</c>.</summary>
        internal readonly int[] Lit = new int[Alphabet];
        /// <summary>codecosts+0x408: command/packet cost table, indexed by the newLZ command byte.</summary>
        internal readonly int[] Packet = new int[Alphabet];
        /// <summary>codecosts+0x808: offset alt-modulo (offset coding mode; 0 = standard bucket reader).</summary>
        internal int OffsetAltModulo;
        /// <summary>codecosts+0x80c: offset-bucket cost table, indexed by the packed-offset bucket byte.</summary>
        internal readonly int[] OffsetBucket = new int[Alphabet];
        /// <summary>codecosts+0xc0c: offset alt cost table (only built when <see cref="OffsetAltModulo"/> &gt; 1).</summary>
        internal readonly int[] OffsetAlt = new int[Alphabet];
        /// <summary>codecosts+0x100c: length cost table; [0..0xFE] per-length, [0xFF] = escape base.</summary>
        internal readonly int[] Length = new int[Alphabet];
    }

    /// <summary>
    /// Builds the five cost tables from a pass
    /// histogram block via <see cref="HistoToCodeCost"/> with the fixed per-table biases (threshold 0xff).
    /// The <paramref name="passinfo"/> block is int-indexed:
    /// <c>[0..0xFF]</c> lit-raw histo, <c>[0x100..0x1FF]</c> lit-sub histo, <c>[0x200..0x2FF]</c> packet,
    /// <c>[0x300..0x3FF]</c> length, <c>[0x400]</c> offset_alt_modulo, <c>[0x401..0x500]</c> offset-bucket,
    /// <c>[0x501..0x600]</c> offset-alt. <paramref name="litMode"/> is the carried codecosts[0] flag.
    /// </summary>
    internal static CodeCosts BuildFromPassinfo(ReadOnlySpan<int> passinfo, int litMode)
    {
        if (passinfo.Length < 0x601)
            throw new ArgumentException("passinfo must have length >= 0x601.");

        var cc = new CodeCosts
        {
            LitMode = litMode,
            LitSubMask = litMode == 1 ? 0 : 0xff,
            OffsetAltModulo = passinfo[0x400],
        };

        HistoToCodeCost(passinfo.Slice(0x401, Alphabet), cc.OffsetBucket, 0x24, 0xff);
        if (passinfo[0x400] > 1)
            HistoToCodeCost(passinfo.Slice(0x501, Alphabet), cc.OffsetAlt, 0, 0xff);
        HistoToCodeCost(passinfo.Slice(0x200, Alphabet), cc.Packet, 0x12, 0xff);
        HistoToCodeCost(passinfo.Slice(0x300, Alphabet), cc.Length, 0xc, 0xff);
        HistoToCodeCost(litMode == 1 ? passinfo.Slice(0, Alphabet) : passinfo.Slice(0x100, Alphabet),
                        cc.Lit, 0, 0xff);
        return cc;
    }

    /// <summary>
    /// Diagnostic: reconstruct a <see cref="CodeCosts"/> from a raw 0x1808-byte codecost blob. Reads
    /// the int32-LE serialized fields directly so the DP can be driven with exact reference codecosts, bypassing
    /// <see cref="BuildFromPassinfo"/>. Layout: +0x04 lit-mask, +0x08 Lit[256], +0x408 Packet[256],
    /// +0x808 offset-alt-modulo, +0x80c OffsetBucket[256], +0xc0c OffsetAlt[256], +0x100c Length[256].
    /// </summary>
    internal static CodeCosts FromRawBlob(ReadOnlySpan<byte> blob)
    {
        if (blob.Length < 0x1808)
            throw new ArgumentException("codecost blob must be >= 0x1808 bytes.");
        int mask = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(0x04, 4));
        var cc = new CodeCosts
        {
            LitMode = mask == 0 ? 1 : 0,
            LitSubMask = mask == 0 ? 0 : 0xff,
            OffsetAltModulo = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(0x808, 4)),
        };
        for (int i = 0; i < Alphabet; i++)
        {
            cc.Lit[i] = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(0x008 + i * 4, 4));
            cc.Packet[i] = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(0x408 + i * 4, 4));
            cc.OffsetBucket[i] = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(0x80c + i * 4, 4));
            cc.OffsetAlt[i] = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(0xc0c + i * 4, 4));
            cc.Length[i] = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(0x100c + i * 4, 4));
        }
        return cc;
    }

    /// <summary>
    /// Cost of a <paramref name="lrl"/>-byte literal run that
    /// starts at <paramref name="start"/> in <paramref name="buf"/>, against the most-recent offset
    /// <paramref name="lo"/> (>= 8). Each byte costs <c>Lit[(buf[p] - (buf[p-lo] &amp; mask)) &amp; 0xff]</c>.
    /// </summary>
    internal static int CostLiterals(ReadOnlySpan<byte> buf, int start, int lrl, int lo, CodeCosts cc)
    {
        if (lrl == 0) return 0;
        int submask = cc.LitSubMask;
        int sum = 0;
        for (int i = 0; i < lrl; i++)
        {
            int p = start + i;
            int refByte = submask == 0 ? 0 : (buf[p - lo] & submask);
            int delta = (buf[p] - refByte) & 0xff;
            sum += cc.Lit[delta];
        }
        return sum;
    }

    /// <summary>
    /// Cost of a single literal at <paramref name="pos"/>
    /// against the most-recent offset <paramref name="lo"/> (&gt;= 8). In raw mode (<c>LitSubMask == 0</c>)
    /// this is simply <c>Lit[buf[pos]]</c>; in sub mode it is the delta against <c>buf[pos-lo]</c>.
    /// </summary>
    internal static int CostAddLiteral(ReadOnlySpan<byte> buf, int pos, int lo, CodeCosts cc)
    {
        int refByte = cc.LitSubMask == 0 ? 0 : (buf[pos - lo] & cc.LitSubMask);
        int delta = (buf[pos] - refByte) & 0xff;
        return cc.Lit[delta];
    }

    /// <summary>
    /// Packed-offset bucket byte for <paramref name="dist"/> (>= 8), identical to
    /// <c>KrakenBitWriter.WriteDistance</c> for the
    /// standard window (bucket &lt; 0xF0, dist &lt;= ~256 KiB). Outputs the extra-bit count in
    /// <paramref name="extraBits"/>.
    /// </summary>
    internal static int OffsetBucketByte(int dist, out int extraBits)
    {
        uint t = (uint)dist + 248;
        int top = 31 - BitOperations.LeadingZeroCount(t);
        int vhi = top - 8;
        uint rem = t - (1u << (vhi + 8));
        uint vlo = rem & 0xF;
        extraBits = vhi + 4;
        return (vhi << 4) | (int)vlo;
    }

    /// <summary>
    /// Standard mode-0 offset path: <c>OffsetBucket[bucket] +
    /// extraBits*32</c> (+0xc for the &gt; 0x7FFF07 huge-offset bucket). Valid for the newLZ window the
    /// nwonly encoder emits (offset coding mode 0).
    /// </summary>
    internal static int CostOffset(int dist, CodeCosts cc)
    {
        int v = OffsetBucketByte(dist, out int extraBits);
        int cost = cc.OffsetBucket[v] + extraBits * 0x20;
        if (dist > 0x7fff07) cost += 0xc;
        return cost;
    }

    /// <summary>Elias-gamma bit count: <c>2*floor(log2(v+1)) + 1</c>.</summary>
    internal static int VarBitsEliasGamma(int val) => (BitLen((uint)(val + 1)) - 1) * 2 + 1;

    /// <summary>Length-escape bit count: <c>VarBitsEliasGamma(val &gt;&gt; nbits) + nbits</c>.</summary>
    internal static int CountBits(uint val, int nbits) => VarBitsEliasGamma((int)(val >> nbits)) + nbits;

    /// <summary>
    /// Length cost: <c>Length[v]</c> for <c>v &lt; 0xFF</c>; otherwise the escape base
    /// <c>Length[0xFF] + CountBits(v - 0xFF, 6)*32</c>.
    /// </summary>
    internal static int CostLen(CodeCosts cc, int v)
    {
        if (v < 0xFF) return cc.Length[v];
        return cc.Length[0xFF] + CountBits((uint)(v - 0xFF), 6) * 0x20;
    }

    /// <summary>
    /// Cost of a repeat-offset match of length
    /// <paramref name="ml"/> with literal field <paramref name="litField"/> (0..3) and recent-offset
    /// index <paramref name="loi"/> (0..2). Short match (<c>ml &lt; 17</c>) → one packet-table lookup;
    /// long match → <c>CostLen(ml-17)</c> plus the escape packet entry.
    /// </summary>
    internal static int CostLoMatch(CodeCosts cc, int litField, int ml, int loi)
    {
        int lenEsc = ml - 0x11;
        if (lenEsc < 0)
            return cc.Packet[litField + (ml - 2) * 4 + loi * 0x40];
        return CostLen(cc, lenEsc) + cc.Packet[litField + 0x3c + loi * 0x40];
    }

    /// <summary>
    /// Packet/length cost of a new-offset match
    /// (offset index 3) of length <paramref name="ml"/> with literal field <paramref name="litField"/>.
    /// The caller adds <see cref="CostOffset"/> for the new distance separately.
    /// </summary>
    internal static int CostNormalMatch(CodeCosts cc, int litField, int ml)
    {
        int lenEsc = ml - 0x11;
        if (lenEsc < 0)
            return cc.Packet[litField + (ml - 2) * 4 + 0xc0];
        return CostLen(cc, lenEsc) + cc.Packet[litField + 0xfc];
    }

}
