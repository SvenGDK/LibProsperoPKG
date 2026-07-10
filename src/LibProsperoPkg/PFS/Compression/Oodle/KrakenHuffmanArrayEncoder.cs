// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// Kraken (newLZ) Huffman ARRAY encoder — the inverse of KrakenDecoder's entropy
// array decode path (DecodeBytes -> DecodeBytesType12 -> HuffMakeLut + 3-stream scalar core). It emits
// a single entropy-coded "array" (chunk type 2 / single 3-stream split, "Old/simple" code-length
// transmission) that the decoder accepts. Operates on byte[]/int indices only.
//
// This is the entropy layer of the Kraken encoder: literal/command/length/offset arrays that
// today are emitted RAW (type 0) can instead be Huffman-coded here, reducing block sizes toward
// encoder output. Matching encoder output additionally requires the same length-limited Huffman,
// transmission-format choice and optimal LZ parse. This encoder provides the decoder-validated
// foundation for that through an in-process round-trip against the decoder.
//
// The bit layout is defined entirely by KrakenDecoder (a GPLv3-licensed translation; see NOTICE).
// LibProsperoPkg is GPLv3; GPLv3 §13 permits the combination. No external Kraken encoder specification is used.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System;
using System.Collections.Generic;

namespace LibProsperoPkg.PFS.Compression.Oodle;

/// <summary>
/// Encodes a byte array into a Kraken entropy "array" (Huffman, chunk-type 2) that
/// <see cref="KrakenDecoder"/> decodes to the original bytes. Returns <c>null</c> when an entropy array
/// would not be smaller than the raw form (caller should then store the array raw, type 0).
/// </summary>
internal static class KrakenHuffmanArrayEncoder
{
    private const int MaxCodeLen = 11;

    /// <summary>
    /// Attempts to Huffman-encode <paramref name="data"/> as a single entropy array. Returns the
    /// on-disk array bytes (header + payload) or <c>null</c> if not beneficial / not representable.
    /// </summary>
    public static byte[]? TryEncode(ReadOnlySpan<byte> data)
    {
        int d = data.Length;
        if (d < 2 || d > 0x3FFFF) return null;

        // Histogram.
        Span<int> freq = stackalloc int[256];
        for (int i = 0; i < d; i++) freq[data[i]]++;
        int distinct = 0;
        for (int s = 0; s < 256; s++) if (freq[s] != 0) distinct++;

        if (distinct == 1)
        {
            // A single-symbol top-level array is rejected by the decoder: Type12 returns a negative
            // consumed length for numSyms==1, which the DecodeBytes caller's "src_used != src_size"
            // check treats as failure. Single-symbol RLE only exists nested inside MultiArray/recursive
            // contexts. Synthesize a phantom second symbol (freq 1, never present in the body) and use
            // the validated 2-symbol path instead. Both symbols get length 1; the body emits only the real one.
            int realSym = 0;
            for (int s = 0; s < 256; s++) if (freq[s] != 0) { realSym = s; break; }
            int phantom = realSym == 0 ? 1 : 0;
            freq[phantom] = 1;
            distinct = 2;
        }

        // Code lengths (length-limited to 11, complete prefix code).
        byte[] lenOfSym = BuildCodeLengths(freq);
        if (lenOfSym.Length == 0) return null;

        // Canonical codes matching HuffMakeLut (codePrefixOrg) — symbols grouped by (len asc, sym asc).
        BuildCanonicalCodes(lenOfSym, out ushort[] codeOfSym);

        // Per-symbol low-bit-first code (the 3-stream core reads LSB-first against the low-bit-first LUT).
        var revOfSym = new ushort[256];
        for (int s = 0; s < 256; s++)
            if (lenOfSym[s] != 0) revOfSym[s] = (ushort)ReverseBits(codeOfSym[s], lenOfSym[s]);

        // 1) Code-length transmission (MSB-first), byte-padded. The encoder selects the
        //    HuffReadCodeLengthsOld sub-mode purely by alphabet size, not by which encoding is smaller.
        //    The packer tests HI->num_non_zero (HI[0x288] — the count of symbols with a nonzero histogram
        //    count, set by the code-length builder):
        //        num_non_zero <  5  ->  write bit 0, SIMPLE list
        //        num_non_zero >= 5  ->  write bit 1, COMPLEX form
        //    `distinct` here is that num_non_zero; both count nonzero histogram buckets. The "New"/Golomb
        //    transmission (tx=1) is disabled at lvl7 unless (flags & 0x40) != 0 && num_non_zero >= 5,
        //    so the "Old" form is always written here. This matters for small alphabets; for example,
        //    an 11-symbol command array can be smaller as SIMPLE, but the count rule writes COMPLEX
        //    because 11 >= 5. A size-min selector can choose the wrong form.
        byte[]? headerBytes = distinct < 5
            ? BuildSimpleCodeLengthHeader(lenOfSym)
            : BuildComplexCodeLengthHeader(lenOfSym);
        if (headerBytes is null) return null;

        // 2) Three interleaved symbol streams (output positions mod 3): A=0,3,..; B=1,4,..; C=2,5,..
        var aw = new LsbBitWriter();
        var bw = new LsbBitWriter();
        var cw = new LsbBitWriter();
        for (int i = 0; i < d; i++)
        {
            byte sym = data[i];
            int len = lenOfSym[sym];
            uint rev = revOfSym[sym];
            switch (i % 3)
            {
                case 0: aw.Write(rev, len); break;
                case 1: bw.Write(rev, len); break;
                default: cw.Write(rev, len); break;
            }
        }
        byte[] aBytes = aw.ToBytesPadded();
        byte[] bBytes = bw.ToBytesPadded();
        byte[] cBytes = cw.ToBytesPadded();

        int lenA = aBytes.Length;
        if (lenA > 0xFFFF) return null; // type-1 splitMid is 16-bit; bigger blocks need the type-4 split.

        // 3) Assemble payload = [2B splitMid=lenA][A][C][reverse(B)].
        int payloadLen = headerBytes.Length + 2 + lenA + cBytes.Length + bBytes.Length;
        if (payloadLen >= d) return null; // not beneficial; caller stores raw.

        byte[] arr = BuildEntropyArray(chunkType: 2, srcSize: payloadLen, dstSize: d, out int bodyOff);
        int p = bodyOff;
        Array.Copy(headerBytes, 0, arr, p, headerBytes.Length); p += headerBytes.Length;
        arr[p++] = (byte)(lenA & 0xFF);
        arr[p++] = (byte)((lenA >> 8) & 0xFF);
        Array.Copy(aBytes, 0, arr, p, lenA); p += lenA;
        Array.Copy(cBytes, 0, arr, p, cBytes.Length); p += cBytes.Length;
        for (int i = 0; i < bBytes.Length; i++) arr[p + i] = bBytes[bBytes.Length - 1 - i];
        p += bBytes.Length;
        return arr;
    }

    // ============================ array header (DecodeBytes entropy mode) ============================
    // The array compression header always uses the 5-byte long form:
    // lVar = (from_len-1)<<18 | comp_len | (chunkType<<36); byte0 = lVar>>32; bytes1..4 =
    // big-endian low32(lVar). This array subtype uses the long entropy header here; the decoder
    // accepts src[0]>=0x80 short headers, but newLZ produces them only via other array sub-types.
    // Always use the long form here, even when the short form would fit.
    private static byte[] BuildEntropyArray(int chunkType, int srcSize, int dstSize, out int bodyOff)
    {
        const int hdrLen = 5;
        var arr = new byte[hdrLen + srcSize];
        int dm1 = dstSize - 1;
        arr[0] = (byte)((chunkType << 4) | ((dm1 >> 14) & 0xF));
        uint bits = (uint)(srcSize | ((dm1 & 0x3FFF) << 18));
        arr[1] = (byte)(bits >> 24);
        arr[2] = (byte)(bits >> 16);
        arr[3] = (byte)(bits >> 8);
        arr[4] = (byte)bits;
        bodyOff = hdrLen;
        return arr;
    }

    // ===================== code-length transmission (HuffReadCodeLengthsOld inverse) =====================
    // SIMPLE sub-mode: [0][0][numSyms:8][codeLenBits:3] then per present symbol {sym:8, (len-1):codeLenBits}.
    // Returns null when not representable (>=256 distinct symbols, or a code length needing >4 bits-1).
    private static byte[]? BuildSimpleCodeLengthHeader(byte[] lenOfSym)
    {
        int distinct = 0, maxLen = 0;
        for (int s = 0; s < 256; s++)
            if (lenOfSym[s] != 0) { distinct++; if (lenOfSym[s] > maxLen) maxLen = lenOfSym[s]; }
        if (distinct < 2 || distinct >= 256) return null; // count is 8-bit; numSyms==1 has a distinct form
        int codeLenBits = BitWidth(maxLen - 1);
        if (codeLenBits > 4) return null;

        var hdr = new MsbBitWriter();
        hdr.Write(0, 1);                  // DecodeBytesType12: 0 => HuffReadCodeLengthsOld
        hdr.Write(0, 1);                  // HuffReadCodeLengthsOld: 0 => simple list
        hdr.Write((uint)distinct, 8);     // numSymbols
        hdr.Write((uint)codeLenBits, 3);
        for (int s = 0; s < 256; s++)
        {
            if (lenOfSym[s] == 0) continue;
            hdr.Write((uint)s, 8);
            if (codeLenBits > 0) hdr.Write((uint)(lenOfSym[s] - 1), codeLenBits);
        }
        return hdr.ToBytesPadded();
    }

    // COMPLEX sub-mode: [0][1][forcedBits:2][skip:1] then, per maximal run
    // of consecutive present symbols: a gap gamma (advance to the run), a run-length gamma, then each
    // symbol's code length as a zig-zag delta from a running predictor, Golomb-Rice coded with forcedBits
    // low bits. Exact inverse of HuffReadCodeLengthsOld's complex branch. Tries forcedBits 0..3, returns
    // the smallest. Returns null only when there are no present symbols.
    private static byte[]? BuildComplexCodeLengthHeader(byte[] lenOfSym)
    {
        int first = -1;
        for (int s = 0; s < 256; s++) if (lenOfSym[s] != 0) { first = s; break; }
        if (first < 0) return null;

        byte[]? best = null;
        int bestBits = int.MaxValue;
        for (int fb = 0; fb <= 3; fb++)
        {
            var w = BuildComplexHeaderForFb(lenOfSym, fb, first == 0);
            if (w is null) continue;
            int bits = w.BitLength;
            if (bits < bestBits) { bestBits = bits; best = w.ToBytesPadded(); }
        }
        return best;
    }

    // Per-fb complex header builder. Returns the writer (with exact BitLength) or null if forcedBits fb
    // cannot represent some zig-zag quotient (q > thres). Factored out so the selector can compare EXACT
    // bit cost, not byte-padded length, across fb candidates.
    private static MsbBitWriter? BuildComplexHeaderForFb(byte[] lenOfSym, int fb, bool skip)
    {
        int maxLz = (int)(20u >> fb); // decoder's thres bounds the unary quotient
        var w = new MsbBitWriter();
        w.Write(0, 1);                // Old
        w.Write(1, 1);                // complex
        w.Write((uint)fb, 2);
        w.Write(skip ? 1u : 0u, 1);

        int avgBitsX4 = 32;
        int sym = 0;
        bool firstSeg = true;
        int s2 = 0;
        while (s2 < 256)
        {
            if (lenOfSym[s2] == 0) { s2++; continue; }
            int runStart = s2;
            int runEnd = s2;
            while (runEnd + 1 < 256 && lenOfSym[runEnd + 1] != 0) runEnd++;
            int n = runEnd - runStart + 1;

            if (!(firstSeg && skip))
                WriteGamma(w, (runStart - sym) + 1); // sym += G-1 lands on runStart
            sym = runStart;
            firstSeg = false;

            WriteGamma(w, n + 1);
            for (int s = runStart; s <= runEnd; s++)
            {
                int predictor = (avgBitsX4 + 2) >> 2;
                int e = lenOfSym[s] - predictor;
                uint v = (uint)((e << 1) ^ (e >> 31)); // zig-zag
                int q = (int)(v >> fb);
                if (q > maxLz) return null;
                for (int z = 0; z < q; z++) w.Write(0, 1);
                w.Write(1, 1);
                if (fb > 0) w.Write(v & ((1u << fb) - 1), fb);
                avgBitsX4 = lenOfSym[s] + ((3 * avgBitsX4 + 2) >> 2);
            }
            sym = runEnd + 1;
            s2 = runEnd + 1;
        }
        if (sym < 256) WriteGamma(w, (256 - sym) + 1); // terminating gap -> sym >= 256
        return w;
    }

    // Writes a gamma-style field F (>= 2) as the decoder reads it: 2*bitlen(F)-2 bits, MSB-first, so the
    // bitlen(F)-2 leading zeros + leading 1 are self-delimiting (decoder reads 2*(clz+1) bits).
    private static void WriteGamma(MsbBitWriter w, int f)
    {
        int bl = 0, t = f;
        while (t > 0) { bl++; t >>= 1; }
        w.Write((uint)f, 2 * bl - 2);
    }

    // ===================== Length-limited Huffman code lengths =====================
    // Returns per-symbol code length (0 = unused). Handles bare-entropy arrays, including
    // hard L11-binding cases.
    // The exact pipeline is:
    //   1. ScaleCounts — scale so total and max both fit in 0xFFFF.
    //   2. Sort — stable ascending by (count, symbol id).
    //   3. InPlaceHuffman (Moffat/Katajainen) — unlimited optimal lengths; if its max <= 11 it is final.
    //   4. Otherwise the length-limited boundary package-merge: MaxCodeLen lists each capped
    //      at 2n-2 items, a package winning a tie against an equal-weight leaf, then a top-down count.
    // The array Huffman encoder drives this with limit 11 at every level; at -lvl 7 the package-merge
    // path, not the heuristic, produces the required length limit. Combined work GPLv3.
    private const int PackageBit = 0x40000000;

    private static byte[] BuildCodeLengths(ReadOnlySpan<int> freq)
    {
        var result = new byte[256];
        var present = new List<int>();
        long total = 0;
        for (int s = 0; s < 256; s++) { int c = freq[s]; if (c != 0) { present.Add(s); total += c; } }
        int n = present.Count;
        if (n == 0) return Array.Empty<byte>();
        if (n == 1) { result[present[0]] = 1; return result; }

        // (1) Scale counts so total and max both fit in 0xFFFF (no-op for small arrays).
        var weight = new long[256];
        ScaleCounts(freq, total, weight);

        // (2) Collect present symbols, sort ascending by count. The sort dispatches by alphabet
        //     size: <=32 distinct symbols -> an unstable median-of-3 introsort keyed on count only;
        //     >=33 -> a stable radix
        //     (counting) sort. The two disagree only on how equal-count symbols are ordered, and that tie
        //     order is exactly what the Moffat builder turns into which symbol gets the shorter code.
        //     Preserve both: the introsort permutation for small alphabets and the symbol-ascending
        //     stable order for large ones. Entries are built symbol-ascending (present is 0..255 order).
        var sym = new int[n + 1];
        var cnt = new int[n + 1];
        for (int i = 0; i < n; i++) { sym[i] = present[i]; cnt[i] = (int)weight[present[i]]; }
        if (n <= 32) SortByCountSmall(sym, cnt, n);
        else StableSortByCount(sym, cnt, n);

        // (3) Unlimited Moffat lengths; if the max is already within the limit, use them directly.
        var moff = new int[n];
        Array.Copy(cnt, moff, n);
        InPlaceHuffman(moff, n);
        if (moff[0] <= MaxCodeLen)
        {
            for (int i = 0; i < n; i++) result[sym[i]] = (byte)moff[i];
            return ValidateKraft(result, present, n) ? result : Array.Empty<byte>();
        }

        // (4) Length-limited boundary package-merge: MaxCodeLen lists, each capped at 2n-2 items.
        int nLevels = MaxCodeLen;
        cnt[n] = int.MaxValue;            // sentinel leaf
        int cap = 2 * n - 2;
        var lvField0 = new int[nLevels + 1][];
        var lvWeight = new long[nLevels + 1][];
        var lvLen = new int[nLevels + 1];
        for (int L = 1; L <= nLevels; L++) { lvField0[L] = new int[cap]; lvWeight[L] = new long[cap]; }

        for (int L = 1; L <= nLevels; L++)
        {
            int i0 = 0, pk = 0, outc = 0;
            int prevCount = (L >= 2) ? lvLen[L - 1] : 0;
            long[]? pw = (L >= 2) ? lvWeight[L - 1] : null;
            while (outc < cap)
            {
                long leafWeight = cnt[i0];
                if (pk + 1 < prevCount && pw![pk] + pw[pk + 1] <= leafWeight)
                {
                    lvWeight[L][outc] = pw[pk] + pw[pk + 1];
                    lvField0[L][outc] = pk | PackageBit;
                    pk += 2;
                }
                else
                {
                    if (i0 >= n) break;
                    lvWeight[L][outc] = leafWeight;
                    lvField0[L][outc] = sym[i0];
                    i0++;
                }
                outc++;
            }
            lvLen[L] = outc;
        }

        // Count phase: walk lists top-down; each leaf appearance lengthens that symbol's code by one.
        int active = lvLen[nLevels];
        for (int L = nLevels; L >= 1; L--)
        {
            int nextActive = 0;
            int[] f0 = lvField0[L];
            for (int j = 0; j < active; j++)
            {
                int v = f0[j];
                if ((v & PackageBit) == 0) result[v]++;
                else nextActive = (v & ~PackageBit) + 2;
            }
            active = nextActive;
        }
        return ValidateKraft(result, present, n) ? result : Array.Empty<byte>();
    }

    // Kraft completeness guard: a valid prefix code satisfies sum 2^-len == 1 over present symbols.
    private static bool ValidateKraft(byte[] result, List<int> present, int n)
    {
        long kraft = 0;
        for (int i = 0; i < n; i++)
        {
            int l = result[present[i]];
            if (l < 1 || l > MaxCodeLen) return false;
            kraft += 1L << (MaxCodeLen - l);
        }
        return kraft == (1L << MaxCodeLen);
    }

    // ScaleCounts: scale so total and max both fit in 0xFFFF; round half up,
    // clamp to 0xFFFF, floor non-zero counts to 1, and absorb any overshoot into the heaviest symbol.
    private static void ScaleCounts(ReadOnlySpan<int> freq, long total, long[] dest)
    {
        long maxCount = 0; int maxi = 0;
        for (int s = 0; s < 256; s++) { long cc = freq[s]; if (maxCount < cc) { maxCount = cc; maxi = s; } }
        const long allowed = 0xFFFF;
        if (maxCount <= allowed && total <= allowed)
        {
            for (int s = 0; s < 256; s++) dest[s] = freq[s];
            return;
        }
        float a = (float)allowed / total;
        float b = (float)allowed / maxCount;
        float fscale = a <= b ? a : b;
        long sumDest = 0;
        for (int s = 0; s < 256; s++)
        {
            if (freq[s] == 0) { dest[s] = 0; continue; }
            uint v = (uint)((float)freq[s] * fscale + 0.5f);
            uint clamped = v < allowed ? v : (uint)allowed;
            long d = clamped < 2 ? 1 : clamped;
            dest[s] = d; sumDest += d;
        }
        if (allowed < sumDest) dest[maxi] += allowed - sumDest;
    }

    // Sort n>=33 path: a stable counting/radix sort on the u16 count. Because
    // counting sort is stable and the entries enter in symbol-ascending order, equal-count symbols keep
    // symbol-ascending order -- which this stable (count, symbol id) sort reproduces exactly.
    private static void StableSortByCount(int[] sym, int[] cnt, int n)
    {
        var idx = new int[n];
        for (int i = 0; i < n; i++) idx[i] = i;
        Array.Sort(idx, (x, y) => cnt[x] != cnt[y] ? cnt[x].CompareTo(cnt[y]) : x.CompareTo(y));
        var s2 = new int[n]; var c2 = new int[n];
        for (int i = 0; i < n; i++) { s2[i] = sym[idx[i]]; c2[i] = cnt[idx[i]]; }
        Array.Copy(s2, sym, n); Array.Copy(c2, cnt, n);
    }

    // Sort n<33 path: an unstable introsort. Median-of-3 quicksort with an insertion base
    // for n<=4 and a heapsort fallback at recursion-depth exhaustion; comparator is count-only
    // strict-less, with no symbol tie-break, so the permutation of equal-count symbols is determined
    // purely by the partition/heap operations. Sorts the symbol-ascending (sym,cnt) entries in place,
    // ascending by cnt. The depth budget repeatedly decays the count by ~0.75 (x>>1)+(x>>2)
    // until 0 -> k frames; when the pending-frame depth reaches k, heapsort the current range
    // instead of partitioning.
    private static void SortByCountSmall(int[] sym, int[] cnt, int n)
    {
        if (n < 2) return;

        void Swap(int i, int j) { (sym[i], sym[j]) = (sym[j], sym[i]); (cnt[i], cnt[j]) = (cnt[j], cnt[i]); }
        // Rot3(x,y,z): swap(x,y); swap(x,z).
        void Rot3(int x, int y, int z) { Swap(x, y); Swap(x, z); }

        // Median-of-3: place the median of {a,b,c} at b; fully sorts 3 elements.
        void Median3(int a, int b, int c)
        {
            if (cnt[b] < cnt[a])
            {
                if (cnt[b] < cnt[c]) { if (cnt[a] < cnt[c]) Swap(a, b); else Rot3(b, a, c); }
                else Swap(a, c);
            }
            else
            {
                if (cnt[c] < cnt[b]) { if (cnt[a] < cnt[c]) Swap(b, c); else Rot3(a, b, c); }
            }
        }

        // Heapsort fallback: max-heap by count, strict-less sift.
        void SiftDown(int lo, int nodeRel, int heapCount)
        {
            while (true)
            {
                int childRel = nodeRel * 2 + 1;
                if (childRel >= heapCount) break;
                int childAbs = lo + childRel;
                if (childRel + 1 < heapCount && cnt[childAbs] < cnt[childAbs + 1]) { childRel++; childAbs++; }
                if (!(cnt[lo + nodeRel] < cnt[childAbs])) break;
                Swap(lo + nodeRel, childAbs);
                nodeRel = childRel;
            }
        }
        void HeapSort(int lo, int count)
        {
            for (int s = count / 2 - 1; s >= 0; s--) SiftDown(lo, s, count);
            for (int end = count - 1; end >= 1; end--) { Swap(lo, lo + end); SiftDown(lo, 0, end); }
        }

        // Introsort recursion-depth budget k.
        int k = 0;
        { uint u = (uint)n; do { u = (u >> 1) + (u >> 2); k++; } while (u != 0); }

        var stack = new System.Collections.Generic.Stack<(int lo, int hi)>();
        int first = 0, last = n - 1, count = n;
        while (true)
        {
            if (count > 1)
            {
                if (count == 2) { if (cnt[last] < cnt[first]) Swap(first, last); }
                else
                {
                    int mid = first + (count >> 1);
                    Median3(first, mid, last);
                    if (count < 5) { if (count == 4) Insert4(first, mid, last); }
                    else if (stack.Count == k) HeapSort(first, count);
                    else
                    {
                        // Hoare partition with the median (now at mid) as pivot, moved to first.
                        int left = first, right = last;
                        Swap(mid, first);
                        while (true)
                        {
                            do { right--; } while (cnt[first] < cnt[right]);
                            if (right <= left) break;
                            do { left++; } while (cnt[left] < cnt[first]);
                            if (right <= left) { left--; break; }
                            Swap(left, right);
                        }
                        Swap(first, left);
                        int pivot = left;
                        // Extend over the equal-to-pivot band so neither half re-sorts it.
                        int hiScan = left;
                        do { hiScan++; } while (hiScan < last && !(cnt[pivot] < cnt[hiScan]));
                        int loScan = left;
                        do { loScan--; } while (first < loScan && !(cnt[loScan] < cnt[pivot]));
                        int leftCount = loScan - first + 1;
                        int rightCount = last - hiScan + 1;
                        // Push the smaller half, loop on the larger (bounds pending depth to O(log n)).
                        if (rightCount < leftCount) { stack.Push((hiScan, last)); last = loScan; count = leftCount; continue; }
                        else { stack.Push((first, loScan)); first = hiScan; count = rightCount; continue; }
                    }
                }
            }
            if (stack.Count == 0) break;
            (first, last) = stack.Pop();
            count = last - first + 1;
        }

        // Insertion of the 4th element for n==4, after Median3 sorted 3.
        void Insert4(int f, int m, int l)
        {
            int x = f + 1;
            if (cnt[m] < cnt[x]) { if (cnt[x] < cnt[l]) Swap(x, m); else Rot3(m, x, l); }
            else { if (cnt[x] < cnt[f]) Swap(f, x); }
        }
    }

    // In-place Moffat/Katajainen Huffman code lengths. cnt ascending in,
    // per-leaf lengths out (index 0 = the lowest-count symbol = the longest code).
    private static void InPlaceHuffman(int[] cnt, int n)
    {
        cnt[0] = cnt[0] + cnt[1];
        int leafLow = 0, nextLeaf = 2;
        for (int next = 1; next < n - 1; next++)
        {
            if (nextLeaf < n && cnt[nextLeaf] <= cnt[leafLow]) { cnt[next] = cnt[nextLeaf]; nextLeaf++; }
            else { cnt[next] = cnt[leafLow]; cnt[leafLow] = next; leafLow++; }
            if (nextLeaf < n && (next <= leafLow || cnt[nextLeaf] <= cnt[leafLow])) { cnt[next] += cnt[nextLeaf]; nextLeaf++; }
            else { cnt[next] += cnt[leafLow]; cnt[leafLow] = next; leafLow++; }
        }
        cnt[n - 2] = 0;
        for (int i = n - 3; i >= 0; i--) cnt[i] = cnt[cnt[i]] + 1;
        int depth = 0, intNode = n - 2, leafW = n - 1, avail = 1;
        while (avail > 0)
        {
            int used = 0;
            while (intNode >= 0 && cnt[intNode] == depth) { used++; intNode--; }
            for (; used < avail; avail--) { cnt[leafW] = depth; leafW--; }
            depth++; avail = used << 1;
        }
    }

    // ============================ canonical code assignment (HuffMakeLut order) ============================
    private static void BuildCanonicalCodes(byte[] lenOfSym, out ushort[] codeOfSym)
    {
        codeOfSym = new ushort[256];
        uint currslot = 0;
        for (int len = 1; len <= MaxCodeLen; len++)
        {
            int stepsize = 1 << (MaxCodeLen - len);
            for (int s = 0; s < 256; s++)
            {
                if (lenOfSym[s] != len) continue;
                codeOfSym[s] = (ushort)(currslot >> (MaxCodeLen - len));
                currslot += (uint)stepsize;
            }
        }
        // currslot must be exactly 2048 for a complete code (asserted by the round-trip self-test).
    }

    private static int ReverseBits(int v, int len)
    {
        int r = 0;
        for (int i = 0; i < len; i++) { r = (r << 1) | (v & 1); v >>= 1; }
        return r;
    }

    private static int BitWidth(int v)
    {
        int b = 0;
        while (v > 0) { b++; v >>= 1; }
        return b;
    }

    // ============================ bit writers ============================
    // MSB-first writer for forward-mode bit reading (first bit written -> bit 7 of byte 0).
    private sealed class MsbBitWriter
    {
        private readonly List<byte> _bytes = new();
        private uint _acc;
        private int _nbits;

        public int BitLength => (_bytes.Count * 8) + _nbits;

        public void Write(uint v, int len)
        {
            for (int i = len - 1; i >= 0; i--)
            {
                _acc = (_acc << 1) | ((v >> i) & 1u);
                if (++_nbits == 8) { _bytes.Add((byte)_acc); _acc = 0; _nbits = 0; }
            }
        }

        public byte[] ToBytesPadded()
        {
            if (_nbits > 0) { _bytes.Add((byte)(_acc << (8 - _nbits))); _acc = 0; _nbits = 0; }
            return _bytes.ToArray();
        }
    }

    // LSB-first writer mirroring the 3-stream core (first bit written -> bit 0 of byte 0).
    private sealed class LsbBitWriter
    {
        private readonly List<byte> _bytes = new();
        private uint _acc;
        private int _nbits;

        public void Write(uint v, int len)
        {
            _acc |= (v & ((1u << len) - 1)) << _nbits;
            _nbits += len;
            while (_nbits >= 8) { _bytes.Add((byte)_acc); _acc >>= 8; _nbits -= 8; }
        }

        public byte[] ToBytesPadded()
        {
            if (_nbits > 0) { _bytes.Add((byte)_acc); _acc = 0; _nbits = 0; }
            return _bytes.ToArray();
        }
    }

}
