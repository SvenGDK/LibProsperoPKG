// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// Kraken (newLZ) encoder producing standard, decoder-valid
// newLZ chunks accepted by the PS5 Kraken decompressor. The PS5 block decompressor is the
// acceptance check. This file emits the documented chunk structure. GPLv3.
//
// A PFS block (up to blockSize, default 256 KiB) is encoded as ONE or TWO headerless newLZ chunks,
// because a single newLZ chunk decodes at most 128 KiB (0x20000). blockSize 0x40000 is therefore
// exactly two chunks; the block-boundary table flags a two-chunk block with the 0x20 bit (flag 0x26
// instead of 0x06) and stores the first chunk's compressed size in its saturating size hint, exactly
// as the frame rebuilder expects when it splits the block
// back into per-chunk OodleLZ frames.
//
// CHUNK FORMAT ("excess mode", post-seed control byte high bit set):
//
// first chunk:[8-byte raw seed][ctrl][lit raw][cmd raw][offs raw][litlen raw][dual bitstream][excess]
// second chunk:[ctrl][lit raw][cmd raw][offs raw][litlen raw][dual bitstream][excess]
//
// * seed = the first 8 bytes of the first chunk (COPY_64); decoding starts at dst+8. The second
// chunk has NO seed — it is decoded at a non-zero output offset and its matches may
// reference back into the first chunk's already-decoded output.
// * ctrl byte = 0x80 | (excessByteCount & 0x3F), with a continuation byte when the low six bits would
// * exceed 0x1F. excessByteCount is the length of the trailing excess sub-stream that carries
// * the literal-length escape values (0 when no literal run exceeds 257).
// * 4 raw arrays, each a DecodeBytes chunk-type-0 raw block: a 3-byte big-endian length header (high
// bit clear, len <= 0x3FFFF) followed by that many raw bytes. Order: lit, cmd, packed_offs,
// packed_litlen.
// * dual bitstream = forward bytes ++ reverse(backward bytes); carries ONLY the offset extra (E) bits,
// alternating new-offset #0 -> forward, #1 -> backward, #2 -> forward,...
// * excess sub-stream (only when excessByteCount > 0) = the chunk's trailing excessByteCount bytes:
// a forward writer (even-index literal-length escapes) ++ reverse(backward writer, odd-index escapes),
// each value written with WriteLength; the decoder's ea/eb readers consume them in the same order.
//
// Command byte f: litfield = f & 3 (== 3 -> packed_litlen carries litlen-3); matchfield = (f >> 2) & 0xF
// (<= 14 -> inline matchlen = matchfield + 2; == 15 -> packed_litlen carries matchlen-17);
// offs_index = f >> 6 (== 3 -> new offset taken from packed_offs + E bits).
//
// CONSTRAINTS THAT MAKE A CHUNK DECODER-VALID:
// 1. Every chunk MUST end with a literal tail; a match may never cover the final 8 bytes of a chunk.
// 2. Minimum new-offset distance is 8 (recent offsets initialise to -8; 1..7 are not encodable).
// 3. matchlen is capped at 271 (split into consecutive same-distance pieces) so packed_litlen never
// needs a match-length escape. A literal run longer than 257 is encoded as follows: packed_litlen stores a
// 255 marker and the (litlen-258) value is emitted into the trailing excess sub-stream. At most 512
// escapes per chunk (the decoder's u32 length-stream cap), else the block is stored raw.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System;
using System.Collections.Generic;

namespace LibProsperoPkg.PFS.Compression.Oodle;

/// <summary>
/// The result of compressing one PFS block: the section-7 payload plus the metadata the boundary
/// table needs (whether the block was split into two chunks, and the first chunk's compressed size).
/// </summary>
internal readonly struct EncodedBlock
{
    /// <summary>The bytes that land in section 7 for this block (one or two concatenated chunks).</summary>
    public readonly byte[] Payload;

    /// <summary>True when the block is two chunks (boundary flag 0x26); false for a single chunk (0x06).</summary>
    public readonly bool MultiChunk;

    /// <summary>The compressed size of the first chunk (the value stored, minus one, in the size hint).</summary>
    public readonly int FirstChunkCompSize;

    public EncodedBlock(byte[] payload, bool multiChunk, int firstChunkCompSize)
    {
        Payload = payload;
        MultiChunk = multiChunk;
        FirstChunkCompSize = firstChunkCompSize;
    }
}

/// <summary>
/// Managed Kraken (newLZ) encoder. Compresses a PFS block into one or two headerless newLZ "excess
/// mode" chunks that round-trip through the PS5 block decompressor.
/// <para>
/// <b>Length escapes.</b> A literal run longer than 257 bytes (packed value <c>litLen-3 &gt;= 255</c>) and
/// a match longer than <see cref="MaxMatch"/> (packed value <c>matchLen-17 &gt;= 255</c>) are carried by a
/// 0xFF packed_litlen marker plus a u32 escape value. Every escape in a chunk is collected in packed_litlen
/// order and written into a trailing excess sub-stream, split even index -&gt; forward writer / odd index
/// -&gt; backward writer and laid out <c>forward ++ reverse(backward)</c>, mirroring the paired readers the
/// decoder uses. The post-seed control byte is <c>0x80 | low6(excessByteCount)</c> with a continuation byte
/// when the count exceeds 0x1F. Over-long matches are split into &lt;= <see cref="MaxMatch"/> pieces so in
/// practice only literal runs escape; a chunk needing more than <see cref="MaxEscapes"/> escapes falls back
/// to the stored path.
/// </para>
/// <para>
/// <b>No match may start in the last <see cref="NoMatchZone"/> (16) bytes of a chunk.</b> The newLZ release
/// parse loop enforces <c>match_zone_end - to_ptr &gt;= lrl</c> where <c>match_zone_end = chunk_end - 16</c>:
/// the literal-run end (= match start) must be &lt;= chunk_end - 16. A match that starts later drifts the
/// decode pointer and the block is rejected with error -1007. The parser therefore stops emitting matches
/// past <c>chunkEnd - NoMatchZone</c> and flushes the remainder as the trailing literal run; a store-raw
/// safety net rejects any chunk that would still violate it.
/// </para>
/// Returns null when compression is not worthwhile (caller stores the block).
/// </summary>
internal static class OodleKrakenEncoder
{
    private const int ChunkMax = 0x20000;       // a single newLZ chunk decodes at most 128 KiB
    private const int MinChunk = 64;            // below this, storing raw is never worse
    private const int MinMatch = 4;
    private const int MinRepMatch = 2;          // a repeat-offset match costs no offset, so length 2 can pay
    private const int MinDistance = 8;          // recent-offset init is -8; shorter distances are illegal
    private const int LiteralTail = 8;          // a match may extend to chunkEnd-8, so >=8 trailing literals remain
    private const int NoMatchZone = 16;         // a match may not START in the last 16 bytes of a chunk (match_zone_end = chunkEnd-16)
    private const int MaxMatch = 271;           // split path caps matchlen-17 <= 254 (packed_litlen < 255); a lone over-long match instead uses the single match-length escape
    private const int MaxArrayLength = 0x3FFFF; // DecodeBytes raw 3-byte size limit
    private const int MaxFirstChunkComp = 0x1FFFF; // size hint is 17-bit; first chunk must fit
    private const int MaxChainWalk = 128;
    private const int HashBits = 17;
    private const int HashSize = 1 << HashBits;
    private const byte CtrlExcessMode = 0x80;   // post-seed control byte:0x80 | low6(excessCount), plus a continuation byte when excessCount > 0x1F
    private const int MaxEscapes = 512;         // the decoder caps u32_len_stream_size (the count of length escapes) at 512

    private readonly struct Command
    {
        public readonly int LitStart;
        public readonly int LitLen;
        public readonly int Distance;
        public readonly int MatchLen;
        public readonly int OffsIndex; // 0/1/2 = reuse a recent offset (no offset emitted); 3 = new offset

        public Command(int litStart, int litLen, int distance, int matchLen, int offsIndex)
        {
            LitStart = litStart;
            LitLen = litLen;
            Distance = distance;
            MatchLen = matchLen;
            OffsIndex = offsIndex;
        }
    }

    /// <summary>
    /// Compresses <paramref name="data"/> (one PFS block) into a section-7 payload of one or two
    /// newLZ chunks, or returns null if the data is too small or does not compress below its original
    /// size.
    /// </summary>
    public static EncodedBlock? EncodeBlock(ReadOnlySpan<byte> data) => EncodeBlock(data, useHuffmanArrays: false);

    /// <summary>
    /// Compresses <paramref name="data"/> (one PFS block) into a section-7 payload of one or two
    /// newLZ chunks, or returns null if the data is too small or does not compress below its original
    /// size. When <paramref name="useHuffmanArrays"/> is true
    /// the literal/command/length arrays are Huffman-coded (entropy chunk type 2) via
    /// <see cref="KrakenHuffmanArrayEncoder"/> when that is smaller than the raw form, shrinking actual
    /// blocks toward their target sizes. The packed-offset array is always left raw because the offset
    /// reader inspects its first byte (the 0x80 bit selects two-table mode), which an entropy header
    /// would corrupt.
    /// </summary>
    public static EncodedBlock? EncodeBlock(ReadOnlySpan<byte> data, bool useHuffmanArrays)
    {
        int n = data.Length;
        if (n < MinChunk)
            return null; // not worth it; caller stores raw

        var head = new int[HashSize];
        var prev = new int[n];
        head.AsSpan().Fill(-1);

        if (n <= ChunkMax)
        {
            byte[]? single = EncodeChunk(data, head, prev, 0, n, withSeed: true, useHuffmanArrays, allowOptimal: true);
            if (single is null || single.Length >= n)
                return null;
            return new EncodedBlock(single, multiChunk: false, single.Length);
        }

        // blockSize is at most 0x40000 (two chunks). A larger block cannot be described by the single
        // first-chunk size hint, so leave it to the stored path.
        if (n > 2 * ChunkMax)
            return null;

        byte[]? chunk0 = EncodeChunk(data, head, prev, 0, ChunkMax, withSeed: true, useHuffmanArrays, allowOptimal: true);
        if (chunk0 is null || chunk0.Length > MaxFirstChunkComp || chunk0.Length >= ChunkMax)
            return null;

        byte[]? chunk1 = EncodeChunk(data, head, prev, ChunkMax, n, withSeed: false, useHuffmanArrays, allowOptimal: true);
        // A second chunk that does not compress below its own size (e.g. an incompressible tail) would be
        // emitted as a degenerate all-literal chunk. Store the whole block instead, matching the
        // single-chunk path's `single.Length >= n` decision.
        if (chunk1 is null || chunk1.Length >= n - ChunkMax)
            return null;

        var payload = new byte[chunk0.Length + chunk1.Length];
        Buffer.BlockCopy(chunk0, 0, payload, 0, chunk0.Length);
        Buffer.BlockCopy(chunk1, 0, payload, chunk0.Length, chunk1.Length);
        if (payload.Length >= n)
            return null;
        return new EncodedBlock(payload, multiChunk: true, chunk0.Length);
    }

    /// <summary>
    /// Encodes the output range [<paramref name="chunkStart"/>, <paramref name="chunkEnd"/>) of
    /// <paramref name="data"/> as one newLZ chunk. The shared <paramref name="head"/>/<paramref name="prev"/>
    /// hash chain lets a later chunk reference matches in an earlier one. When
    /// <paramref name="withSeed"/> is false the chunk omits the 8-byte COPY_64 seed (used for any
    /// chunk decoded at a non-zero output offset).
    /// </summary>
    private static byte[]? EncodeChunk(ReadOnlySpan<byte> data, int[] head, int[] prev,
        int chunkStart, int chunkEnd, bool withSeed, bool useHuffmanArrays, bool allowOptimal = false)
    {
        int matchLimit = chunkEnd - LiteralTail; // a match may EXTEND up to here, so >= LiteralTail trailing literals remain
        // The newLZ decoder forbids a match from STARTING in the last 16 bytes of a chunk. Its release
        // parse loop (the algorithm) enforces `match_zone_end - to_ptr >= lrl` with
        // match_zone_end = chunk_end - 16: the match start
        // (= literal-run end) must be <= chunk_end - 16. A match that starts later drifts the decode
        // pointer and the block is rejected with decompression error -1007, even
        // though our own (lenient) decoder round-trips it. So the last legal match-start is chunkEnd-NoMatchZone.
        int matchStartLimit = chunkEnd - NoMatchZone;
        int firstMatchPos = withSeed ? chunkStart + 8 : chunkStart; // seed is the first 8 bytes
        // The seed bytes are valid copy sources (the decoder emits them before the first command), so
        // index them in the hash chain. Without this the parser cannot find a match that references the
        // first 8 bytes of a seeded chunk and the first match is delayed by up to 8 literals, which is
        // exactly how the parser handles a periodic block (e.g. a distance-16 match at position 16 referencing
        // position 0). The seedless second chunk needs nothing here — its predecessors are already indexed.
        if (withSeed)
        {
            for (int p = chunkStart; p < firstMatchPos; p++)
                Insert(data, p, head, prev);
        }
        // Literals before the first match begin where matching begins (the seed is emitted separately).
        // A single-chunk block (allowOptimal) has no cross-chunk backward dependency, so it is
        // parsed with the Optimal3 multi-candidate selection: greedy mml=4/3/8 plus one seeded
        // forward-DP, choosing the candidate with the smallest real entropy-coded emit size.
        // Because plain greedy is included as a candidate, this cannot enlarge the block. The
        // forward-DP needs mml=3 (UseDpMml3) to surface length-3 matches. Multi-chunk blocks stay
        // on the shared-chain greedy so the seedless second chunk can still reference the first.
        //
        // The matcher is a bounded suffix-trie; this managed DP is O(n^2) in the block length,
        // so the optimal parse is limited to genuinely small standalone blocks (ProductionOptimalMaxBlock)
        // — the small config/text system files stored as per-file standalone blocks —
        // keeping build times fast. Larger single-chunk blocks fall back to the linear greedy parse.
        bool blockOptimalSmall = allowOptimal && ProductionOptimalSingleChunk
            && (chunkEnd - chunkStart) <= ProductionOptimalMaxBlock;
        // Large single-chunk blocks: windowed Optimal3 DP (near-linear, seeded). Best-of-{greedy,DP}
        // by real emit size so it never enlarges the block versus the greedy fallback.
        int blockLen = chunkEnd - chunkStart;
        bool blockOptimalWindowed = allowOptimal && ProductionWindowedOptimal
            && blockLen > ProductionOptimalMaxBlock && blockLen <= ProductionOptimalWindowedMaxBlock;
        bool optimal = UseOptimalParse || blockOptimalSmall || blockOptimalWindowed;
        List<Command> commands;
        if (optimal)
        {
            bool savedMml3 = UseDpMml3, savedWin = UseWindowedParse, savedFront = UseFrontierGate, savedTiny = UseTinyOffsetRemap, savedSkip = UseLongMatchSkip;
            UseDpMml3 = true;
            // Enable windowing plus long-match skipping for the large-block path while leaving the
            // monolithic small-block path untouched. The long-match skip replaces the earlier
            // cross-position frontier gate, which over-suppressed candidates; with the skip enabled,
            // disabling the frontier gate keeps the windowed DP aligned with the intended parse.
            if (blockOptimalWindowed && !UseOptimalParse) { UseWindowedParse = true; UseFrontierGate = false; UseLongMatchSkip = true; UseTinyOffsetRemap = true; }
            try
            {
                commands = ParseOptimal(data, head, prev, firstMatchPos, firstMatchPos, matchLimit, matchStartLimit,
                    chunkStart, chunkEnd, withSeed, useHuffmanArrays);
            }
            finally { UseDpMml3 = savedMml3; UseWindowedParse = savedWin; UseFrontierGate = savedFront; UseTinyOffsetRemap = savedTiny; UseLongMatchSkip = savedSkip; }
        }
        else
        {
            commands = Parse(data, head, prev, firstMatchPos, firstMatchPos, matchLimit, matchStartLimit);
        }
        if (commands.Count == 0)
            return null;

        // Shipping validity path: raw literals (litMode 1). The literal mode is signaled OUT-OF-BAND
        // by the PFS boundary-table flag bit (KrakenDecoder.DecodeBlock reads chunk0 0x01 /
        // chunk1 0x10: set = sub, clear = raw), so the emitted literal-array content and that flag must
        // agree. Emitting the cheaper SUB array (ChooseLitMode) requires also setting that flag in
        // the block builder; that end-to-end sub plumbing belongs to the byte-identity (UseOptimalParse)
        // path, so the validity deliverable stays raw and round-trips green.
        return EmitChunkFromCommands(data, commands, chunkStart, chunkEnd, withSeed, useHuffmanArrays, litMode: 1);
    }

    /// <summary>
    /// Builds the newLZ stream arrays from an already-computed parse and assembles the chunk bytes
    /// (entropy-coding the lit/cmd/length arrays when beneficial). Factored out of <see cref="EncodeChunk"/>
    /// so a diagnostic can measure the actual entropy-coded emit size of an externally supplied parse
    /// (its size vs the DP's) — the metric the level-7 producer actually minimises in its final
    /// greedy-vs-DP selection (actual-emit-size pick). Returns null when the parse needs a store-raw
    /// fallback (a literal run over MaxLitRun or a match starting inside the no-match zone).
    /// </summary>
    private static byte[]? EmitChunkFromCommands(ReadOnlySpan<byte> data, List<Command> commands,
        int chunkStart, int chunkEnd, bool withSeed, bool useHuffmanArrays, int litMode = 1)
    {
        int matchStartLimit = chunkEnd - NoMatchZone;
        // Store-raw safety net: a match may not start inside the no-match zone (the last 16 bytes of the
        // chunk). The parser already enforces this, so in practice this never triggers.
        foreach (var cmd in commands)
        {
            if (cmd.MatchLen > 0 && cmd.LitStart + cmd.LitLen > matchStartLimit)
                return null;
        }

        var litRaw = new List<byte>(chunkEnd - chunkStart); // mode 1:raw literals
        var litSub = new List<byte>(chunkEnd - chunkStart); // mode 0:sub/delta literals (byte - dst[p+lastOffset])
        BuildLiteralStreams(data, commands, chunkEnd, litRaw, litSub);
        var cmdStream = new List<byte>();
        var packedOffs = new List<byte>();
        var packedLitLen = new List<byte>();
        var forward = new KrakenBitWriter();
        var backward = new KrakenBitWriter();
        // Length-escape u32 values (one per 0xFF packed_litlen marker), collected in packed_litlen order.
        // They are written into the trailing excess sub-stream after the main streams are assembled.
        var escapeValues = new List<uint>();

        // Local helper: append a length's packed value to packed_litlen, escaping when it reaches 255.
        // A literal run longer than 257 bytes (packed value litLen-3 >= 255) escapes; matches are split
        // into <= MaxMatch pieces below, so their packed length (piece-17 <= 254) never escapes.
        void EmitLen(int packedValue)
        {
            if (packedValue < 255)
            {
                packedLitLen.Add((byte)packedValue);
            }
            else
            {
                packedLitLen.Add(255);                        // u32 length-escape marker
                escapeValues.Add((uint)(packedValue - 255));  // decoder: length value = u32 + 255
            }
        }

        int offsetIndex = 0;
        foreach (var c in commands)
        {
            // Literal streams (litRaw/litSub) were built up-front by BuildLiteralStreams; this loop only
            // assembles the command/offset/length streams. The encoder emits exactly ONE command
            // per parse command regardless of match length: a match longer than 16 sets matchField=15 and
            // transmits (matchLen-17) through the shared length stream, escaping to the trailing excess
            // sub-stream when the packed value reaches 255 (matchLen >= 272). A trailing command with
            // MatchLen==0 (the final literal run) contributes no command byte -- the decoder copies its
            // literals in the tail loop. Splitting an over-long match into rep0 continuation pieces would
            // still round-trip through our lenient decoder, but it is NOT what the encoder emits, so the
            // block bytes would differ (extra command bytes, no escape) -- hence one command, one escape.
            if (c.MatchLen == 0)
                continue;

            int curLit = c.LitLen;
            int litField = curLit >= 3 ? 3 : curLit;
            int matchField = c.MatchLen <= 16 ? c.MatchLen - 2 : 15;
            cmdStream.Add((byte)((c.OffsIndex << 6) | (matchField << 2) | litField));

            if (litField == 3)
                EmitLen(curLit - 3);

            if (c.OffsIndex == 3)
            {
                // Only a new offset is transmitted: one packed_offs byte plus its E bits in the dual
                // bitstream, alternating forward/backward per new offset. Recent-offset reuse
                // (index 0/1/2) writes nothing here.
                byte v = (offsetIndex & 1) == 0
                    ? forward.WriteDistance(c.Distance)
                    : backward.WriteDistance(c.Distance);
                packedOffs.Add(v);
                offsetIndex++;
            }

            if (matchField == 15)
                EmitLen(c.MatchLen - 17);
        }

        if (escapeValues.Count > MaxEscapes)
            return null; // more length escapes than the decoder accepts; store raw instead

        // Both literal models hold the same number of literals; the array-length guard is mode-independent.
        if (litRaw.Count > MaxArrayLength || cmdStream.Count > MaxArrayLength ||
            packedOffs.Count > MaxArrayLength || packedLitLen.Count > MaxArrayLength)
        {
            return null; // arrays too large for the raw 3-byte header; store raw instead
        }

        // Literal model selection (newLZ "sub" vs "raw"): the only chunk array that depends on the
        // model. The encoder keeps whichever
        // yields the smaller entropy-coded literal array; litMode forces it (0 = sub, 1 = raw) for
        // diagnostics, -1 = auto (ChooseLitMode = the validated decision).
        List<byte> lit;
        if (litMode == 0) lit = litSub;
        else if (litMode == 1) lit = litRaw;
        else lit = ChooseLitMode(litRaw, litSub, useHuffmanArrays) == 0 ? litSub : litRaw;

        byte[] forwardBytes = forward.ToBytes();
        byte[] backwardBytes = backward.ToBytes();

        var outBuf = new List<byte>(chunkEnd - chunkStart);
        if (withSeed)
        {
            for (int i = 0; i < 8; i++)
                outBuf.Add(data[chunkStart + i]); // seed
        }
        // Trailing excess sub-stream = the length-escape u32 values, split even index -> forward writer,
        // odd index -> backward writer, then laid out forward ++ reverse(backward) exactly like the main
        // bitstream so the decoder's paired readers meet.
        var excessF = new KrakenBitWriter();
        var excessB = new KrakenBitWriter();
        for (int i = 0; i < escapeValues.Count; i++)
        {
            if ((i & 1) == 0) excessF.WriteLength(escapeValues[i]);
            else excessB.WriteLength(escapeValues[i]);
        }
        byte[] excessFwd = excessF.ToBytes();
        byte[] excessBwd = excessB.ToBytes();
        int excessCount = excessFwd.Length + excessBwd.Length;
        if (excessCount > 0x1FFF)
            return null; // continuation byte cannot encode this many excess bytes; store raw instead

        // Post-seed control byte: 0x80 | low6(excessCount). When excessCount > 0x1F a continuation byte
        // carries the high bits: low6 = 0x20 | (excessCount & 0x1F), continuation = (excessCount >> 5) - 1
        // (decoder: excessCount = low6 + continuation * 0x20).
        if (excessCount <= 0x1F)
        {
            outBuf.Add((byte)(CtrlExcessMode | excessCount));
        }
        else
        {
            outBuf.Add((byte)(CtrlExcessMode | 0x20 | (excessCount & 0x1F)));
            outBuf.Add((byte)((excessCount >> 5) - 1));
        }
        WriteArray(outBuf, lit, useHuffmanArrays);
        WriteArray(outBuf, cmdStream, useHuffmanArrays);
        // packed_offs: Huffman-code this array when beneficial (single-table offset mode).
        // The offset-mode reader inspects this array's first byte for bit 0x80 (set = two-table scaling
        // byte). KrakenHuffmanArrayEncoder always emits the 5-byte long-form entropy header whose first
        // byte is (chunkType<<4)|... = 0x20..0x2F for chunkType 2 (bit 0x80 CLEAR), and a raw array's
        // first byte is (len>>16) <= 3 (also clear), so either form stays in single-table mode.
        // A previous validity-only version forced this raw; Huffman form is needed for text/data offsets.
        WriteArray(outBuf, packedOffs, useHuffmanArrays);
        WriteArray(outBuf, packedLitLen, useHuffmanArrays);
        // main dual bitstream region = forward ++ reverse(backward)
        outBuf.AddRange(forwardBytes);
        for (int i = backwardBytes.Length - 1; i >= 0; i--)
            outBuf.Add(backwardBytes[i]);
        // trailing excess sub-stream = forward ++ reverse(backward)
        outBuf.AddRange(excessFwd);
        for (int i = excessBwd.Length - 1; i >= 0; i--)
            outBuf.Add(excessBwd[i]);

        return outBuf.ToArray();
    }

    private static void WriteRawArray(List<byte> outBuf, List<byte> array)
    {
        int len = array.Count;
        outBuf.Add((byte)((len >> 16) & 0xFF)); // high bit clear (len <= 0x3FFFF), chunk type 0
        outBuf.Add((byte)((len >> 8) & 0xFF));
        outBuf.Add((byte)(len & 0xFF));
        outBuf.AddRange(array);
    }

    // Builds the raw and sub (delta) literal byte streams for a parse. subLastOffset tracks r0 (the
    // active offset for the current run's literals): init -8, updated to -Distance after each match.
    // The decoder applies the old lastOffset to a command's literals and only updates it after them
    // (ProcessLzRunsType0), so literals use the PREVIOUS command's offset; the trailing run after the
    // final match uses the last chosen offset. Shared by EmitChunkFromCommands and ChooseLitMode so
    // the litMode decision scores exactly the bytes the emit would write.
    private static void BuildLiteralStreams(ReadOnlySpan<byte> data, List<Command> commands,
        int chunkEnd, List<byte> litRaw, List<byte> litSub)
    {
        int subLastOffset = -8;
        foreach (var c in commands)
        {
            for (int i = 0; i < c.LitLen; i++)
            {
                int p = c.LitStart + i;
                litRaw.Add(data[p]);
                litSub.Add((byte)(data[p] - data[p + subLastOffset]));
            }
            if (c.MatchLen > 0)
                subLastOffset = -c.Distance;
        }
        var last = commands[^1];
        int tailStart = last.LitStart + last.LitLen + last.MatchLen;
        for (int i = tailStart; i < chunkEnd; i++)
        {
            litRaw.Add(data[i]);
            litSub.Add((byte)(data[i] - data[i + subLastOffset]));
        }
    }

    // Literal-mode decision for optimal level 7: chooses sub vs raw.
    // * literal_count < 32 -> raw (1).
    // * else encode BOTH literal arrays for actual (array histogram encoder / our M2 array calc) and keep
    // the cheaper. Sub is evaluated first against the running budget; raw replaces it only when
    // STRICTLY cheaper (put_array_histo's budget ceiling is the incumbent sub cost), so sub wins
    // ties. Level 7 (`5 < level`) skips the level<=5 entropy-estimate pre-pick and compares the
    // actual encoded sizes directly. (The lambda space-speed term is 0 for a pure -lvl 7 ratio run.)
    // Returns 0 = sub, 1 = raw.
    internal static int ChooseLitMode(List<byte> litRaw, List<byte> litSub, bool useHuffmanArrays)
    {
        if (litSub.Count < 32) return 1; // raw: too few literals to entropy-code a sub stream
        int subSize = EncodedArraySize(litSub, useHuffmanArrays);
        int rawSize = EncodedArraySize(litRaw, useHuffmanArrays);
        // Prefer RAW on a tie: a near-constant block can make the sub/delta transform entropy-code
        // to the same size as raw, and raw preserves the intended literal stream. Sub still wins when
        // it is strictly smaller.
        return rawSize <= subSize ? 1 : 0;
    }

    // Convenience overload: choose the litMode a parse would emit, used to seed the DP cost build
    // with the greedy/seed parse's litMode so the winning greedy's choice becomes codecosts[0].
    private static int LitModeForParse(ReadOnlySpan<byte> data, List<Command> commands,
        int chunkEnd, bool useHuffmanArrays)
    {
        if (commands.Count == 0) return 1;
        var litRaw = new List<byte>(chunkEnd);
        var litSub = new List<byte>(chunkEnd);
        BuildLiteralStreams(data, commands, chunkEnd, litRaw, litSub);
        return ChooseLitMode(litRaw, litSub, useHuffmanArrays);
    }

    private static int EncodedArraySize(List<byte> array, bool useHuffman)
    {
        int raw = array.Count + 3;
        if (useHuffman && array.Count >= 2)
        {
            byte[]? huff = KrakenHuffmanArrayEncoder.TryEncode(
                System.Runtime.InteropServices.CollectionsMarshal.AsSpan(array));
            if (huff is not null && huff.Length < raw)
                return huff.Length;
        }
        return raw;
    }

    // Space-speed lambda used by the array method decision (see HuffmanBeatsRawJ). It weights
    // the Huffman-array decode-time estimate in the raw-vs-Huffman J-cost. Observed array decisions
    // pin it to the open interval (0.0321, 0.0662]; 0.046 is the geometric centre, maximising the
    // classification margin to every observed raw/Huffman decision.
    private const float ArrayJLambda = 0.046f;

    // Raw-vs-Huffman array choice. This is not a raw byte-size compare: the encoder keeps the
    // Huffman form only when its space-speed J cost is <= the raw form's:
    //     raw_J  = N + 3                                  (3-byte raw header; no decode-time term)
    //     huff_J = huffTotalBytes + lambda * decode_time(N)
    //     keep huff  iff  !(raw_J < huff_J)               (ties resolve to Huffman)
    // decode_time(N) is the mean of four affine decode-time estimates. Arrays with N < 32 are
    // always stored raw, which keeps tiny marginal arrays raw.
    private static bool HuffmanBeatsRawJ(int huffTotalBytes, int n)
    {
        if (n < 32) return false;
        float fn = n;
        float time = ((0.172f * fn + 284.97f) + (0.282f * fn + 326.121f)
                    + (0.377f * fn + 388.669f) + (0.161f * fn + 274.27f)) * 0.25f;
        float huffJ = huffTotalBytes + ArrayJLambda * time;
        float rawJ = n + 3;
        return !(rawJ < huffJ);
    }

    /// <summary>
    /// Writes <paramref name="array"/> as an entropy (Huffman) array when <paramref name="useHuffman"/>
    /// is set and the Huffman form wins the space-speed J cost against the raw
    /// form (see <see cref="HuffmanBeatsRawJ"/>); otherwise writes it raw. The literal/command/length
    /// streams are read by the decoder via plain <c>DecodeBytes</c>, so a type-2 entropy array is
    /// transparently accepted in their place.
    /// </summary>
    private static void WriteArray(List<byte> outBuf, List<byte> array, bool useHuffman)
    {
        if (useHuffman && array.Count >= 2)
        {
            byte[]? huff = KrakenHuffmanArrayEncoder.TryEncode(
                System.Runtime.InteropServices.CollectionsMarshal.AsSpan(array));
            if (huff is not null && HuffmanBeatsRawJ(huff.Length, array.Count))
            {
                outBuf.AddRange(huff);
                return;
            }
        }
        WriteRawArray(outBuf, array);
    }

    /// <summary>
    /// Value-model lazy parse over the output range. Each candidate match is scored as
    /// <c>len*4 - (isRep ? 0 : bitlen(dist)+2)</c>, preferring repeat offsets because they transmit no offset and preferring the shortest new distance on value ties.
    /// A two-step lazy look-ahead defers the match start when the next one or two positions pass the configured value-delta gates, then emits the selected command without starting matches past <paramref name="matchStartLimit"/> or extending them past <paramref name="matchLimit"/>.
    /// </summary>
    private static List<Command> Parse(ReadOnlySpan<byte> data, int[] head, int[] prev,
        int startPos, int litStart0, int matchLimit, int matchStartLimit)
    {
        var commands = new List<Command>();

        int litStart = litStart0;
        int pos = startPos;
        // A match may not start past chunkEnd-16 (the match_zone_end). Everything after the last
        // legal match start is emitted as the trailing literal run, which the decoder copies verbatim.
        int maxLast = matchStartLimit;

        // The decoder's three recent offsets (distances), most-recent first, move-to-front. The
        // decoder initialises recent[3..5] = -8, i.e. distance 8.
        int r0 = MinDistance, r1 = MinDistance, r2 = MinDistance;

        // Hash-chain watermark: positions [startPos, inserted) are present in the chain. We insert
        // every position exactly once, in order, as the parse passes it (so a match at p can only
        // reference earlier positions — the decoder is causal).
        int inserted = startPos;

        while (pos <= maxLast)
        {
            inserted = InsertUpTo(data, head, prev, inserted, pos);
            Cand cur = UseExactGreedy
                ? FindMatchExact(data, pos, head, prev, matchLimit, r0, r1, r2, pos - litStart)
                : FindMatch(data, pos, head, prev, matchLimit, r0, r1, r2);
            if (!cur.Valid)
            {
                pos++;
                continue;
            }

            // 2-step lazy look-ahead: defer the match start while a strictly better match appears.
            while (pos + 1 <= maxLast)
            {
                inserted = InsertUpTo(data, head, prev, inserted, pos + 1);
                Cand m1 = UseExactGreedy
                    ? FindMatchExact(data, pos + 1, head, prev, matchLimit, r0, r1, r2, (pos + 1) - litStart)
                    : FindMatch(data, pos + 1, head, prev, matchLimit, r0, r1, r2);
                if (m1.Value - cur.Value - 4 >= 1) // pos+1 strictly better after the +4 bias
                {
                    pos++;
                    cur = m1;
                    continue;
                }
                if (pos + 2 > maxLast)
                    break;
                inserted = InsertUpTo(data, head, prev, inserted, pos + 2);
                Cand m2 = UseExactGreedy
                    ? FindMatchExact(data, pos + 2, head, prev, matchLimit, r0, r1, r2, (pos + 2) - litStart)
                    : FindMatch(data, pos + 2, head, prev, matchLimit, r0, r1, r2);
                if (m2.Value - cur.Value - 4 >= 4) // pos+2 better by the larger threshold
                {
                    pos += 2;
                    cur = m2;
                    continue;
                }
                break;
            }

            commands.Add(new Command(litStart, pos - litStart, cur.Dist, cur.Len, cur.Idx));
            UpdateRecent(ref r0, ref r1, ref r2, cur.Idx, cur.Dist);
            int end = pos + cur.Len;
            inserted = InsertUpTo(data, head, prev, inserted, Math.Min(end, maxLast + 1));
            pos = end;
            litStart = end;
        }

        return commands;
    }

    /// <summary>Bit length of <paramref name="v"/> computed as <c>32 - leadingZeroCount(v)</c>.</summary>
    private static int BitLen(uint v) =>
        v == 0 ? 0 : 32 - System.Numerics.BitOperations.LeadingZeroCount(v);

    /// <summary>
    /// A candidate match. <see cref="Idx"/> 0/1/2 means repeat-offset reuse, 3 means new offset, and -1 means none.
    /// <see cref="Value"/> is <c>len*4 - (isRep ? 0 : bitlen(dist)+2)</c>; a none candidate scores a large negative value so it never wins a comparison.
    /// </summary>
    private readonly struct Cand
    {
        public readonly int Len;
        public readonly int Dist;
        public readonly int Idx;
        public Cand(int len, int dist, int idx) { Len = len; Dist = dist; Idx = idx; }
        public bool Valid => Idx >= 0;
        public int Value => Idx < 0 ? -0x40000000 : Len * 4 - (Idx < 3 ? 0 : BitLen((uint)Dist) + 2);
    }

    /// <summary>
    /// Per-position value-model match finder for the greedy parser.
    /// It returns the highest-value match at <paramref name="pos"/> given the three recent offsets, preferring repeat-offset reuse on ties and otherwise the shortest-distance new offset on a value tie.
    /// </summary>
    private static Cand FindMatch(ReadOnlySpan<byte> data, int pos, int[] head, int[] prev,
        int matchLimit, int r0, int r1, int r2)
    {
        // Repeat-offset candidate: longest reuse among the three recent distances (value = len*4).
        int repLen0 = RepMatchLength(data, pos, r0, matchLimit);
        int repLen1 = RepMatchLength(data, pos, r1, matchLimit);
        int repLen2 = RepMatchLength(data, pos, r2, matchLimit);
        int bestRepLen = repLen0, bestRepIdx = 0;
        if (repLen1 > bestRepLen) { bestRepLen = repLen1; bestRepIdx = 1; }
        if (repLen2 > bestRepLen) { bestRepLen = repLen2; bestRepIdx = 2; }

        // New-offset candidate via the shared hash chain, scored by value (shortest distance wins ties
        // because the chain is walked most-recent-first and we keep the first strictly-greater value).
        int effMml = GreedyMmlOverride > 0 ? GreedyMmlOverride : MinMatch;
        int bestNewLen = 0, bestNewDist = 0, bestNewValue = -0x40000000;
        uint h = Hash(data, pos);
        int cand = head[h];
        int walk = 0;
        while (cand >= 0 && walk < MaxChainWalk)
        {
            int dist = pos - cand;
            if (dist >= MinDistance)
            {
                int len = MatchLength(data, cand, pos, matchLimit);
                if (len >= effMml)
                {
                    int val = len * 4 - (BitLen((uint)dist) + 2);
                    if (val > bestNewValue)
                    {
                        bestNewValue = val;
                        bestNewLen = len;
                        bestNewDist = dist;
                    }
                }
            }
            cand = prev[cand];
            walk++;
        }

        bool repViable = bestRepLen >= MinRepMatch;
        bool newViable = bestNewLen >= effMml;
        int repValue = repViable ? bestRepLen * 4 : -0x40000000;
        int newValue = newViable ? bestNewValue : -0x40000000;
        if (!repViable && !newViable)
            return new Cand(0, 0, -1);
        // Repeat reuse wins ties (its offset is free and seeds future cheap reps).
        if (repValue >= newValue)
            return new Cand(bestRepLen, bestRepIdx == 0 ? r0 : bestRepIdx == 1 ? r1 : r2, bestRepIdx);
        return new Cand(bestNewLen, bestNewDist, 3);
    }

    // ===========================================================================================
    // GREEDY SELECTOR — implementation of the per-position match heuristic and its decision
    // helpers. Replaces the value-model FindMatch when UseExactGreedy is set so Tally(the greedy
    // parse) == Tally(the greedy selector). The 2-step lazy main loop (Parse) is unchanged; only
    // the per-position selector it calls switches.
    // ===========================================================================================

    // algorithm short-match offset thresholds [ml]: a new match of length ml &lt; 6 is
    // allowed only when off &lt; threshold[ml]. ml is always &gt;= 3 (the asserted minimum).
    private static readonly int[] NormalMatchOffsetThreshold = { 0, 0, 0, 0x4000, 0x20000, 0x100000 };

    /// <summary>
    /// Exact greedy per-position selector used when <see cref="UseExactGreedy"/> is enabled.
    /// It searches repeat offsets first, then scans the four-pair Pareto new-match frontier through <see cref="IsAllowedNormalMatch"/> and <see cref="IsNormalMatchBetter"/>, and finally chooses between repeat and new matches with <see cref="TakeNewOverRep"/>.
    /// </summary>
    private static Cand FindMatchExact(ReadOnlySpan<byte> data, int pos, int[] head, int[] prev,
        int matchLimit, int r0, int r1, int r2, int lrl)
    {
        // Rep search over the three recent distances (loi 0,1,2). Strict '<' ⇒ the lowest loi wins ties.
        int rl0 = RepExtendMml2(data, pos, r0, matchLimit);
        int rl1 = RepExtendMml2(data, pos, r1, matchLimit);
        int rl2 = RepExtendMml2(data, pos, r2, matchLimit);
        int bestRepLen = -1, bestRepIdx = -1;
        if (bestRepLen < rl0) { bestRepLen = rl0; bestRepIdx = 0; }
        if (bestRepLen < rl1) { bestRepLen = rl1; bestRepIdx = 1; }
        if (bestRepLen < rl2) { bestRepLen = rl2; bestRepIdx = 2; }

        // A rep of length >= 4 short-circuits: the selector returns it immediately with no new-match search.
        if (bestRepLen >= 4)
            return new Cand(bestRepLen, bestRepIdx == 0 ? r0 : bestRepIdx == 1 ? r1 : r2, bestRepIdx);

        int mml = GreedyMmlOverride > 0 ? GreedyMmlOverride : MinMatch;
        if (lrl > 0x37)
        {
            if (bestRepLen < 3) bestRepLen = 0; // a short (len-2) rep is dropped after a long literal run
            mml += 1;
        }

        // New-match candidates = the 4-pair Pareto frontier (length-descending) fed by the
        // suffix-trie match finder. No synthetic off-8 candidate is included; the selector reads
        // only matchTable[0..3].
        Span<int> cl = stackalloc int[4];
        Span<int> co = stackalloc int[4];
        int np = FindParetoPairs(data, pos, head, prev, matchLimit, cl, co);
        int bestNewLen = 0, bestNewOff = 0;
        for (int i = 0; i < np; i++)
        {
            int ml = cl[i], off = co[i];
            if (ml < mml) break; // length-descending ⇒ every later pair is shorter still
            int useLen = ml, useOff = off;
            if (UseTinyOffsetRemap && off < MinDistance)
            {
                // A sub-8 distance is rounded up to a codeable one, the match length is
                // recomputed at the rounded distance, and the candidate is kept only if it still reaches mml.
                int rounded = RoundUpTiny(off);
                if (rounded == 0 || rounded > pos) continue;     // <= absPos (valid backref) else skip
                int rlen = MatchLength(data, pos - rounded, pos, matchLimit);
                if (rlen < mml) continue;                        // <= recomputed len else skip
                useLen = rlen;
                useOff = rounded;
            }
            if (IsAllowedNormalMatch(useLen, useOff) && IsNormalMatchBetter(useLen, useOff, bestNewLen, bestNewOff))
            {
                bestNewLen = useLen;
                bestNewOff = useOff;
            }
        }

        // Final pick: keep the rep unless the new match is clearly longer. When the rep is
        // kept its length is >= 2 (TakeNewOverRep returns false only for repLen >= 2), so bestRepIdx is valid.
        if (!TakeNewOverRep(bestRepLen, bestNewLen, bestNewOff))
            return new Cand(bestRepLen, bestRepIdx == 0 ? r0 : bestRepIdx == 1 ? r1 : r2, bestRepIdx);
        return bestNewLen > 0 ? new Cand(bestNewLen, bestNewOff, 3) : new Cand(0, 0, -1);
    }

    /// <summary>
    /// Reproduces the suffix-trie match output: the per-position Pareto frontier (closest
    /// offset per achievable length), capped to the 4 longest pairs, length-descending. Walks the full-history
    /// 4-byte hash chain most-recent-first (distance ascending) and records (len,dist) only when len exceeds
    /// the running best. This is the same walk <see cref="FindCandidates"/> uses for the DP, minus the
    /// synthetic off-8 append the greedy selector must not see.
    /// </summary>
    private static int FindParetoPairs(ReadOnlySpan<byte> data, int pos, int[] head, int[] prev,
        int matchLimit, Span<int> outLen, Span<int> outDist)
    {
        int recordMmlEx = GreedyMmlOverride > 0 ? GreedyMmlOverride : MinMatch;
        // Rolling buffer of the 4 LONGEST Pareto records. The suffix-trie matcher (num_firstbytes=2) records the
        // closest match of EVERY achievable length; on staircase/periodic data there can be thousands of them, so
        // a fixed record buffer would truncate to the SHORTEST few. Because Pareto records are length-monotonic
        // (distance ascending ⇒ length strictly increasing), keeping only the most recent 4 yields the 4 globally
        // longest — matching find_all_matches num_pairs==4 without an entry cap.
        Span<int> fl = stackalloc int[4];
        Span<int> fd = stackalloc int[4];
        int fn = 0; // entries currently held (0..4), ascending length
        int bestLen = 0;
        int distFloor = UseTinyOffsetRemap ? 1 : MinDistance; // include dist 1..7 so the selector can round them up
        // the suffix-trie matcher (num_firstbytes=2) records the closest match of EVERY achievable length down to
        // its minimum, and a single such table is shared by all three greedy pre-passes (mml 4/3/8). The
        // mml=3 pass therefore sees length-3 NEW matches the mml=4/8 passes filter out. Mirror that by
        // recording down to the pass's effective mml (3 when GreedyMmlOverride==3) rather than the constant
        // MinMatch. Production (GreedyMmlOverride==0) is unchanged: it still gates at MinMatch (4).
        int recordMml = GreedyMmlOverride > 0 ? GreedyMmlOverride : MinMatch;
        int chunkEnd = matchLimit + LiteralTail; // rank by the TRUE (uncapped-to-chunk) length, like the trie
        uint hs = Hash(data, pos);
        int c = head[hs];
        int maxLen = chunkEnd - pos; // the longest match physically possible at this position
        while (c >= 0)
        {
            int dist = pos - c;
            if (dist >= distFloor)
            {
                int len = MatchLength(data, c, pos, chunkEnd);
                if (len > bestLen)
                {
                    bestLen = len;
                    if (len >= recordMml)
                    {
                        if (fn < 4) { fl[fn] = len; fd[fn] = dist; fn++; }
                        else { fl[0] = fl[1]; fl[1] = fl[2]; fl[2] = fl[3]; fl[3] = len; fd[0] = fd[1]; fd[1] = fd[2]; fd[2] = fd[3]; fd[3] = dist; }
                    }
                    // A match reaching the chunk end is the longest possible here; since the walk is
                    // most-recent-first (closest first), no earlier candidate can be strictly longer. Stop.
                    // Bounds this greedy match-finder on long-run inputs (otherwise a single hash chain is O(n^2)).
                    if (bestLen >= maxLen) break;
                }
            }
            c = prev[c];
        }
        int keep = fn; // already capped at 4
        int tailEmit = -1; // capped length shared by tail-overrunning matches (fill longest-uncapped first)
        int outN = 0;
        for (int i = 0; i < keep; i++)
        {
            int idx = keep - 1 - i; // ascending buffer → longest first
            int clen = fl[idx], cdst = fd[idx];
            // Sub-8 distances are left raw here (FindMatchExact rounds them up itself). Only codeable
            // distances get the tail cap: a match may extend only to matchLimit (LiteralTail trailing
            // literals reserved). The trie ranked by FULL length, so a long periodic match that overruns
            // the tail keeps its farthest, longest-UNCAPPED distance — closer distances that collapse to the
            // same capped tail end are dropped. This is the greedy analog of FindCandidates' tail collapse
            // and makes a block-start periodic tail choose d=65536 (period) over d=65528.
            // Inputs without a tail-overrunning periodic match keep the legacy matchLimit-walk behavior.
            if (cdst >= MinDistance && clen > matchLimit - pos)
            {
                clen = matchLimit - pos;
                if (clen < recordMml) continue;
                if (clen == tailEmit) continue; // collapsed into an already-emitted longer-uncapped tail
                tailEmit = clen;
            }
            outLen[outN] = clen;
            outDist[outN] = cdst;
            outN++;
        }
        return outN;
    }

    /// <summary>
    /// Rep-match length with the mml2 quantization:0 for fewer than 2 matching leading
    /// bytes, exactly 2 or 3 for a 2- or 3-byte lead, or the full forward length for a 4+-byte lead. The raw
    /// count already yields 2/3/full for those cases; only a raw count of 1 must be clamped to 0 (a rep is
    /// never length 1).
    /// </summary>
    private static int RepExtendMml2(ReadOnlySpan<byte> data, int pos, int dist, int limit)
    {
        int rl = RepMatchLength(data, pos, dist, limit);
        return rl < 2 ? 0 : rl;
    }

    /// <summary>
    /// New-match comparator used by the exact greedy selector.
    /// Longer matches win, equal lengths prefer the closer offset, and a one-byte length gain must stay within the configured offset growth bound.
    /// </summary>
    private static bool IsNormalMatchBetter(int newml, int newoff, int bestml, int bestoff)
    {
        if (newml < bestml) return false;
        if (newml == bestml) return newoff < bestoff;
        if (newml >= bestml + 2) return true;
        return (newoff >> 7) <= bestoff; // newml == bestml + 1
    }

    /// <summary>
    /// Returns whether a new-offset match should replace the best repeat-offset match.
    /// Repeat matches are favored unless the new match is sufficiently longer for its offset range; repeat lengths below two always lose.
    /// </summary>
    private static bool TakeNewOverRep(int repLen, int newLen, int newOff)
    {
        if (repLen < 2) return true;
        if (newLen < repLen + 2) return false;
        if (newLen < repLen + 3 && newOff >= 0x400) return false;
        if (newLen < repLen + 4 && newOff >= 0x10000) return false;
        return true;
    }

    /// <summary>
    /// Returns whether a new-offset match is allowed by the short-match offset ceiling.
    /// Lengths below six use <see cref="NormalMatchOffsetThreshold"/>; lengths six and above are always allowed in the supported window size.
    /// </summary>
    private static bool IsAllowedNormalMatch(int ml, int off)
    {
        if (ml < 6) return off < NormalMatchOffsetThreshold[ml];
        return true;
    }

    /// <summary>Inserts every position in <c>[inserted, target)</c> into the hash chain, in order.</summary>
    private static int InsertUpTo(ReadOnlySpan<byte> data, int[] head, int[] prev, int inserted, int target)
    {
        while (inserted < target)
        {
            Insert(data, inserted, head, prev);
            inserted++;
        }
        return inserted;
    }

    /// <summary>
    /// Applies the decoder's recent-offset move-to-front update for the chosen offset index. Index
    /// 0/1/2 promotes that recent distance to the front; index 3 pushes a brand-new distance to the
    /// front and evicts the oldest. This exactly mirrors the <c>recent[]</c> shuffle in
    /// <see cref="KrakenDecoder"/>'s LZ-run loop.
    /// </summary>
    private static void UpdateRecent(ref int r0, ref int r1, ref int r2, int idx, int dist)
    {
        switch (idx)
        {
            case 0:
                break; // [r0, r1, r2] unchanged
            case 1:
                (r0, r1) = (r1, r0); // [r1, r0, r2]
                break;
            case 2:
                { int t = r2; r2 = r1; r1 = r0; r0 = t; } // [r2, r0, r1]
                break;
            default:
                r2 = r1; r1 = r0; r0 = dist; // new offset:[dist, r0, r1]
                break;
        }
    }

    /// <summary>
    /// Length of a repeat-offset match at <paramref name="dist"/> bytes back from <paramref name="pos"/>,
    /// capped so the match ends at or before <paramref name="limit"/>. Returns 0 when the source would
    /// fall before the start of the buffer.
    /// </summary>
    private static int RepMatchLength(ReadOnlySpan<byte> data, int pos, int dist, int limit)
    {
        int src = pos - dist;
        if (src < 0)
            return 0;
        int len = 0;
        int max = limit - pos;
        while (len < max && data[src + len] == data[pos + len])
            len++;
        return len;
    }

    private static void Insert(ReadOnlySpan<byte> data, int pos, int[] head, int[] prev)
    {
        uint h = Hash(data, pos);
        prev[pos] = head[h];
        head[h] = pos;
    }

    private static uint Hash(ReadOnlySpan<byte> data, int pos)
    {
        // The mml=3 greedy pre-pass needs length-3 matches, so positions that share only 3 bytes must
        // collide; a 3-byte hash makes them. The 4-byte hash is the production default.
        if (GreedyHashBytesOverride == 3)
        {
            uint x3 = (uint)(data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16));
            return (x3 * 506832829u) >> (32 - HashBits);
        }
        uint x = (uint)(data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24));
        return (x * 2654435761u) >> (32 - HashBits);
    }

    private static int MatchLength(ReadOnlySpan<byte> data, int a, int b, int limit)
    {
        int len = 0;
        int max = limit - b;
        while (len < max && data[a + len] == data[b + len])
            len++;
        return len;
    }

    // ===========================================================================================
    // Optimal3 (Kraken level-7) forward cost DP. Opt-in: the production default remains the
    // value-model greedy Parse; when UseOptimalParse is set, EncodeChunk routes here.
    // KrakenOptimalCost supplies the integer cost model consumed by the DP.
    // ===========================================================================================

    /// <summary>
    /// When true, <see cref="EncodeChunk"/> uses <see cref="ParseOptimal"/> instead of the greedy <see cref="Parse"/> path.
    /// Default false keeps the production encode path on the greedy parser unless a caller explicitly enables the optimal parse.
    /// </summary>
    internal static bool UseOptimalParse;

    /// <summary>
    /// When true, eligible single-chunk blocks may use the multi-candidate optimal parse instead of always using the greedy parser.
    /// Default true lets standalone blocks choose the smallest emitted candidate while multi-chunk blocks keep the shared-chain greedy path.
    /// </summary>
    internal static bool ProductionOptimalSingleChunk = true;

    /// <summary>
    /// Maximum single-chunk block size, in bytes, allowed to use the monolithic Optimal3 DP.
    /// Default <c>0x1000</c> limits that quadratic parse to small standalone blocks; larger eligible blocks use the greedy or windowed path.
    /// </summary>
    internal static int ProductionOptimalMaxBlock = 0x1000;

    /// <summary>
    /// When true, single-chunk blocks larger than <see cref="ProductionOptimalMaxBlock"/> and not larger than <see cref="ProductionOptimalWindowedMaxBlock"/> may use the windowed Optimal3 DP.
    /// Default true allows large standalone blocks to try the near-linear windowed parse and still select the smaller emitted result against greedy.
    /// </summary>
    internal static bool ProductionWindowedOptimal = true;

    /// <summary>
    /// Maximum single-chunk block size, in bytes, allowed to use the windowed Optimal3 DP.
    /// Default <c>0x40000</c> covers a full PFSC block, so every single-chunk block above <see cref="ProductionOptimalMaxBlock"/> is eligible.
    /// </summary>
    internal static int ProductionOptimalWindowedMaxBlock = 0x40000;

    /// <summary>
    /// With <see cref="UseSuffixTrieFinder"/> disabled, true makes <see cref="ForwardDp"/> collect candidates from the bounded two-row <see cref="Ctmf"/> cache instead of only walking the hash chain.
    /// Default true configures the CTMF path for diagnostic runs; the default suffix-trie path bypasses it.
    /// </summary>
    internal static bool UseCtmfFinder = true;

    /// <summary>
    /// Overrides the number of ways per CTMF row when nonzero; zero uses the built-in 16-way row depth.
    /// Default <c>0</c> keeps the standard CTMF row depth.
    /// </summary>
    internal static int CtmfWaysOverride = 0;

    /// <summary>
    /// When true on the CTMF path, <see cref="ForwardDp"/> unions CTMF candidates with the hash-chain candidates at the same position.
    /// Default false keeps the CTMF candidate set bounded unless <see cref="UseLrmSupplement"/> contributes strictly longer matches.
    /// </summary>
    internal static bool UseChainUnion = false;

    /// <summary>
    /// When true on the CTMF path, the hash chain supplements CTMF candidates only with matches longer than the best CTMF match at that position.
    /// Default false leaves CTMF results unsupplemented unless full union is enabled by <see cref="UseChainUnion"/>.
    /// </summary>
    internal static bool UseLrmSupplement = false;

    /// <summary>
    /// When true, <see cref="ForwardDp"/> uses a full-history Pareto candidate walk that keeps up to four longest length-improving matches per position.
    /// Default true makes <see cref="UseOptimalParse"/> use that full-history finder instead of the bounded CTMF path.
    /// </summary>
    internal static bool UseSuffixTrieFinder = true;

    /// <summary>
    /// When true, the CTMF query skips row A and uses only row B.
    /// Default false queries both CTMF rows.
    /// </summary>
    internal static bool CtmfRowAOff = false;

    /// <summary>
    /// Overrides the CTMF table-bit count when greater than zero; zero computes the bit count from the input size.
    /// Default <c>0</c> uses automatic CTMF sizing.
    /// </summary>
    internal static int CtmfBitsOverride = 0;

    /// <summary>
    /// Thread-local greedy minimum-match override; zero uses <see cref="MinMatch"/>.
    /// Default <c>0</c> keeps the normal greedy minimum of four bytes unless a pre-pass sets another value.
    /// </summary>
    [ThreadStatic] internal static int GreedyMmlOverride;

    /// <summary>
    /// Thread-local override for the greedy hash width; zero uses the normal four-byte hash in <see cref="Hash"/>.
    /// Default <c>0</c> keeps the standard hash, while selected short-match passes set three-byte hashing so <see cref="MatchLength"/> can verify length-three candidates.
    /// </summary>
    [ThreadStatic] internal static int GreedyHashBytesOverride;

    /// <summary>
    /// When true with <see cref="UseOptimalParse"/>, match relaxation also evaluates an immediate rep0 continuation through <see cref="Faef0"/>.
    /// Default true lets the DP propagate that bundled continuation; disabling it restricts arrivals to the primary match only.
    /// </summary>
    internal static bool UseFaef0 = true;

    /// <summary>
    /// When true, the greedy <see cref="Parse"/> path uses <see cref="FindMatchExact"/> instead of the value-model <see cref="FindMatch"/> selector.
    /// Default false keeps production greedy parsing on the existing value-model selector unless a diagnostic or optimal pre-pass enables it.
    /// </summary>
    [ThreadStatic] internal static bool UseExactGreedy;

    /// <summary>
    /// When true, the greedy seed histogram is passed through <see cref="DecaySeedPassinfo"/> before code-cost tables are built for a single DP pass.
    /// Default false leaves the seed histogram unchanged except in code paths that apply decay directly.
    /// </summary>
    [ThreadStatic] internal static bool UseSeedDecay;

    /// <summary>
    /// When true, <see cref="ForwardDp"/> builds and queries the DP candidate chain with a three-byte minimum-match configuration.
    /// Default false keeps DP candidate discovery on the normal four-byte minimum-match path.
    /// </summary>
    [ThreadStatic] internal static bool UseDpMml3;

    /// <summary>
    /// Minimum match length used by the optional three-byte DP candidate path.
    /// The constant value is <c>3</c>.
    /// </summary>
    private const int DpMml3 = 3;

    /// <summary>
    /// When true, <see cref="ForwardDp"/> fills sublength arrivals only when <see cref="SublenFillAllowed"/> accepts the match length window.
    /// Default false preserves unconditional sublength filling in the production path.
    /// </summary>
    [ThreadStatic] internal static bool UseSublenGate;

    /// <summary>
    /// When true, the LRL-source loop stops after a relaxed match at the position reaches the optimal-skip length.
    /// Default true prevents additional source arrivals at that position; disabling it relaxes every LRL source.
    /// </summary>
    internal static bool UseLrlExitGate = true;

    /// <summary>
    /// When true, a parse position whose longest relaxed match reaches the optimal-skip length advances directly to that match frontier.
    /// Default true skips intermediate parse positions inside the long match; disabling it scans every position.
    /// </summary>
    internal static bool UseLongMatchSkip = true;

    /// <summary>
    /// When true, a windowed re-anchor accepts an equal-cost committed arrival by using <c>&lt;=</c> instead of strict <c>&lt;</c>.
    /// Default false keeps strict improvement as the re-anchor condition.
    /// </summary>
    internal static bool UseReanchorTie;

    /// <summary>
    /// When true, repeat-offset relaxations that do not extend past the current DP frontier are suppressed.
    /// Default false allows those repeat relaxations to be considered.
    /// </summary>
    internal static bool UseRepFrontierGate;

    /// <summary>
    /// High bound used by the sublength-fill gate at level 7.
    /// The constant value is <c>128</c>.
    /// </summary>
    private const int SublenFillThreshold = 128;

    /// <summary>
    /// The sublen-fill predicate: fill is allowed iff <c>(uint)(len − lo) &lt; range</c>
    /// (cfg <c>{lo, range}</c> from the helper-style <c>{A, B−A}</c>). Unsigned compare folds
    /// the lower bound (<c>len &lt; lo</c> underflows to a huge value ⇒ false) into a single branch.
    /// </summary>
    private static bool SublenFillAllowed(int lo, int range, int len) => (uint)(len - lo) < (uint)range;

    /// <summary>
    /// When true, equal-cost writes in <see cref="RelaxRep"/> and <see cref="RelaxNew"/> replace the existing arrival.
    /// Default false keeps the first equal-cost arrival and only replaces it on a strictly lower cost.
    /// </summary>
    [ThreadStatic] internal static bool UseTieBreakLast;

    /// <summary>
    /// When true, <see cref="ForwardDp"/> runs the adaptive windowed optimal parse instead of one monolithic full-chunk DP pass.
    /// Default false keeps the classic single-pass DP unless production block selection enables the windowed path.
    /// </summary>
    [ThreadStatic] internal static bool UseWindowedParse;


    /// <summary>
    /// When true, long new-match relaxations that do not extend past <see cref="DpMaxReached"/> are suppressed.
    /// Default false leaves frontier suppression disabled until a windowed parse path enables it.
    /// </summary>
    [ThreadStatic] internal static bool UseFrontierGate;

    /// <summary>
    /// Furthest position reached by any relaxation in the current windowed DP segment.
    /// Default thread-local value <c>0</c> is updated only while <see cref="UseWindowedParse"/> is active.
    /// </summary>
    [ThreadStatic] internal static int DpMaxReached;

    /// <summary>
    /// Commit stride, in bytes, used by the windowed parse.
    /// The constant value is <c>0x100</c>.
    /// </summary>
    private const int WindowCommitStride = 0x100;

    /// <summary>
    /// Maximum lookahead, in bytes, for a windowed parse segment before an overflow commit is forced.
    /// The constant value is <c>0x1000</c>.
    /// </summary>
    private const int WindowLookahead = 0x1000;

    /// <summary>
    /// When true, sub-<see cref="MinDistance"/> new-match candidates are rounded up with <see cref="RoundUpTiny"/> and rechecked before normal candidate gates run.
    /// Default false leaves tiny-distance candidates unavailable to the production path.
    /// </summary>
    [ThreadStatic] internal static bool UseTinyOffsetRemap;

    /// <summary>
    /// Lookup table used by <see cref="RoundUpTiny"/> to map distances 1..7 to offset44-codeable distances that preserve the period.
    /// Index <c>0</c> is unused.
    /// </summary>
    private static readonly int[] RoundUpTinyTable = { 0, 8, 8, 9, 8, 10, 12, 14 };

    /// <summary>Rounds a tiny distance (1..7) up to its offset44-codeable equivalent via <see cref="RoundUpTinyTable"/>.</summary>
    private static int RoundUpTiny(int dist) => RoundUpTinyTable[dist];

    /// <summary>A forward-DP arrival: the cheapest way to reach a buffer position (the 0x28-byte record).</summary>
    private struct Arrival
    {
        public int Cost;          // 0x7fffffff = unreached
        public int R0, R1, R2;    // the three recent offsets at this arrival
        public int Ml, Lrl, Src;  // command that produced it: Lrl literals at Src, then a match of Ml
        public int Idx, Dist;     // OffsIndex (0/1/2 rep, 3 new) and the chosen distance
        public int ContLrl, ContMl; // field [6]: a free rep0 continuation bundled into this arrival
                                    // (ContLrl literals then a rep0 match of ContMl at distance R0); 0 = none
    }

    /// <summary>
    /// Optimal3 level-7 parse selection. Runs greedy pre-passes at mml 4, 3, and 8, then one DP pass
    /// seeded from the best greedy histogram after seed decay. The final parse is the candidate with the
    /// smallest real entropy-coded emit size rather than the integer DP cost proxy.
    /// </summary>
    private static List<Command> ParseOptimal(ReadOnlySpan<byte> data, int[] head, int[] prev,
        int startPos, int litStart0, int matchLimit, int matchStartLimit,
        int chunkStart, int chunkEnd, bool withSeed, bool useHuffmanArrays)
    {
        // Real entropy-coded emit size of a candidate parse (the shipping back-end, litMode=1 raw). A parse
        // that falls back to store-raw (null) scores int.MaxValue so it is never selected over a valid one.
        int RealEmit(ReadOnlySpan<byte> d, List<Command> cand)
        {
            if (cand.Count == 0) return int.MaxValue;
            byte[]? b = EmitChunkFromCommands(d, cand, chunkStart, chunkEnd, withSeed, useHuffmanArrays, litMode: 1);
            return b?.Length ?? int.MaxValue;
        }

        // One greedy pre-pass at the given minimum-match length / hash width, on a PRIVATE causal chain
        // (Parse advances whatever chain it is given, so each pre-pass needs its own). The mml=3 pass uses a
        // 3-byte hash so positions sharing only three bytes collide and length-3 matches become visible —
        // exactly the greedy pre-pass configuration.
        List<Command> Greedy(ReadOnlySpan<byte> d, int mml, int hashBytes)
        {
            int sMml = GreedyMmlOverride, sHb = GreedyHashBytesOverride; bool sEx = UseExactGreedy, sTiny = UseTinyOffsetRemap;
            GreedyMmlOverride = mml; GreedyHashBytesOverride = hashBytes; UseExactGreedy = true; UseTinyOffsetRemap = true;
            try
            {
                var h = new int[HashSize]; h.AsSpan().Fill(-1);
                var pv = new int[d.Length]; pv.AsSpan().Fill(-1);
                // Index the full pre-chunk history [0, startPos) — not just [chunkStart, startPos) — so a
                // second chunk's parse can back-reference the first chunk (cross-chunk matches), matching the
                // shared-chain greedy. For a first/single chunk chunkStart==0 so this is unchanged.
                for (int p = 0; p < startPos; p++) Insert(d, p, h, pv);
                return Parse(d, h, pv, startPos, litStart0, matchLimit, matchStartLimit);
            }
            finally { GreedyMmlOverride = sMml; GreedyHashBytesOverride = sHb; UseExactGreedy = sEx; UseTinyOffsetRemap = sTiny; }
        }

        var g4 = Greedy(data, 4, 0);
        if (g4.Count == 0)
            return g4; // no legal parse (store-raw handled upstream)

        var best = g4;
        int bestEmit = RealEmit(data, g4);
        foreach (var g in new[] { Greedy(data, 3, 3), Greedy(data, 8, 0) })
        {
            int e = RealEmit(data, g);
            if (e < bestEmit) { bestEmit = e; best = g; }
        }
        var bestGreedy = best;

        // ONE DP pass seeded from the best greedy's histogram, decayed per 256-entry region
        // (table[i] = (table[i] >> 4) + 1). The DP's cost model is this
        // decayed histogram; its output competes with the best greedy purely on real emit size.
        var dpHead = new int[HashSize];
        var dpPrev = new int[data.Length];
        int seedLitMode = LitModeForParse(data, bestGreedy, chunkEnd, useHuffmanArrays);
        // Seed passinfo tallies the best greedy with inc=1. The windowed re-tally accumulates
        // with a separate increment (see ForwardDp).
        int[] passinfo = Tally(bestGreedy, data, startPos, 1);
        DecaySeedPassinfo(passinfo);
        var cc = KrakenOptimalCost.BuildFromPassinfo(passinfo, seedLitMode);
        // When the adaptive windowed parse is enabled, thread the (decayed) seed passinfo + its lit mode into
        // the DP: it re-tallies each committed 256-stride segment onto this cumulative passinfo and rebuilds
        // the cost tables per commit. Null (default) ⇒ the classic single monolithic pass runs unchanged.
        int[]? adapt = UseWindowedParse ? passinfo : null;
        var dp = ForwardDp(data, dpHead, dpPrev, startPos, matchLimit, matchStartLimit, cc, adapt, seedLitMode);
        int dpEmit = RealEmit(data, dp);
        if (dpEmit < bestEmit) { best = dp; }

        return best;
    }

    /// <summary>
    /// Total cost (bits×32) of a command list under <paramref name="cc"/>, accumulated exactly as the
    /// forward DP accumulates an arrival (literal run + LRL escape + rep/new match) plus the trailing
    /// literal run to <paramref name="chunkEnd"/>. Used to pick the cheapest parse across passes.
    /// </summary>
    private static long CostOfParse(List<Command> cmds, ReadOnlySpan<byte> data, int start, int chunkEnd,
        KrakenOptimalCost.CodeCosts cc)
    {
        long cost = 0;
        int r0 = MinDistance, r1 = MinDistance, r2 = MinDistance;
        int endPos = start;
        foreach (var c in cmds)
        {
            int lo = r0 < MinDistance ? MinDistance : r0;
            cost += KrakenOptimalCost.CostLiterals(data, c.LitStart, c.LitLen, lo, cc);
            int litField = c.LitLen < 3 ? c.LitLen : 3;
            if (c.LitLen > 2) cost += KrakenOptimalCost.CostLen(cc, c.LitLen - 3);
            if (c.OffsIndex < 3)
                cost += KrakenOptimalCost.CostLoMatch(cc, litField, c.MatchLen, c.OffsIndex);
            else
                cost += KrakenOptimalCost.CostOffset(c.Distance, cc) +
                        KrakenOptimalCost.CostNormalMatch(cc, litField, c.MatchLen);
            UpdateRecent(ref r0, ref r1, ref r2, c.OffsIndex, c.Distance);
            endPos = c.LitStart + c.LitLen + c.MatchLen;
        }
        int tlo = r0 < MinDistance ? MinDistance : r0;
        cost += KrakenOptimalCost.CostLiterals(data, endPos, chunkEnd - endPos, tlo, cc);
        return cost;
    }

    /// <summary>
    /// Applies per-region decay to seed passinfo before a DP pass builds its code-cost tables.
    /// Each 256-entry histogram region is transformed with <c>(count &gt;&gt; 4) + SeedDecayBase</c>, while the offset-alt modulo scalar at index <c>0x400</c> is preserved.
    /// </summary>
    internal static void DecaySeedPassinfo(int[] pi)
    {
        int b = SeedDecayBase;
        void Decay(int[] p, int start, int bias, bool blend)
        {
            for (int i = 0; i < 0x100; i++) p[start + i] = (p[start + i] >> 4) + b;
        }
        Decay(pi, 0x000, 0x00, blend: true);  // literals raw
        Decay(pi, 0x100, 0x00, blend: true);  // literals sub
        Decay(pi, 0x401, 0x24, blend: true);  // offset bucket
        if (pi[0x400] > 1)
            Decay(pi, 0x501, 0x00, blend: true); // offset alt (only when modulo > 1)
        Decay(pi, 0x200, 0x12, blend: true);  // packet
        Decay(pi, 0x300, 0x0c, blend: true);  // length
    }

    /// <summary>
    /// Thread-local override for the uniform base added by <see cref="SeedDecayBase"/> after seed histogram decay; zero uses the property default.
    /// Default <c>0</c> leaves <see cref="DecaySeedPassinfo"/> using the built-in seed-decay base.
    /// </summary>
    [ThreadStatic] internal static int SeedDecayBaseOverride;
    internal static int SeedDecayBase => SeedDecayBaseOverride != 0 ? SeedDecayBaseOverride : 1;

    private static int[] Tally(List<Command> commands, ReadOnlySpan<byte> data, int start, int inc = 2, int chunkEnd = -1)
    {
        int r0 = MinDistance, r1 = MinDistance, r2 = MinDistance;
        return TallyRecents(commands, data, start, inc, chunkEnd, ref r0, ref r1, ref r2);
    }

    /// <summary>
    /// Tally variant that threads recent-offset state in and out across committed windows.
    /// Threading keeps the sub-literal histogram based on the carried recent offset instead of resetting to the initial offsets for each window.
    /// </summary>
    private static int[] TallyRecents(List<Command> commands, ReadOnlySpan<byte> data, int start, int inc,
        int chunkEnd, ref int r0, ref int r1, ref int r2)
    {
        var pi = new int[0x601];
        int lastEnd = start;
        foreach (var cmd in commands)
        {
            int p = cmd.LitStart;
            for (int i = 0; i < cmd.LitLen; i++)
            {
                int b = data[p + i];
                pi[b] += inc;
                int refIdx = p + i - r0;
                int refb = refIdx >= 0 ? data[refIdx] : 0;
                pi[0x100 + ((b - refb) & 0xff)] += inc;
            }
            if (cmd.LitLen >= 3)
                pi[0x300 + Math.Min(cmd.LitLen - 3, 0xff)] += inc;

            int litField = cmd.LitLen < 3 ? cmd.LitLen : 3;
            int ml = cmd.MatchLen;
            bool isRep = cmd.OffsIndex < 3;
            int matchByte = ml < 0x11 ? ml - 2 : 0xf;
            int off3 = isRep ? cmd.OffsIndex * 0x40 : 0xc0;
            pi[0x200 + litField + matchByte * 4 + off3] += inc;
            if (ml >= 0x11)
                pi[0x300 + Math.Min(ml - 0x11, 0xff)] += inc;
            if (!isRep)
                pi[0x401 + KrakenOptimalCost.OffsetBucketByte(cmd.Distance, out _)] += inc;

            UpdateRecent(ref r0, ref r1, ref r2, cmd.OffsIndex, cmd.Distance);
            lastEnd = cmd.LitStart + cmd.LitLen + cmd.MatchLen;
        }
        // Greedy SEED only (chunkEnd >= 0): the trailing literals after the last match (to chunk end)
        // are tallied into the literal histograms only (no packet/length/offset event). Seed passinfo
        // is built this way; the DP re-tally (inc=2, chunkEnd=-1) does not add a tail.
        if (chunkEnd > lastEnd)
        {
            for (int p = lastEnd; p < chunkEnd; p++)
            {
                int b = data[p];
                pi[b] += inc;
                int refIdx = p - r0;
                int refb = refIdx >= 0 ? data[refIdx] : 0;
                pi[0x100 + ((b - refb) & 0xff)] += inc;
            }
        }
        return pi;
    }

    /// <summary>
    /// One forward-DP pass (the single-TLL algorithm). Fills the arrival table left to right
    /// with the anchor/accumulated-literal bookkeeping, the lrl loop (0..3, the 4th = the full run from
    /// the anchor), rep relaxation (longest-first gating) and new-match relaxation (new-minimum-base gate,
    /// length-desc candidates, break once a candidate is no longer than the longest rep), then backtraces
    /// the cheapest reachable arrival plus its trailing literals into a command list.
    /// </summary>
    private static List<Command> ForwardDp(ReadOnlySpan<byte> data, int[] dpHead, int[] dpPrev,
        int startPos, int matchLimit, int matchStartLimit, KrakenOptimalCost.CodeCosts cc,
        int[]? adaptPassinfo = null, int adaptLitMode = 1)
    {
        // Level-7 suffix-trie match finder mml=3 (firstbytes=2): build the DP chain AND its
        // candidate query with a 3-byte hash so positions sharing only 3 bytes collide and length-3 matches
        // become visible. Restored in finally so the thread-static never leaks past the DP.
        int saveDpHb = GreedyHashBytesOverride;
        if (UseDpMml3) GreedyHashBytesOverride = DpMml3;
        try
        {
            int chunkEnd = matchLimit + LiteralTail;
            int maxArr = matchLimit; // a match can end at most here
            var arr = new Arrival[maxArr + 1];
            for (int i = 0; i <= maxArr; i++) arr[i].Cost = int.MaxValue;
            arr[startPos] = new Arrival
            {
                Cost = 0,
                R0 = MinDistance,
                R1 = MinDistance,
                R2 = MinDistance,
                Src = startPos,
                Idx = -1,
            };

            // Seed-index the private chain with the chunk's seed bytes [startPos-LiteralTail, startPos) so the
            // DP can find matches that reference the 8-byte COPY_64 seed (e.g. a match that backward-extends
            // into the seed). EncodeChunk indexes these into the shared greedy chain; the DP's private chain
            // must mirror that or it underfinds the very first backward-extended match.
            dpHead.AsSpan().Fill(-1);
            // Index the full pre-chunk history [0, startPos): for a first/single chunk this is the seed
            // region [0,8); for a second chunk it is the entire first chunk, so the DP finds cross-chunk
            // back-matches (the private chain must mirror the shared greedy chain, or chunk1 underfinds).
            int inserted = 0;

            // Cache-table finder bits N = clamp(ceil_log2(len), 18, 24). Even tiny buffers use
            // N=18 (a 2^18 zero-init table), so the 16-way windows plus check bits have the same
            // layout regardless of input size.
            int ctmfBits;
            {
                int len = data.Length < 1 ? 1 : data.Length;
                int cl = 0;
                while (cl < 24 && (1 << cl) < len) cl++; // ceil_log2(len), capped (no overflow)
                ctmfBits = cl < 18 ? 18 : cl;
            }
            if (CtmfBitsOverride > 0) ctmfBits = CtmfBitsOverride;
            Ctmf? ctmf = UseCtmfFinder ? new Ctmf(ctmfBits, data.Length) : null;
            int ctmfIns = inserted;

            Span<int> cml = stackalloc int[8];
            Span<int> cdist = stackalloc int[8];
            Span<int> coff = stackalloc int[8];

            // Adaptive windowed parse (num_tlls==1 / lvl7): advance in 256-byte
            // commit strides with a 4096-byte lookahead window, committing at a clean re-anchor (frontier fully
            // behind pos) or a window overflow, and re-tallying the committed segment + rebuilding the cost model
            // after every commit. When adaptPassinfo is null the classic single monolithic full-chunk pass runs
            // unchanged.
            bool windowed = UseWindowedParse && adaptPassinfo != null;
            int end = matchStartLimit;
            int segStart = startPos;
            List<Command>? outCmds = windowed ? new List<Command>() : null;
            // Cumulative recent-offset state for the windowed re-tally. Threading it across committed
            // windows prevents a per-window reset from drifting the sub-literal histogram.
            int tr0 = MinDistance, tr1 = MinDistance, tr2 = MinDistance;

            int anchor = startPos;
            long accLit = 0;

            while (true)
            {
                int windowEnd = end;
                if (windowed)
                {
                    anchor = segStart;
                    accLit = 0;
                    // Frontier starts one commit-stride ahead (the maxreached=min(segStart+256,end),
                    // snapped to end when within the no-match zone); relaxations grow it via DpMaxReached.
                    int mr = segStart + WindowCommitStride;
                    if (mr > end) mr = end;
                    if (end - NoMatchZone <= mr) mr = end;
                    DpMaxReached = mr;
                    windowEnd = segStart + WindowLookahead;
                    if (windowEnd > end) windowEnd = end;
                    if (end - NoMatchZone <= windowEnd) windowEnd = end;
                    // Reset stale forward arrivals left by the PREVIOUS window's lookahead: they were relaxed
                    // under the previous window's codecost and must be recomputed under the new (rebuilt) one.
                    // arr[segStart] (the committed boundary cost) is preserved.
                    if (segStart > startPos)
                        for (int i = segStart + 1; i <= maxArr; i++) arr[i].Cost = int.MaxValue;
                }
                int commitEnd = -1; // -1 ⇒ the pos loop ran to matchStartLimit ⇒ final segment

                for (int pos = segStart; pos <= matchStartLimit; pos++)
                {
                    if (windowed)
                    {
                        if (DpMaxReached > windowEnd) { commitEnd = DpMaxReached; break; } // window overflow
                        if (pos >= end) { commitEnd = -1; break; }                          // final commit at pos==end
                    }
                    if (pos > segStart)
                    {
                        int alo = arr[anchor].R0 < MinDistance ? MinDistance : arr[anchor].R0;
                        accLit += KrakenOptimalCost.CostAddLiteral(data, pos - 1, alo, cc);
                        if (arr[pos].Cost != int.MaxValue)
                        {
                            int run0 = pos - anchor;
                            long viaAnchor = (long)arr[anchor].Cost +
                                             (run0 > 2 ? KrakenOptimalCost.CostLen(cc, run0 - 3) : 0) + accLit;
                            if (UseReanchorTie ? arr[pos].Cost <= viaAnchor : arr[pos].Cost < viaAnchor)
                            {
                                anchor = pos;
                                accLit = 0;
                            }
                        }
                    }

                    inserted = InsertUpTo(data, dpHead, dpPrev, inserted, pos);
                    if (ctmf != null)
                        while (ctmfIns < inserted) { ctmf.Insert(data, ctmfIns); ctmfIns++; }
                    int nc = FindCandidates(data, pos, dpHead, dpPrev, matchLimit, cc, cml, cdist, coff, ctmf);

                    long minBase = long.MaxValue;
                    // longestReach: the longest rep/new match relaxed at this position across all LRL
                    // iterations. Once it reaches 1<<level (128 @ lvl7), new-match relaxation is skipped
                    // for the remaining LRL iterations. This keeps a long match's first shorter-run arrival
                    // instead of overwriting it from a longer literal run. Reset per position.
                    int longestReach = 0;
                    for (int lrl = 0; lrl <= 3; lrl++)
                    {
                        int run = lrl;
                        if (lrl == 3 && 3 < pos - anchor) run = pos - anchor; // 4th iteration = full run from anchor
                        int src = pos - run;
                        if (src < startPos) continue;
                        if (arr[src].Cost == int.MaxValue) continue;

                        int slo = arr[src].R0 < MinDistance ? MinDistance : arr[src].R0;
                        long litcost = (run == pos - anchor)
                            ? accLit
                            : KrakenOptimalCost.CostLiterals(data, pos - run, run, slo, cc);
                        long baseCost = (long)arr[src].Cost + litcost;
                        int litField = run < 3 ? run : 3;
                        if (run > 2) baseCost += KrakenOptimalCost.CostLen(cc, run - 3);

                        int sr0 = arr[src].R0, sr1 = arr[src].R1, sr2 = arr[src].R2;

                        // Rep matches, longest-first: a shorter rep than one already relaxed is never tried.
                        int longestlo = 0;
                        for (int loi = 0; loi < 3; loi++)
                        {
                            int rdist = loi == 0 ? sr0 : loi == 1 ? sr1 : sr2;
                            if (rdist < MinDistance) continue;
                            int repLen = RepMatchLength(data, pos, rdist, matchLimit);
                            if (repLen < MinRepMatch || repLen <= longestlo) continue;
                            longestlo = repLen;

                            int n1, n2;
                            if (loi == 0) { n1 = sr1; n2 = sr2; }
                            else if (loi == 1) { n1 = sr0; n2 = sr2; }
                            else { n1 = sr0; n2 = sr1; }

                            // Frontier domination gate: a rep whose reach does not exceed the frontier already
                            // established by an earlier position (pos+repLen <= DpMaxReached) is an arrival that
                            // lands inside a committed long match. Such positions are not re-processed after a
                            // frontier-extending match, which prevents off-path rep sublengths from drifting the
                            // segment cadence.
                            bool repDominated = UseRepFrontierGate && windowed && (long)pos + repLen <= DpMaxReached;
                            if (!repDominated)
                            {
                                // Full-length relax always; fill rep sublengths only when repLen < 128. A match
                                // >= 1<<level (128 @lvl7) creates only its full-length arrival, with no
                                // intermediate sublength arrivals. Filling those would manufacture off-path
                                // arrivals.
                                RelaxRep(arr, pos, repLen, loi, baseCost, litField, rdist, n1, n2, run, src, cc);
                                if (SublenFillAllowed(3, SublenFillThreshold - 3, repLen))
                                    for (int m = MinRepMatch; m < repLen; m++)
                                        RelaxRep(arr, pos, m, loi, baseCost, litField, rdist, n1, n2, run, src, cc);

                                // Value the immediate rep0 continuation off this full-length rep match.
                                if (UseFaef0)
                                {
                                    long costAtE = baseCost + KrakenOptimalCost.CostLoMatch(cc, litField, repLen, loi);
                                    Faef0(arr, data, pos + repLen, costAtE, repLen, run, loi, rdist, src,
                                          rdist, n1, n2, rdist, matchLimit, cc);
                                }
                            }
                        }
                        // Accumulate this LRL iteration's longest rep into the position-wide longest-reach,
                        // which gates the new-match relax below.
                        if (longestlo > longestReach) longestReach = longestlo;

                        // Once any relaxed match (rep or, from a prior lrl, new) reaches >= 1<<level
                        // (128 @lvl7), exit the whole lrl source loop instead of advancing to higher-lrl /
                        // anchor-jump sources. Otherwise farther sources can manufacture off-path arrivals
                        // that over-extend the frontier and drift the segment cadence.
                        if (UseLrlExitGate && longestReach >= SublenFillThreshold) break;

                        // New-offset matches only when this lrl iteration set a new minimum base. On an EXACT base
                        // tie the DP still relaxes the (later, longer-LRL) run so its earlier-source path can win the
                        // arrival tie (see UseTieBreakLast): the gate becomes <= and RelaxNew keeps the last equal.
                        // Skip the new-match relax entirely once a >=128 match already reaches here.
                        if (longestReach < SublenFillThreshold &&
                            (UseTieBreakLast ? baseCost <= minBase : baseCost < minBase))
                        {
                            minBase = baseCost;
                            for (int i = 0; i < nc; i++)
                            {
                                int cm = cml[i];
                                if (cm <= longestlo) break; // candidates are length-desc
                                int d = cdist[i];
                                if (d == sr0 || d == sr1 || d == sr2) continue; // a recent distance is a rep, not new
                                // Cross-position frontier gate: a long match (cm >= 1<<level) that reaches no
                                // further than the frontier already established by an earlier position is
                                // suppressed. This keeps the earlier cheaper-LRL arrival rather than overwriting
                                // it from a later start.
                                if (UseFrontierGate && windowed && cm >= SublenFillThreshold && pos + cm <= DpMaxReached)
                                    continue;
                                if (cm > longestReach) longestReach = cm; // ref line ~958: local_2a4 = max(local_2a4, ml)
                                long baseOff = baseCost + coff[i];
                                // Full-length relax always; fill new-match sublengths only when cm < 128.
                                int newFloor = UseDpMml3 ? 3 : 4;
                                int newLo = newFloor + 1;
                                RelaxNew(arr, pos, cm, baseOff, litField, d, sr0, sr1, run, src, cc);
                                if (SublenFillAllowed(newLo, SublenFillThreshold - newLo, cm))
                                    for (int m = newFloor; m < cm; m++)
                                        RelaxNew(arr, pos, m, baseOff, litField, d, sr0, sr1, run, src, cc);

                                // Value the immediate rep0 continuation off this full-length new match.
                                if (UseFaef0)
                                {
                                    long costAtE = baseOff + KrakenOptimalCost.CostNormalMatch(cc, litField, cm);
                                    Faef0(arr, data, pos + cm, costAtE, cm, run, 3, d, src,
                                          d, sr0, sr1, d, matchLimit, cc);
                                }
                            }
                        }
                    }
                    // Long-match skip: after processing a position, if the longest match relaxed there reaches
                    // the optimal-skip length (1<<level = 128 @lvl7), jump the parse position to the match
                    // end (pos + longestReach, <= the frontier). If that match end equals the frontier,
                    // commit the segment there; otherwise re-anchor to the match end and resume. This
                    // suppresses off-path arrivals that an every-position scan would manufacture.
                    if (windowed && UseLongMatchSkip && longestReach >= SublenFillThreshold)
                    {
                        int skipTarget = pos + longestReach; // = longestml_arrival_pos, <= DpMaxReached
                        if (skipTarget > matchStartLimit) skipTarget = matchStartLimit;
                        if (skipTarget > pos && arr[skipTarget].Cost != int.MaxValue)
                        {
                            anchor = skipTarget;
                            accLit = 0;
                            {
                                // the long match reaches the frontier exactly → commit the segment at the match end
                                commitEnd = skipTarget;
                                break;
                            }
                        }
                    }
                }
                if (!windowed)
                {
                    int bestEndNw = EstarSelect(arr, data, startPos, matchLimit, chunkEnd, cc);
                    if (bestEndNw < 0) return new List<Command>();
                    var revNw = BackTraceSeg(arr, startPos, bestEndNw, maxArr);
                    return revNw ?? new List<Command>();
                }
                bool finalSeg = commitEnd < 0 || commitEnd >= end;
                if (finalSeg)
                {
                    int bestEndF = EstarSelect(arr, data, segStart, matchLimit, chunkEnd, cc);
                    if (bestEndF > segStart)
                    {
                        var segF = BackTraceSeg(arr, segStart, bestEndF, maxArr);
                        if (segF != null) outCmds!.AddRange(segF);
                    }
                    return outCmds!;
                }

                var seg = BackTraceSeg(arr, segStart, commitEnd, maxArr);
                if (seg == null) return outCmds!; // trace failed → return the committed prefix (ParseOptimal reselects)
                outCmds!.AddRange(seg);
                // Re-tally the committed segment into the cumulative passinfo and rebuild the cost tables (the
                // lvl7 rebuild interval = 1 ⇒ rebuild on every commit).
                int[] tal = TallyRecents(seg, data, segStart, 2, -1, ref tr0, ref tr1, ref tr2);
                int nAdapt = adaptPassinfo!.Length < tal.Length ? adaptPassinfo.Length : tal.Length;
                for (int i = 0; i < nAdapt; i++) adaptPassinfo[i] += tal[i];
                segStart = commitEnd;
                if (segStart >= end)
                {
                    int bestEndT = EstarSelect(arr, data, segStart, matchLimit, chunkEnd, cc);
                    if (bestEndT > segStart)
                    {
                        var tail = BackTraceSeg(arr, segStart, bestEndT, maxArr);
                        if (tail != null) outCmds!.AddRange(tail);
                    }
                    return outCmds!;
                }
            } // end while(true) — process the next segment
        }
        finally { GreedyHashBytesOverride = saveDpHb; }
    }

    /// <summary>
    /// E* selection: the cheapest reachable arrival in <c>(from, matchLimit]</c> plus its trailing
    /// literal run to <paramref name="chunkEnd"/>. Returns the winning end index, or -1 if none is reachable.
    /// </summary>
    private static int EstarSelect(Arrival[] arr, ReadOnlySpan<byte> data, int from, int matchLimit,
        int chunkEnd, KrakenOptimalCost.CodeCosts cc)
    {
        int bestEnd = -1;
        long bestTotal = long.MaxValue;
        for (int e = from + 1; e <= matchLimit; e++)
        {
            if (arr[e].Cost == int.MaxValue) continue;
            int lo = arr[e].R0 < MinDistance ? MinDistance : arr[e].R0;
            long total = (long)arr[e].Cost + KrakenOptimalCost.CostLiterals(data, e, chunkEnd - e, lo, cc);
            if (total < bestTotal)
            {
                bestTotal = total;
                bestEnd = e;
            }
        }
        return bestEnd;
    }

    /// <summary>
    /// Backward-traces the arrival chain from <paramref name="to"/> to <paramref name="from"/>, emitting one
    /// <see cref="Command"/> per arrival (a two-step bundle emits its free rep0 continuation first). Returns the
    /// commands in forward order, or null if the chain does not cleanly reach <paramref name="from"/>.
    /// </summary>
    private static List<Command>? BackTraceSeg(Arrival[] arr, int from, int to, int maxArr)
    {
        var rev = new List<Command>();
        int p2 = to;
        int guard = 0;
        while (p2 != from && guard++ <= maxArr)
        {
            Arrival a = arr[p2];
            if (a.Ml <= 0 || a.Src < from || a.Src >= p2)
                break;
            if (a.ContMl > 0)
            {
                // Two-step arrival: a primary match then a free rep0 continuation. Emit later-first
                // (continuation, then primary); the rep0 reuses the primary's distance (idx 0).
                int sCont = a.Src + a.Lrl + a.Ml; // end of primary = start of continuation literals
                rev.Add(new Command(sCont, a.ContLrl, a.R0, a.ContMl, 0));
            }
            rev.Add(new Command(a.Src, a.Lrl, a.Dist, a.Ml, a.Idx));
            p2 = a.Src;
        }
        if (p2 != from)
            return null; // trace did not reach the origin → discard
        rev.Reverse();
        return rev;
    }

    private static void RelaxRep(Arrival[] arr, int pos, int ml, int loi, long baseCost, int litField,
        int r0, int r1, int r2, int run, int src, KrakenOptimalCost.CodeCosts cc)
    {
        long total = baseCost + KrakenOptimalCost.CostLoMatch(cc, litField, ml, loi);
        int dst = pos + ml;
        if (UseWindowedParse && dst > DpMaxReached) DpMaxReached = dst;
        if (UseTieBreakLast ? total <= arr[dst].Cost : total < arr[dst].Cost)
        {
            arr[dst].Cost = (int)total;
            arr[dst].R0 = r0; arr[dst].R1 = r1; arr[dst].R2 = r2;
            arr[dst].Ml = ml; arr[dst].Lrl = run; arr[dst].Src = src;
            arr[dst].Idx = loi; arr[dst].Dist = r0;
            arr[dst].ContLrl = 0; arr[dst].ContMl = 0;
        }
    }

    private static void RelaxNew(Arrival[] arr, int pos, int ml, long baseWithOff, int litField,
        int dist, int sr0, int sr1, int run, int src, KrakenOptimalCost.CodeCosts cc)
    {
        long total = baseWithOff + KrakenOptimalCost.CostNormalMatch(cc, litField, ml);
        int dst = pos + ml;
        if (UseWindowedParse && dst > DpMaxReached) DpMaxReached = dst;
        if (UseTieBreakLast ? total <= arr[dst].Cost : total < arr[dst].Cost)
        {
            arr[dst].Cost = (int)total;
            arr[dst].R0 = dist; arr[dst].R1 = sr0; arr[dst].R2 = sr1;
            arr[dst].Ml = ml; arr[dst].Lrl = run; arr[dst].Src = src;
            arr[dst].Idx = 3; arr[dst].Dist = dist;
            arr[dst].ContLrl = 0; arr[dst].ContMl = 0;
        }
    }

    /// <summary>
    /// Rep0-continuation pre-relaxation for the forward DP.
    /// Given a primary match and its post-match front offset, it evaluates an immediate rep0 continuation and records the bundled continuation in <see cref="Arrival.ContLrl"/> and <see cref="Arrival.ContMl"/> when that arrival is cheaper.
    /// </summary>
    private static void Faef0(Arrival[] arr, ReadOnlySpan<byte> data, int s, long costAtE,
        int primaryMl, int primaryLrl, int primaryIdx, int primaryDist, int src,
        int pr0, int pr1, int pr2, int contDist, int matchLimit,
        KrakenOptimalCost.CodeCosts cc)
    {
        int d = contDist;
        if (s + 3 > matchLimit) return;            // forward-extend window must lie inside the match zone
        if (d < MinDistance || s + 1 - d < 0) return;

        // backExt: 2 if both s+1 and s+2 match their -d back-refs; 1 if only s+2; 0 otherwise.
        int backExt = data[s + 2] == data[s + 2 - d] ? (data[s + 1] == data[s + 1 - d] ? 2 : 1) : 0;
        int fwd = RepMatchLength(data, s + 3, d, matchLimit);
        int lrl2 = 3 - backExt;
        int ml2 = fwd + backExt;
        if (ml2 < MinRepMatch) return;             // guard: only when 1 < ml2

        long cost = costAtE + KrakenOptimalCost.CostLiterals(data, s, lrl2, d, cc);
        int litField2 = lrl2;
        if (lrl2 > 2) { litField2 = 3; cost += KrakenOptimalCost.CostLen(cc, 0); }
        cost += KrakenOptimalCost.CostLoMatch(cc, litField2, ml2, 0);   // loi 0 = rep0

        int e2 = s + lrl2 + ml2;                   // == s + 3 + fwd, always <= matchLimit
        if (UseWindowedParse && e2 > DpMaxReached) DpMaxReached = e2;
        if (UseTieBreakLast ? cost <= arr[e2].Cost : cost < arr[e2].Cost)
        {
            arr[e2].Cost = (int)cost;
            arr[e2].R0 = pr0; arr[e2].R1 = pr1; arr[e2].R2 = pr2;
            arr[e2].Ml = primaryMl; arr[e2].Lrl = primaryLrl; arr[e2].Src = src;
            arr[e2].Idx = primaryIdx; arr[e2].Dist = primaryDist;
            arr[e2].ContLrl = lrl2; arr[e2].ContMl = ml2;
        }
    }

    /// <summary>
    /// Collects up to four longest distinct-distance new-offset candidates from the causal hash chain plus
    /// a forced distance-8 (init offset) candidate, sorted by length descending, caching each one's
    /// <see cref="KrakenOptimalCost.CostOffset"/>. Approximates the find_all_matches 4-pair table.
    /// </summary>
    private static int FindCandidates(ReadOnlySpan<byte> data, int pos, int[] dpHead, int[] dpPrev,
        int matchLimit, KrakenOptimalCost.CodeCosts cc, Span<int> cml, Span<int> cdist, Span<int> coff,
        Ctmf? ctmf)
    {
        int n = 0;
        int chunkEnd = matchLimit + LiteralTail;
        if (UseSuffixTrieFinder)
        {
            // Full-history Pareto finder = output-equivalent to the suffix-trie matcher.
            // Walk the whole hash chain (most-recent-first ⇒ distance ascending). A
            // candidate is on the Pareto frontier iff it is strictly longer than every CLOSER candidate, so
            // recording (len,dist) only when len exceeds the running best yields the closest offset for each
            // achievable length. Keep the 4 LONGEST pairs (find_all_matches num_pairs==4), ml-descending.
            // The buffer holds only the most recent 4 records; since records are length-monotonic those ARE the
            // 4 longest, so staircase/periodic inputs (thousands of achievable lengths) are handled without a cap.
            Span<int> fl = stackalloc int[4];
            Span<int> fd = stackalloc int[4];
            int fn = 0;
            int bestLen = 0;
            int recMin = UseDpMml3 ? DpMml3 : MinMatch; // lvl7 suffix-trie match finder mml (3 vs 4)
            int distFloor = UseTinyOffsetRemap ? 1 : MinDistance; // include dist 1..7 for the round-up below
            uint hs = Hash(data, pos);
            int c = dpHead[hs];
            int maxLen = chunkEnd - pos; // the longest match physically possible at this position
            while (c >= 0)
            {
                int dist = pos - c;
                if (dist >= distFloor)
                {
                    int len = MatchLength(data, c, pos, chunkEnd);
                    if (len > bestLen)
                    {
                        bestLen = len;
                        if (len >= recMin)
                        {
                            if (fn < 4) { fl[fn] = len; fd[fn] = dist; fn++; }
                            else { fl[0] = fl[1]; fl[1] = fl[2]; fl[2] = fl[3]; fl[3] = len; fd[0] = fd[1]; fd[1] = fd[2]; fd[2] = fd[3]; fd[3] = dist; }
                        }
                        // A match that reaches the chunk end is the longest possible here; since the walk is
                        // most-recent-first (closest offset first), no earlier (farther) candidate can be
                        // strictly longer, so nothing more would be recorded. Stop. This leaves the finder's
                        // output identical while bounding the walk on long-run inputs (e.g. the zero-padded
                        // metadata region), which otherwise makes a single hash chain O(n^2).
                        if (bestLen >= maxLen) break;
                    }
                }
                c = dpPrev[c];
            }
            int keep = fn; // already capped at 4
            int tailEmit = -1; // capped length shared by tail-overrunning matches (fill longest-first)
            for (int i = 0; i < keep; i++)
            {
                int idx = keep - 1 - i; // ascending buffer → longest first
                int clen = fl[idx], cdst = fd[idx];
                if (UseTinyOffsetRemap && cdst < MinDistance)
                {
                    // The DP rounds a sub-8 distance up and recomputes its length too.
                    int rounded = RoundUpTiny(cdst);
                    if (rounded == 0 || rounded > pos) continue;
                    int rlen = MatchLength(data, pos - rounded, pos, matchLimit);
                    if (rlen < recMin) continue;
                    clen = rlen;
                    cdst = rounded;
                }
                else if (clen > matchLimit - pos)
                {
                    // Tail cap: the trie ranked this match by its full length, but a match may only extend to
                    // matchLimit (LiteralTail trailing literals reserved). Cap the emitted length yet keep the
                    // farther distance. The optimal-parse match fill runs longest-first and fills lengths down
                    // to the previous candidate's capped length, so shorter-uncapped matches that collapse to
                    // the same tail end are not emitted; only this longest-uncapped distance survives.
                    clen = matchLimit - pos;
                }
                if (clen < recMin) continue;
                if (clen == tailEmit) continue; // collapsed into an already-emitted longer-uncapped tail match
                if (pos + clen >= matchLimit) tailEmit = clen;
                n = InsertCandidate(cml, cdist, n, clen, cdst, 4);
            }
            int off8s = RepMatchLength(data, pos, MinDistance, matchLimit);
            if (off8s >= MinMatch)
                n = InsertCandidate(cml, cdist, n, off8s, MinDistance, cml.Length);
            for (int i = 0; i < n; i++)
                coff[i] = KrakenOptimalCost.CostOffset(cdist[i], cc);
            return n;
        }
        int bestCtmfLen = 0;
        if (ctmf != null)
        {
            // The cache-table finder emits strictly-length-improving (len,dist) pairs scanning row A then
            // row B (shared monotonic prevml), already distinct/ascending in length. Feed them longest-first
            // into the length-descending candidate set.
            Span<int> qlen = stackalloc int[40];
            Span<int> qdist = stackalloc int[40];
            int qn = ctmf.Query(data, pos, matchLimit, qlen, qdist);
            for (int i = qn - 1; i >= 0; i--)
            {
                n = InsertCandidate(cml, cdist, n, qlen[i], qdist[i], 4);
                if (qlen[i] > bestCtmfLen) bestCtmfLen = qlen[i];
            }
        }
        if (ctmf == null || UseChainUnion || UseLrmSupplement)
        {
            // Strictly-longer-only when supplementing the CTMF (the LRM-equivalent path); full union otherwise.
            bool supplement = ctmf != null && !UseChainUnion;
            uint h = Hash(data, pos);
            int cand = dpHead[h];
            int walk = 0;
            while (cand >= 0 && walk < MaxChainWalk)
            {
                int dist = pos - cand;
                if (dist >= MinDistance)
                {
                    int len = MatchLength(data, cand, pos, matchLimit);
                    if (len >= MinMatch && (!supplement || len > bestCtmfLen))
                        n = InsertCandidate(cml, cdist, n, len, dist, 4);
                }
                cand = dpPrev[cand];
                walk++;
            }
        }
        int off8 = RepMatchLength(data, pos, MinDistance, matchLimit);
        if (off8 >= MinMatch)
            n = InsertCandidate(cml, cdist, n, off8, MinDistance, cml.Length);
        for (int i = 0; i < n; i++)
            coff[i] = KrakenOptimalCost.CostOffset(cdist[i], cc);
        return n;
    }

    /// <summary>Inserts (len,dist) into the length-descending candidate arrays, deduping by distance, capped at <paramref name="cap"/>.</summary>
    private static int InsertCandidate(Span<int> cml, Span<int> cdist, int n, int len, int dist, int cap)
    {
        for (int k = 0; k < n; k++)
            if (cdist[k] == dist)
                return n; // keep the first (longest) occurrence of this distance
        int posi = 0;
        while (posi < n && cml[posi] >= len) posi++;
        if (posi >= cap)
            return n;
        int last = n < cap ? n : cap - 1;
        for (int k = last; k > posi; k--) { cml[k] = cml[k - 1]; cdist[k] = cdist[k - 1]; }
        cml[posi] = len; cdist[posi] = dist;
        return n < cap ? n + 1 : n;
    }

    /// <summary>
    /// Two-row, 16-way check-bit cache-table match finder used by the CTMF candidate path.
    /// Each row scans newest-first, emits strictly length-improving matches, then the row outputs are sorted, deduplicated by length, and capped to four candidates.
    /// </summary>
    private sealed class Ctmf
    {
        private const uint Mul4 = 0xB7A56463u;            // row-A 4-byte context multiplier (shared mul >> 32)
        private const ulong Mul8 = 0xCF1BBCDCB7A56463UL;  // row-B 8-byte context multiplier
        private const int Ways = 16;                       // 16 entries per row window
        private const uint PosMask = 0x03FFFFFFu;          // entry low 26 bits = position
        private const uint CheckMask = 0xFC000000u;        // entry top 6 bits = check

        private readonly int _bits;
        private readonly int _ways;                        // window length (16 = faithful; CtmfWaysOverride probes retention depth)
        private readonly int _maskA;                       // (1<<bits) - 16 (row-A index mask, 16-aligned, faithful)
        private readonly int _shiftB;                      // 64 - bits (row-B top-bits shift)
        private readonly uint[] _table;                    // ONE flat 2^bits table (+pad), zero-init (both rows share it)

        public Ctmf(int bits, int dataLength)
        {
            _ = dataLength;
            _bits = bits & 31;
            if (_bits < 5) _bits = 5;                      // need >= 4 index bits above the 16-way window
            _ways = CtmfWaysOverride > 0 ? CtmfWaysOverride : Ways;
            _maskA = (1 << _bits) - Ways;                  // index stays 16-aligned; only the window length varies
            _shiftB = 64 - _bits;
            _table = new uint[(1 << _bits) + 64];          // memset 0; +64 pads windows longer than 16
        }

        private static uint Read32(ReadOnlySpan<byte> d, int p)
        {
            uint v = 0; int n = d.Length;
            for (int i = 0; i < 4; i++) { int q = p + i; if ((uint)q < (uint)n) v |= (uint)d[q] << (8 * i); }
            return v;
        }

        private static ulong Read64(ReadOnlySpan<byte> d, int p)
        {
            ulong v = 0; int n = d.Length;
            for (int i = 0; i < 8; i++) { int q = p + i; if ((uint)q < (uint)n) v |= (ulong)d[q] << (8 * i); }
            return v;
        }

        private static uint Rotl32(uint v, int r) { r &= 31; return r == 0 ? v : (v << r) | (v >> (32 - r)); }

        // row-A / hash1 = rotl32(low32(read32(ptr) * 0xB7A56463), bits ); the top 6 bits are the stored check.
        private uint Hash1(ReadOnlySpan<byte> d, int p) => Rotl32(Read32(d, p) * Mul4, _bits);
        private int RowA(uint h1) => (int)(h1 & (uint)_maskA);
        // row-B index = ((read64(ptr) * 0xCF1BBCDCB7A56463) >> (64-bits)) & ~0xF (16-aligned, in [0, 2^bits)).
        private int RowB(ReadOnlySpan<byte> d, int p) => (int)((uint)((Read64(d, p) * Mul8) >> _shiftB) & ~(uint)0xF);

        /// <summary>Inserts position <paramref name="p"/> into both hash rows (16-way FIFO shift, newest at slot 0).</summary>
        public void Insert(ReadOnlySpan<byte> d, int p)
        {
            uint h1 = Hash1(d, p);
            uint entry = ((uint)p & PosMask) | (h1 & CheckMask);
            InsertRow(RowA(h1), entry);
            InsertRow(RowB(d, p), entry);
        }

        private void InsertRow(int row, uint entry)
        {
            uint[] t = _table;
            for (int k = Ways - 1; k > 0; k--) t[row + k] = t[row + k - 1];
            t[row] = entry;
        }

        /// <summary>
        /// Scans row A then row B (newest-first), emitting strictly-length-improving (len,dist) pairs into
        /// <paramref name="outLen"/>/<paramref name="outDist"/> with a shared monotonic prevml
        /// across both rows. Returns the pair count (ascending, distinct lengths == the post sort+dedup set).
        /// </summary>
        public int Query(ReadOnlySpan<byte> d, int pos, int matchLimit, Span<int> outLen, Span<int> outDist)
        {
            int n = 0;
            uint h1 = Hash1(d, pos);
            uint check = h1 & CheckMask;
            if (!CtmfRowAOff)
            {
                int prevmlA = 0;   // reset the threshold to 0 at the start of each row
                n = ScanRow(d, pos, matchLimit, RowA(h1), check, ref prevmlA, outLen, outDist, n);
            }
            int prevmlB = 0;       // row B starts its strictly-increasing subsequence fresh (NOT continuing row A)
            n = ScanRow(d, pos, matchLimit, RowB(d, pos), check, ref prevmlB, outLen, outDist, n);
            return n;
        }

        private int ScanRow(ReadOnlySpan<byte> d, int pos, int matchLimit, int row, uint check,
            ref int prevml, Span<int> outLen, Span<int> outDist, int n)
        {
            uint[] t = _table;
            for (int w = 0; w < Ways; w++)
            {
                uint entry = t[row + w];
                if ((entry & CheckMask) != check) continue;          // check-bit reject (also drops empty slots)
                int epos = (int)(entry & PosMask);
                int dist = (int)(((uint)(pos - 1 - epos) & PosMask) + 1);
                if (dist < MinDistance) continue;
                if (dist > pos) continue;                            // in-window: dist <= (ptr - base) = pos
                int cand = pos - dist;
                if (Read32(d, cand) != Read32(d, pos)) continue;     // 4-byte verify 
                int len = MatchLength(d, cand, pos, matchLimit);
                if (len > prevml)                                    // strictly longer (assert "len > prevml")
                {
                    if (n < outLen.Length) { outLen[n] = len; outDist[n] = dist; n++; }
                    prevml = len;
                }
            }
            return n;
        }
    }
}
