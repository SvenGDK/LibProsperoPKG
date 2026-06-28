// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// Oodle Kraken (newLZ) encoder — a from-scratch managed encoder producing standard, decoder-valid
// newLZ chunks accepted by the reference PS5 Oodle 2.8.0 decompressor (the reference compressor
// -decompress is the acceptance check). No bytes are copied from any Oodle source — only the published
// format is generated and validated byte-exact against the reference output. GPLv3.
//
// A PFS block (up to blockSize, default 256 KiB) is encoded as ONE or TWO headerless newLZ chunks,
// because a single newLZ chunk decodes at most 128 KiB (0x20000). blockSize 0x40000 is therefore
// exactly two chunks; the block-boundary table flags a two-chunk block with the 0x20 bit (flag 0x26
// instead of 0x06) and stores the first chunk's compressed size in its saturating size hint, exactly
// as the reference frame rebuilder (reference routine in the reference implementation) expects when it splits the block
// back into per-chunk OodleLZ frames.
//
// CHUNK FORMAT ("excess mode", post-seed control byte high bit set):
//
//   first  chunk: [8-byte raw seed][ctrl][lit raw][cmd raw][offs raw][litlen raw][dual bitstream][excess]
//   second chunk:              [ctrl][lit raw][cmd raw][offs raw][litlen raw][dual bitstream][excess]
//
// * seed       = the first 8 bytes of the first chunk (COPY_64); decoding starts at dst+8. The second
//                chunk has NO seed — it is decoded at a non-zero output offset and its matches may
//                reference back into the first chunk's already-decoded output.
// * ctrl byte  = 0x80 | (excessByteCount & 0x3F), with a continuation byte when the low six bits would
// *              exceed 0x1F. excessByteCount is the length of the trailing excess sub-stream that carries
// *              the literal-length escape values (0 when no literal run exceeds 257).
// * 4 raw arrays, each a DecodeBytes chunk-type-0 raw block: a 3-byte big-endian length header (high
//   bit clear, len <= 0x3FFFF) followed by that many raw bytes. Order: lit, cmd, packed_offs,
//   packed_litlen.
// * dual bitstream = forward bytes ++ reverse(backward bytes); carries ONLY the offset extra (E) bits,
//   alternating new-offset #0 -> forward, #1 -> backward, #2 -> forward, ...
// * excess sub-stream (only when excessByteCount > 0) = the chunk's trailing excessByteCount bytes:
//   a forward writer (even-index literal-length escapes) ++ reverse(backward writer, odd-index escapes),
//   each value written with WriteLength; the decoder's ea/eb readers consume them in the same order.
//
// Command byte f: litfield = f & 3 (== 3 -> packed_litlen carries litlen-3); matchfield = (f >> 2) & 0xF
// (<= 14 -> inline matchlen = matchfield + 2; == 15 -> packed_litlen carries matchlen-17);
// offs_index = f >> 6 (== 3 -> new offset taken from packed_offs + E bits).
//
// CONSTRAINTS THAT MAKE A CHUNK DECODER-VALID (validated byte-exact through the actual decoder):
//   1. Every chunk MUST end with a literal tail; a match may never cover the final 8 bytes of a chunk.
//   2. Minimum new-offset distance is 8 (recent offsets initialise to -8; 1..7 are not encodable).
//   3. matchlen is capped at 271 (split into consecutive same-distance pieces) so packed_litlen never
//      needs a match-length escape. A literal run longer than 257 is encoded as follows: packed_litlen stores a
//      255 marker and the (litlen-258) value is emitted into the trailing excess sub-stream. At most 512
//      escapes per chunk (the decoder's u32 length-stream cap), else the block is stored raw.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System;
using System.Collections.Generic;
using System.Text;

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
/// Managed Oodle Kraken encoder. Compresses a PFS block into one or two headerless newLZ "excess
/// mode" chunks that round-trip through the reference PS5 decompressor (validated byte-exact against
/// <c>reference decompression output</c>).
/// <para>
/// <b>Literal-length escapes stay disabled</b>: literal runs are capped at <see cref="MaxLitRun"/>,
/// so packed_litlen never carries a literal-run escape. The actual Oodle 2.8.0 vectorized excess reader
/// uses a divider_lrl Golomb scheme whose multi-escape forward/backward layout a flat reproduction
/// cannot match (the reference acceptance is non-monotonic in excess count), and the reference implementation stores such
/// regions rather than escaping them. An over-long literal run truncates the parse into the unbounded
/// literal tail.
/// </para>
/// <para>
/// <b>A single match-length escape IS emitted.</b> When exactly one match in a chunk exceeds
/// <see cref="MaxMatch"/> it is written as one <c>matchField=15</c> command whose length is carried by
/// a u32 escape: a 0xFF packed_litlen marker plus the value <c>(matchLen - 272)</c> in a one-value
/// FORWARD excess sub-stream, with the control byte set to <c>0x80 | excessByteCount</c> and the excess
/// bytes appended after the main bitstream. This is the exact, single-value layout the reference implementation emits
/// for a lone long match (control byte 0x84 for a 4-byte escape) and is validated byte-for-byte by the
/// periodic-tile byte-identity probe. Two or more over-long matches would require the rejected
/// forward/backward multi-escape layout, so such a chunk falls back to splitting every over-long match
/// into &lt;= <see cref="MaxMatch"/> pieces (always valid, never escaped).
/// </para>
/// <para>
/// <b>No match may start in the last <see cref="NoMatchZone"/> (16) bytes of a chunk.</b> The reference newLZ
/// release parse loop (the reference implementation) enforces
/// <c>match_zone_end - to_ptr &gt;= lrl</c> where <c>match_zone_end = chunk_end - 16</c>
/// (<c>ptr_sub_saturate</c>, <c>reference routine</c>, margin 0x10): the literal-run end (= match start)
/// must be &lt;= chunk_end - 16. A match that starts later drifts the decode pointer and the block is
/// rejected with <c>SCE_COMPRESSION_ERROR_DECOMPRESSION_FAILED</c> (-1007), even though a lenient decoder
/// round-trips it. The parser therefore stops emitting matches past <c>chunkEnd - NoMatchZone</c> and
/// flushes the remainder as the trailing literal run; a store-raw safety net rejects any chunk that would
/// still violate it. (validated against reference decompression output on the
/// 683-byte binary case that previously failed.)
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
    private const int NoMatchZone = 16;         // the reference newLZ: a match may not START in the last 16 bytes of a chunk (match_zone_end = chunkEnd-16)
    private const int MaxMatch = 271;           // split path caps matchlen-17 <= 254 (packed_litlen < 255); a lone over-long match instead uses the single match-length escape
    private const int MaxArrayLength = 0x3FFFF; // DecodeBytes raw 3-byte size limit
    private const int MaxFirstChunkComp = 0x1FFFF; // size hint is 17-bit; first chunk must fit
    private const int MaxChainWalk = 128;
    private const int HashBits = 17;
    private const int HashSize = 1 << HashBits;
    private const byte CtrlExcessMode = 0x80;   // post-seed control byte: 0x80 | (excessCount & 0x3F)
    private const int MaxLitRun = 257;          // litLen-3 <= 254, so packed_litlen stays < 255 (no escape)

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
    /// blocks toward the reference sizes. The packed-offset array is always left raw because the offset
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
            byte[]? single = EncodeChunk(data, head, prev, 0, n, withSeed: true, useHuffmanArrays);
            if (single is null || single.Length >= n)
                return null;
            return new EncodedBlock(single, multiChunk: false, single.Length);
        }

        // blockSize is at most 0x40000 (two chunks). A larger block cannot be described by the single
        // first-chunk size hint, so leave it to the stored path.
        if (n > 2 * ChunkMax)
            return null;

        byte[]? chunk0 = EncodeChunk(data, head, prev, 0, ChunkMax, withSeed: true, useHuffmanArrays);
        if (chunk0 is null || chunk0.Length > MaxFirstChunkComp || chunk0.Length >= ChunkMax)
            return null;

        byte[]? chunk1 = EncodeChunk(data, head, prev, ChunkMax, n, withSeed: false, useHuffmanArrays);
        if (chunk1 is null)
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
        int chunkStart, int chunkEnd, bool withSeed, bool useHuffmanArrays)
    {
        int matchLimit = chunkEnd - LiteralTail; // a match may EXTEND up to here, so >= LiteralTail trailing literals remain
        // The reference newLZ decoder forbids a match from STARTING in the last 16 bytes of a chunk. Its release
        // parse loop (the reference routine) enforces `match_zone_end - to_ptr >= lrl` with
        // match_zone_end = chunk_end - 16 (ptr_sub_saturate reference routine, margin 0x10): the match start
        // (= literal-run end) must be <= chunk_end - 16. A match that starts later drifts the decode
        // pointer and the block is rejected with SCE_COMPRESSION_ERROR_DECOMPRESSION_FAILED (-1007), even
        // though our own (lenient) decoder round-trips it. So the last legal match-start is chunkEnd-NoMatchZone.
        int matchStartLimit = chunkEnd - NoMatchZone;
        int firstMatchPos = withSeed ? chunkStart + 8 : chunkStart; // seed is the first 8 bytes
        // The seed bytes are valid copy sources (the decoder emits them before the first command), so
        // index them in the hash chain. Without this the parser cannot find a match that references the
        // first 8 bytes of a seeded chunk and the first match is delayed by up to 8 literals, which is
        // exactly how the reference parses a periodic block (e.g. a distance-16 match at position 16 referencing
        // position 0). The seedless second chunk needs nothing here — its predecessors are already indexed.
        if (withSeed)
        {
            for (int p = chunkStart; p < firstMatchPos; p++)
                Insert(data, p, head, prev);
        }
        // Literals before the first match begin where matching begins (the seed is emitted separately).
        var commands = UseOptimalParse
            ? ParseOptimal(data, head, prev, firstMatchPos, firstMatchPos, matchLimit, matchStartLimit)
            : Parse(data, head, prev, firstMatchPos, firstMatchPos, matchLimit, matchStartLimit);
        if (commands.Count == 0)
            return null;

        // Shipping validity path: raw literals (litMode 1). The literal mode is signaled OUT-OF-BAND
        // by the PFS boundary-table flag bit (KrakenDecoder.DecodeBlock reads chunk0 0x01 /
        // chunk1 0x10: set = sub, clear = raw), so the emitted literal-array content and that flag must
        // agree. Emitting the reference cheaper SUB array (ChooseLitMode) requires also setting that flag in
        // the block builder; that end-to-end sub plumbing belongs to the byte-identity (UseOptimalParse)
        // path, so the validity deliverable stays raw and round-trips green.
        return EmitChunkFromCommands(data, commands, chunkStart, chunkEnd, withSeed, useHuffmanArrays, litMode: 1);
    }

    /// <summary>
    /// Builds the newLZ stream arrays from an already-computed parse and assembles the chunk bytes
    /// (entropy-coding the lit/cmd/length arrays when beneficial). Factored out of <see cref="EncodeChunk"/>
    /// so a diagnostic can measure the actual entropy-coded emit size of an externally supplied parse
    /// (the reference vs the DP's) — the metric the reference level-7 producer actually minimises in its final
    /// greedy-vs-DP selection (fc6e0 actual-emit-size pick). Returns null when the parse needs a store-raw
    /// fallback (a literal run over MaxLitRun or a match starting inside the no-match zone).
    /// </summary>
    private static byte[]? EmitChunkFromCommands(ReadOnlySpan<byte> data, List<Command> commands,
        int chunkStart, int chunkEnd, bool withSeed, bool useHuffmanArrays, int litMode = 1)
    {
        int matchStartLimit = chunkEnd - NoMatchZone;
        // A literal run > MaxLitRun would require a length escape, but the reference vectorized excess reader
        // does not accept our escape layout (it stores such regions instead). So a
        // chunk that needs one is left to the stored path: return null and let the caller store it raw.
        // The same store-raw safety net also rejects any match that would start inside the no-match zone
        // (belt-and-suspenders: the parser already enforces this, so this never triggers in practice).
        foreach (var cmd in commands)
        {
            if (cmd.LitLen > MaxLitRun)
                return null;
            if (cmd.MatchLen > 0 && cmd.LitStart + cmd.LitLen > matchStartLimit)
                return null;
        }

        var litRaw = new List<byte>(chunkEnd - chunkStart); // mode 1: raw literals
        var litSub = new List<byte>(chunkEnd - chunkStart); // mode 0: sub/delta literals (byte - dst[p+lastOffset])
        BuildLiteralStreams(data, commands, chunkEnd, litRaw, litSub);
        var cmdStream = new List<byte>();
        var packedOffs = new List<byte>();
        var packedLitLen = new List<byte>();
        var forward = new KrakenBitWriter();
        var backward = new KrakenBitWriter();
        var excessForward = new KrakenBitWriter();

        // A match longer than MaxMatch would normally be split into several <= MaxMatch pieces. When
        // EXACTLY ONE match in the chunk is over-long it is instead emitted as a single matchField=15
        // command whose length carries a u32 escape: a 0xFF packed_litlen marker plus the escape value
        // (matchLen - 272) in a one-value forward excess sub-stream. This is the layout the reference emits
        // for a single long match (e.g. control byte 0x84 for a 4-byte escape, validated byte-for-byte
        // against reference compressor). Two or more escapes would need the forward/backward
        // multi-escape layout that the reference vectorized excess reader rejects, so a chunk with several
        // over-long matches falls back to splitting every one of them (always valid, never escaped).
        int longMatchCount = 0, escapeCmdIndex = -1;
        for (int i = 0; i < commands.Count; i++)
        {
            if (commands[i].MatchLen > MaxMatch)
            {
                longMatchCount++;
                escapeCmdIndex = i;
            }
        }
        if (longMatchCount != 1)
            escapeCmdIndex = -1;

        int offsetIndex = 0;
        for (int ci = 0; ci < commands.Count; ci++)
        {
            var c = commands[ci];
            // Literal streams (litRaw/litSub) were built up-front by BuildLiteralStreams; this loop
            // only assembles the command/offset/length streams.
            if (ci == escapeCmdIndex)
            {
                // Single over-long match: one matchField=15 command, length via the u32 escape.
                int curLit = c.LitLen;
                int litField = curLit >= 3 ? 3 : curLit;
                cmdStream.Add((byte)((c.OffsIndex << 6) | (15 << 2) | litField));
                if (litField == 3)
                    packedLitLen.Add((byte)(curLit - 3));
                if (c.OffsIndex == 3)
                {
                    byte vo = (offsetIndex & 1) == 0
                        ? forward.WriteDistance(c.Distance)
                        : backward.WriteDistance(c.Distance);
                    packedOffs.Add(vo);
                    offsetIndex++;
                }
                packedLitLen.Add(255);                                  // u32 length-escape marker
                excessForward.WriteLength((uint)(c.MatchLen - 272));    // decoder: actual = u32 + 272
                continue;
            }

            // Split the match into <= MaxMatch pieces; only the first piece carries the literal run.
            // The first piece carries the command's offset index (a recent-offset reuse or a new
            // offset); every continuation piece is rep0 (offset index 0) because the chosen offset is
            // now the most-recent one, so it costs nothing further. This mirrors the decoder's LRU.
            int remaining = c.MatchLen;
            bool first = true;
            while (remaining > 0)
            {
                int piece = remaining > MaxMatch ? MaxMatch : remaining;
                if (remaining - piece > 0 && remaining - piece < MinMatch)
                    piece = remaining - MinMatch; // never leave an illegal tiny match piece

                int curLit = first ? c.LitLen : 0;
                int litField = curLit >= 3 ? 3 : curLit;
                int matchField = piece <= 16 ? piece - 2 : 15;
                int pieceOffsIndex = first ? c.OffsIndex : 0;
                cmdStream.Add((byte)((pieceOffsIndex << 6) | (matchField << 2) | litField));

                if (litField == 3)
                {
                    packedLitLen.Add((byte)(curLit - 3)); // curLit <= MaxLitRun, so <= 254 (no escape)
                }

                if (pieceOffsIndex == 3)
                {
                    // Only a new offset is transmitted: one packed_offs byte plus its E bits in the
                    // dual bitstream, alternating forward/backward per new offset. Recent-offset reuse
                    // (index 0/1/2) writes nothing here.
                    byte v = (offsetIndex & 1) == 0
                        ? forward.WriteDistance(c.Distance)
                        : backward.WriteDistance(c.Distance);
                    packedOffs.Add(v);
                    offsetIndex++;
                }

                if (matchField == 15)
                    packedLitLen.Add((byte)(piece - 17)); // <= 254, no escape

                remaining -= piece;
                first = false;
            }
        }

        // Both literal models hold the same number of literals; the array-length guard is mode-independent.
        if (litRaw.Count > MaxArrayLength || cmdStream.Count > MaxArrayLength ||
            packedOffs.Count > MaxArrayLength || packedLitLen.Count > MaxArrayLength)
        {
            return null; // arrays too large for the raw 3-byte header; store raw instead
        }

        // Literal model selection (newLZ "sub" vs "raw"): the only chunk array that depends on the
        // model. the reference encoder (newLZ_encoder_arrays_output, reference routine) keeps whichever
        // yields the smaller entropy-coded literal array; litMode forces it (0 = sub, 1 = raw) for
        // diagnostics, -1 = auto (ChooseLitMode = the validated f3130 decision).
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
        // Post-seed control byte = 0x80 | excessCount, where excessCount is the byte length of the
        // trailing excess sub-stream that holds the single match-length escape value (0 when no match
        // was escaped). The single forward escape never exceeds a few bytes, so excessCount stays well
        // under 0x1F and needs no continuation byte. Literal runs are capped at MaxLitRun so they never
        // add an escape of their own.
        byte[] excessBytes = excessForward.ToBytes();
        outBuf.Add((byte)(CtrlExcessMode | excessBytes.Length));
        WriteArray(outBuf, lit, useHuffmanArrays);
        WriteArray(outBuf, cmdStream, useHuffmanArrays);
        WriteRawArray(outBuf, packedOffs); // must stay raw: the offset reader inspects its first byte
        WriteArray(outBuf, packedLitLen, useHuffmanArrays);
        // dual bitstream region = forward ++ reverse(backward)
        outBuf.AddRange(forwardBytes);
        for (int i = backwardBytes.Length - 1; i >= 0; i--)
            outBuf.Add(backwardBytes[i]);
        // trailing excess sub-stream: the single forward-coded match-length escape, if any
        outBuf.AddRange(excessBytes);

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

    /// <summary>
    /// Returns the byte length <see cref="WriteArray"/> would emit for <paramref name="array"/> (the
    /// smaller of the raw 3-byte-header form and the Huffman form), without writing. Used to pick the
    /// cheaper literal model (sub vs raw) the way the reference f3130 array coder does.
    /// </summary>
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

    // validated against newLZ_encoder_arrays_output (reference routine) at optimal level 7:
    // fb270 passes its litMode-out to f3130, which decides sub vs raw.
    //   * literal_count < 32  -> raw (1)            [f3130: `if (literal_count < 0x20) *litmode = 1`]
    //   * else encode BOTH literal arrays for actual (newLZ_put_array_histo / our M2 array calc) and keep
    //     the cheaper. Sub is evaluated first against the running budget; raw replaces it only when
    //     STRICTLY cheaper (put_array_histo's budget ceiling is the incumbent sub cost), so sub wins
    //     ties. Level 7 (`5 < level`) skips the level<=5 entropy-estimate pre-pick and compares the
    //     actual encoded sizes directly. (The lambda space-speed term is 0 for a pure -lvl 7 ratio run.)
    // Returns 0 = sub, 1 = raw.
    internal static int ChooseLitMode(List<byte> litRaw, List<byte> litSub, bool useHuffmanArrays)
    {
        if (litSub.Count < 32) return 1; // raw: too few literals to entropy-code a sub stream
        int subSize = EncodedArraySize(litSub, useHuffmanArrays);
        int rawSize = EncodedArraySize(litRaw, useHuffmanArrays);
        return rawSize < subSize ? 1 : 0; // sub on tie (raw needs a strict win)
    }

    // Convenience overload: choose the litMode a parse would emit (used to seed the DP cost build with
    // the greedy/seed parse's litMode, mirroring the reference where the winning greedy's f3130 choice becomes
    // codecosts[0]).
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

    /// <summary>
    /// Writes <paramref name="array"/> as an entropy (Huffman) array when <paramref name="useHuffman"/>
    /// is set and the Huffman form is strictly smaller than the raw form; otherwise writes it raw.
    /// The literal/command/length streams are read by the decoder via plain <c>DecodeBytes</c>, so a
    /// type-2 entropy array is transparently accepted in their place.
    /// </summary>
    private static void WriteArray(List<byte> outBuf, List<byte> array, bool useHuffman)
    {
        if (useHuffman && array.Count >= 2)
        {
            byte[]? huff = KrakenHuffmanArrayEncoder.TryEncode(
                System.Runtime.InteropServices.CollectionsMarshal.AsSpan(array));
            if (huff is not null && huff.Length < array.Count + 3) // 3 = raw header length
            {
                outBuf.AddRange(huff);
                return;
            }
        }
        WriteRawArray(outBuf, array);
    }

    /// <summary>
    /// Diagnostic only: measure the actual entropy-coded emit size, in bytes, of an
    /// externally supplied full-chunk parse (e.g. the reference captured command list vs the DP's command
    /// list) under the actual newLZ back-end (the same stream-build + array entropy-coder the shipping
    /// encoder uses). This is the metric the reference level-7 producer minimises when it picks the final
    /// parse (fc6e0 greedy-vs-DP actual-emit-size selection, <c>local_134 &lt; local_3184</c>), so it is
    /// the authoritative arbiter for why the reference emits an integer-"costlier" near-offset rep0 cascade.
    /// The parse is the seeded first chunk (firstMatchPos = 8). litStart is reconstructed by walking.
    /// Returns the encoded byte length, or -1 when the parse falls back to store-raw.
    /// </summary>
    internal static int DiagRealEmitSize(byte[] data, int[] litLen, int[] dist, int[] match, int[] idx,
        bool useHuffmanArrays = true, int litMode = 1)
    {
        var commands = new List<Command>(litLen.Length);
        int pos = 8; // withSeed chunk: the 8-byte COPY_64 seed precedes the first command
        for (int i = 0; i < litLen.Length; i++)
        {
            commands.Add(new Command(pos, litLen[i], dist[i], match[i], idx[i]));
            pos += litLen[i] + match[i];
        }
        byte[]? bytes = EmitChunkFromCommands(data, commands, 0, data.Length, true, useHuffmanArrays, litMode);
        return bytes?.Length ?? -1;
    }

    /// <summary>
    /// Diagnostic only: same as <see cref="DiagRealEmitSize"/> but returns the actual
    /// emitted chunk bytes (seed + ctrl + arrays + dual bitstream) so a diagnostic can byte-compare my
    /// emit of an externally supplied parse against the reference actual section-7 chunk. Returns null on a
    /// store-raw fallback.
    /// </summary>
    internal static byte[]? DiagEmitChunkBytes(byte[] data, int[] litLen, int[] dist, int[] match, int[] idx,
        bool useHuffmanArrays = true, int litMode = 1)
    {
        var commands = new List<Command>(litLen.Length);
        int pos = 8; // withSeed chunk: the 8-byte COPY_64 seed precedes the first command
        for (int i = 0; i < litLen.Length; i++)
        {
            commands.Add(new Command(pos, litLen[i], dist[i], match[i], idx[i]));
            pos += litLen[i] + match[i];
        }
        return EmitChunkFromCommands(data, commands, 0, data.Length, true, useHuffmanArrays, litMode);
    }

    /// <summary>
    /// Value-model lazy parse over the output range, a faithful managed implementation of the reference
    /// <c>newLZ_encode_chunk_optimal_greedy</c> (the reference implementation). Each
    /// candidate match is scored by the reference exact value function (<see cref="FindMatch"/> /
    /// <see cref="MatchValue"/>): <c>len*4 - (isRep ? 0 : bitlen(dist)+2)</c> — validated from
    /// <c>reference routine</c> + <c>reference routine</c> (<c>bitlen = 32 - clz</c>). Repeat-offset matches
    /// transmit no offset, so they cost 0 there and are strongly preferred; among new offsets the
    /// finder keeps the highest value and, on a value tie, the SHORTEST distance (the hash chain is
    /// walked most-recent-first, so the nearer offset is seen first and wins the tie). Picking the
    /// nearer offset on ties seeds a reusable recent-offset that subsequent positions re-use as cheap
    /// reps — exactly the rep-reuse cascade the reference parser produces (e.g. introducing dist=57 then
    /// reusing it for hundreds of commands instead of walking dist=552,553,554...).
    /// <para>
    /// A 2-step lazy look-ahead defers the match start while a later position yields a strictly better
    /// match, using the reference exact comparator and thresholds: defer by 1 when
    /// <c>value(pos+1) - value(cur) - 4 &gt;= 1</c>, else defer by 2 when
    /// <c>value(pos+2) - value(cur) - 4 &gt;= 4</c>, else emit <c>cur</c> (the <c>+4</c> incumbent bias
    /// and the <c>&lt;1</c>/<c>&lt;4</c> gates are <c>reference routine</c>'s).
    /// </para>
    /// Matches never start past <paramref name="matchStartLimit"/> (the reference match_zone_end, chunkEnd-16)
    /// nor extend past <paramref name="matchLimit"/> (chunkEnd-8), preserving the trailing literal run.
    /// </summary>
    private static List<Command> Parse(ReadOnlySpan<byte> data, int[] head, int[] prev,
        int startPos, int litStart0, int matchLimit, int matchStartLimit)
    {
        var commands = new List<Command>();

        int litStart = litStart0;
        int pos = startPos;
        // A match may not start past chunkEnd-16 (the reference match_zone_end). Everything after the last
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
                if (m1.Value - cur.Value - 4 >= 1) // pos+1 strictly better (the reference +4 bias)
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

    /// <summary>Bit length of <paramref name="v"/> (the reference <c>reference routine</c>: <c>32 - clz</c>).</summary>
    private static int BitLen(uint v) =>
        v == 0 ? 0 : 32 - System.Numerics.BitOperations.LeadingZeroCount(v);

    /// <summary>
    /// A candidate match. <see cref="Idx"/> 0/1/2 = repeat-offset reuse (no offset transmitted),
    /// 3 = new offset, -1 = none. <see cref="Value"/> is the reference match value model
    /// (<c>reference routine</c>): <c>len*4 - (isRep ? 0 : bitlen(dist)+2)</c>. A none candidate scores a
    /// large negative value so it never wins a comparison.
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
    /// the reference per-position match finder (<c>reference routine</c>, value model): returns the highest-value
    /// match at <paramref name="pos"/> given the three recent offsets, preferring a repeat-offset reuse
    /// on ties (its offset is free) and otherwise the shortest-distance new offset on a value tie.
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
    // BYTE-EXACT GREEDY SELECTOR — implementation of the reference per-position newLZ_get_match_heuristic
    // (reference routine) and its decision helpers, validated against
    // the reference implementation. Replaces the value-model FindMatch when UseExactGreedy is
    // set so Tally(the greedy parse) == Tally(the reference greedy). The fb270 2-step lazy main loop (Parse) is
    // unchanged — only the per-position selector it calls switches.
    // ===========================================================================================

    // reference routine short-match offset thresholds DAT_1805498e0[ml]: a new match of length ml &lt; 6 is
    // allowed only when off &lt; threshold[ml]. ml is always &gt;= 3 (the asserted minimum).
    private static readonly int[] NormalMatchOffsetThreshold = { 0, 0, 0, 0x4000, 0x20000, 0x100000 };

    /// <summary>
    /// Byte-exact implementation of the reference per-position selector <c>newLZ_get_match_heuristic</c> (reference routine):
    /// rep search (mml2-quantized via <see cref="RepExtendMml2"/>, reference routine) with an early return on a
    /// length-&gt;=4 rep; otherwise the 4-pair Pareto new-match scan gated by <see cref="IsAllowedNormalMatch"/>
    /// (reference routine) and ranked by <see cref="IsNormalMatchBetter"/> (reference routine); final rep-vs-new pick
    /// by <see cref="TakeNewOverRep"/> (reference routine). <paramref name="lrl"/> is the current literal-run
    /// length (pos − litStart): only the rare <c>lrl &gt; 0x37</c> long-run adjustment consumes it.
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

        // A rep of length >= 4 short-circuits: the reference returns it immediately with no new-match search.
        if (bestRepLen >= 4)
            return new Cand(bestRepLen, bestRepIdx == 0 ? r0 : bestRepIdx == 1 ? r1 : r2, bestRepIdx);

        int mml = GreedyMmlOverride > 0 ? GreedyMmlOverride : MinMatch;
        if (lrl > 0x37)
        {
            if (bestRepLen < 3) bestRepLen = 0; // a short (len-2) rep is dropped after a long literal run
            mml += 1;
        }

        // New-match candidates = the 4-pair Pareto frontier (length-descending), exactly what the reference
        // SuffixTrie2 find_all_matches feeds the selector. NO synthetic off-8 candidate (f9b90 reads
        // only matchTable[0..3]).
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
                // f9b90 lines 113-124: a sub-8 distance is rounded up to a codeable one, the match length is
                // recomputed at the rounded distance, and the candidate is kept only if it still reaches mml.
                int rounded = RoundUpTiny(off);
                if (rounded == 0 || rounded > pos) continue;     // local_10 <= absPos (valid backref) else skip
                int rlen = MatchLength(data, pos - rounded, pos, matchLimit);
                if (rlen < mml) continue;                        // param_5 <= recomputed len else skip
                useLen = rlen;
                useOff = rounded;
            }
            if (IsAllowedNormalMatch(useLen, useOff) && IsNormalMatchBetter(useLen, useOff, bestNewLen, bestNewOff))
            {
                bestNewLen = useLen;
                bestNewOff = useOff;
            }
        }

        // Final pick (reference routine): keep the rep unless the new match is clearly longer. When the rep is
        // kept its length is >= 2 (TakeNewOverRep returns false only for repLen >= 2), so bestRepIdx is valid.
        if (!TakeNewOverRep(bestRepLen, bestNewLen, bestNewOff))
            return new Cand(bestRepLen, bestRepIdx == 0 ? r0 : bestRepIdx == 1 ? r1 : r2, bestRepIdx);
        return bestNewLen > 0 ? new Cand(bestNewLen, bestNewOff, 3) : new Cand(0, 0, -1);
    }

    /// <summary>
    /// Reproduces the reference SuffixTrie2 <c>find_all_matches</c> output: the per-position Pareto frontier (closest
    /// offset per achievable length), capped to the 4 longest pairs, length-descending. Walks the full-history
    /// 4-byte hash chain most-recent-first (distance ascending) and records (len,dist) only when len exceeds
    /// the running best. This is the same walk <see cref="FindCandidates"/> uses for the DP, minus the
    /// synthetic off-8 append the greedy selector must not see.
    /// </summary>
    private static int FindParetoPairs(ReadOnlySpan<byte> data, int pos, int[] head, int[] prev,
        int matchLimit, Span<int> outLen, Span<int> outDist)
    {
        Span<int> fl = stackalloc int[64];
        Span<int> fd = stackalloc int[64];
        int fn = 0;
        int bestLen = 0;
        int distFloor = UseTinyOffsetRemap ? 1 : MinDistance; // include dist 1..7 so the selector can round them up
        // the reference SuffixTrie2 (num_firstbytes=2) records the closest match of EVERY achievable length down to
        // its minimum, and a single such table is shared by all three greedy pre-passes (mml 4/3/8). The
        // mml=3 pass therefore sees length-3 NEW matches the mml=4/8 passes filter out. Mirror that by
        // recording down to the pass's effective mml (3 when GreedyMmlOverride==3) rather than the constant
        // MinMatch. Production (GreedyMmlOverride==0) is unchanged: it still gates at MinMatch (4).
        int recordMml = GreedyMmlOverride > 0 ? GreedyMmlOverride : MinMatch;
        uint hs = Hash(data, pos);
        int c = head[hs];
        while (c >= 0)
        {
            int dist = pos - c;
            if (dist >= distFloor)
            {
                int len = MatchLength(data, c, pos, matchLimit);
                if (len > bestLen)
                {
                    bestLen = len;
                    if (len >= recordMml && fn < fl.Length) { fl[fn] = len; fd[fn] = dist; fn++; }
                }
            }
            c = prev[c];
        }
        int keep = fn > 4 ? 4 : fn;
        for (int i = 0; i < keep; i++)
        {
            int idx = fn - 1 - i; // length-ascending walk → take the last 'keep' validated = longest first
            outLen[i] = fl[idx];
            outDist[i] = fd[idx];
        }
        return keep;
    }

    /// <summary>
    /// Rep-match length with the reference mml2 quantization (reference routine): 0 for fewer than 2 matching leading
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
    /// reference routine (newLZ asymmetric match comparator): is the new (len,off) strictly better than the current
    /// best (len,off)? Longer always wins; equal length prefers the closer offset; one byte longer wins only if
    /// the new offset is within 128× the incumbent; two-or-more longer always wins. The first candidate
    /// (best = 0) is always accepted since any candidate length is &gt;= mml &gt;= 2.
    /// </summary>
    private static bool IsNormalMatchBetter(int newml, int newoff, int bestml, int bestoff)
    {
        if (newml < bestml) return false;
        if (newml == bestml) return newoff < bestoff;
        if (newml >= bestml + 2) return true;
        return (newoff >> 7) <= bestoff; // newml == bestml + 1
    }

    /// <summary>
    /// reference routine: should the new match be taken over the rep match? the reference is strongly rep-biased — a new
    /// match must be at least 2 longer than the rep, and longer still as its offset grows (3+ longer for
    /// offset &gt;= 0x400, 4+ longer for offset &gt;= 0x10000). A rep shorter than 2 always loses.
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
    /// reference routine (IsAllowedNormalMatch). Short matches (ml &lt; 6) are gated by an offset ceiling
    /// (<see cref="NormalMatchOffsetThreshold"/>); ml &gt;= 6 is always allowed. The far-offset gate
    /// reference routine is a proven no-op for our window: cfg[0x44] = window bits = 18, so
    /// <c>off &lt; (1&lt;&lt;18)</c> holds for every offset in a &lt;=256KB window and f2350 returns
    /// <c>off &lt; 0x100000 = true</c>.
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
                r2 = r1; r1 = r0; r0 = dist; // new offset: [dist, r0, r1]
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
    // Reference Optimal3 (Kraken level-7) forward float-cost DP — validated against
    // the reference routine (newLZ_encode_chunk_optimal_tll, single-TLL
    // path, num_tlls=1, max_search_lrl=3) against reference behavior. Opt-in: the shipped value-model greedy Parse
    // stays the validated production default; when UseOptimalParse is set, EncodeChunk routes here.
    // The integer cost model (KrakenOptimalCost) is validated byte-exact and validated separately.
    // ===========================================================================================

    /// <summary>
    /// When true, <see cref="EncodeChunk"/> parses with the validated reference Optimal3 forward cost DP
    /// (<see cref="ParseOptimal"/>) instead of the value-model greedy <see cref="Parse"/>. Default off:
    /// the greedy parse is the validated production default until the DP is byte-identical to the reference.
    /// </summary>
    internal static bool UseOptimalParse;

    /// <summary>
    /// When true (and <see cref="UseOptimalParse"/> is set), the forward DP's candidate finder is the reference
    /// CacheTableMatchFinder (CTMF) instead of an unbounded hash chain. validated against
    /// the reference implementation <c>CacheTableMatchFinder::ProcessChunk</c> (reference routine): a
    /// <b>two-row, sixteen-way</b> check-bit cache. Each entry is a u32 {position:26, check:6}; a query scans
    /// the 32 most-recent same-context positions (16 ways × 2 hash rows) and emits strictly-length-improving
    /// (len,dist) pairs (the <c>len &gt; prevml</c> selection in ProcessChunk). The bounded cache evicts the
    /// cheap periodic near-copies the unbounded chain surfaces, which is what forces the reference farther-offset
    /// choices. The far periodic copies the 16-way recency eviction drops (text cmd-20 dist-551, cmd-34
    /// dist-950) come from the reference windowed long-range matcher (see <see cref="UseLrmSupplement"/>), unioned in.
    /// </summary>
    internal static bool UseCtmfFinder = true;

    /// <summary>
    /// Diagnostic: when CTMF is active, ALSO walk the unbounded hash chain and union both candidate sets
    /// (the reference <c>find_all_matches</c> returns up to 4 pairs unioned from the CTMF and a long-range matcher).
    /// Lets the DP see far periodic copies the 4-way cache evicted (e.g. the text-vector cmd-34 dist-950 match).
    /// </summary>
    /// <summary>Diagnostic (default 0 = 16): override the CTMF bucket depth (ways per bucket, power of two).</summary>
    internal static int CtmfWaysOverride = 0;

    internal static bool UseChainUnion = false;

    /// <summary>
    /// Diagnostic (LRM-equivalent): when the CTMF is active, ALSO walk the deep hash chain but contribute ONLY
    /// matches STRICTLY LONGER than the CTMF's best at this position. This mirrors the reference windowed long-range
    /// matcher (LRMScannerWindowed_FindMatchAndRoll, reference routine), which surfaces the FAR periodic copy the
    /// CTMF's 16-way recency eviction drops (text-vector cmd-20 dist-551, cmd-34 dist-950) — without re-introducing
    /// the equal-length NEAR copies a naive <see cref="UseChainUnion"/> surfaces (which re-breaks cmd-20). The
    /// strictly-longer gate is the faithful "len &gt; prevml" pair-selection semantics observed in ProcessChunk.
    /// </summary>
    internal static bool UseLrmSupplement = false;

    /// <summary>
    /// Reproduces the OUTPUT of the reference level-7 (Optimal3) match finder
    /// <c>SuffixTrie2::SuffixTrie2MatchFinder::ProcessChunk</c> (the reference implementation
    /// reference routine; ctor reference routine installs <c>SuffixTrie2::SuffixTrie2MatchFinder::vftable</c>,
    /// source <c>suffixtrie2.inl</c>; created by <c>SuffixTrie_CreateMatchFinder</c> reference routine,
    /// selected for levels ≥6 by <c>Kraken_FillVTable</c> reference routine). The optimal parser asserts
    /// <c>find_all_matches_num_pairs == 4</c> (reference routine), i.e. up to 4 (len,offset) pairs
    /// per position.
    /// <para>★ ROOT-CAUSE CORRECTION: levels 0-4 (greedy/fast) use the 2-row 16-way
    /// <c>CacheTableMatchFinder</c> (the <see cref="Ctmf"/> implementation); levels 5/6+ (Optimal1/2/3…) use this
    /// <b>full-history suffix trie</b>. A suffix trie keeps the ENTIRE window (no 16-way recency eviction),
    /// so it retains the far periodic copy the cache drops (text cmd-34 dist-950 @ pos 6, ~17 periods back).
    /// That is exactly why the faithful 16-way cache could not surface dist-950 while the reference emits it.</para>
    /// <para>A suffix trie is only an acceleration structure; its <c>find_all_matches</c> output is the
    /// per-position <b>Pareto frontier</b> (closest offset for each achievable length), capped to the 4
    /// longest, ml-descending. That output is reproducible by an exhaustive full-depth walk of the 4-byte
    /// hash chain: every length≥4 match source shares the position's first 4 bytes, so it is in the bucket;
    /// <see cref="MatchLength"/> verifies the bytes. When set (with <see cref="UseOptimalParse"/>), the
    /// finder supplies this exhaustive Pareto set instead of the cache query.</para>
    /// <para>★★★ EMPIRICALLY DECISIVE (diagnostic comparison fixpoint reference, analysis-grounded): switching the finder from
    /// the 16-way cache to this full-history Pareto walk advanced the text-vector parse divergence from
    /// <b>cmd 34 → cmd 124</b> (90 commands) — the single largest convergence jump of the whole effort, and
    /// proof the suffix-trie-full-history model is the correct level-7 finder (the prior "check-bit cache
    /// retention" / "LRM union" conclusions were artifacts of modeling the wrong, levels-0-4 finder). LRM
    /// stays delta-0 (DP invariant holds). Default ON so <see cref="UseOptimalParse"/> uses the validated-
    /// correct finder; it stays gated behind <see cref="UseOptimalParse"/> (default off) so production is
    /// unaffected.</para>
    /// <para>★ THE cmd-124 RESIDUAL is NOT this finder and NOT the sublen-fill window. The sublen-fill gate
    /// <c>reference routine(cfg,len) = (uint)(len-cfg.lo) &lt; cfg.range</c> with level-7 cfg <c>rep={3,125}</c>,
    /// <c>new={mml+1,123}</c> reduces to <c>len &lt; (1&lt;&lt;min(level,8)) = 128</c> (reference routine lines
    /// 376-379) — every text match (len ≤ ~57) fills sublens, exactly like this implementation's FILL-ALL, so there is
    /// no over-supply there. The DP min-match is <c>mml = max(4, options[4]) = 4</c> (line 309); the reference
    /// length-3 NEW matches (text cmd-125 <c>mat=3 dist=237</c>) come ONLY from the <b>mml=3 greedy
    /// pre-pass</b> (lines 318/325/354), not the DP. The residual is the reference outer selection (lines 311-352):
    /// it runs greedy pre-passes at mml=3, mml=4 and mml=8 (<c>newLZ_encode_chunk_optimal_greedy</c>
    /// reference routine), seeds the histogram from the cheapest, and keeps the min-cost parse across
    /// {greedy-mml-3/4/8, DP} under a FLOAT size estimate (param_10/param_11). That float-cost
    /// multi-greedy-mml selection is the documented reference-less cost-fixpoint wall (same class as
    /// cmd-23/cmd-35), now pushed from cmd-34 to cmd-124. Reproducing it byte-exact needs the reference short-match
    /// (3-byte) greedy finder + the float outer-cost order — not yet validated; not speculated.</para>
    /// </summary>
    internal static bool UseSuffixTrieFinder = true;

    /// <summary>Diagnostic (default off): query only CTMF row B (the validated 8-byte hash2), ignoring row A.</summary>
    internal static bool CtmfRowAOff = false;

    /// <summary>Diagnostic (default 0 = auto): override the CTMF table bits (tableBits) used by the finder.</summary>
    internal static int CtmfBitsOverride = 0;

    /// <summary>
    /// Greedy minimum-match override (0 = use <see cref="MinMatch"/> = 4). the reference level-7 optimal encoder
    /// runs <c>newLZ_encode_chunk_optimal_greedy</c> (reference routine) as up to three pre-passes with
    /// mml ∈ {4, 3, 8} (reference routine lines 311-355: mml=4 always, mml=3 when level&gt;6 &amp;&amp; opt[4]&lt;4,
    /// mml=8 when opt[4]&lt;8) and keeps each whose float emit-cost is lower. The mml=3 pre-pass is the ONLY
    /// source of the reference length-3 NEW matches (the DP min-match is fixed at 4). Set per-thread by
    /// <see cref="DiagGreedyParse"/> so a single parameterised greedy can model each pre-pass.
    /// </summary>
    [ThreadStatic] internal static int GreedyMmlOverride;

    /// <summary>
    /// Greedy hash-chain width override (0 = the default 4-byte hash). For the mml=3 pre-pass the finder must
    /// surface length-3 new matches, which a 4-byte hash chain cannot (its members share 4 bytes). Set to 3
    /// to switch <see cref="Hash"/> to a 3-byte hash so positions sharing only 3 bytes land in the same
    /// bucket; <see cref="MatchLength"/> still verifies the true match length. Set per-thread by
    /// <see cref="DiagGreedyParse"/>.
    /// </summary>
    [ThreadStatic] internal static int GreedyHashBytesOverride;

    /// <summary>
    /// When true (and <see cref="UseOptimalParse"/> is set), each match relax also runs the reference rep0-continuation
    /// pre-relax (reference routine): after placing a match ending at E with new front-offset d, it values the
    /// immediate rep0 continuation [3-byte transition + forward rep0 match at d] and relaxes the arrival at its
    /// end, bundling the continuation into field [6] of that arrival. This is a "poor man's multi-arrival" that
    /// lets a locally-non-minimal match still propagate its free rep cascade (the cmd-21 defer-to-lock-rep case).
    /// validated against the reference routine + its two call sites in reference routine.
    /// </summary>
    internal static bool UseFaef0 = true;

    /// <summary>
    /// When set (with the greedy <see cref="Parse"/>), the per-position selector is the byte-exact implementation of
    /// the reference <c>newLZ_get_match_heuristic</c> (reference routine) — <see cref="FindMatchExact"/> — instead of the
    /// value-model <see cref="FindMatch"/>. It reproduces the reference greedy decision chain exactly: rep search with
    /// mml2 quantization (reference routine), <see cref="IsAllowedNormalMatch"/> (reference routine + the always-true
    /// far gate reference routine for ≤256KB windows), <see cref="IsNormalMatchBetter"/> (reference routine) and
    /// <see cref="TakeNewOverRep"/> (reference routine), reading the 4-pair Pareto frontier from the full-history
    /// SuffixTrie2 walk. The goal is <c>Tally(the greedy parse) == Tally(the reference greedy)</c> so the single level-7 DP
    /// pass under the greedy histogram reproduces the reference emitted parse (the one-DP-pass byte-identity model).
    /// Thread-static, default off ⇒ the production greedy path is byte-identical to before.
    /// </summary>
    [ThreadStatic] internal static bool UseExactGreedy;

    /// <summary>
    /// Diagnostic (default off): apply the <see cref="DecaySeedPassinfo"/> (<c>fc430</c>) per-region
    /// histogram decay to the greedy seed Tally before the single DP pass builds its cost tables, exactly
    /// as the reference does for a standalone level-7 chunk. Thread-static so the production path is unaffected.
    /// </summary>
    [ThreadStatic] internal static bool UseSeedDecay;

    /// <summary>
    /// Diagnostic (default off): run the level-7 forward DP with the SuffixTrie2 <c>find_all_matches</c>
    /// minimum match length of <b>3</b> (mml=3, <c>SuffixTrie_CreateMatchFinder</c>
    /// firstbytes=2 ⇒ the trie reports length-3 matches at lvl7). The DP's candidate chain is built with a
    /// 3-byte hash so positions sharing only 3 bytes collide, the Pareto frontier records length-3 pairs, and
    /// a length-3 NEW match is relaxed as a primary (the sublen-FILL floor stays 4 per the new cfg
    /// <c>lo=local_3190+1=4</c>). This surfaces the reference text cmd-125 <c>mat3 dist237</c> the 4-byte finder
    /// structurally cannot. Thread-static so the production path (4-byte finder) is unaffected.
    /// </summary>
    [ThreadStatic] internal static bool UseDpMml3;

    /// <summary>The SuffixTrie2 find_all_matches minimum match length at level 7 ( firstbytes=2 ⇒ 3).</summary>
    private const int DpMml3 = 3;

    /// <summary>
    /// Diagnostic (default off): enable the per-match <b>sublen-FILL</b> in <see cref="ForwardDp"/> with the reference
    /// predicate <c>reference routine(cfg,len) = (uint)(len − cfg[0]) &lt; (uint)cfg[1]</c> instead of filling every
    /// sublength unconditionally. validated against <c>reference routine</c> lines 376-379: the per-pass cfg
    /// is built by <c>reference routine(cfg, A, B) ⇒ cfg = {A, B−A}</c> with <c>B = local_185c = 1&lt;&lt;level = 128</c>
    /// (lvl7). REP cfg <c>local_1850 = {3, 125}</c>; NEW cfg <c>local_1830 = {local_3190+1, 128−(local_3190+1)}</c>
    /// (<c>local_3190 = 3</c> on the lvl7 mml=3 path ⇒ <c>{4, 124}</c>). Both collapse to "fill sublengths only
    /// when the match length &lt; 128": the reference always relaxes the FULL-length match, then fills shorter lengths
    /// ONLY inside the window. Earlier FILL-ALL over-relaxed long matches (≥128 B, e.g. the rep8_4k/zeros4k
    /// 4080-byte runs), creating thousands of intermediate arrivals the reference never makes. Thread-static, default off
    /// so the production path is byte-identical to before; A/B'd via diagnostic comparison.
    /// </summary>
    [ThreadStatic] internal static bool UseSublenGate;

    /// <summary>the reference sublen-fill window high bound <c>local_185c = 1&lt;&lt;level</c> (level 7 ⇒ 128).</summary>
    private const int SublenFillThreshold = 128;

    /// <summary>
    /// the reference sublen-fill predicate <c>reference routine</c>: fill is allowed iff <c>(uint)(len − lo) &lt; range</c>
    /// (cfg <c>{lo, range}</c> from the helper-style <c>{A, B−A}</c>). Unsigned compare folds
    /// the lower bound (<c>len &lt; lo</c> underflows to a huge value ⇒ false) into a single branch.
    /// </summary>
    private static bool SublenFillAllowed(int lo, int range, int len) => (uint)(len - lo) < (uint)range;

    /// <summary>
    /// Diagnostic (default off): on an EXACT-cost arrival tie, keep the LATER-tried relaxation instead of the
    /// first one (i.e. use <c>total &lt;= arr[dst].Cost</c> rather than strict <c>&lt;</c> in
    /// <see cref="RelaxRep"/>/<see cref="RelaxNew"/>). validated from the cmd-20 divergence: under the reference exact
    /// captured seed the two local paths (<c>1 lit + match@556</c> vs <c>2 lit + match@557</c>, both len-47,
    /// distances 551 vs 496 in the SAME offset bucket) cost <b>byte-identically</b> (proven term-by-term via the
    /// diagnostic comparison cost probe: lit/packet/offset all equal, delta 0). the reference keeps the path whose match starts one
    /// byte EARLIER (src 603, the longer LRL=2 run at pos 605) — i.e. with the ascending LRL loop the last equal
    /// relaxation wins. Strict-<c>&lt;</c> kept the first (src 604) path. Thread-static, default off so the
    /// production path is unchanged; A/B'd via diagnostic comparison (must extend EXTSEED call0 past cmd-20 while keeping the
    /// zeros/rep8_4k vectors byte-exact).
    /// </summary>
    [ThreadStatic] internal static bool UseTieBreakLast;

    /// <summary>Diagnostic (default 0/0 = off): when <see cref="DpProbeHi"/> &gt; 0, <see cref="ForwardDp"/>
    /// dumps the final arrival row (cost, src, lrl, ml, idx, dist, reps) for every position in
    /// <c>[DpProbeLo, DpProbeHi]</c> after the forward pass. Lets the diagnostic see exactly which arrivals the DP
    /// materialized at the cmd-20 reconvergence (is the reference match@556→arrival[603] path even created?).</summary>
    [ThreadStatic] internal static int DpProbeLo;
    /// <summary>Upper bound (inclusive) of the <see cref="DpProbeLo"/> arrival dump; 0 disables.</summary>
    [ThreadStatic] internal static int DpProbeHi;
    /// <summary>Diagnostic (default 0 = off): when <c>pos == DpTracePos</c> in <see cref="ForwardDp"/>,
    /// dump each LRL iteration's src / arrival cost / r0 / literal cost / base cost, plus the arr[DpTraceDst]
    /// state after each iteration. Lets the diagnostic see the exact tie-break ordering at a divergence pos.</summary>
    [ThreadStatic] internal static int DpTracePos;
    /// <summary>Companion to <see cref="DpTracePos"/>: the arrival index whose state is printed after each LRL iter.</summary>
    [ThreadStatic] internal static int DpTraceDst;
    /// <summary>Diagnostic (default 0 = off): when a rep/new relax writes (or attempts) arr[DiagWatchDst],
    /// log pos / ml / loi / base / matchcost / total / won. Pins which path sets a contested arrival cost.</summary>
    [ThreadStatic] internal static int DiagWatchDst;
    /// <summary>Diagnostic / reference diagnostic ONLY (default null): when set, <see cref="FindCandidates"/>
    /// ignores the managed hash-chain finder and instead reads the reference captured per-position match table —
    /// a flat array of <c>npos*8</c> ints (4 <c>(len,dist)</c> pairs/pos, length-descending, len&lt;=0 terminator),
    /// exactly the SuffixTrie2 ProcessChunk output in <c>finder_call1.bin</c>. Used to prove the LZ-parse gap is
    /// 100% the finder (len-2/3 short matches the 4-byte-hash finder can't surface) without implementing the trie.</summary>
    [ThreadStatic] internal static int[]? DiagExternalFinder;

    /// <summary>DIAGNOSTIC only: raw 0x1808-byte codecost blob captured live from the reference
    /// encoder (faef0 <c>param_14</c>). When set, <see cref="DiagDpFromExternalPassinfo"/> drives the DP
    /// with this EXACT codecost (via <see cref="KrakenOptimalCost.FromRawBlob"/>) instead of building from
    /// the passinfo seed — isolating "wrong codecost" from "wrong DP recurrence".</summary>
    [ThreadStatic] internal static byte[]? DiagExternalCodeCostBlob;

    /// <summary>
    /// Diagnostic (default off): implement the reference tiny-offset round-up branch (<c>newLZ_offset44_round_up_tiny</c>,
    /// reference routine, table <c>DAT_180714048</c>) into the exact-greedy selector (reference routine lines 113-124)
    /// AND the level-7 DP candidate set (reference routine line 635). A new-match candidate whose distance is
    /// &lt; 8 (sub-<see cref="MinDistance"/>, un-codeable in the offset44 scheme) is NOT discarded as the Pareto
    /// walk otherwise does; the reference rounds the distance up to the smallest codeable distance that preserves the
    /// tiny period (<see cref="RoundUpTinyTable"/>), recomputes the match length at that rounded distance
    /// (reference routine → reference routine), and — if it still reaches the mml — feeds it through the normal
    /// allowed/better gates. This is the last not-yet-modeled greedy micro-branch; surfacing these short-period
    /// candidates perturbs the greedy <c>Tally</c> histogram that seeds the one-DP-pass cost tables. Thread-static
    /// so the production path (which never sees dist&lt;8) is byte-identical to before.
    /// </summary>
    [ThreadStatic] internal static bool UseTinyOffsetRemap;

    /// <summary>
    /// <c>newLZ_offset44_round_up_tiny</c> table <c>DAT_180714048</c> (read byte-exact against reference behavior): maps a
    /// tiny distance 1..7 to the smallest offset44-codeable distance (≥8) that preserves the tiny period
    /// (1→8, 2→8, 3→9, 4→8, 5→10, 6→12, 7→14). Index 0 is unused (distance is always ≥1).
    /// </summary>
    private static readonly int[] RoundUpTinyTable = { 0, 8, 8, 9, 8, 10, 12, 14 };

    /// <summary>Rounds a tiny distance (1..7) up to its offset44-codeable equivalent via <see cref="RoundUpTinyTable"/>.</summary>
    private static int RoundUpTiny(int dist) => RoundUpTinyTable[dist];

    /// <summary>A forward-DP arrival: the cheapest way to reach a buffer position (the reference 0x28-byte record).</summary>
    private struct Arrival
    {
        public int Cost;          // 0x7fffffff = unreached
        public int R0, R1, R2;    // the three recent offsets at this arrival
        public int Ml, Lrl, Src;  // command that produced it: Lrl literals at Src, then a match of Ml
        public int Idx, Dist;     // OffsIndex (0/1/2 rep, 3 new) and the chosen distance
        public int ContLrl, ContMl; // the reference field [6]: a free rep0 continuation bundled into this arrival
                                     // (ContLrl literals then a rep0 match of ContMl at distance R0); 0 = none
    }

    /// <summary>
    /// Reference Optimal3 parse: seed the integer cost model from the greedy value-model parse, then iterate
    /// the forward DP (<see cref="ForwardDp"/>) to a fixpoint, keeping the lowest-cost command list. The
    /// greedy result is the fallback and the lower bound (the DP can never be selected if it scores worse
    /// under the seed cost model, so this never regresses ratio). Mirrors <see cref="Parse"/>'s signature.
    /// </summary>
    private static List<Command> ParseOptimal(ReadOnlySpan<byte> data, int[] head, int[] prev,
        int startPos, int litStart0, int matchLimit, int matchStartLimit)
    {
        var greedy = Parse(data, head, prev, startPos, litStart0, matchLimit, matchStartLimit);
        if (greedy.Count == 0)
            return greedy;

        int chunkEnd = matchLimit + LiteralTail;

        // Private causal hash chain for the DP candidate finder (independent of the caller's chain,
        // which the greedy seed above leaves advanced for the next chunk).
        var dpHead = new int[HashSize];
        var dpPrev = new int[data.Length];

        // Score every candidate parse under a single consistent model (the greedy seed's) so selection
        // is apples-to-apples and never picks a parse worse than greedy. litMode for the cost build is
        // the greedy seed's f3130 sub-vs-raw choice (the reference seeds the DP's codecosts[0] with the winning
        // greedy's litMode), not a hardcoded raw.
        int seedLitMode = LitModeForParse(data, greedy, chunkEnd, useHuffmanArrays: true);
        var cc0 = KrakenOptimalCost.BuildFromPassinfo(Tally(greedy, data, startPos), seedLitMode);
        var best = greedy;
        long bestCost = CostOfParse(greedy, data, startPos, chunkEnd, cc0);

        int[] passinfo = Tally(greedy, data, startPos);
        List<Command>? prevParse = null;
        for (int pass = 0; pass < 8; pass++)
        {
            var cc = KrakenOptimalCost.BuildFromPassinfo(passinfo, seedLitMode);
            var parsed = ForwardDp(data, dpHead, dpPrev, startPos, matchLimit, matchStartLimit, cc);
            if (parsed.Count == 0)
                break;
            long sc = CostOfParse(parsed, data, startPos, chunkEnd, cc0);
            if (sc < bestCost)
            {
                bestCost = sc;
                best = parsed;
            }
            if (prevParse != null && SameParse(prevParse, parsed))
                break; // fixpoint: the parse stopped changing
            prevParse = parsed;
            passinfo = Tally(parsed, data, startPos);
        }
        return best;
    }

    // =====================================================================================
    // DIAGNOSTIC HOOK (diagnostic comparison fixpoint reference) — NOT used by production. Seeds the DP's pass
    // histogram from an externally supplied parse (e.g. the reference own decoded parse), then runs ONE
    // forward-DP pass under those tables and returns the DP parse + both parses' costs. If the DP
    // reproduces the seed parse, the DP recurrence + integer cost model are byte-correct and any
    // residual divergence is purely the seed/finder basin; otherwise the first differing command
    // localizes a actual DP bug. Single seeded chunk (startPos = 8; the diagnostic comparison vectors < ChunkMax).
    // Parallel arrays keep the private Command/Arrival types off the public surface.
    // =====================================================================================
    internal static void DiagDpFromSeed(
        byte[] data,
        int[] seedLitStart, int[] seedLitLen, int[] seedDist, int[] seedMatch, int[] seedIdx,
        out int[] dpLitStart, out int[] dpLitLen, out int[] dpDist, out int[] dpMatch, out int[] dpIdx,
        out long dpCost, out long seedCost)
    {
        int n = data.Length;
        int matchLimit = n - LiteralTail;
        int matchStartLimit = n - NoMatchZone;
        int startPos = 8;
        int chunkEnd = n;

        var seed = new List<Command>(seedLitStart.Length);
        for (int i = 0; i < seedLitStart.Length; i++)
            seed.Add(new Command(seedLitStart[i], seedLitLen[i], seedDist[i], seedMatch[i], seedIdx[i]));

        int[] passinfo = Tally(seed, data, startPos);
        if (UseSeedDecay) DecaySeedPassinfo(passinfo);
        var cc = KrakenOptimalCost.BuildFromPassinfo(passinfo, LitModeForParse(data, seed, chunkEnd, useHuffmanArrays: true));

        var dpHead = new int[HashSize];
        var dpPrev = new int[n];
        var dp = ForwardDp(data, dpHead, dpPrev, startPos, matchLimit, matchStartLimit, cc);

        dpLitStart = new int[dp.Count]; dpLitLen = new int[dp.Count];
        dpDist = new int[dp.Count]; dpMatch = new int[dp.Count]; dpIdx = new int[dp.Count];
        for (int i = 0; i < dp.Count; i++)
        {
            dpLitStart[i] = dp[i].LitStart; dpLitLen[i] = dp[i].LitLen;
            dpDist[i] = dp[i].Distance; dpMatch[i] = dp[i].MatchLen; dpIdx[i] = dp[i].OffsIndex;
        }
        dpCost = CostOfParse(dp, data, startPos, chunkEnd, cc);
        seedCost = CostOfParse(seed, data, startPos, chunkEnd, cc);
    }

    // =====================================================================================
    // DIAGNOSTIC HOOK (interop reference) — NOT production. Runs ONE forward-DP pass using
    // the reference EXACT seed histogram captured by the seeddump diagnostic (the fc180 passinfo arg, dumped
    // from rcx). The dump is in the reference fc180 passinfo layout (int offsets):
    //   [0]    lit mode (1 = raw)
    //   [2..0x101]    lit histogram (256)
    //   [0x102..0x201] packet histogram (256)
    //   [0x202]       offset_alt_modulo
    //   [0x203..0x302] offset-bucket histogram (256)
    //   [0x303..0x402] offset-alt histogram (256)
    //   [0x403..0x502] length histogram (256)
    // This is TRANSLATED into the BuildFromPassinfo 0x601-int layout (raw@0/sub@0x100/packet@0x200/
    // length@0x300/modulo@0x400/offbucket@0x401/offalt@0x501), cost tables are built via the byte-exact
    // fc180 implementation, and ONE ForwardDp pass runs under them. Decisive test: if DP(the reference true seed) ==
    // the reference parse, the residual is purely the seed (match the reference greedy/decay in managed code); if it
    // still diverges, it is a DP bug the fixpoint reference's flatter histogram happened to avoid.
    // =====================================================================================
    internal static void DiagDpFromExternalPassinfo(
        byte[] data, int[] referencePassinfo, int litMode,
        out int[] dpLitLen, out int[] dpDist, out int[] dpMatch, out int[] dpIdx)
    {
        int n = data.Length;
        int matchLimit = n - LiteralTail;
        int matchStartLimit = n - NoMatchZone;
        int startPos = 8;

        // CORRECTED LAYOUT (proven byte-exact via the ccdiff diagnostic): the seeddump `call*_rcx`
        // capture is the fc180 `passinfo` arg (rcx), and the reference fc180 reads it in EXACTLY my
        // BuildFromPassinfo 0x601-int layout — raw@0, sub@0x100, packet@0x200, length@0x300,
        // modulo@0x400, offbucket@0x401, offalt@0x501. No translation is needed; copy verbatim.
        // litMode is NOT in passinfo — it is codecosts[0] (`*param_9`, the winning greedy's choice),
        // captured separately in `call*_rdx`. The caller passes it in explicitly.
        var pi = new int[0x601];
        Array.Copy(referencePassinfo, pi, Math.Min(referencePassinfo.Length, 0x601));

        // DIAGNOSTIC only: if a raw codecost blob is injected, drive the DP with the reference
        // EXACT captured codecost (faef0 param_14) instead of building from the passinfo seed. This
        // isolates "wrong codecost" from "wrong DP recurrence".
        var cc = DiagExternalCodeCostBlob != null
            ? KrakenOptimalCost.FromRawBlob(DiagExternalCodeCostBlob)
            : KrakenOptimalCost.BuildFromPassinfo(pi, litMode);

        var dpHead = new int[HashSize];
        var dpPrev = new int[n];
        var dp = ForwardDp(data, dpHead, dpPrev, startPos, matchLimit, matchStartLimit, cc);

        dpLitLen = new int[dp.Count]; dpDist = new int[dp.Count];
        dpMatch = new int[dp.Count]; dpIdx = new int[dp.Count];
        for (int i = 0; i < dp.Count; i++)
        {
            dpLitLen[i] = dp[i].LitLen; dpDist[i] = dp[i].Distance;
            dpMatch[i] = dp[i].MatchLen; dpIdx[i] = dp[i].OffsIndex;
        }
    }

    // =====================================================================================
    // DIAGNOSTIC HOOK (diagnostic comparison one-pass reference) — NOT production. Reproduces the reference level-7
    // structure byte-faithfully per the ONE-DP-PASS reference routine: run the greedy at
    // the given mml (one of the reference 4/3/8 pre-passes), tally ITS parse into passinfo, build cost
    // tables, and run EXACTLY ONE forward-DP pass under those tables. Returns both the greedy parse
    // and the one-pass DP parse so the diagnostic can check whether ForwardDp(Tally(greedy)) reproduces
    // the reference emitted parse (the make-or-break: if the greedy parse ≈ the reference greedy, the single DP pass under
    // the greedy histogram = the reference parse). Seeded exactly like a actual chunk (8 COPY_64 positions).
    // =====================================================================================
    internal static void DiagOnePassFromGreedy(
        byte[] data, int mml, int hashBytes,
        out int[] gLitLen, out int[] gDist, out int[] gMatch, out int[] gIdx,
        out int[] dpLitLen, out int[] dpDist, out int[] dpMatch, out int[] dpIdx)
    {
        int saveMml = GreedyMmlOverride, saveHb = GreedyHashBytesOverride;
        bool saveExact = UseExactGreedy;
        GreedyMmlOverride = mml;
        GreedyHashBytesOverride = hashBytes;
        UseExactGreedy = true; // the one-DP-pass model needs the byte-exact greedy seed
        try
        {
            int n = data.Length;
            int matchLimit = n - LiteralTail;
            int matchStartLimit = n - NoMatchZone;
            int startPos = 8;

            var head = new int[HashSize]; head.AsSpan().Fill(-1);
            var prev = new int[n]; prev.AsSpan().Fill(-1);
            for (int p = 0; p < startPos; p++) Insert(data, p, head, prev);

            var greedy = Parse(data, head, prev, startPos, startPos, matchLimit, matchStartLimit);

            // Tally(greedy) → [fc430 seed decay] → cost tables → ONE forward-DP pass (the reference level-7 structure).
            int[] passinfo = Tally(greedy, data, startPos);
            if (UseSeedDecay) DecaySeedPassinfo(passinfo);
            var cc = KrakenOptimalCost.BuildFromPassinfo(passinfo, LitModeForParse(data, greedy, n, useHuffmanArrays: true));
            var dpHead = new int[HashSize]; dpHead.AsSpan().Fill(-1);
            var dpPrev = new int[n];
            var dp = ForwardDp(data, dpHead, dpPrev, startPos, matchLimit, matchStartLimit, cc);

            gLitLen = new int[greedy.Count]; gDist = new int[greedy.Count];
            gMatch = new int[greedy.Count]; gIdx = new int[greedy.Count];
            for (int i = 0; i < greedy.Count; i++)
            {
                gLitLen[i] = greedy[i].LitLen; gDist[i] = greedy[i].Distance;
                gMatch[i] = greedy[i].MatchLen; gIdx[i] = greedy[i].OffsIndex;
            }
            dpLitLen = new int[dp.Count]; dpDist = new int[dp.Count];
            dpMatch = new int[dp.Count]; dpIdx = new int[dp.Count];
            for (int i = 0; i < dp.Count; i++)
            {
                dpLitLen[i] = dp[i].LitLen; dpDist[i] = dp[i].Distance;
                dpMatch[i] = dp[i].MatchLen; dpIdx[i] = dp[i].OffsIndex;
            }
        }
        finally { GreedyMmlOverride = saveMml; GreedyHashBytesOverride = saveHb; UseExactGreedy = saveExact; }
    }

    // =====================================================================================
    // DIAGNOSTIC HOOK (diagnostic comparison codecost reference) — NOT production. Builds the DP codecost EXACTLY
    // as the one-pass level-7 model does (greedy at mml/hashBytes -> Tally -> BuildFromPassinfo) and
    // exposes the four cost tables so the diagnostic can byte-diff them against the reference actual DP codecost
    // (faef0 param_14 capture). Decides whether the greedy parse Tally builds the reference codecost: if a table
    // differs, the greedy/tally is the lever (not the DP recurrence, proven byte-exact under faef0 cc).
    // =====================================================================================
    // Diagnostic: build the GREEDY SEED passinfo exactly as the reference fb270 does for verification — tally the
    // greedy parse with a chosen increment (the reference seed uses +1; the DP re-tally fbc50 uses +2) and include
    // the trailing-tail literals (chunkEnd). Returns the raw passinfo so the diagnostic can compare to the reference
    // captured pre-decay seed (decayin0.bin) and, after DecaySeedPassinfo, to the fc180 input (call1_rcx).
    internal static int[] DiagSeedPassinfo(byte[] data, int mml, int hashBytes, int inc, bool includeTail)
    {
        int saveMml = GreedyMmlOverride, saveHb = GreedyHashBytesOverride;
        bool saveExact = UseExactGreedy;
        GreedyMmlOverride = mml;
        GreedyHashBytesOverride = hashBytes;
        UseExactGreedy = true;
        try
        {
            int n = data.Length;
            int matchLimit = n - LiteralTail;
            int matchStartLimit = n - NoMatchZone;
            int startPos = 8;
            var head = new int[HashSize]; head.AsSpan().Fill(-1);
            var prev = new int[n]; prev.AsSpan().Fill(-1);
            for (int p = 0; p < startPos; p++) Insert(data, p, head, prev);
            var greedy = Parse(data, head, prev, startPos, startPos, matchLimit, matchStartLimit);
            return Tally(greedy, data, startPos, inc, includeTail ? n : -1);
        }
        finally { GreedyMmlOverride = saveMml; GreedyHashBytesOverride = saveHb; UseExactGreedy = saveExact; }
    }

    internal static void DiagGreedyCodeCost(
        byte[] data, int mml, int hashBytes, int litModeOverride,
        out int[] packet, out int[] length, out int[] lit, out int[] offbucket,
        out int litModeUsed, out int[] passinfoOut)
    {
        int saveMml = GreedyMmlOverride, saveHb = GreedyHashBytesOverride;
        bool saveExact = UseExactGreedy;
        GreedyMmlOverride = mml;
        GreedyHashBytesOverride = hashBytes;
        UseExactGreedy = true;
        try
        {
            int n = data.Length;
            int matchLimit = n - LiteralTail;
            int matchStartLimit = n - NoMatchZone;
            int startPos = 8;
            var head = new int[HashSize]; head.AsSpan().Fill(-1);
            var prev = new int[n]; prev.AsSpan().Fill(-1);
            for (int p = 0; p < startPos; p++) Insert(data, p, head, prev);
            var greedy = Parse(data, head, prev, startPos, startPos, matchLimit, matchStartLimit);
            int[] passinfo = Tally(greedy, data, startPos);
            int litMode = litModeOverride >= 0 ? litModeOverride
                : LitModeForParse(data, greedy, n, useHuffmanArrays: true);
            litModeUsed = litMode;
            var cc = KrakenOptimalCost.BuildFromPassinfo(passinfo, litMode);
            packet = (int[])cc.Packet.Clone();
            length = (int[])cc.Length.Clone();
            lit = (int[])cc.Lit.Clone();
            offbucket = (int[])cc.OffsetBucket.Clone();
            passinfoOut = passinfo;
        }
        finally { GreedyMmlOverride = saveMml; GreedyHashBytesOverride = saveHb; UseExactGreedy = saveExact; }
    }

    /// <summary>
    /// Diagnostic: run the value-model greedy (<see cref="Parse"/>) as one of the reference pre-passes at a chosen
    /// minimum match length (<paramref name="mml"/>) and hash width (<paramref name="hashBytes"/>, 3 or 4),
    /// seeded exactly like a actual chunk (8 COPY_64 seed positions indexed before parsing). the reference level-7
    /// encoder runs this at mml ∈ {4, 3, 8}; the mml=3 pass is the only producer of length-3 NEW matches.
    /// Returns the parse so the fixpoint diagnostic can test whether a faithful mml=3 greedy
    /// reproduces the reference exact text parse (the make-or-break for the float emit-size selection).
    /// </summary>
    internal static void DiagGreedyParse(
        byte[] data, int mml, int hashBytes,
        out int[] litStart, out int[] litLen, out int[] dist, out int[] match, out int[] idx)
    {
        int saveMml = GreedyMmlOverride, saveHb = GreedyHashBytesOverride;
        bool saveExact = UseExactGreedy;
        GreedyMmlOverride = mml;
        GreedyHashBytesOverride = hashBytes;
        UseExactGreedy = true; // model the reference greedy with the byte-exact selector for the comparison
        try
        {
            int n = data.Length;
            int matchLimit = n - LiteralTail;
            int matchStartLimit = n - NoMatchZone;
            int firstMatchPos = 8;
            var head = new int[HashSize]; head.AsSpan().Fill(-1);
            var prev = new int[n]; prev.AsSpan().Fill(-1);
            for (int p = 0; p < firstMatchPos; p++) Insert(data, p, head, prev);
            var parse = Parse(data, head, prev, firstMatchPos, firstMatchPos, matchLimit, matchStartLimit);
            litStart = new int[parse.Count]; litLen = new int[parse.Count];
            dist = new int[parse.Count]; match = new int[parse.Count]; idx = new int[parse.Count];
            for (int i = 0; i < parse.Count; i++)
            {
                litStart[i] = parse[i].LitStart; litLen[i] = parse[i].LitLen;
                dist[i] = parse[i].Distance; match[i] = parse[i].MatchLen; idx[i] = parse[i].OffsIndex;
            }
        }
        finally { GreedyMmlOverride = saveMml; GreedyHashBytesOverride = saveHb; UseExactGreedy = saveExact; }
    }

    /// <summary>
    /// Diagnostic: replays the reference seed parse left-to-right, building the CTMF exactly as <see cref="ForwardDp"/>
    /// does (same seed-index, same scan-then-insert order), and at each command's match-start position reports
    /// the CTMF's emitted (len,dist) pairs and whether the reference chosen distance was among them. Pinpoints whether
    /// a far new match (e.g. cmd-34 dist-950) is a genuine 16-way eviction or a implementation bug.
    /// </summary>
    internal static void DiagFinderAlongSeed(
        byte[] data, int[] seedLitStart, int[] seedLitLen, int[] seedDist, int[] seedMatch, int[] seedIdx,
        Action<string> log)
    {
        int n = data.Length;
        int matchLimit = n - LiteralTail;
        int startPos = 8;

        int ctmfBits;
        {
            int len = data.Length < 1 ? 1 : data.Length;
            int cl = 0;
            while (cl < 24 && (1 << cl) < len) cl++;
            ctmfBits = cl < 18 ? 18 : cl;
        }
        if (CtmfBitsOverride > 0) ctmfBits = CtmfBitsOverride;

        var dpHead = new int[HashSize]; dpHead.AsSpan().Fill(-1);
        var dpPrev = new int[n];
        var ctmf = new Ctmf(ctmfBits, data.Length);
        int inserted = startPos > LiteralTail ? startPos - LiteralTail : 0;
        int ctmfIns = inserted;

        Span<int> qlen = stackalloc int[40];
        Span<int> qdist = stackalloc int[40];

        for (int k = 0; k < seedLitStart.Length; k++)
        {
            if (seedIdx[k] < 0) break; // tail
            int matchPos = seedLitStart[k] + seedLitLen[k];
            if (matchPos > matchLimit) break;
            inserted = InsertUpTo(data, dpHead, dpPrev, inserted, matchPos);
            while (ctmfIns < inserted) { ctmf.Insert(data, ctmfIns); ctmfIns++; }
            int qn = ctmf.Query(data, matchPos, matchLimit, qlen, qdist);

            bool newMatch = seedIdx[k] == 3;
            bool offered = false; int offeredLen = 0;
            for (int i = 0; i < qn; i++) if (qdist[i] == seedDist[k]) { offered = true; offeredLen = qlen[i]; }

            if (newMatch)
            {
                var sb = new StringBuilder();
                for (int i = 0; i < qn; i++) sb.Append($"({qlen[i]},{qdist[i]})");
                // Also report whether pos-seedDist is genuinely present anywhere earlier (a actual match exists)
                int cand = matchPos - seedDist[k];
                int realLen = cand >= 0 ? MatchLength(data, cand, matchPos, matchLimit) : -1;
                log($"cmd{k} pos={matchPos} REF new dist={seedDist[k]} mat={seedMatch[k]} | CTMF[{qn}]={sb} | offered={offered}({offeredLen}) realLenAtDist={realLen}");
            }
        }
    }

    private static bool SameParse(List<Command> a, List<Command> b)
    {
        if (a.Count != b.Count) return false;
        for (int i = 0; i < a.Count; i++)
        {
            if (a[i].LitStart != b[i].LitStart || a[i].LitLen != b[i].LitLen ||
                a[i].Distance != b[i].Distance || a[i].MatchLen != b[i].MatchLen ||
                a[i].OffsIndex != b[i].OffsIndex)
                return false;
        }
        return true;
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
    /// <c>optimal_update_passinfo</c> (reference routine): tally a command list into a 0x601-int pass
    /// histogram (+2 per event). Tracks the three recent offsets (init distance 8) with the decoder's
    /// move-to-front so rep indices are scored correctly. litMode is raw (1); both literal histograms are
    /// filled (build picks one). Layout: [0..0xFF] lit-raw, [0x100..0x1FF] lit-sub, [0x200..0x2FF] packet,
    /// [0x300..0x3FF] length (shared LRL+ML escapes), [0x400] offset_alt_modulo (0), [0x401..0x500]
    /// offset-bucket, [0x501..0x600] offset-alt (0).
    /// </summary>
    /// <summary>
    /// <c>optimal_passinfo_seed_default</c> — the per-region histogram decay applied to the seed
    /// passinfo BEFORE the single DP pass builds its codecost tables. validated against
    /// <c>reference routine</c> (the reference implementation), which calls <c>reference routine</c> on each
    /// 256-entry region: <c>c' = (c &gt;&gt; 4) + 1</c>. This strongly smooths the greedy's raw Tally toward
    /// uniform, flattening the cost model so the level-7 DP behaves greedy-like (it stops detouring to a
    /// nearer offset just to save a single offset bit — the cmd-20 lit=1/dist=551 vs lit=2/dist=496 flip).
    /// Applies to literals-raw (0), literals-sub (0x100), packet (0x200), length (0x300), offset-bucket
    /// (0x401), and offset-alt (0x501, only when the modulo at 0x400 &gt; 1). The scalar at int-index 0x400
    /// (offset_alt_modulo) is preserved. This is the standalone-chunk path (no carried encoder state,
    /// <c>param_1[0x1e] &lt; 0</c>); the carried-merge path (fc500/fc3b0) is the multi-chunk variant.
    /// </summary>
    internal static void DecaySeedPassinfo(int[] pi)
    {
        static void Decay(int[] p, int start)
        {
            for (int i = 0; i < 0x100; i++) p[start + i] = (p[start + i] >> 4) + 1;
        }
        Decay(pi, 0x000); // literals raw
        Decay(pi, 0x100); // literals sub
        Decay(pi, 0x401); // offset bucket
        if (pi[0x400] > 1)
            Decay(pi, 0x501); // offset alt (only when modulo > 1)
        Decay(pi, 0x200); // packet
        Decay(pi, 0x300); // length
    }

    private static int[] Tally(List<Command> commands, ReadOnlySpan<byte> data, int start, int inc = 2, int chunkEnd = -1)
    {
        var pi = new int[0x601];
        int r0 = MinDistance, r1 = MinDistance, r2 = MinDistance;
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
        // Greedy SEED only (chunkEnd >= 0): the trailing literals after the last match (to chunk end) are
        // tallied into the literal histograms ONLY (no packet/length/offset event). the reference fb270 builds its
        // seed passinfo this way; the DP re-tally (fbc50, inc=2, chunkEnd=-1) does not add a tail.
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
    /// One forward-DP pass (the reference routine body, single-TLL). Fills the arrival table left to right
    /// with the anchor/accumulated-literal bookkeeping, the lrl loop (0..3, the 4th = the full run from
    /// the anchor), rep relaxation (longest-first gating) and new-match relaxation (new-minimum-base gate,
    /// length-desc candidates, break once a candidate is no longer than the longest rep), then backtraces
    /// the cheapest reachable arrival plus its trailing literals into a command list.
    /// </summary>
    private static List<Command> ForwardDp(ReadOnlySpan<byte> data, int[] dpHead, int[] dpPrev,
        int startPos, int matchLimit, int matchStartLimit, KrakenOptimalCost.CodeCosts cc)
    {
        // Level-7 SuffixTrie2 find_all_matches mml=3 ( firstbytes=2): build the DP chain AND its
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
        // must mirror that or it underfinds the very first match (the cmd-0 backward-extension divergence).
        dpHead.AsSpan().Fill(-1);
        int inserted = startPos > LiteralTail ? startPos - LiteralTail : 0;

        // the reference CacheTableMatchFinder table-bits N = clamp(ceil_log2(len), 18, 24) (reference routine/reference routine
        // saturate then ceil-log2; <19 -> 18, else min(.,24)). Even tiny buffers use N=18 (a 2^18 zero-init table),
        // so the 16-way windows + check bits behave identically to the reference regardless of input size.
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

        int anchor = startPos;
        long accLit = 0;

        Span<int> cml = stackalloc int[8];
        Span<int> cdist = stackalloc int[8];
        Span<int> coff = stackalloc int[8];

        for (int pos = startPos; pos <= matchStartLimit; pos++)
        {
            if (pos > startPos)
            {
                int alo = arr[anchor].R0 < MinDistance ? MinDistance : arr[anchor].R0;
                accLit += KrakenOptimalCost.CostAddLiteral(data, pos - 1, alo, cc);
                if (arr[pos].Cost != int.MaxValue)
                {
                    int run0 = pos - anchor;
                    long viaAnchor = (long)arr[anchor].Cost +
                                     (run0 > 2 ? KrakenOptimalCost.CostLen(cc, run0 - 3) : 0) + accLit;
                    if (arr[pos].Cost < viaAnchor)
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

                if (pos == DpTracePos)
                    Console.WriteLine($"        [dptrace] pos={pos} lrl={lrl} run={run} src={src} arr[src].cost={arr[src].Cost} r0={arr[src].R0} litcost={litcost} base={baseCost} minBase={(minBase == long.MaxValue ? -1 : minBase)}");


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

                    if (UseSublenGate)
                    {
                        // the reference routine: full-length relax always; sublen-fill gated by cfg
                        // local_1850 = {3, 125} ⇒ fill only when repLen < 128 (reference routine).
                        RelaxRep(arr, pos, repLen, loi, baseCost, litField, rdist, n1, n2, run, src, cc);
                        if (SublenFillAllowed(3, SublenFillThreshold - 3, repLen))
                            for (int m = MinRepMatch; m < repLen; m++)
                                RelaxRep(arr, pos, m, loi, baseCost, litField, rdist, n1, n2, run, src, cc);
                    }
                    else
                    {
                        int hi = repLen < MinRepMatch + 8192 ? repLen : MinRepMatch + 8192;
                        for (int m = MinRepMatch; m <= hi; m++)
                            RelaxRep(arr, pos, m, loi, baseCost, litField, rdist, n1, n2, run, src, cc);
                        if (repLen > hi)
                            RelaxRep(arr, pos, repLen, loi, baseCost, litField, rdist, n1, n2, run, src, cc);
                    }

                    // faef0: value the immediate rep0 continuation off this full-length rep match.
                    if (UseFaef0)
                    {
                        long costAtE = baseCost + KrakenOptimalCost.CostLoMatch(cc, litField, repLen, loi);
                        Faef0(arr, data, pos + repLen, costAtE, repLen, run, loi, rdist, src,
                              rdist, n1, n2, rdist, matchLimit, cc);
                    }
                }

                // New-offset matches only when this lrl iteration set a new minimum base. On an EXACT base
                // tie the reference still relaxes the (later, longer-LRL) run so its earlier-source path can win the
                // arrival tie (see UseTieBreakLast): the gate becomes <= and RelaxNew keeps the last equal.
                if (UseTieBreakLast ? baseCost <= minBase : baseCost < minBase)
                {
                    minBase = baseCost;
                    for (int i = 0; i < nc; i++)
                    {
                        int cm = cml[i];
                        if (cm <= longestlo) break; // candidates are length-desc
                        int d = cdist[i];
                        if (d == sr0 || d == sr1 || d == sr2) continue; // a recent distance is a rep, not new
                        long baseOff = baseCost + coff[i];
                        if (UseSublenGate)
                        {
                            // the reference routine: full-length relax always; sublen-fill gated by cfg
                            // local_1830 = {local_3190+1, 128−(local_3190+1)}, fill floor local_3190
                            // (= 3 on the lvl7 mml=3 path, else 4) ⇒ fill only when cm < 128.
                            int newFloor = UseDpMml3 ? 3 : 4;
                            int newLo = newFloor + 1;
                            RelaxNew(arr, pos, cm, baseOff, litField, d, sr0, sr1, run, src, cc);
                            if (SublenFillAllowed(newLo, SublenFillThreshold - newLo, cm))
                                for (int m = newFloor; m < cm; m++)
                                    RelaxNew(arr, pos, m, baseOff, litField, d, sr0, sr1, run, src, cc);
                        }
                        else
                        {
                            // the reference routine (faafdump ground truth, pos=1123 d567): the NEW-match
                            // relax loop runs over EVERY length from the DP mml (3 on the lvl7 mml=3 path,
                            // else MinMatch=4) up to the full candidate length cm — NOT from MinMatch. A
                            // len-3 sublen of a longer (cm>=4) match (e.g. arr[1126]=NEW(3,d567)) is the
                            // FIRST arrival-cost divergence vs the reference; flooring at MinMatch=4 skipped it.
                            int newFloor = UseDpMml3 ? 3 : MinMatch;
                            int hi = cm < newFloor + 8192 ? cm : newFloor + 8192;
                            for (int m = newFloor; m <= hi; m++)
                                RelaxNew(arr, pos, m, baseOff, litField, d, sr0, sr1, run, src, cc);
                            if (cm > hi)
                                RelaxNew(arr, pos, cm, baseOff, litField, d, sr0, sr1, run, src, cc);
                            else if (cm < newFloor)
                                // a finder match shorter than the floor (only possible when mml>cm):
                                // relax it directly as the primary so it is not dropped entirely.
                                RelaxNew(arr, pos, cm, baseOff, litField, d, sr0, sr1, run, src, cc);
                        }

                        // faef0: value the immediate rep0 continuation off this full-length new match.
                        if (UseFaef0)
                        {
                            long costAtE = baseOff + KrakenOptimalCost.CostNormalMatch(cc, litField, cm);
                            Faef0(arr, data, pos + cm, costAtE, cm, run, 3, d, src,
                                  d, sr0, sr1, d, matchLimit, cc);
                        }
                    }
                }

                if (pos == DpTracePos && DpTraceDst > 0 && DpTraceDst < arr.Length)
                {
                    Arrival t = arr[DpTraceDst];
                    Console.WriteLine($"        [dptrace]   after lrl={lrl}: arr[{DpTraceDst}] cost={(t.Cost == int.MaxValue ? -1 : t.Cost)} src={t.Src} lrl={t.Lrl} ml={t.Ml} idx={t.Idx} dist={t.Dist}");
                }
            }
        }

        // Cheapest reachable arrival + its trailing literal run.
        if (DpProbeHi > 0)
        {
            for (int q = DpProbeLo; q <= DpProbeHi && q < arr.Length; q++)
            {
                Arrival a = arr[q];
                if (a.Cost == int.MaxValue)
                    Console.WriteLine($"        [dpprobe] arr[{q}] UNREACHED");
                else
                    Console.WriteLine($"        [dpprobe] arr[{q}] cost={a.Cost} src={a.Src} lrl={a.Lrl} ml={a.Ml} idx={a.Idx} dist={a.Dist} reps=({a.R0},{a.R1},{a.R2}) cont(lrl={a.ContLrl},ml={a.ContMl})");
            }
        }
        int bestEnd = -1;
        long bestTotal = long.MaxValue;
        for (int e = startPos + 1; e <= matchLimit; e++)
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
        if (bestEnd < 0)
            return new List<Command>();

        var rev = new List<Command>();
        int p2 = bestEnd;
        int guard = 0;
        while (p2 != startPos && guard++ <= maxArr)
        {
            Arrival a = arr[p2];
            if (DpTraceDst > 0 && p2 >= DpTracePos - 6 && p2 <= DpTraceDst + 56)
                Console.WriteLine($"        [dpback] p2={p2} src={a.Src} lrl={a.Lrl} ml={a.Ml} idx={a.Idx} dist={a.Dist} contMl={a.ContMl} cost={(a.Cost == int.MaxValue ? -1 : a.Cost)}");
            if (a.Ml <= 0 || a.Src < startPos || a.Src >= p2)
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
        if (p2 != startPos)
            return new List<Command>(); // trace did not reach the origin → discard (greedy fallback)
        rev.Reverse();
        return rev;
        }
        finally { GreedyHashBytesOverride = saveDpHb; }
    }

    private static void RelaxRep(Arrival[] arr, int pos, int ml, int loi, long baseCost, int litField,
        int r0, int r1, int r2, int run, int src, KrakenOptimalCost.CodeCosts cc)
    {
        long total = baseCost + KrakenOptimalCost.CostLoMatch(cc, litField, ml, loi);
        int dst = pos + ml;
        if (DiagWatchDst != 0 && dst == DiagWatchDst)
            Console.WriteLine($"        [watch REP] dst={dst} pos={pos} src={src} run={run} ml={ml} loi={loi} litField={litField} base={baseCost} mc={KrakenOptimalCost.CostLoMatch(cc, litField, ml, loi)} total={total} cur={(arr[dst].Cost == int.MaxValue ? -1 : arr[dst].Cost)} won={(UseTieBreakLast ? total <= arr[dst].Cost : total < arr[dst].Cost)}");
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
        if (DiagWatchDst != 0 && dst == DiagWatchDst)
            Console.WriteLine($"        [watch NEW] dst={dst} pos={pos} src={src} run={run} ml={ml} dist={dist} litField={litField} baseWithOff={baseWithOff} mc={KrakenOptimalCost.CostNormalMatch(cc, litField, ml)} total={total} cur={(arr[dst].Cost == int.MaxValue ? -1 : arr[dst].Cost)} won={(UseTieBreakLast ? total <= arr[dst].Cost : total < arr[dst].Cost)}");
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
    /// the reference rep0-continuation pre-relax (reference routine). Given a primary match ending at <paramref name="s"/>
    /// whose post-match front offset is <paramref name="contDist"/>, this values the immediate rep0 continuation
    /// — a 3-byte literal/back-extend transition followed by a forward rep0 match at <paramref name="contDist"/> —
    /// and, when the bundled (primary + free continuation) arrival is cheaper, writes it into <c>arr[e2]</c> with
    /// the continuation packet recorded in <see cref="Arrival.ContLrl"/>/<see cref="Arrival.ContMl"/>. The
    /// continuation is always rep0, so the post-continuation recents equal the post-primary recents
    /// (<paramref name="pr0"/>,<paramref name="pr1"/>,<paramref name="pr2"/>). This is the reference "two-step arrival":
    /// it lets a locally non-minimal match still propagate its free rep cascade. validated against
    /// the reference routine (param_5 = forward-extend end cap, param_13 = recents).
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
        if (ml2 < MinRepMatch) return;             // faef0 guard: only when 1 < ml2

        long cost = costAtE + KrakenOptimalCost.CostLiterals(data, s, lrl2, d, cc);
        int litField2 = lrl2;
        if (lrl2 > 2) { litField2 = 3; cost += KrakenOptimalCost.CostLen(cc, 0); }
        cost += KrakenOptimalCost.CostLoMatch(cc, litField2, ml2, 0);   // loi 0 = rep0

        int e2 = s + lrl2 + ml2;                   // == s + 3 + fwd, always <= matchLimit
        if (DiagWatchDst != 0 && e2 == DiagWatchDst)
            Console.WriteLine($"        [watch FAEF] e2={e2} s={s} src={src} d={d} costAtE={costAtE} backExt={backExt} fwd={fwd} lrl2={lrl2} ml2={ml2} lits={KrakenOptimalCost.CostLiterals(data, s, lrl2, d, cc)} lomatch={KrakenOptimalCost.CostLoMatch(cc, litField2, ml2, 0)} total={cost} cur={(arr[e2].Cost == int.MaxValue ? -1 : arr[e2].Cost)} won={(UseTieBreakLast ? cost <= arr[e2].Cost : cost < arr[e2].Cost)}");
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
    /// <see cref="KrakenOptimalCost.CostOffset"/>. Approximates the reference find_all_matches 4-pair table.
    /// </summary>
    private static int FindCandidates(ReadOnlySpan<byte> data, int pos, int[] dpHead, int[] dpPrev,
        int matchLimit, KrakenOptimalCost.CodeCosts cc, Span<int> cml, Span<int> cdist, Span<int> coff,
        Ctmf? ctmf)
    {
        int n = 0;
        if (DiagExternalFinder != null)
        {
            // Reference diagnostic: use the reference captured ProcessChunk table verbatim (4 pairs, len-desc).
            int baseI = pos * 8;
            if (baseI + 8 <= DiagExternalFinder.Length)
            {
                int recMinE = UseDpMml3 ? DpMml3 : MinMatch;
                for (int k = 0; k < 4; k++)
                {
                    int len = DiagExternalFinder[baseI + k * 2];
                    int dist = DiagExternalFinder[baseI + k * 2 + 1];
                    if (len <= 0) break; // length-descending, len<=0 terminates
                    if (dist < MinDistance)
                    {
                        // Mirror the normal SuffixTrie path's sub-8 handling (tiny-offset round-up or skip).
                        if (!UseTinyOffsetRemap) continue;
                        int rounded = RoundUpTiny(dist);
                        if (rounded == 0 || rounded > pos) continue;
                        int rlen = MatchLength(data, pos - rounded, pos, matchLimit);
                        if (rlen < recMinE) continue;
                        len = rlen; dist = rounded;
                    }
                    if (len < recMinE) continue;
                    if (pos + len > matchLimit) len = matchLimit - pos;
                    if (len < recMinE) continue;
                    n = InsertCandidate(cml, cdist, n, len, dist, 4);
                }
            }
            int off8e = RepMatchLength(data, pos, MinDistance, matchLimit);
            if (off8e >= MinMatch)
                n = InsertCandidate(cml, cdist, n, off8e, MinDistance, cml.Length);
            for (int i = 0; i < n; i++)
                coff[i] = KrakenOptimalCost.CostOffset(cdist[i], cc);
            return n;
        }
        if (UseSuffixTrieFinder)
        {
            // Full-history Pareto finder = OUTPUT-equivalent of the reference SuffixTrie2MatchFinder::ProcessChunk
            // (reference routine). Walk the WHOLE 4-byte hash chain (most-recent-first ⇒ distance ascending). A
            // candidate is on the Pareto frontier iff it is strictly longer than every CLOSER candidate, so
            // recording (len,dist) only when len exceeds the running best yields the closest offset for each
            // achievable length. Keep the 4 LONGEST pairs (find_all_matches num_pairs==4), ml-descending.
            Span<int> fl = stackalloc int[64];
            Span<int> fd = stackalloc int[64];
            int fn = 0;
            int bestLen = 0;
            int recMin = UseDpMml3 ? DpMml3 : MinMatch; // lvl7 SuffixTrie2 find_all_matches mml (3 vs 4)
            int distFloor = UseTinyOffsetRemap ? 1 : MinDistance; // include dist 1..7 for the round-up below
            uint hs = Hash(data, pos);
            int c = dpHead[hs];
            while (c >= 0)
            {
                int dist = pos - c;
                if (dist >= distFloor)
                {
                    int len = MatchLength(data, c, pos, matchLimit);
                    if (len > bestLen)
                    {
                        bestLen = len;
                        if (len >= recMin && fn < fl.Length) { fl[fn] = len; fd[fn] = dist; fn++; }
                    }
                }
                c = dpPrev[c];
            }
            int keep = fn > 4 ? 4 : fn;
            for (int i = 0; i < keep; i++)
            {
                int idx = fn - 1 - i; // length-ascending array → longest first
                int clen = fl[idx], cdst = fd[idx];
                if (UseTinyOffsetRemap && cdst < MinDistance)
                {
                    // fc6e0 line 635: the DP rounds a sub-8 distance up and recomputes its length too.
                    int rounded = RoundUpTiny(cdst);
                    if (rounded == 0 || rounded > pos) continue;
                    int rlen = MatchLength(data, pos - rounded, pos, matchLimit);
                    if (rlen < recMin) continue;
                    clen = rlen;
                    cdst = rounded;
                }
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
            // the reference CacheTableMatchFinder emits strictly-length-improving (len,dist) pairs scanning row A then
            // row B (shared monotonic prevml = local_620), already distinct/ascending in length. Feed them
            // longest-first into the length-descending candidate set.
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

    /// <summary>
    /// DIAGNOSTIC (default-unused, TEST-ONLY): dumps the per-position level-7 finder Pareto table so it can be
    /// diffed against the reference reference <c>ProcessChunk</c> (reference routine / find_all_matches) output captured
    /// by the findump diagnostic. For each position it walks the SAME 4-byte hash chain <see cref="FindCandidates"/>
    /// uses (most-recent-first ⇒ distance ascending) and records the closest-offset-per-length frontier,
    /// length-descending, up to 4 pairs — the pure find_all_matches analog (NO rep0/off-8 supplement, which the
    /// DP adds separately). Layout = <c>data.Length * 8</c> ints = {len0,dist0,len1,dist1,len2,dist2,len3,dist3}
    /// per position (0 = unused slot). <paramref name="recMin"/> sets the minimum recorded length (4 = production
    /// mml; the reference num_firstbytes=2 finder also reports len 2/3 which a 4-byte hash cannot surface).
    /// </summary>
    internal static int[] DiagDumpFinderTable(ReadOnlySpan<byte> data, int recMin = MinMatch)
    {
        int n = data.Length;
        var head = new int[HashSize];
        var prev = new int[n];
        head.AsSpan().Fill(-1);
        int inserted = 0;
        var table = new int[n * 8];
        Span<int> fl = stackalloc int[128];
        Span<int> fd = stackalloc int[128];
        int matchLimit = n;
        int posEnd = n - 3; // Hash reads data[pos+3]; tail positions [n-3,n) left as empty slots
        for (int pos = 0; pos < posEnd; pos++)
        {
            inserted = InsertUpTo(data, head, prev, inserted, pos);
            int fn = 0, bestLen = 0;
            uint hs = Hash(data, pos);
            int c = head[hs];
            while (c >= 0)
            {
                int dist = pos - c;
                if (dist >= MinDistance)
                {
                    int len = MatchLength(data, c, pos, matchLimit);
                    if (len > bestLen)
                    {
                        bestLen = len;
                        if (len >= recMin && fn < fl.Length) { fl[fn] = len; fd[fn] = dist; fn++; }
                    }
                }
                c = prev[c];
            }
            int keep = fn > 4 ? 4 : fn;
            int bas = pos * 8;
            for (int i = 0; i < keep; i++)
            {
                int idx = fn - 1 - i; // length-ascending record → longest first
                table[bas + i * 2] = fl[idx];
                table[bas + i * 2 + 1] = fd[idx];
            }
        }
        return table;
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
    /// the reference level-7 match finder, validated against <c>CacheTableMatchFinder::ProcessChunk</c>
    /// (the reference routine; constructor reference routine; hashes reference routine/reference routine;
    /// insert reference routine; eval reference routine/reference routine; table-init reference routine; sort/dedup
    /// reference routine/reference routine). It is a <b>flat 2-row, 16-way check-bit cache table</b> (NOT a hash chain):
    /// <list type="bullet">
    /// <item><b>One flat table</b> <c>uint[1&lt;&lt;N]</c>, <b>zero-initialised</b> (memset 0), shared by both rows;
    /// N = <c>clamp(ceil_log2(len), 18, 24)</c> (so N=18 for our vectors). Each entry packs
    /// <c>{position: low 26 bits (0x03FFFFFF), check: top 6 bits (0xFC000000)}</c>; window = 2^26.</item>
    /// <item><b>Row A (4-byte context):</b> <c>hash1 = rotl32(low32(read32(ptr)·0xB7A56463), N)</c>; index =
    /// <c>hash1 &amp; ((1&lt;&lt;N)−16)</c> (bits [4..N), 16-aligned); the stored/compared <c>check</c> = the top
    /// 6 bits of hash1. <b>Row B (8-byte context):</b> index =
    /// <c>((read64(ptr)·0xCF1BBCDCB7A56463) &gt;&gt; (64−N)) &amp; ~0xF</c> (16-aligned). Both select a 16-entry
    /// window <c>table[idx .. idx+16)</c>; the rows are decorrelated.</item>
    /// <item><b>Insert</b> (reference routine) FIFO-shifts both rows: <c>memmove(ways+1, ways, 15·4)</c> then
    /// <c>ways[0] = (pos &amp; 0x3FFFFFF) | (check &amp; 0xFC000000)</c> — newest at slot 0.</item>
    /// <item><b>Query</b> scans row A then row B (newest-first). Per way: reject unless
    /// <c>(entry &amp; 0xFC000000) == check</c>; <c>dist = ((pos−1−epos) &amp; 0x3FFFFFF) + 1</c>; require
    /// <c>dist &lt;= pos</c> (in-window); 4-byte verify; full length; emit <c>(len,dist)</c> only when
    /// <c>len &gt; prevml</c> (the asserted <c>"len &gt; prevml"</c>, ctmf.cpp:0xe7/0x11d). <c>prevml</c>
    /// (local_620) is <b>reset to 0 at the start of each row</b> (ProcessChunk line 381), so each row emits its
    /// own strictly length-increasing subsequence; the two rows' emissions are then sort+dedup-by-length, keep ≤4.</item>
    /// </list>
    /// Empty slots (entry 0) are naturally rejected by the check compare + 4-byte verify (a position-0 spurious
    /// hit only survives when the bytes truly match — the reference-faithful, benign). This exact bounded retention is what
    /// the depth sweep proved no hash-chain depth reproduces (shallow under-supplies cmd-34's far copy, deep
    /// over-supplies cmd-35). the reference separate windowed long-range matcher emits only matches ≥256 B and is
    /// excluded here (it cannot supply the 55-byte far copy).
    /// </summary>
    private sealed class Ctmf
    {
        private const uint Mul4 = 0xB7A56463u;            // row-A 4-byte context multiplier (shared mul >> 32)
        private const ulong Mul8 = 0xCF1BBCDCB7A56463UL;  // row-B 8-byte context multiplier
        private const int Ways = 16;                       // 16 entries per row window (the reference SIMD 16-lane width)
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

        // row-A / hash1 = rotl32( low32(read32(ptr) * 0xB7A56463), bits ); the top 6 bits are the stored check.
        private uint Hash1(ReadOnlySpan<byte> d, int p) => Rotl32(Read32(d, p) * Mul4, _bits);
        private int RowA(uint h1) => (int)(h1 & (uint)_maskA);
        // row-B index = ((read64(ptr) * 0xCF1BBCDCB7A56463) >> (64-bits)) & ~0xF  (16-aligned, in [0, 2^bits)).
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
        /// <paramref name="outLen"/>/<paramref name="outDist"/> with a shared monotonic prevml (the reference local_620
        /// across both rows). Returns the pair count (ascending, distinct lengths == the post sort+dedup set).
        /// </summary>
        public int Query(ReadOnlySpan<byte> d, int pos, int matchLimit, Span<int> outLen, Span<int> outDist)
        {
            int n = 0;
            uint h1 = Hash1(d, pos);
            uint check = h1 & CheckMask;
            if (!CtmfRowAOff)
            {
                int prevmlA = 0;   // the reference resets local_620=0 at the start of EACH row (ProcessChunk line 381)
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
                if (Read32(d, cand) != Read32(d, pos)) continue;     // 4-byte verify (reference routine)
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
