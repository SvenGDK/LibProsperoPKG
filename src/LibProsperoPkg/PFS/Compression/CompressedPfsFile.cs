// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Reader/parser for the PS5 PFSv3 (and PFSv2) compression file format — the "PFSC"
// container.
//
// IMPORTANT: this is a DIFFERENT format from the zlib "PFSC" image handled by
// LibProsperoPkg.PFS.PfscEncoder/PFSCReader. The two collide on the 4-byte 'PFSC' magic but
// differ in everything else; they are disambiguated by the format-version field at offset 0x04
// (version 2 or 3; the zlib variant stores 0 there).
//
// Every field decoded here was validated byte-for-byte against reference output, including: the SHA3-256 file digest at 0x28, the 7-entry section directory at
// 0x48, the block boundary table (id=3) and the per-block SHA3-256 hash table (id=4).
#nullable enable
using LibProsperoPkg.PFS.Compression.Oodle;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace LibProsperoPkg.PFS.Compression;

/// <summary>
/// One block of a parsed <see cref="CompressedPfsFile"/>.
/// </summary>
public readonly struct PfsBlock
{
    /// <summary>The zero-based block index.</summary>
    public int Index { get; init; }

    /// <summary>The absolute byte offset of this block's compressed data within the container file.</summary>
    public long CompressedOffset { get; init; }

    /// <summary>The compressed size, in bytes, of this block within the container.</summary>
    public int CompressedSize { get; init; }

    /// <summary>The logical (uncompressed) byte offset this block expands to.</summary>
    public long UncompressedOffset { get; init; }

    /// <summary>The uncompressed size, in bytes, this block expands to.</summary>
    public int UncompressedSize { get; init; }

    /// <summary>
    /// The block's stored SHA3-256 digest (32 bytes), taken over the <i>uncompressed</i> block bytes.
    /// Verify a decoded block with <see cref="PfsDigest.VerifyBlockDigest"/>.
    /// </summary>
    public ReadOnlyMemory<byte> Hash { get; init; }

    /// <summary>The raw compressed bytes of this block (a slice of the container buffer).</summary>
    public ReadOnlyMemory<byte> CompressedData { get; init; }

    /// <summary>
    /// <c>true</c> when the block is stored uncompressed (<see cref="CompressedSize"/> equals
    /// <see cref="UncompressedSize"/>), as the format does for incompressible data; otherwise the
    /// block is a Kraken bitstream.
    /// </summary>
    public bool IsStored => CompressedSize == UncompressedSize;

    /// <summary>
    /// <c>true</c> when a compressed block is split into two newLZ chunks (boundary flag <c>0x26</c>
    /// rather than <c>0x06</c>), which happens for blocks larger than 128 KiB. The first chunk's
    /// compressed size is then <see cref="FirstChunkCompressedSize"/>.
    /// </summary>
    public bool IsMultiChunk { get; init; }

    /// <summary>
    /// <c>true</c> when a compressed block is a single bare-entropy array rather than an LZ stream
    /// (boundary flag bit <c>0x02</c> clear). The whole block payload is then one Kraken entropy array
    /// (typically a type-2 Huffman array) that expands directly to the uncompressed bytes — no seed,
    /// no LZ table, no literal model. The encoder emits this form when entropy coding helps but LZ matching
    /// does not (skewed-frequency data). Always <c>false</c> for stored and newLZ blocks.
    /// </summary>
    public bool IsBareEntropy { get; init; }

    /// <summary>
    /// For a two-chunk compressed block, the compressed size in bytes of the first chunk (recovered
    /// from the boundary size hint); zero otherwise. The second chunk occupies the remaining bytes.
    /// </summary>
    public int FirstChunkCompressedSize { get; init; }

    /// <summary>
    /// The newLZ literal model for this compressed block, recovered from the boundary flag's low bit
    /// (the bit the PFS layer feeds into the reconstructed Oodle chunk header): <c>1</c> = raw literals,
    /// <c>0</c> = sub/delta literals. Irrelevant for stored blocks.
    /// </summary>
    public int LiteralMode { get; init; }

    /// <summary>
    /// The raw boundary-table flag byte for this block (bits 48..55 of the id=3 entry). This is the
    /// authoritative per-sub-chunk type/literal-model selector consumed by
    /// <see cref="Oodle.KrakenDecoder.DecodeBlock"/>: chunk0 newLZ = bit <c>0x02</c> (literal model
    /// bit <c>0x01</c>); chunk1 newLZ = bit <c>0x20</c> (literal model bit <c>0x10</c>), bare-entropy
    /// chunk1 = bit <c>0x40</c>. Zero for stored blocks.
    /// </summary>
    public int Flags { get; init; }

    /// <summary>
    /// The pre-compression shuffle applied to this block. Containers produced without region hints
    /// (all known default-output containers) always use <see cref="PfsShufflePattern.None"/>.
    /// </summary>
    /// <remarks>
    /// The per-block storage location of a non-<see cref="PfsShufflePattern.None"/> pattern has not
    /// been validated against reference output, so this reader
    /// reports <see cref="PfsShufflePattern.None"/>. Do not rely on it to detect shuffled blocks.
    /// </remarks>
    public PfsShufflePattern ShufflePattern => PfsShufflePattern.None;
}

/// <summary>
/// A parsed PS5 PFSv2/PFSv3 compression container ("PFSC"). Provides the header fields,
/// the file-level SHA3-256 digest, the per-block table and full decompression of containers
/// produced by <see cref="CompressedPfsFileWriter"/> as well as reference containers: stored
/// blocks plus this library's Kraken codec, which decodes the entropy-coded
/// (Huffman) arrays and the post-seed excess framing used by reference blocks.
/// </summary>
public sealed class CompressedPfsFile
{
    /// <summary>The 4-byte container magic, 'P','F','S','C' (little-endian <c>0x43534650</c>).</summary>
    public const uint Magic = 0x43534650;

    private const ulong NewLzFlagBit = 0x02;       // boundary flag bit: set = newLZ (LZ table); clear = bare-entropy
    private const int ChunkMaxUncompressed = 0x20000; // one internal Kraken chunk decodes at most 128 KiB

    // Header field offsets.
    private const int OffMagic = 0x00;
    private const int OffVersion = 0x04;
    private const int OffSectionCount = 0x06;
    private const int OffBlockSize = 0x08;
    private const int OffEncodeParams = 0x10;
    private const int OffUncompressedSize = 0x18;
    private const int OffTotalCompressedSize = 0x20;
    private const int OffFileDigest = 0x28;
    private const int OffSectionDirectory = 0x48;
    private const int SectionEntrySize = 16;
    private const int MinHeaderSize = OffSectionDirectory + SectionEntrySize;

    // Section ids in the directory.
    private const int SectionGitHash = 1;
    private const int SectionShuffleTable = 2;
    private const int SectionBlockBoundaries = 3;
    private const int SectionBlockHashes = 4;
    private const int SectionBlockData = 7;

    private readonly ReadOnlyMemory<byte> _buffer;

    private CompressedPfsFile(ReadOnlyMemory<byte> buffer) => _buffer = buffer;

    /// <summary>The container format version (<see cref="PfsCompressionFormat.Version2"/> or <see cref="PfsCompressionFormat.Version3"/>).</summary>
    public PfsCompressionFormat Version { get; private init; }

    /// <summary>The compression algorithm recorded in the header (always <see cref="CompressionAlgorithm.Kraken"/> for PS5).</summary>
    public CompressionAlgorithm Algorithm { get; private init; }

    /// <summary>
    /// The Kraken compression level recorded in the header (encode-parameter byte <c>0x11</c>).
    /// Accepted levels are <c>0..9</c> and the fast range <c>-4..-1</c>; default-output containers use level 7.
    /// </summary>
    public int CompressionLevel { get; private init; }

    /// <summary>The Kraken sliding-window bits recorded in the header (encode-parameter byte <c>0x12</c>, normally 18).</summary>
    public int WindowBits { get; private init; }

    /// <summary>The logical block size, in bytes (256 KiB for PS5 v3).</summary>
    public int BlockSize { get; private init; }

    /// <summary>The total uncompressed size, in bytes, of the payload the container expands to.</summary>
    public long UncompressedSize { get; private init; }

    /// <summary>The total compressed size, in bytes, of the whole container file (including metadata).</summary>
    public long TotalCompressedSize { get; private init; }

    /// <summary>The header's 32-byte SHA3-256 file digest (offset <c>0x28</c>).</summary>
    public ReadOnlyMemory<byte> FileDigest { get; private init; }

    /// <summary>The 20-byte revision hash recorded in the metadata (section id=1), or empty when absent.</summary>
    public ReadOnlyMemory<byte> GitHash { get; private init; }

    /// <summary>The absolute byte offset where compressed block data begins (the metadata size).</summary>
    public long DataOffset { get; private init; }

    /// <summary>The parsed per-block table.</summary>
    public IReadOnlyList<PfsBlock> Blocks { get; private init; } = Array.Empty<PfsBlock>();

    // Byte ranges of the three metadata sections that feed the file digest.
    private (int Offset, int Size) _shuffleRange;
    private (int Offset, int Size) _boundaryRange;
    private (int Offset, int Size) _blockHashRange;

    /// <summary>
    /// Recomputes the file-level SHA3-256 digest from the parsed metadata and compares it to the
    /// value stored at header offset <c>0x28</c>. Returns <c>true</c> when they match.
    /// </summary>
    /// <remarks>
    /// This is the file-level integrity check performed when opening a container: <c>SHA3-256(header32 || shuffleSection || boundarySection || blockHashSection)</c>.
    /// </remarks>
    /// <exception cref="PlatformNotSupportedException">SHA3-256 is unavailable on this host.</exception>
    public bool VerifyFileDigest()
    {
        ReadOnlySpan<byte> span = _buffer.Span;
        return PfsDigest.VerifyFileDigest(
            span.Slice(OffBlockSize, PfsDigest.FileDigestHeaderParamsLength),
            span.Slice(_shuffleRange.Offset, _shuffleRange.Size),
            span.Slice(_boundaryRange.Offset, _boundaryRange.Size),
            span.Slice(_blockHashRange.Offset, _blockHashRange.Size),
            FileDigest.Span);
    }

    /// <summary>
    /// Decompresses the whole container back to its original payload. Stored blocks are copied
    /// verbatim; compressed blocks are decoded with the Kraken codec
    /// (<see cref="Oodle.KrakenDecoder"/>), which reads both this library's own output and
    /// reference blocks (entropy-coded arrays + the post-seed excess framing). The result has
    /// length <see cref="UncompressedSize"/>.
    /// </summary>
    /// <returns>The reconstructed uncompressed payload.</returns>
    /// <exception cref="InvalidDataException">
    /// A block is malformed or uses an unsupported entropy/excess form.
    /// </exception>
    public byte[] Decompress()
    {
        var output = new byte[UncompressedSize];
        foreach (PfsBlock block in Blocks)
        {
            Span<byte> dstBlock = output.AsSpan((int)block.UncompressedOffset, block.UncompressedSize);
            if (block.IsStored)
            {
                block.CompressedData.Span.CopyTo(dstBlock);
                continue;
            }

            KrakenDecodeStatus status = KrakenDecoder.DecodeBlock(
                block.CompressedData.Span, block.Flags, block.FirstChunkCompressedSize, dstBlock);
            if (status != KrakenDecodeStatus.Success)
                throw new InvalidDataException($"Block {block.Index} could not be decoded ({status}).");
        }

        return output;
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="data"/> begins with a PS5 PFSv2/PFSv3 compression
    /// container, distinguishing it from the zlib "PFSC" image (which stores 0 in the
    /// version field).
    /// </summary>
    public static bool IsScePfsCompressed(ReadOnlySpan<byte> data)
    {
        if (data.Length < MinHeaderSize)
            return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(data[OffMagic..]) != Magic)
            return false;
        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(data[OffVersion..]);
        return version is 2 or 3;
    }

    /// <summary>Parses a PS5 PFSv2/PFSv3 compression container from <paramref name="buffer"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is null.</exception>
    /// <exception cref="InvalidDataException">The buffer is not a valid PS5 PFS compression container.</exception>
    public static CompressedPfsFile Parse(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        return Parse(buffer.AsMemory());
    }

    /// <summary>Parses a PS5 PFSv2/PFSv3 compression container from <paramref name="buffer"/>.</summary>
    /// <exception cref="InvalidDataException">The buffer is not a valid PS5 PFS compression container.</exception>
    public static CompressedPfsFile Parse(ReadOnlyMemory<byte> buffer)
    {
        ReadOnlySpan<byte> span = buffer.Span;
        if (span.Length < MinHeaderSize)
            throw new InvalidDataException("Buffer is too small to be a PFS compression container.");
        if (BinaryPrimitives.ReadUInt32LittleEndian(span[OffMagic..]) != Magic)
            throw new InvalidDataException("Missing 'PFSC' magic.");

        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(span[OffVersion..]);
        if (version is not (2 or 3))
            throw new InvalidDataException(
                $"Unsupported PFS compression version {version}; expected 2 or 3 (a zlib 'PFSC' image stores 0 here).");

        long uncompressedSize = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(span[OffUncompressedSize..]));
        long totalCompressedSize = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(span[OffTotalCompressedSize..]));

        // Section directory: 16-byte entries from 0x48 up to the first (lowest) section offset.
        Dictionary<int, (long Offset, long Size)> sections = ReadSectionDirectory(span);

        long dataOffset = sections.TryGetValue(SectionBlockData, out var dataSec) ? dataSec.Offset : 0;
        var blocks = ReadBlocks(buffer, span, sections, dataOffset);

        ReadOnlyMemory<byte> gitHash = ReadOnlyMemory<byte>.Empty;
        if (sections.TryGetValue(SectionGitHash, out var git) && InRange(span.Length, git.Offset, git.Size))
            gitHash = buffer.Slice((int)git.Offset, (int)git.Size);

        int len = span.Length;
        (int, int) RangeOf(int id) =>
            sections.TryGetValue(id, out var s) && InRange(len, s.Offset, s.Size)
                ? ((int)s.Offset, (int)s.Size)
                : (0, 0);

        return new CompressedPfsFile(buffer)
        {
            Version = version == 3 ? PfsCompressionFormat.Version3 : PfsCompressionFormat.Version2,
            Algorithm = (CompressionAlgorithm)span[OffEncodeParams],
            CompressionLevel = (sbyte)span[OffEncodeParams + 1],
            WindowBits = span[OffEncodeParams + 2],
            BlockSize = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(span[OffBlockSize..])),
            UncompressedSize = uncompressedSize,
            TotalCompressedSize = totalCompressedSize,
            FileDigest = buffer.Slice(OffFileDigest, PfsDigest.DigestLength),
            GitHash = gitHash,
            DataOffset = dataOffset,
            Blocks = blocks,
            _shuffleRange = RangeOf(SectionShuffleTable),
            _boundaryRange = RangeOf(SectionBlockBoundaries),
            _blockHashRange = RangeOf(SectionBlockHashes),
        };
    }

    private static Dictionary<int, (long Offset, long Size)> ReadSectionDirectory(ReadOnlySpan<byte> span)
    {
        var sections = new Dictionary<int, (long, long)>();

        // The directory holds exactly the declared number of 16-byte entries (header offset 0x06)
        // and ends at the lowest section offset (the first section immediately follows it).
        int declaredCount = BinaryPrimitives.ReadUInt16LittleEndian(span[OffSectionCount..]);
        uint firstOffset = BinaryPrimitives.ReadUInt32LittleEndian(span[(OffSectionDirectory + 2)..]);
        long dirEnd = firstOffset >= OffSectionDirectory + SectionEntrySize && firstOffset <= span.Length
            ? firstOffset
            : span.Length;

        int read = 0;
        for (long p = OffSectionDirectory;
             p + SectionEntrySize <= dirEnd && (declaredCount == 0 || read < declaredCount);
             p += SectionEntrySize, read++)
        {
            int pos = (int)p;
            ushort id = BinaryPrimitives.ReadUInt16LittleEndian(span[pos..]);
            if (id == 0)
                break;
            long offset = BinaryPrimitives.ReadUInt32LittleEndian(span[(pos + 2)..]);
            long size = BinaryPrimitives.ReadUInt32LittleEndian(span[(pos + 10)..]);
            sections[id] = (offset, size);
        }

        return sections;
    }

    private static List<PfsBlock> ReadBlocks(
        ReadOnlyMemory<byte> buffer,
        ReadOnlySpan<byte> span,
        Dictionary<int, (long Offset, long Size)> sections,
        long dataOffset)
    {
        var blocks = new List<PfsBlock>();
        if (!sections.TryGetValue(SectionBlockBoundaries, out var bnd) || bnd.Size < 2 * SectionEntrySize)
            return blocks;
        if (!InRange(span.Length, bnd.Offset, bnd.Size))
            throw new InvalidDataException("Block boundary table is out of range.");

        int blockCount = (int)(bnd.Size / SectionEntrySize) - 1;
        sections.TryGetValue(SectionBlockHashes, out var hashSec);
        bool haveHashes = hashSec.Size >= (long)blockCount * PfsDigest.DigestLength
                          && InRange(span.Length, hashSec.Offset, hashSec.Size);

        for (int i = 0; i < blockCount; i++)
        {
            int e = (int)bnd.Offset + i * SectionEntrySize;
            ulong e0 = BinaryPrimitives.ReadUInt64LittleEndian(span[e..]);
            ulong e1 = BinaryPrimitives.ReadUInt64LittleEndian(span[(e + 8)..]);
            long compRel = (long)(e0 & 0xFFFFFFFFFFFUL);          // bits[0:44]
            ulong flags = (e0 >> 48) & 0xFF;                       // bits[48:56]
            long uncompRel = (long)(e1 & 0xFFFFFFFFFFFUL);        // bits[0:44]
            int sizeHint = (int)((e1 >> 44) & 0x1FFFF);           // bits[44:61] = (firstChunkComp - 1)

            ulong compNext = BinaryPrimitives.ReadUInt64LittleEndian(span[(e + SectionEntrySize)..]) & 0xFFFFFFFFFFFUL;
            ulong uncompNext = BinaryPrimitives.ReadUInt64LittleEndian(span[(e + SectionEntrySize + 8)..]) & 0xFFFFFFFFFFFUL;

            int compSize = checked((int)((long)compNext - compRel));
            int uncompSize = checked((int)((long)uncompNext - uncompRel));
            if (compSize < 0 || uncompSize < 0)
                throw new InvalidDataException($"Block {i} has a negative size in the boundary table.");

            long absOffset = dataOffset + compRel;
            if (!InRange(span.Length, absOffset, compSize))
                throw new InvalidDataException($"Block {i} compressed data is out of range.");

            bool stored = compSize == uncompSize;
            // A single internal Kraken chunk decodes at most 128 KiB, and a PFS block is at most 256 KiB,
            // so any compressed block whose uncompressed size exceeds one chunk is split into exactly two
            // sub-chunks. This is authoritative; the boundary flag bit varies (newLZ uses 0x20 or 0x40,
            // bare-entropy uses 0x40), so the uncompressed size — not a flag bit — drives the split.
            bool multiChunk = !stored && uncompSize > ChunkMaxUncompressed;
            bool bareEntropy = !stored && (flags & NewLzFlagBit) == 0;
            int firstChunkComp = multiChunk ? sizeHint + 1 : 0;
            int literalMode = (flags & 1) != 0 ? 0 : 1;

            ReadOnlyMemory<byte> hash = ReadOnlyMemory<byte>.Empty;
            if (haveHashes)
                hash = buffer.Slice((int)hashSec.Offset + i * PfsDigest.DigestLength, PfsDigest.DigestLength);

            blocks.Add(new PfsBlock
            {
                Index = i,
                CompressedOffset = absOffset,
                CompressedSize = compSize,
                UncompressedOffset = uncompRel,
                UncompressedSize = uncompSize,
                Hash = hash,
                CompressedData = buffer.Slice((int)absOffset, compSize),
                IsMultiChunk = multiChunk,
                IsBareEntropy = bareEntropy,
                FirstChunkCompressedSize = firstChunkComp,
                LiteralMode = literalMode,
                Flags = (int)flags,
            });
        }

        return blocks;
    }

    private static bool InRange(int length, long offset, long size)
        => offset >= 0 && size >= 0 && offset + size <= length;
}
