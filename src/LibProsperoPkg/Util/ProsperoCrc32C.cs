// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// CRC-32C (Castagnoli) reducer used by reference tool for the PS5 sce_suppl
// config/{content-id}/playgo-chunk.crc file. The publishing tool reduces the *finalized mount
// image* in 64KiB blocks: each block's CRC-32C is appended as a little-endian uint32, in block
// order. This was decoded byte-for-byte from the reference debug packages in TestFiles/PS5/PKG/Debug
// (Downloads/InternetBrowser = 17 dwords over a 0x110000 mount image, DebugSettings = 90 dwords
// over a 0x5A0000 mount image) and reproduces all of them exactly.
//
// The variant is the standard ("reflected") CRC-32C used by iSCSI/SCTP/ext4/Btrfs and exposed by
// the SSE4.2 CRC32 instruction: polynomial 0x1EDC6F41 (reflected 0x82F63B78), initial value
// 0xFFFFFFFF, input/output reflected, final XOR 0xFFFFFFFF. Known-answer: CRC32C("123456789")
// == 0xE3069283.

#nullable enable
using System;

namespace LibProsperoPkg.Util;

/// <summary>
/// Standard reflected CRC-32C (Castagnoli, reflected polynomial 0x82F63B78, init/xorout
/// 0xFFFFFFFF). This is the exact reducer reference tool uses to build
/// <c>playgo-chunk.crc</c>; see the file header for the decoded layout and validation.
/// </summary>
public static class ProsperoCrc32C
{
    /// <summary>The reflected CRC-32C generator polynomial (0x1EDC6F41 reflected).</summary>
    public const uint ReflectedPolynomial = 0x82F63B78u;

    // 256-entry lookup table, built once. A static readonly array is initialized lazily and
    // thread-safely by the runtime, so no extra synchronization is needed.
    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? ReflectedPolynomial ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        return table;
    }

    /// <summary>
    /// Continues a running CRC-32C over <paramref name="data"/>. Pass <see cref="uint.MaxValue"/>
    /// as the initial <paramref name="crc"/> for a fresh checksum; the returned value is the
    /// *internal* running register (NOT yet finalized). Finalize with <c>~result</c> or use
    /// <see cref="Compute"/> for one-shot use.
    /// </summary>
    public static uint Update(uint crc, ReadOnlySpan<byte> data)
    {
        uint c = crc;
        foreach (byte b in data)
            c = Table[(c ^ b) & 0xFF] ^ (c >> 8);
        return c;
    }

    /// <summary>Computes the finalized standard CRC-32C of <paramref name="data"/>.</summary>
    public static uint Compute(ReadOnlySpan<byte> data) => ~Update(uint.MaxValue, data);

}
