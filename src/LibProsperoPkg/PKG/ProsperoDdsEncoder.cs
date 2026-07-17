// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PS5 sce_sys DDS (texture) encoder. Next to each of the icon0.png / pic0.png / pic1.png /
// pic2.png media files, a same-named *.dds re-encode of the image is created (entry ids
// 0x1280 / 0x12A0 / 0x12C0 / 0x2060). These are DX10 DDS files holding a single, full-resolution,
// no-mipmap surface in DXGI_FORMAT_BC7_UNORM (0x62) — e.g. icon0.dds is 512x512 (262292 bytes)
// and pic*.dds are 3840x2160 (8294548 bytes), exactly 148 header bytes + width*height BC7 payload
// bytes.
//
// This file produces deterministic DDS headers and a spec-conformant BC7 payload using mode 6
// (single subset, RGBA, 7-bit endpoints + per-endpoint p-bit, 16 four-bit indices). Mode 6 is the
// simplest BC7 block that still covers the full RGBA range, so the output is a valid BC7 texture
// the console GPU can sample.

#nullable enable

using System;
using System.IO;

namespace LibProsperoPkg.PKG;

/// <summary>
/// PNG-to-DDS (BC7) re-encoder for the PS5 <c>sce_sys</c> icon/pic media. Produces a
/// DX10 <c>DXGI_FORMAT_BC7_UNORM</c> DDS with no mipmaps, matching the surface dimensions and
/// header layout of the standard <c>icon0.dds</c> / <c>pic0.dds</c> / <c>pic1.dds</c> / <c>pic2.dds</c>.
/// </summary>
public static class ProsperoDdsEncoder
{
    /// <summary>The total size, in bytes, of the DDS magic + DDS_HEADER + DDS_HEADER_DXT10 prefix.</summary>
    public const int HeaderSize = 148;

    /// <summary>DXGI_FORMAT_BC7_UNORM, the texture format used by the PS5 sce_sys *.dds files.</summary>
    private const uint DxgiFormatBc7Unorm = 98; // 0x62

    // BC7 4-bit index interpolation weights (aWeight4 from the BC7 spec).
    private static readonly int[] Weights4 =
        { 0, 4, 9, 13, 17, 21, 26, 30, 34, 38, 43, 47, 51, 55, 60, 64 };

    /// <summary>
    /// Decodes <paramref name="pngBytes"/> and re-encodes it as a BC7 DX10 DDS file (full
    /// resolution, no mipmaps). Throws if the image cannot be decoded.
    /// </summary>
    public static byte[] EncodePngToDds(byte[] pngBytes)
    {
        if (pngBytes is null || pngBytes.Length == 0)
            throw new ArgumentException("Empty image.", nameof(pngBytes));

        ProsperoPngDecoder.Image image = ProsperoPngDecoder.Decode(pngBytes);
        if (image.Width <= 0 || image.Height <= 0)
            throw new InvalidDataException("Image has no pixels.");

        return EncodeRgbaToDds(image.Rgba, image.Width, image.Height);
    }

    /// <summary>
    /// Encodes a tightly-packed top-down RGBA8 buffer (<paramref name="width"/>x<paramref name="height"/>,
    /// 4 bytes/pixel) into a BC7 DX10 DDS file. The header carries the true image dimensions; the block
    /// surface is rounded up to a multiple of four (edge pixels are repeated) for the partial-block payload.
    /// </summary>
    public static byte[] EncodeRgbaToDds(byte[] rgba, int width, int height)
    {
        if (width <= 0 || height <= 0)
            throw new ArgumentOutOfRangeException(nameof(width), "Invalid image dimensions.");
        if (rgba.Length < width * height * 4)
            throw new ArgumentException("RGBA buffer is smaller than width*height*4.", nameof(rgba));

        int blocksX = (width + 3) / 4;
        int blocksY = (height + 3) / 4;
        int surfaceWidth = blocksX * 4;
        int surfaceHeight = blocksY * 4;
        long payloadSize = (long)surfaceWidth * surfaceHeight; // BC7 is 16 bytes per 4x4 block = 1 byte/texel.

        byte[] dds = new byte[HeaderSize + payloadSize];
        // dwWidth/dwHeight are the true image dimensions; block padding is implicit in the BC7 format.
        WriteHeader(dds, width, height, (uint)payloadSize);

        int offset = HeaderSize;
        var block = new byte[16 * 4];
        for (int by = 0; by < blocksY; by++)
        {
            for (int bx = 0; bx < blocksX; bx++)
            {
                GatherBlock(rgba, width, height, bx * 4, by * 4, block);
                EncodeBlockMode6(block, dds, offset);
                offset += 16;
            }
        }

        return dds;
    }

    private static void WriteHeader(byte[] dst, int width, int height, uint linearSize)
    {
        // "DDS " magic.
        dst[0] = (byte)'D'; dst[1] = (byte)'D'; dst[2] = (byte)'S'; dst[3] = (byte)' ';
        WriteU32(dst, 0x04, 124);                       // dwSize (DDS_HEADER)
        WriteU32(dst, 0x08, 0x000A1007);                // CAPS | HEIGHT | WIDTH | PIXELFORMAT | MIPMAPCOUNT | LINEARSIZE
        WriteU32(dst, 0x0C, (uint)height);              // dwHeight
        WriteU32(dst, 0x10, (uint)width);               // dwWidth
        WriteU32(dst, 0x14, linearSize);                // dwPitchOrLinearSize
        WriteU32(dst, 0x18, 0);                         // dwDepth
        WriteU32(dst, 0x1C, 1);                         // dwMipMapCount
        // 0x20..0x4B: 11 reserved dwords (already zero).
        WriteU32(dst, 0x4C, 32);                        // ddspf.dwSize
        WriteU32(dst, 0x50, 0x04);                      // ddspf.dwFlags = DDPF_FOURCC
        dst[0x54] = (byte)'D'; dst[0x55] = (byte)'X'; dst[0x56] = (byte)'1'; dst[0x57] = (byte)'0'; // "DX10"
        // 0x58..0x6B: ddspf masks (zero).
        WriteU32(dst, 0x6C, 0x1000);                    // dwCaps = DDSCAPS_TEXTURE
        // 0x70..0x7F: caps2/3/4 + reserved2 (zero).
        WriteU32(dst, 0x80, DxgiFormatBc7Unorm);        // DXGI format
        WriteU32(dst, 0x84, 3);                         // resourceDimension = TEXTURE2D
        WriteU32(dst, 0x88, 0);                         // miscFlag
        WriteU32(dst, 0x8C, 1);                         // arraySize
        WriteU32(dst, 0x90, 0);                         // miscFlags2
    }

    private static void WriteU32(byte[] dst, int offset, uint value)
    {
        dst[offset] = (byte)value;
        dst[offset + 1] = (byte)(value >> 8);
        dst[offset + 2] = (byte)(value >> 16);
        dst[offset + 3] = (byte)(value >> 24);
    }

    // Copies a 4x4 RGBA block from (x0,y0); pixels past the image edge repeat the nearest valid pixel.
    private static void GatherBlock(byte[] rgba, int width, int height, int x0, int y0, byte[] block)
    {
        for (int y = 0; y < 4; y++)
        {
            int sy = Math.Min(y0 + y, height - 1);
            for (int x = 0; x < 4; x++)
            {
                int sx = Math.Min(x0 + x, width - 1);
                int src = (sy * width + sx) * 4;
                int dst = (y * 4 + x) * 4;
                block[dst] = rgba[src];
                block[dst + 1] = rgba[src + 1];
                block[dst + 2] = rgba[src + 2];
                block[dst + 3] = rgba[src + 3];
            }
        }
    }

    // Encodes 16 RGBA pixels into a single BC7 mode-6 block written little-endian at dst[offset..offset+16).
    private static void EncodeBlockMode6(byte[] block, byte[] dst, int offset)
    {
        // 1) Bounding-box endpoints over the block.
        var min = new int[4] { 255, 255, 255, 255 };
        var max = new int[4] { 0, 0, 0, 0 };
        for (int i = 0; i < 16; i++)
        {
            int p = i * 4;
            for (int c = 0; c < 4; c++)
            {
                int v = block[p + c];
                if (v < min[c]) min[c] = v;
                if (v > max[c]) max[c] = v;
            }
        }

        // 2) Quantize each endpoint to a 7-bit base + shared 1-bit p-bit (reconstructed = (base<<1)|p).
        QuantizeEndpoint(min, out int[] base0, out int p0, out int[] e0);
        QuantizeEndpoint(max, out int[] base1, out int p1, out int[] e1);

        // 3) Pick the best 4-bit index per pixel against the reconstructed endpoint line.
        var indices = new int[16];
        for (int i = 0; i < 16; i++)
            indices[i] = BestIndex(e0, e1, block, i * 4);

        // 4) Anchor rule: index[0] must have its high bit clear (value < 8). If not, swap the two
        // endpoints and invert all indices — the decoded result is identical.
        if (indices[0] >= 8)
        {
            (base0, base1) = (base1, base0);
            (p0, p1) = (p1, p0);
            for (int i = 0; i < 16; i++)
                indices[i] = 15 - indices[i];
        }

        // 5) Pack the 128-bit block (LSB-first) into lo/hi.
        ulong lo = 0, hi = 0;
        int pos = 0;
        Put(ref lo, ref hi, ref pos, 1u << 6, 7);          // mode 6 token: six zero bits then a 1
        Put(ref lo, ref hi, ref pos, (uint)base0[0], 7);   // R0
        Put(ref lo, ref hi, ref pos, (uint)base1[0], 7);   // R1
        Put(ref lo, ref hi, ref pos, (uint)base0[1], 7);   // G0
        Put(ref lo, ref hi, ref pos, (uint)base1[1], 7);   // G1
        Put(ref lo, ref hi, ref pos, (uint)base0[2], 7);   // B0
        Put(ref lo, ref hi, ref pos, (uint)base1[2], 7);   // B1
        Put(ref lo, ref hi, ref pos, (uint)base0[3], 7);   // A0
        Put(ref lo, ref hi, ref pos, (uint)base1[3], 7);   // A1
        Put(ref lo, ref hi, ref pos, (uint)p0, 1);         // P0
        Put(ref lo, ref hi, ref pos, (uint)p1, 1);         // P1
        Put(ref lo, ref hi, ref pos, (uint)indices[0], 3); // anchor index (3 bits)
        for (int i = 1; i < 16; i++)
            Put(ref lo, ref hi, ref pos, (uint)indices[i], 4);

        for (int i = 0; i < 8; i++) dst[offset + i] = (byte)(lo >> (i * 8));
        for (int i = 0; i < 8; i++) dst[offset + 8 + i] = (byte)(hi >> (i * 8));
    }

    // Chooses the p-bit and 7-bit bases minimising the squared error of the reconstructed endpoint.
    private static void QuantizeEndpoint(int[] v, out int[] best, out int bestP, out int[] recon)
    {
        best = new int[4];
        recon = new int[4];
        bestP = 0;
        long bestErr = long.MaxValue;
        for (int p = 0; p <= 1; p++)
        {
            long err = 0;
            var b = new int[4];
            var r = new int[4];
            for (int c = 0; c < 4; c++)
            {
                int q = (v[c] - p + 1) >> 1;          // round((v - p) / 2)
                if (q < 0) q = 0; else if (q > 127) q = 127;
                int rec = (q << 1) | p;
                int diff = rec - v[c];
                err += (long)diff * diff;
                b[c] = q;
                r[c] = rec;
            }
            if (err < bestErr)
            {
                bestErr = err;
                bestP = p;
                best = b;
                recon = r;
            }
        }
    }

    // Returns the 4-bit index whose interpolated colour is closest to the pixel at block[po..po+4).
    private static int BestIndex(int[] e0, int[] e1, byte[] block, int po)
    {
        int best = 0;
        long bestErr = long.MaxValue;
        for (int i = 0; i < 16; i++)
        {
            int w = Weights4[i];
            long err = 0;
            for (int c = 0; c < 4; c++)
            {
                int v = (e0[c] * (64 - w) + e1[c] * w + 32) >> 6;
                int diff = v - block[po + c];
                err += (long)diff * diff;
            }
            if (err < bestErr)
            {
                bestErr = err;
                best = i;
            }
        }
        return best;
    }

    private static void Put(ref ulong lo, ref ulong hi, ref int pos, uint value, int count)
    {
        for (int i = 0; i < count; i++)
        {
            if (((value >> i) & 1u) != 0)
            {
                int bit = pos + i;
                if (bit < 64) lo |= 1UL << bit;
                else hi |= 1UL << (bit - 64);
            }
        }
        pos += count;
    }

}
