// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PNG image decoder used by the sce_sys DDS (BC7) re-encoder to obtain a tightly-packed,
// top-down RGBA8 surface from icon0.png / pic0.png / pic1.png / pic2.png. Supports the full set
// of PNG colour types (greyscale, truecolour, indexed, greyscale+alpha, truecolour+alpha), bit
// depths 1/2/4/8/16, all five scanline filters, transparency (tRNS) and Adam7 interlacing.

using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;

namespace LibProsperoPkg.PKG;

/// <summary>
/// Decodes a PNG byte stream into a tightly-packed, top-down, 8-bit-per-channel RGBA surface.
/// </summary>
public static class ProsperoPngDecoder
{
    private static readonly byte[] Signature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    // Adam7 interlacing pass geometry: starting column/row and column/row stride per pass.
    private static readonly int[] PassStartX = [0, 4, 0, 2, 0, 1, 0];
    private static readonly int[] PassStartY = [0, 0, 4, 0, 2, 0, 1];
    private static readonly int[] PassStepX = [8, 8, 4, 4, 2, 2, 1];
    private static readonly int[] PassStepY = [8, 8, 8, 4, 4, 2, 2];

    /// <summary>A decoded image: its pixel dimensions and RGBA pixel data.</summary>
    public readonly struct Image
    {
        /// <summary>The image width in pixels.</summary>
        public int Width { get; init; }

        /// <summary>The image height in pixels.</summary>
        public int Height { get; init; }

        /// <summary>Tightly-packed top-down RGBA8 pixels (<see cref="Width"/> * <see cref="Height"/> * 4 bytes).</summary>
        public byte[] Rgba { get; init; }
    }

    /// <summary>
    /// Decodes <paramref name="png"/> into an RGBA8 surface.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="png"/> is empty.</exception>
    /// <exception cref="InvalidDataException">The stream is not a valid, supported PNG.</exception>
    public static Image Decode(byte[] png)
    {
        if (png is null || png.Length == 0)
            throw new ArgumentException("Empty image.", nameof(png));
        if (png.Length < 8 || !png.AsSpan(0, 8).SequenceEqual(Signature))
            throw new InvalidDataException("Not a PNG stream (bad signature).");

        int width = 0, height = 0;
        int bitDepth = 0, colorType = -1, interlace = 0;
        byte[]? palette = null;
        byte[]? paletteAlpha = null;
        byte[]? transparentColor = null;
        using var idat = new MemoryStream();
        bool sawIhdr = false;

        int pos = 8;
        while (pos + 8 <= png.Length)
        {
            uint length = BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(pos, 4));
            string type = System.Text.Encoding.ASCII.GetString(png, pos + 4, 4);
            int dataStart = pos + 8;
            if (length > int.MaxValue || dataStart + (long)length + 4 > png.Length)
                throw new InvalidDataException($"Truncated PNG chunk '{type}'.");

            int len = (int)length;
            switch (type)
            {
                case "IHDR":
                    if (len < 13)
                        throw new InvalidDataException("Malformed IHDR.");
                    width = (int)BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(dataStart, 4));
                    height = (int)BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(dataStart + 4, 4));
                    bitDepth = png[dataStart + 8];
                    colorType = png[dataStart + 9];
                    if (png[dataStart + 10] != 0)
                        throw new InvalidDataException("Unsupported PNG compression method.");
                    if (png[dataStart + 11] != 0)
                        throw new InvalidDataException("Unsupported PNG filter method.");
                    interlace = png[dataStart + 12];
                    sawIhdr = true;
                    break;

                case "PLTE":
                    palette = png.AsSpan(dataStart, len).ToArray();
                    break;

                case "tRNS":
                    if (colorType == 3)
                        paletteAlpha = png.AsSpan(dataStart, len).ToArray();
                    else
                        transparentColor = png.AsSpan(dataStart, len).ToArray();
                    break;

                case "IDAT":
                    idat.Write(png, dataStart, len);
                    break;

                case "IEND":
                    pos = png.Length; // stop.
                    break;

                default:
                    break;
            }

            if (type == "IEND")
                break;
            pos = dataStart + len + 4; // skip data + CRC.
        }

        if (!sawIhdr)
            throw new InvalidDataException("PNG has no IHDR chunk.");
        if (width <= 0 || height <= 0)
            throw new InvalidDataException("PNG has no pixels.");
        if (colorType == 3 && palette is null)
            throw new InvalidDataException("Indexed PNG has no PLTE chunk.");
        ValidateColorBitDepth(colorType, bitDepth);

        byte[] raw = Inflate(idat.GetBuffer(), (int)idat.Length);
        int channels = ChannelCount(colorType);

        var ctx = new DecodeContext
        {
            Width = width,
            Height = height,
            BitDepth = bitDepth,
            ColorType = colorType,
            Channels = channels,
            Palette = palette,
            PaletteAlpha = paletteAlpha,
            TransparentColor = transparentColor,
        };

        byte[] rgba = new byte[(long)width * height * 4 is var n && n <= int.MaxValue
            ? (int)n
            : throw new InvalidDataException("Image is too large to decode.")];

        if (interlace == 0)
        {
            DecodePass(ctx, raw, 0, 0, 1, 1, width, height, rgba);
        }
        else if (interlace == 1)
        {
            int offset = 0;
            for (int p = 0; p < 7; p++)
            {
                int passW = (width - PassStartX[p] + PassStepX[p] - 1) / PassStepX[p];
                int passH = (height - PassStartY[p] + PassStepY[p] - 1) / PassStepY[p];
                if (passW <= 0 || passH <= 0)
                    continue;

                int consumed = DecodePass(ctx, raw, offset, p, interlace, PassStepX[p], passW, passH, rgba,
                    PassStartX[p], PassStartY[p], PassStepX[p], PassStepY[p]);
                offset += consumed;
            }
        }
        else
        {
            throw new InvalidDataException("Unsupported PNG interlace method.");
        }

        return new Image { Width = width, Height = height, Rgba = rgba };
    }

    private sealed class DecodeContext
    {
        public int Width { get; init; }
        public int Height { get; init; }
        public int BitDepth { get; init; }
        public int ColorType { get; init; }
        public int Channels { get; init; }
        public byte[]? Palette { get; init; }
        public byte[]? PaletteAlpha { get; init; }
        public byte[]? TransparentColor { get; init; }
    }

    // Decodes one (possibly interlaced) pass of packed pixel rows into the RGBA target.
    // For the non-interlaced case pass geometry collapses to the full image.
    private static int DecodePass(
        DecodeContext ctx, byte[] raw, int rawOffset, int pass, int interlace, int unusedStep,
        int passWidth, int passHeight, byte[] rgba,
        int startX = 0, int startY = 0, int stepX = 1, int stepY = 1)
    {
        _ = pass;
        _ = interlace;
        _ = unusedStep;

        int bitsPerPixel = ctx.BitDepth * ctx.Channels;
        int bytesPerPixel = Math.Max(1, bitsPerPixel / 8);
        int rowBytes = (passWidth * bitsPerPixel + 7) / 8;

        byte[] previous = new byte[rowBytes];
        byte[] current = new byte[rowBytes];

        int offset = rawOffset;
        for (int y = 0; y < passHeight; y++)
        {
            if (offset + 1 + rowBytes > raw.Length)
                throw new InvalidDataException("PNG pixel data is shorter than the header describes.");

            byte filter = raw[offset++];
            Buffer.BlockCopy(raw, offset, current, 0, rowBytes);
            offset += rowBytes;

            Unfilter(filter, current, previous, bytesPerPixel);
            EmitRow(ctx, current, passWidth, startY + y * stepY, startX, stepX, rgba);

            (previous, current) = (current, previous);
        }

        return offset - rawOffset;
    }

    // Reverses one scanline's PNG filter in place.
    private static void Unfilter(byte filter, byte[] cur, byte[] prev, int bpp)
    {
        switch (filter)
        {
            case 0:
                break;
            case 1:
                for (int i = bpp; i < cur.Length; i++)
                    cur[i] = (byte)(cur[i] + cur[i - bpp]);
                break;
            case 2:
                for (int i = 0; i < cur.Length; i++)
                    cur[i] = (byte)(cur[i] + prev[i]);
                break;
            case 3:
                for (int i = 0; i < cur.Length; i++)
                {
                    int a = i >= bpp ? cur[i - bpp] : 0;
                    cur[i] = (byte)(cur[i] + ((a + prev[i]) >> 1));
                }
                break;
            case 4:
                for (int i = 0; i < cur.Length; i++)
                {
                    int a = i >= bpp ? cur[i - bpp] : 0;
                    int b = prev[i];
                    int c = i >= bpp ? prev[i - bpp] : 0;
                    cur[i] = (byte)(cur[i] + Paeth(a, b, c));
                }
                break;
            default:
                throw new InvalidDataException($"Unsupported PNG scanline filter {filter}.");
        }
    }

    private static int Paeth(int a, int b, int c)
    {
        int p = a + b - c;
        int pa = Math.Abs(p - a);
        int pb = Math.Abs(p - b);
        int pc = Math.Abs(p - c);
        if (pa <= pb && pa <= pc) return a;
        return pb <= pc ? b : c;
    }

    // Expands one unfiltered scanline into RGBA8 pixels at the given output row.
    private static void EmitRow(DecodeContext ctx, byte[] row, int passWidth, int destY, int startX, int stepX, byte[] rgba)
    {
        if (destY < 0 || destY >= ctx.Height)
            return;

        long rowBase = (long)destY * ctx.Width * 4;
        for (int x = 0; x < passWidth; x++)
        {
            int destX = startX + x * stepX;
            if (destX < 0 || destX >= ctx.Width)
                continue;

            ReadPixel(ctx, row, x, out byte r, out byte g, out byte b, out byte a);

            int di = (int)(rowBase + (long)destX * 4);
            rgba[di] = r;
            rgba[di + 1] = g;
            rgba[di + 2] = b;
            rgba[di + 3] = a;
        }
    }

    private static void ReadPixel(DecodeContext ctx, byte[] row, int x, out byte r, out byte g, out byte b, out byte a)
    {
        a = 255;
        switch (ctx.ColorType)
        {
            case 0: // greyscale
                {
                    int gray16 = SampleChannel(row, x, 0, ctx.BitDepth, 1);
                    byte gray = ScaleToByte(gray16, ctx.BitDepth);
                    if (IsTransparentGray(ctx, gray16))
                        a = 0;
                    r = g = b = gray;
                    break;
                }
            case 2: // truecolour
                {
                    int r16 = SampleChannel(row, x, 0, ctx.BitDepth, 3);
                    int g16 = SampleChannel(row, x, 1, ctx.BitDepth, 3);
                    int b16 = SampleChannel(row, x, 2, ctx.BitDepth, 3);
                    if (IsTransparentColor(ctx, r16, g16, b16))
                        a = 0;
                    r = ScaleToByte(r16, ctx.BitDepth);
                    g = ScaleToByte(g16, ctx.BitDepth);
                    b = ScaleToByte(b16, ctx.BitDepth);
                    break;
                }
            case 3: // indexed
                {
                    int index = SampleChannel(row, x, 0, ctx.BitDepth, 1);
                    byte[] pal = ctx.Palette!;
                    int pi = index * 3;
                    if (pi + 2 < pal.Length)
                    {
                        r = pal[pi];
                        g = pal[pi + 1];
                        b = pal[pi + 2];
                    }
                    else
                    {
                        r = g = b = 0;
                    }
                    a = ctx.PaletteAlpha is { } pa2 && index < pa2.Length ? pa2[index] : (byte)255;
                    break;
                }
            case 4: // greyscale + alpha
                {
                    int gray16 = SampleChannel(row, x, 0, ctx.BitDepth, 2);
                    int alpha16 = SampleChannel(row, x, 1, ctx.BitDepth, 2);
                    byte gray = ScaleToByte(gray16, ctx.BitDepth);
                    r = g = b = gray;
                    a = ScaleToByte(alpha16, ctx.BitDepth);
                    break;
                }
            case 6: // truecolour + alpha
                {
                    int r16 = SampleChannel(row, x, 0, ctx.BitDepth, 4);
                    int g16 = SampleChannel(row, x, 1, ctx.BitDepth, 4);
                    int b16 = SampleChannel(row, x, 2, ctx.BitDepth, 4);
                    int a16 = SampleChannel(row, x, 3, ctx.BitDepth, 4);
                    r = ScaleToByte(r16, ctx.BitDepth);
                    g = ScaleToByte(g16, ctx.BitDepth);
                    b = ScaleToByte(b16, ctx.BitDepth);
                    a = ScaleToByte(a16, ctx.BitDepth);
                    break;
                }
            default:
                throw new InvalidDataException($"Unsupported PNG colour type {ctx.ColorType}.");
        }
    }

    // Reads channel value for pixel x, packing sub-byte samples MSB-first per the PNG spec.
    private static int SampleChannel(byte[] row, int x, int channel, int bitDepth, int channels)
    {
        switch (bitDepth)
        {
            case 8:
                return row[x * channels + channel];
            case 16:
                {
                    int idx = (x * channels + channel) * 2;
                    return (row[idx] << 8) | row[idx + 1];
                }
            default:
                {
                    // 1/2/4-bit samples: only valid for single-channel colour types (grey / indexed).
                    int bitIndex = (x * channels + channel) * bitDepth;
                    int byteIndex = bitIndex >> 3;
                    int shift = 8 - bitDepth - (bitIndex & 7);
                    int mask = (1 << bitDepth) - 1;
                    return (row[byteIndex] >> shift) & mask;
                }
        }
    }

    // Scales a sample of the given bit depth up to the 0..255 range.
    private static byte ScaleToByte(int value, int bitDepth)
    {
        return bitDepth switch
        {
            16 => (byte)(value >> 8),
            8 => (byte)value,
            4 => (byte)(value * 0x11),
            2 => (byte)(value * 0x55),
            1 => (byte)(value * 0xFF),
            _ => (byte)value,
        };
    }

    private static bool IsTransparentGray(DecodeContext ctx, int gray)
    {
        if (ctx.TransparentColor is not { Length: >= 2 } t)
            return false;
        int key = (t[0] << 8) | t[1];
        return key == gray;
    }

    private static bool IsTransparentColor(DecodeContext ctx, int r, int g, int b)
    {
        if (ctx.TransparentColor is not { Length: >= 6 } t)
            return false;
        int kr = (t[0] << 8) | t[1];
        int kg = (t[2] << 8) | t[3];
        int kb = (t[4] << 8) | t[5];
        return kr == r && kg == g && kb == b;
    }

    private static byte[] Inflate(byte[] zlib, int length)
    {
        if (length < 2)
            throw new InvalidDataException("PNG has no image data.");

        using var input = new MemoryStream(zlib, 0, length, writable: false);
        using var deflate = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        deflate.CopyTo(output);
        return output.ToArray();
    }

    private static int ChannelCount(int colorType) => colorType switch
    {
        0 => 1,
        2 => 3,
        3 => 1,
        4 => 2,
        6 => 4,
        _ => throw new InvalidDataException($"Unsupported PNG colour type {colorType}."),
    };

    private static void ValidateColorBitDepth(int colorType, int bitDepth)
    {
        bool ok = colorType switch
        {
            0 => bitDepth is 1 or 2 or 4 or 8 or 16,
            3 => bitDepth is 1 or 2 or 4 or 8,
            2 or 4 or 6 => bitDepth is 8 or 16,
            _ => false,
        };
        if (!ok)
            throw new InvalidDataException($"Unsupported PNG colour type {colorType} / bit depth {bitDepth} combination.");
    }
}
