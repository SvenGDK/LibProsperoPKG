// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// Kraken (newLZ) bit writer — the inverse of the decoder's bit reader.
//
// The bit-level layout it produces is the Kraken format. Portions carry a GPLv3 attribution; see
// NOTICE. LibProsperoPkg is licensed under the GNU GPLv3 (section 13 permits combining GPLv3 code).
//
// Bits are packed MSB-first to mirror the reader's 24-bit refill window. A "forward" stream's bytes go
// at the start of the bit region in order; a "backward" stream's bytes are written in reverse order onto the region's
// tail (region = forwardBytes ++ reverse(backwardBytes)) so the two readers meet at the same byte.
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System.Collections.Generic;
using System.Numerics;

namespace LibProsperoPkg.PFS.Compression.Oodle;

/// <summary>Accumulates bits MSB-first into bytes; one instance per bitstream direction.</summary>
internal sealed class KrakenBitWriter
{
    private readonly List<byte> _bytes = new();
    private uint _cur;
    private int _curBits;

    /// <summary>Number of whole bytes produced once the trailing partial byte is flushed.</summary>
    public int ByteLength => _bytes.Count + (_curBits > 0 ? 1 : 0);

    /// <summary>Writes the low <paramref name="n"/> bits of <paramref name="value"/>, MSB-first.</summary>
    public void WriteBits(uint value, int n)
    {
        for (int i = n - 1; i >= 0; i--)
            WriteBit((value >> i) & 1);
    }

    /// <summary>Writes <paramref name="count"/> zero bits.</summary>
    public void WriteZeros(int count)
    {
        for (int i = 0; i < count; i++)
            WriteBit(0);
    }

    private void WriteBit(uint bit)
    {
        _cur = (_cur << 1) | (bit & 1);
        _curBits++;
        if (_curBits == 8)
        {
            _bytes.Add((byte)_cur);
            _cur = 0;
            _curBits = 0;
        }
    }

    /// <summary>Writes the Elias-gamma length-stream-size prefix for <paramref name="size"/> (>= 0).</summary>
    public void WriteLenStreamSizePrefix(int size)
    {
        uint field = (uint)size + 1;
        int fieldBits = 32 - BitOperations.LeadingZeroCount(field);
        WriteZeros(fieldBits - 1);
        WriteBits(field, fieldBits);
    }

    /// <summary>Writes a Kraken length code for <paramref name="value"/> (the u32 length-stream value).</summary>
    public void WriteLength(uint value)
    {
        uint field = value + 64;
        int fieldBits = 32 - BitOperations.LeadingZeroCount(field);
        WriteZeros(fieldBits - 7);
        WriteBits(field, fieldBits);
    }

    /// <summary>
    /// Encodes distance <paramref name="distance"/> (>= 8): returns the packed-offset command byte and
    /// writes the associated extra bits. Only the &lt; 0xF0 bucket (window &lt;= 256 KiB) is produced.
    /// </summary>
    public byte WriteDistance(int distance)
    {
        uint t = (uint)distance + 248;
        int top = 31 - BitOperations.LeadingZeroCount(t); // floor(log2(t))
        int vhi = top - 8;
        uint rem = t - (1u << (vhi + 8));
        uint vlo = rem & 0xF;
        uint e = rem >> 4;
        int n = vhi + 4;
        WriteBits(e, n);
        return (byte)((vhi << 4) | (int)vlo);
    }

    /// <summary>Flushes any partial byte (zero-padded) and returns the produced bytes in write order.</summary>
    public byte[] ToBytes()
    {
        if (_curBits > 0)
        {
            _bytes.Add((byte)(_cur << (8 - _curBits)));
            _cur = 0;
            _curBits = 0;
        }
        return _bytes.ToArray();
    }
}
