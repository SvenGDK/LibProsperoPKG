// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// Kraken (newLZ) bit reader.
//
// Derived from the Kraken *decompression* reference implementation in the project "ooz"
// (https://github.com/powzix/ooz), file kraken.cpp, which is licensed under the GNU GPL v3.
// LibProsperoPkg as a whole is licensed under the GNU GPLv3; section 13 of the GPLv3 expressly
// permits conveying a work that links/combines GPLv3-covered code. The bit-level layout implemented
// here is the public Kraken format; this file carries the original ooz/GPL attribution.
//
// This reader is the precise inverse of the encoder's bit writer (KrakenBitWriter): MSB-first, with a
// 24-bit refill window, and two independent readers (one forward from the start of the bit region, one
// backward from its end) that must meet at the same byte. It is index-based (no pointers,).
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System;
using System.Numerics;

namespace LibProsperoPkg.PFS.Compression.Oodle;

/// <summary>
/// A single Oodle Kraken bit reader over a byte region. Operates either forward (from the region
/// start) or backward (from the region end), mirroring the dual readers Kraken uses to code offsets
/// and lengths. MSB-first with a 24-bit refill window.
/// </summary>
internal ref struct KrakenBitReader
{
    private readonly ReadOnlySpan<byte> _region;
    private readonly bool _backward;

    /// <summary>The bit-position accounting value (number of bits owed; may go slightly negative).</summary>
    public int BitPos;

    /// <summary>The 32-bit accumulator; valid bits live at the top.</summary>
    public uint Bits;

    /// <summary>The current byte index into the region.</summary>
    public int P;

    private KrakenBitReader(ReadOnlySpan<byte> region, bool backward, int start)
    {
        _region = region;
        _backward = backward;
        BitPos = 24;
        Bits = 0;
        P = start;
    }

    /// <summary>Creates a forward reader starting at the beginning of <paramref name="region"/>.</summary>
    public static KrakenBitReader CreateForward(ReadOnlySpan<byte> region)
    {
        var r = new KrakenBitReader(region, backward: false, start: 0);
        r.Refill();
        return r;
    }

    /// <summary>Creates a backward reader starting at the end of <paramref name="region"/>.</summary>
    public static KrakenBitReader CreateBackward(ReadOnlySpan<byte> region)
    {
        var r = new KrakenBitReader(region, backward: true, start: region.Length);
        r.Refill();
        return r;
    }

    private byte At(int i) => (uint)i < (uint)_region.Length ? _region[i] : (byte)0;

    /// <summary>Refills the accumulator to keep at least 24 valid bits, in the reader's direction.</summary>
    public void Refill()
    {
        if (_backward)
        {
            while (BitPos > 0)
            {
                P--;
                Bits |= (uint)At(P) << BitPos;
                BitPos -= 8;
            }
        }
        else
        {
            while (BitPos > 0)
            {
                Bits |= (uint)At(P) << BitPos;
                BitPos -= 8;
                P++;
            }
        }
    }

    private uint ReadBitsNoRefill(int n)
    {
        uint r = Bits >> (32 - n);
        Bits <<= n;
        BitPos += n;
        return r;
    }

    private uint ReadBitsNoRefillZero(int n)
    {
        uint r = Bits >> 1 >> (31 - n);
        Bits <<= n;
        BitPos += n;
        return r;
    }

    /// <summary>Reads <paramref name="n"/> bits (n may exceed 24), refilling as needed.</summary>
    public uint ReadMoreThan24Bits(int n)
    {
        uint rv;
        if (n <= 24)
        {
            rv = ReadBitsNoRefillZero(n);
        }
        else
        {
            rv = ReadBitsNoRefill(24) << (n - 24);
            Refill();
            rv += ReadBitsNoRefill(n - 24);
        }
        Refill();
        return rv;
    }

    /// <summary>Reads a Kraken distance code parameterized by <paramref name="v"/> (a packed-offset byte).</summary>
    public uint ReadDistance(uint v)
    {
        uint w, m, rv;
        int n;
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
            Refill();
            rv += Bits >> 20;
            BitPos += 12;
            Bits <<= 12;
        }
        Refill();
        return rv;
    }

    /// <summary>Reads a Kraken length code into <paramref name="value"/>; returns false on malformed input.</summary>
    public bool ReadLength(out uint value)
    {
        value = 0;
        int n = BitOperations.LeadingZeroCount(Bits);
        if (n > 12)
            return false;
        BitPos += n;
        Bits <<= n;
        Refill();
        n += 7;
        BitPos += n;
        value = (Bits >> (32 - n)) - 64;
        Bits <<= n;
        Refill();
        return true;
    }

    /// <summary>
    /// Reads the Elias-gamma length-stream-size prefix used when the excess flag is clear. Returns
    /// false when the accumulator lacks the sanity minimum the format guarantees.
    /// </summary>
    public bool TryReadLenStreamSizePrefix(out int size)
    {
        size = 0;
        if (Bits < 0x2000)
            return false;
        int n = BitOperations.LeadingZeroCount(Bits);
        BitPos += n;
        Bits <<= n;
        Refill();
        n++;
        size = (int)((Bits >> (32 - n)) - 1);
        BitPos += n;
        Bits <<= n;
        Refill();
        return true;
    }

    /// <summary>The byte index where reading truly stopped (correcting for the refill look-ahead).</summary>
    public int SeamIndex => _backward ? P + ((24 - BitPos) >> 3) : P - ((24 - BitPos) >> 3);
}
