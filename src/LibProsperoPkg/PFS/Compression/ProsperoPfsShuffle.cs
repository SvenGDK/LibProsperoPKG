// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Pre-compression byte shuffles for the PS5 PFSv3 compression file format.
//
// A shuffle is a reversible structure-of-arrays de-interleave applied to a block before Kraken
// compression: a fixed-size vector (8 or 16 bytes) is split into fields, and every field is grouped
// together across all vectors so that similar bytes become adjacent and compress better. The exact
// field decompositions match the target format and are validated against the documented ASCII examples.
#nullable enable
using System;

namespace LibProsperoPkg.PFS.Compression;

/// <summary>
/// Implements the 13 pre-compression shuffles of <see cref="ProsperoPfsShufflePattern"/> and their
/// exact inverses. Both directions are deterministic and allocation-light, and round-trip for
/// any input length.
/// </summary>
/// <remarks>
/// Whole vectors (8 or 16 bytes) are shuffled; a trailing partial vector (when the input length
/// is not a multiple of the stride) is passed through unchanged so that
/// <see cref="Deshuffle(System.ReadOnlySpan{byte}, ProsperoPfsShufflePattern)"/> exactly reverses
/// <see cref="Shuffle(System.ReadOnlySpan{byte}, ProsperoPfsShufflePattern)"/>.
/// </remarks>
public static class ProsperoPfsShuffle
{
    // Field decompositions for each pattern. Each inner array
    // sums to its stride (8 or 16). None has no fields (identity transform).
    private static readonly int[] Fields44 = [4, 4];
    private static readonly int[] Fields224 = [2, 2, 4];
    private static readonly int[] Fields116 = [1, 1, 6];
    private static readonly int[] Fields11111111 = [1, 1, 1, 1, 1, 1, 1, 1];
    private static readonly int[] Fields8224 = [8, 2, 2, 4];
    private static readonly int[] Fields116224 = [1, 1, 6, 2, 2, 4];
    private static readonly int[] Fields116116 = [1, 1, 6, 1, 1, 6];
    private static readonly int[] Fields4444 = [4, 4, 4, 4];
    private static readonly int[] Fields88 = [8, 8];
    private static readonly int[] Fields844 = [8, 4, 4];
    private static readonly int[] Fields26 = [2, 6];
    private static readonly int[] Fields2626 = [2, 6, 2, 6];

    /// <summary>
    /// Returns the byte stride (8 or 16, or 0 for <see cref="ProsperoPfsShufflePattern.None"/>) and the
    /// field sizes that make up one vector for <paramref name="pattern"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="pattern"/> is not a defined pattern.</exception>
    public static (int Stride, int[] Fields) Describe(ProsperoPfsShufflePattern pattern) => pattern switch
    {
        ProsperoPfsShufflePattern.None => (0, []),
        ProsperoPfsShufflePattern.Shuffle44 => (8, Fields44),
        ProsperoPfsShufflePattern.Shuffle224 => (8, Fields224),
        ProsperoPfsShufflePattern.Shuffle116 => (8, Fields116),
        ProsperoPfsShufflePattern.Shuffle11111111 => (8, Fields11111111),
        ProsperoPfsShufflePattern.Shuffle8224 => (16, Fields8224),
        ProsperoPfsShufflePattern.Shuffle116224 => (16, Fields116224),
        ProsperoPfsShufflePattern.Shuffle116116 => (16, Fields116116),
        ProsperoPfsShufflePattern.Shuffle4444 => (16, Fields4444),
        ProsperoPfsShufflePattern.Shuffle88 => (16, Fields88),
        ProsperoPfsShufflePattern.Shuffle844 => (16, Fields844),
        ProsperoPfsShufflePattern.Shuffle26 => (8, Fields26),
        ProsperoPfsShufflePattern.Shuffle2626 => (16, Fields2626),
        _ => throw new ArgumentOutOfRangeException(nameof(pattern), pattern, "Undefined PFS shuffle pattern."),
    };

    /// <summary>Applies the forward shuffle for <paramref name="pattern"/> to <paramref name="input"/>.</summary>
    /// <returns>A new buffer the same length as <paramref name="input"/> with the bytes shuffled.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="pattern"/> is not a defined pattern.</exception>
    public static byte[] Shuffle(ReadOnlySpan<byte> input, ProsperoPfsShufflePattern pattern)
    {
        (int stride, int[] fields) = Describe(pattern);
        var output = new byte[input.Length];
        if (stride == 0)
        {
            input.CopyTo(output);
            return output;
        }

        int vectorCount = input.Length / stride;
        int outPos = 0;
        int fieldOffset = 0;
        foreach (int size in fields)
        {
            for (int v = 0; v < vectorCount; v++)
            {
                input.Slice((v * stride) + fieldOffset, size).CopyTo(output.AsSpan(outPos, size));
                outPos += size;
            }

            fieldOffset += size;
        }

        int remainderStart = vectorCount * stride;
        input[remainderStart..].CopyTo(output.AsSpan(outPos));
        return output;
    }

    /// <summary>Reverses <see cref="Shuffle"/> for <paramref name="pattern"/>.</summary>
    /// <returns>A new buffer the same length as <paramref name="input"/> with the bytes restored.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="pattern"/> is not a defined pattern.</exception>
    public static byte[] Deshuffle(ReadOnlySpan<byte> input, ProsperoPfsShufflePattern pattern)
    {
        (int stride, int[] fields) = Describe(pattern);
        var output = new byte[input.Length];
        if (stride == 0)
        {
            input.CopyTo(output);
            return output;
        }

        int vectorCount = input.Length / stride;
        int inPos = 0;
        int fieldOffset = 0;
        foreach (int size in fields)
        {
            for (int v = 0; v < vectorCount; v++)
            {
                input.Slice(inPos, size).CopyTo(output.AsSpan((v * stride) + fieldOffset, size));
                inPos += size;
            }

            fieldOffset += size;
        }

        int remainderStart = vectorCount * stride;
        input[inPos..].CopyTo(output.AsSpan(remainderStart));
        return output;
    }
}
