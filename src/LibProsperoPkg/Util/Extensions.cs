// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// Shared utility primitives: crypto, binary IO and stream helpers.
#nullable disable
using System.Collections.Generic;

namespace LibProsperoPkg.Util;

public static class DictionaryExtensions
{
    public static V GetOrDefault<K, V>(this Dictionary<K, V> d, K key, V def = default(V))
    {
        if (d.ContainsKey(key)) return d[key];
        return def;
    }
}

public static class ArrayExtensions
{
    public static T[] Fill<T>(this T[] arr, T val)
    {
        for (var i = 0; i < arr.Length; i++)
        {
            arr[i] = val;
        }
        return arr;
    }
}

public static class ByteArrayExtensions
{
    public static string ToHexCompact(this byte[] b)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var x in b) sb.AppendFormat("{0:X2}", x);
        return sb.ToString();
    }
}
#if !CORE_DISABLED_PSMT
// The custom Tuple Deconstruct below is provided by the BCL (System.TupleExtensions)
// on .NET 10, so it is intentionally disabled to avoid an ambiguous-call conflict.
#endif
