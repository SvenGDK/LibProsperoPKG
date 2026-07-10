using System;
using System.Globalization;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

internal static class ParseHelpers
{
    public static ulong U64(string? text)
    {
        text = text?.Trim();
        if (string.IsNullOrEmpty(text))
            return 0;
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.Parse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        return ulong.Parse(text, NumberStyles.Integer, CultureInfo.InvariantCulture);
    }

    public static string Passcode(string? text)
        => string.IsNullOrWhiteSpace(text) ? new string('0', 32) : text.Trim();

    public static ulong[] HexWords(string? text, int max)
    {
        text = text?.Trim();
        if (string.IsNullOrEmpty(text))
            return [];

        string[] parts = text.Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries);
        int count = Math.Min(parts.Length, max);
        var words = new ulong[count];
        for (int i = 0; i < count; i++)
            words[i] = U64(parts[i]);
        return words;
    }
}
