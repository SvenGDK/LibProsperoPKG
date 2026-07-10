using LibProsperoPkg.Content;
using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using System;
using System.Collections.Generic;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class AuthInfoPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _readPath;
    private readonly TextFieldViewModel _writePath;
    private readonly TextFieldViewModel _paid;
    private readonly TextFieldViewModel _capabilities;
    private readonly TextFieldViewModel _attributes;

    public AuthInfoPage(IAppHost host)
        : base(host, "Auth info", "Read or write a SELF authentication-info sidecar.")
    {
        _readPath = Text("Auth-info file", pick: PickKind.OpenFile);
        Run("Read", Read, primary: true);

        _writePath = Text("Output file", pick: PickKind.SaveFile, suggestedName: "eboot.bin.auth_info");
        _paid = Text("Program id", watermark: "Decimal or 0x hex");
        _capabilities = Text("Capabilities", watermark: "Up to 4 hex words, space-separated");
        _attributes = Text("Attributes", watermark: "Up to 4 hex words, space-separated");
        Run("Write", Write);
    }

    private void Read(Action<string> log)
    {
        var info = ProsperoSelfAuthInfo.ReadFile(_readPath.Value.Trim());
        log($"Program id: 0x{info.Paid:X16}");
        log("Category: " + info.Category);
        log("Capabilities: " + string.Join(' ', FormatWords(info.Capabilities)));
        log("Attributes: " + string.Join(' ', FormatWords(info.Attributes)));
    }

    private void Write(Action<string> log)
    {
        ulong paid = ParseHelpers.U64(_paid.Value);
        ulong[] capabilities = ParseHelpers.HexWords(_capabilities.Value, ProsperoSelfAuthInfo.CapabilityWordCount);
        ulong[] attributes = ParseHelpers.HexWords(_attributes.Value, ProsperoSelfAuthInfo.AttributeWordCount);
        ProsperoSelfAuthInfo.Create(paid, capabilities, attributes).WriteFile(_writePath.Value.Trim());
        log("Wrote: " + _writePath.Value.Trim());
    }

    private static string[] FormatWords(IReadOnlyList<ulong> words)
    {
        var text = new string[words.Count];
        for (int i = 0; i < words.Count; i++)
            text[i] = "0x" + words[i].ToString("X16");
        return text;
    }
}
