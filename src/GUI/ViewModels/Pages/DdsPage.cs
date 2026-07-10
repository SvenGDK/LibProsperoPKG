using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.PKG;
using System;
using System.IO;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class DdsPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _input;
    private readonly TextFieldViewModel _output;

    public DdsPage(IAppHost host)
        : base(host, "Texture", "Encode a PNG image to a DDS texture.")
    {
        _input = Text("PNG file", pick: PickKind.OpenFile, filterName: "PNG image", extensions: ["png"]);
        _output = Text("DDS file", pick: PickKind.SaveFile, suggestedName: "icon0.dds");
        Run("Encode", Encode, primary: true);
    }

    private void Encode(Action<string> log)
    {
        byte[] dds = ProsperoDdsEncoder.EncodePngToDds(File.ReadAllBytes(_input.Value.Trim()));
        File.WriteAllBytes(_output.Value.Trim(), dds);
        log($"Output: {_output.Value.Trim()} ({dds.Length} bytes)");
    }
}
