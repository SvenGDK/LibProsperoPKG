using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.PFS;
using LibProsperoPkg.PFS.Compression;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class PfscPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _input;
    private readonly TextFieldViewModel _output;

    public PfscPage(IAppHost host)
        : base(host, "PFSC container", "Pack and unpack compressed PFS containers.")
    {
        _input = Text("Source file", pick: PickKind.OpenFile);
        _output = Text("Destination file", pick: PickKind.SaveFile);

        Run("Pack (zlib)", PackZlib, primary: true);
        Run("Unpack (zlib)", UnpackZlib);
        Run("Pack (block)", PackBlock);
        Run("Unpack (block)", UnpackBlock);
        Run("Check container", CheckContainer);
    }

    private string Input => _input.Value.Trim();

    private string Output => _output.Value.Trim();

    private void PackZlib(Action<string> log)
    {
        ProsperoPfscResult result = ProsperoPfsc.PackFile(Input, Output, null, log);
        log($"Output: {result.OutputPath} (raw={result.RawSize}, encoded={result.EncodedSize}, stored raw={result.StoredRaw})");
    }

    private void UnpackZlib(Action<string> log)
        => log("Unpacked bytes: " + ProsperoPfsc.Unpack(Input, Output, log));

    private void PackBlock(Action<string> log)
    {
        ProsperoCompressedPfsImage.PackFile(Input, Output, ProsperoCompressedPfsImage.DefaultLevel, ProsperoCompressedPfsImage.DefaultBlockSize, log);
        log("Packed: " + Output);
    }

    private void UnpackBlock(Action<string> log)
        => log("Unpacked bytes: " + ProsperoCompressedPfsImage.UnpackFile(Input, Output, log));

    private void CheckContainer(Action<string> log)
        => log("PFSC container: " + (ProsperoPfsc.IsPfsc(Input) ? "yes" : "no"));
}
