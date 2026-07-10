using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.PKG;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class MergePage : ToolPageViewModel
{
    private readonly TextFieldViewModel _input;
    private readonly TextFieldViewModel _output;
    private readonly CheckFieldViewModel _digest;

    public MergePage(IAppHost host)
        : base(host, "Merge split package", "Merge split package parts found in a folder.")
    {
        _input = Text("Input folder", pick: PickKind.OpenFolder);
        _output = Text("Output folder", pick: PickKind.OpenFolder, watermark: "Optional; defaults next to the input");
        _digest = Check("Compute SHA-256 for each merged package");

        Run("Merge", Merge, primary: true);
    }

    private void Merge(Action<string> log)
    {
        string? output = _output.Value.Trim();
        if (output.Length == 0)
            output = null;

        var results = ProsperoPkgMerger.MergeDirectory(_input.Value.Trim(), output, _digest.Value);
        log("Merged packages: " + results.Count);
        foreach (ProsperoPkgMergeResult result in results)
            log("  " + result.OutputPath);
    }
}
