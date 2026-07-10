using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class ComparePage : ToolPageViewModel
{
    private readonly TextFieldViewModel _reference;
    private readonly TextFieldViewModel _candidate;

    public ComparePage(IAppHost host)
        : base(host, "Compare containers", "List the differences between two metadata containers.")
    {
        _reference = Text("Reference file", pick: PickKind.OpenFile, filterName: "Package", extensions: ["pkg"]);
        _candidate = Text("Candidate file", pick: PickKind.OpenFile, filterName: "Package", extensions: ["pkg"]);

        Run("Compare", Compare, primary: true);
    }

    private void Compare(Action<string> log)
    {
        var diffs = ProsperoPackageBuilder.CompareContainers(_reference.Value.Trim(), _candidate.Value.Trim());
        if (diffs.Count == 0)
        {
            log("Containers match.");
            return;
        }

        log("Differences: " + diffs.Count);
        foreach (string diff in diffs)
            log("  " + diff);
    }
}
