using LibProsperoPkg.Content;
using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using System;
using System.IO;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class UcpPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _path;
    private readonly TextFieldViewModel _repairOutput;
    private readonly TextFieldViewModel _directory;
    private readonly TextFieldViewModel _buildOutput;

    public UcpPage(IAppHost host)
        : base(host, "Content protection", "Validate, verify, build and repair content protection files.")
    {
        _path = Text("Protection file", pick: PickKind.OpenFile);
        Run("Validate", Validate, primary: true);
        Run("Verify digest", VerifyDigest);

        _repairOutput = Text("Repaired output", pick: PickKind.SaveFile);
        Run("Repair digest", RepairDigest);

        _directory = Text("Source directory", pick: PickKind.OpenFolder);
        _buildOutput = Text("Build output", pick: PickKind.SaveFile);
        Run("Build from directory", BuildFromDirectory);
    }

    private void Validate(Action<string> log)
    {
        bool ok = ProsperoUcp.Validate(File.ReadAllBytes(_path.Value.Trim()), out string? error);
        log("Valid: " + (ok ? "yes" : "no"));
        if (!ok && error is not null)
            log("Reason: " + error);
    }

    private void VerifyDigest(Action<string> log)
        => log("Digest: " + (ProsperoUcp.VerifyDigest(File.ReadAllBytes(_path.Value.Trim())) ? "match" : "mismatch"));

    private void RepairDigest(Action<string> log)
    {
        byte[] repaired = ProsperoUcp.WithRepairedDigest(File.ReadAllBytes(_path.Value.Trim()));
        File.WriteAllBytes(_repairOutput.Value.Trim(), repaired);
        log($"Output: {_repairOutput.Value.Trim()} ({repaired.Length} bytes)");
    }

    private void BuildFromDirectory(Action<string> log)
    {
        byte[] ucp = ProsperoUcp.BuildFromDirectory(_directory.Value.Trim());
        File.WriteAllBytes(_buildOutput.Value.Trim(), ucp);
        log($"Output: {_buildOutput.Value.Trim()} ({ucp.Length} bytes)");
    }
}
