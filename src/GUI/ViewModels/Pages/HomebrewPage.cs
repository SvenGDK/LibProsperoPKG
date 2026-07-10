using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.PKG;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class HomebrewPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _source;
    private readonly TextFieldViewModel _output;
    private readonly TextFieldViewModel _contentId;
    private readonly TextFieldViewModel _title;
    private readonly TextFieldViewModel _version;
    private readonly TextFieldViewModel _passcode;
    private readonly TextFieldViewModel _module;
    private readonly ChoiceFieldViewModel _compression;

    public HomebrewPage(IAppHost host)
        : base(host, "Homebrew package", "Build a package from a homebrew folder.")
    {
        _source = Text("Homebrew folder", pick: PickKind.OpenFolder, watermark: "Folder holding the main module and assets");
        _output = Text("Output folder", pick: PickKind.OpenFolder);
        _contentId = Text("Content id", watermark: "Optional; a default is used when blank");
        _title = Text("Title", watermark: "Optional display name");
        _version = Text("Version", value: "01.00");
        _passcode = Text("Passcode", watermark: "32 characters (blank uses the all-zero default)");
        _module = Text("Main module", watermark: "Defaults to eboot.bin");
        _compression = EnumChoice("Inner compression", ProsperoInnerCompression.NwonlyDataFirst);

        Run("Build", Build, primary: true);
    }

    private void Build(Action<string> log)
    {
        var options = new ProsperoHomebrewPackageOptions
        {
            HomebrewFolder = _source.Value.Trim(),
            OutputFolder = _output.Value.Trim(),
            ContentId = _contentId.Value.Trim(),
            Passcode = ParseHelpers.Passcode(_passcode.Value),
            Title = _title.Value,
            Version = _version.Value.Trim(),
            InnerCompression = _compression.SelectedAs<ProsperoInnerCompression>(),
        };

        string module = _module.Value.Trim();
        if (module.Length > 0)
            options.ModuleName = module;

        ProsperoHomebrewPackageResult result = ProsperoHomebrewPackager.Package(options);
        log("Output: " + result.OutputPath);

        var readiness = result.LaunchReadiness;
        log($"Launch ready: {(readiness.IsLaunchReady ? "yes" : "no")} (main module={readiness.HasEboot}, param.json={readiness.HasParamJson}, modules={readiness.Modules.Count}, issues={readiness.Issues.Count})");
        foreach (string issue in readiness.Issues)
            log("issue: " + issue);
    }
}
