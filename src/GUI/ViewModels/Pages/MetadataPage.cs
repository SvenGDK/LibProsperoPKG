using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.Metadata;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class MetadataPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _contentId;
    private readonly TextFieldViewModel _titleId;
    private readonly TextFieldViewModel _titleName;
    private readonly ChoiceFieldViewModel _drmType;
    private readonly TextFieldViewModel _paramOutput;

    private readonly TextFieldViewModel _appName;
    private readonly TextFieldViewModel _appVersion;
    private readonly TextFieldViewModel _manifestTitleId;
    private readonly TextFieldViewModel _runtimeVersion;
    private readonly TextFieldViewModel _branchType;
    private readonly CheckFieldViewModel _twinTurbo;
    private readonly TextFieldViewModel _manifestOutput;

    public MetadataPage(IAppHost host)
        : base(host, "Metadata", "Create a default param file or an application manifest.")
    {
        _contentId = Text("Content id");
        _titleId = Text("Title id");
        _titleName = Text("Title name");
        _drmType = EnumChoice("DRM type", ProsperoDrmType.Standard);
        _paramOutput = Text("param output", pick: PickKind.SaveFile, suggestedName: "param.json");
        Run("Create param", CreateParam, primary: true);

        _appName = Text("Application name");
        _appVersion = Text("Application version", value: "01.00");
        _manifestTitleId = Text("Title id (manifest)");
        _runtimeVersion = Text("Runtime version");
        _branchType = Text("Branch type", value: "release");
        _twinTurbo = Check("Twin turbo", value: true);
        _manifestOutput = Text("manifest output", pick: PickKind.SaveFile, suggestedName: "manifest.json");
        Run("Create manifest", CreateManifest);
    }

    private void CreateParam(Action<string> log)
    {
        var param = ProsperoParam.CreateDefault(
            _contentId.Value.Trim(),
            _titleId.Value.Trim(),
            _titleName.Value,
            _drmType.SelectedAs<ProsperoDrmType>());
        param.Save(_paramOutput.Value.Trim());
        log("Output: " + _paramOutput.Value.Trim());
    }

    private void CreateManifest(Action<string> log)
    {
        var manifest = ProsperoManifest.Create(
            _appName.Value.Trim(),
            _appVersion.Value.Trim(),
            _manifestTitleId.Value.Trim(),
            _runtimeVersion.Value.Trim(),
            string.IsNullOrWhiteSpace(_branchType.Value) ? "release" : _branchType.Value.Trim(),
            _twinTurbo.Value);
        manifest.Save(_manifestOutput.Value.Trim());
        log("Output: " + _manifestOutput.Value.Trim());
    }
}
