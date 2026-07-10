using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.PKG;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class BuildPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _source;
    private readonly TextFieldViewModel _output;
    private readonly TextFieldViewModel _contentId;
    private readonly TextFieldViewModel _titleId;
    private readonly TextFieldViewModel _title;
    private readonly TextFieldViewModel _version;
    private readonly TextFieldViewModel _passcode;
    private readonly TextFieldViewModel _drm;
    private readonly ChoiceFieldViewModel _mode;
    private readonly ChoiceFieldViewModel _format;
    private readonly ChoiceFieldViewModel _compression;
    private readonly ChoiceFieldViewModel _applicationType;
    private readonly CheckFieldViewModel _generateParam;
    private readonly CheckFieldViewModel _compressInner;
    private readonly CheckFieldViewModel _signModules;
    private readonly CheckFieldViewModel _licenseFree;

    public BuildPage(IAppHost host)
        : base(host, "Build package", "Build a package from a prepared source folder.")
    {
        _source = Text("Source folder", pick: PickKind.OpenFolder, watermark: "Folder holding the prepared file set");
        _output = Text("Output folder", pick: PickKind.OpenFolder, watermark: "Where the built package is written");
        _contentId = Text("Content id", watermark: "36-character content id");
        _titleId = Text("Title id", watermark: "PPSAxxxxx");
        _title = Text("Title", watermark: "Display name");
        _version = Text("Version", value: "01.00");
        _passcode = Text("Passcode", watermark: "32 characters (blank uses the all-zero default)");
        _mode = EnumChoice("Mode", ProsperoPackageMode.Application);
        _format = EnumChoice("Output format", ProsperoOutputFormat.MetadataContainer);
        _compression = EnumChoice("Inner compression", ProsperoInnerCompression.None);
        _applicationType = EnumChoice("Application type", ProsperoApplicationType.PaidStandaloneFullApp);
        _drm = Text("Application DRM type", watermark: "Optional token override (free / standard / freemium)");
        _generateParam = Check("Generate param.json when missing", value: true);
        _compressInner = Check("Compress inner image");
        _signModules = Check("Sign executable modules", value: true);
        _licenseFree = Check("License-free debug package");

        Run("Build", Build, primary: true);
    }

    private void Build(System.Action<string> log)
    {
        var options = new ProsperoBuildOptions
        {
            SourceFolder = _source.Value.Trim(),
            OutputFolder = _output.Value.Trim(),
            ContentId = _contentId.Value.Trim(),
            TitleId = _titleId.Value.Trim(),
            Title = _title.Value,
            Version = string.IsNullOrWhiteSpace(_version.Value) ? "01.00" : _version.Value.Trim(),
            Passcode = string.IsNullOrWhiteSpace(_passcode.Value) ? new string('0', 32) : _passcode.Value.Trim(),
            Mode = _mode.SelectedAs<ProsperoPackageMode>(),
            OutputFormat = _format.SelectedAs<ProsperoOutputFormat>(),
            InnerCompression = _compression.SelectedAs<ProsperoInnerCompression>(),
            ApplicationType = _applicationType.SelectedAs<ProsperoApplicationType>(),
            GenerateParamJsonIfMissing = _generateParam.Value,
            CompressInnerImage = _compressInner.Value,
            FakeSignSelfModules = _signModules.Value,
            LicenseFree = _licenseFree.Value,
        };

        string drm = _drm.Value.Trim();
        if (drm.Length > 0)
            options.ApplicationDrmType = drm;

        ProsperoBuildResult result = ProsperoPackageBuilder.Build(options, log);
        log("Output: " + result.OutputPath);
        foreach (string warning in result.Warnings)
            log("warning: " + warning);
    }
}
