using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class BackupConvertPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _source;
    private readonly TextFieldViewModel _output;
    private readonly TextFieldViewModel _contentId;
    private readonly TextFieldViewModel _passcode;
    private readonly TextFieldViewModel _version;

    public BackupConvertPage(IAppHost host)
        : base(host, "Convert backup", "Convert a decrypted application backup into a debug package.")
    {
        _source = Text("Backup folder", pick: PickKind.OpenFolder);
        _output = Text("Output folder", pick: PickKind.OpenFolder);
        _contentId = Text("Content id", watermark: "Optional; taken from the backup when blank");
        _passcode = Text("Passcode", watermark: "32 characters (blank uses the all-zero default)");
        _version = Text("Version", watermark: "Optional; taken from the backup when blank");

        Run("Convert", Convert, primary: true);
    }

    private void Convert(Action<string> log)
    {
        var options = new ProsperoBackupConversionOptions
        {
            BackupFolder = _source.Value.Trim(),
            OutputFolder = _output.Value.Trim(),
            ContentId = _contentId.Value.Trim(),
            Passcode = ParseHelpers.Passcode(_passcode.Value),
            Version = _version.Value.Trim(),
        };

        ProsperoBackupConversionResult result = ProsperoBackupConverter.Convert(options);
        log("Output: " + result.OutputPath);
        log("Substituted modules: " + result.SubstitutedModules.Count);
        foreach (string module in result.SubstitutedModules)
            log("  " + module);
    }
}
