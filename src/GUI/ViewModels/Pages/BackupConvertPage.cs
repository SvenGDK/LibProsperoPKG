using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.PKG;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class BackupConvertPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _source;
    private readonly TextFieldViewModel _output;
    private readonly TextFieldViewModel _contentId;
    private readonly TextFieldViewModel _passcode;
    private readonly TextFieldViewModel _version;
    private readonly TextFieldViewModel _decryptedSubfolder;
    private readonly CheckFieldViewModel _embeddedModule;

    public BackupConvertPage(IAppHost host)
        : base(host, "Convert backup", "Convert a decrypted application backup into a debug package.")
    {
        _source = Text("Backup folder", pick: PickKind.OpenFolder);
        _output = Text("Output folder", pick: PickKind.OpenFolder);
        _contentId = Text("Content id", watermark: "Optional; taken from the backup when blank");
        _passcode = Text("Passcode", watermark: "32 characters (blank uses the all-zero default)");
        _version = Text("Version", watermark: "Optional; taken from the backup when blank");
        _decryptedSubfolder = Text("Decrypted subfolder", watermark: "Holds the raw module copies; blank uses \"decrypted\"");
        _embeddedModule = Check("Use the embedded debug module");

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
            UseEmbeddedRightSprx = _embeddedModule.Value,
        };

        string subfolder = _decryptedSubfolder.Value.Trim();
        if (subfolder.Length > 0)
            options.DecryptedSubfolder = subfolder;

        ProsperoBackupConversionResult result = ProsperoBackupConverter.Convert(options, log);
        log("Output: " + result.OutputPath);

        log("Substituted modules: " + result.SubstitutedModules.Count);
        foreach (string module in result.SubstitutedModules)
            log("  " + module);
        log("Plaintext modules: " + result.PlaintextModules.Count);
        foreach (string module in result.PlaintextModules)
            log("  " + module);
        if (result.UnresolvedModules.Count > 0)
        {
            log("Unresolved modules: " + result.UnresolvedModules.Count);
            foreach (string module in result.UnresolvedModules)
                log("  " + module);
        }

        var readiness = result.LaunchReadiness;
        log($"Launch ready: {(readiness.IsLaunchReady ? "yes" : "no")} (main module={readiness.HasEboot}, param.json={readiness.HasParamJson}, modules={readiness.Modules.Count})");
        foreach (string warning in result.Warnings)
            log("warning: " + warning);
    }
}
