using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.PFS;
using LibProsperoPkg.PKG;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class ExtractPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _path;
    private readonly TextFieldViewModel _output;
    private readonly TextFieldViewModel _passcode;
    private readonly TextFieldViewModel _imageKey;
    private readonly CheckFieldViewModel _extractOuter;

    public ExtractPage(IAppHost host)
        : base(host, "Extract package", "Extract inner files using a passcode or a 32-byte image key.")
    {
        _path = Text("Package file", pick: PickKind.OpenFile, filterName: "Package", extensions: ["pkg"]);
        _output = Text("Output folder", pick: PickKind.OpenFolder);
        _passcode = Text("Passcode", watermark: "32 characters (blank uses the all-zero default)");
        _imageKey = Text("Image key (hex)", watermark: "Optional 64 hex characters; overrides the passcode");
        _extractOuter = Check("Also write outer metadata files");

        Run("List files", ListFiles);
        Run("Extract", Extract, primary: true);
    }

    private ProsperoExtractionKey BuildKey()
    {
        string hex = _imageKey.Value.Trim();
        if (hex.Length > 0)
            return ProsperoExtractionKey.FromEkpfs(Convert.FromHexString(hex));
        return ProsperoExtractionKey.FromPasscode(ParseHelpers.Passcode(_passcode.Value));
    }

    private void ListFiles(Action<string> log)
    {
        int count = 0;
        foreach (ProsperoExtractedEntry entry in ProsperoPackageExtractor.ListFiles(_path.Value.Trim(), BuildKey()))
        {
            log($"  {entry.RelativePath}  ({entry.Size} bytes){(entry.IsCompressed ? " [compressed]" : "")}");
            count++;
        }

        log("Files: " + count);
    }

    private void Extract(Action<string> log)
    {
        var options = new ProsperoExtractionOptions { ExtractOuterMetadata = _extractOuter.Value };
        ProsperoPackageManifest manifest = ProsperoPackageExtractor.Extract(_path.Value.Trim(), _output.Value.Trim(), BuildKey(), options);
        log("Extracted files: " + manifest.ExtractedFileCount);
    }
}
