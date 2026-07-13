using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.PFS;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class PfsImagePage : ToolPageViewModel
{
    private readonly TextFieldViewModel _source;
    private readonly TextFieldViewModel _layoutOutput;

    private readonly TextFieldViewModel _imagePath;
    private readonly TextFieldViewModel _contentId;
    private readonly TextFieldViewModel _passcode;

    public PfsImagePage(IAppHost host)
        : base(host, "PFS image", "Build an image layout from a folder, or check and decrypt an image.")
    {
        _source = Text("Source folder", pick: PickKind.OpenFolder);
        _layoutOutput = Text("Output image", pick: PickKind.SaveFile, suggestedName: "uroot.img");
        Run("Build layout", BuildLayout, primary: true);

        _imagePath = Text("Image file", pick: PickKind.OpenFile);
        _contentId = Text("Content id");
        _passcode = Text("Passcode", watermark: "32 characters (blank uses the all-zero default)");
        Run("Check encryption", CheckEncryption);
        Run("Decrypt in place", Decrypt);
    }

    private void BuildLayout(Action<string> log)
    {
        ProsperoPfsLayoutResult result = ProsperoPfsLayout.BuildFromFolder(_source.Value.Trim(), _layoutOutput.Value.Trim(), options: null, logger: log);
        log("Output: " + result.OutputPath);
        log($"Files: {result.FileCount}, directories: {result.DirectoryCount}");
    }

    private void CheckEncryption(Action<string> log)
        => log("Encrypted: " + (ProsperoPfsImage.IsEncrypted(_imagePath.Value.Trim()) ? "yes" : "no"));

    private void Decrypt(Action<string> log)
    {
        byte[] ekpfs = ProsperoPfsKeys.DeriveEkpfs(_contentId.Value.Trim(), ParseHelpers.Passcode(_passcode.Value));
        ProsperoPfsImage.DecryptInPlace(_imagePath.Value.Trim(), new ProsperoPfsImageOptions { Ekpfs = ekpfs }, log);
        log("Decrypted: " + _imagePath.Value.Trim());
    }
}
