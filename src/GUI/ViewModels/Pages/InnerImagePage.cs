using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class InnerImagePage : ToolPageViewModel
{
    private readonly TextFieldViewModel _source;
    private readonly TextFieldViewModel _output;
    private readonly TextFieldViewModel _contentId;
    private readonly TextFieldViewModel _passcode;
    private readonly ChoiceFieldViewModel _form;

    private readonly TextFieldViewModel _encryptPath;
    private readonly TextFieldViewModel _encryptContentId;
    private readonly TextFieldViewModel _encryptPasscode;

    public InnerImagePage(IAppHost host)
        : base(host, "Inner image", "Lay out an inner image from a folder, or encrypt an existing image in place.")
    {
        _source = Text("Source folder", pick: PickKind.OpenFolder);
        _output = Text("Output image", pick: PickKind.SaveFile, suggestedName: "uroot.img");
        _contentId = Text("Content id");
        _passcode = Text("Passcode", watermark: "32 characters (blank uses the all-zero default)");
        _form = EnumChoice("Image form", InnerImageForm.Plaintext);
        Run("Build image", BuildImage, primary: true);

        _encryptPath = Text("Image to encrypt", pick: PickKind.OpenFile);
        _encryptContentId = Text("Content id (encrypt)");
        _encryptPasscode = Text("Passcode (encrypt)", watermark: "32 characters (blank uses the all-zero default)");
        Run("Encrypt in place", Encrypt);
    }

    private void BuildImage(Action<string> log)
    {
        string result = ProsperoPackageBuilder.BuildInnerImage(
            _source.Value.Trim(),
            _output.Value.Trim(),
            _contentId.Value.Trim(),
            ParseHelpers.Passcode(_passcode.Value),
            _form.SelectedAs<InnerImageForm>(),
            log);
        log("Output: " + result);
    }

    private void Encrypt(Action<string> log)
    {
        ProsperoPackageBuilder.EncryptPfsImage(
            _encryptPath.Value.Trim(),
            _encryptContentId.Value.Trim(),
            ParseHelpers.Passcode(_encryptPasscode.Value),
            seed: null,
            logger: log);
        log("Encrypted: " + _encryptPath.Value.Trim());
    }
}
