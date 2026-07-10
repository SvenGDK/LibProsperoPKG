using LibProsperoPkg.Content;
using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using System;
using System.IO;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class FselfPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _elfPath;
    private readonly TextFieldViewModel _outPath;
    private readonly TextFieldViewModel _appVersion;
    private readonly TextFieldViewModel _firmwareVersion;
    private readonly TextFieldViewModel _authorityId;
    private readonly TextFieldViewModel _folder;

    public FselfPage(IAppHost host)
        : base(host, "Fake-self", "Generate a fake-self from an ELF, or fake-sign every module in a folder.")
    {
        _elfPath = Text("ELF file", pick: PickKind.OpenFile);
        _outPath = Text("Output file", pick: PickKind.SaveFile, suggestedName: "eboot.bin");
        _appVersion = Text("Application version", watermark: "Decimal or 0x hex; blank for 0");
        _firmwareVersion = Text("Firmware version", watermark: "Decimal or 0x hex; blank for 0");
        _authorityId = Text("Authority id", watermark: "Optional; decimal or 0x hex");
        Run("Generate", Generate, primary: true);

        _folder = Text("Module folder", pick: PickKind.OpenFolder);
        Run("Fake-sign folder", FakeSignFolder);
    }

    private FselfOptions BuildOptions()
    {
        string authority = _authorityId.Value.Trim();
        return new FselfOptions
        {
            AppVersion = ParseHelpers.U64(_appVersion.Value),
            FirmwareVersion = ParseHelpers.U64(_firmwareVersion.Value),
            AuthorityId = authority.Length > 0 ? (ulong?)ParseHelpers.U64(authority) : null,
        };
    }

    private void Generate(Action<string> log)
    {
        byte[] elf = File.ReadAllBytes(_elfPath.Value.Trim());
        byte[] fself = ProsperoFself.MakeFself(elf, BuildOptions());
        File.WriteAllBytes(_outPath.Value.Trim(), fself);
        log($"Output: {_outPath.Value.Trim()} ({fself.Length} bytes)");
    }

    private void FakeSignFolder(Action<string> log)
    {
        int count = ProsperoPackageBuilder.FakeSignModulesInPlace(_folder.Value.Trim(), BuildOptions());
        log("Modules converted: " + count);
    }
}
