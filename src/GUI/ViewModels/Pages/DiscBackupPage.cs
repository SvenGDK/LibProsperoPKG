using LibProsperoPkg.DiscBackup;
using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.NpDrm;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class DiscBackupPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _manifest;
    private readonly TextFieldViewModel _output;

    public DiscBackupPage(IAppHost host)
        : base(host, "Disc backup", "Reassemble and verify a split disc backup.")
    {
        _manifest = Text("Manifest or folder", pick: PickKind.OpenFile, watermark: "app.json or the folder containing it");
        _output = Text("Output file", pick: PickKind.SaveFile, suggestedName: "backup.pkg");
        Run("Reassemble", Reassemble, primary: true);
        Run("Verify", Verify);
        Run("Content info", ContentInfo);
    }

    private ProsperoDiscBackup Open() => ProsperoDiscBackup.Open(_manifest.Value.Trim());

    private void Reassemble(Action<string> log)
    {
        long written = Open().ReassembleTo(_output.Value.Trim());
        log($"Output: {_output.Value.Trim()} ({written} bytes)");
    }

    private void Verify(Action<string> log)
    {
        ProsperoDiscBackup backup = Open();
        log("Package digest: " + (backup.VerifyPackageDigest() ? "match" : "mismatch"));
        log("Chunk CRC hash: " + (backup.VerifyChunkCrcHash() ? "match" : "mismatch"));
        bool crcs = backup.VerifyChunkCrcs(out int mismatch);
        log("Chunk CRCs: " + (crcs ? "all match" : "mismatch at chunk " + mismatch));
    }

    private void ContentInfo(Action<string> log)
    {
        ProsperoNpDrmContentInfo info = Open().ReadContentInfo();
        log("Content id: " + info.ContentId);
        log("Title id: " + info.TitleId);
        log($"DRM type: {info.DrmType}  Content type: {info.ContentType}");
    }
}
