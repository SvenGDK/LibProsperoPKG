using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.PlayGo;
using System;
using System.IO;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class PlayGoPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _contentId;
    private readonly TextFieldViewModel _chunkOutput;
    private readonly TextFieldViewModel _moduleOutput;
    private readonly TextFieldViewModel _mountImage;
    private readonly TextFieldViewModel _crcOutput;

    public PlayGoPage(IAppHost host)
        : base(host, "PlayGo", "Generate auxiliary PlayGo files.")
    {
        _contentId = Text("Content id");
        _chunkOutput = Text("Chunk file output", pick: PickKind.SaveFile, suggestedName: "playgo-chunk.dat");
        Run("Build chunk file", BuildChunk, primary: true);

        _moduleOutput = Text("Module output", pick: PickKind.SaveFile, suggestedName: "right.sprx");
        Run("Write module", WriteModule);

        _mountImage = Text("Mount image", pick: PickKind.OpenFile);
        _crcOutput = Text("Chunk CRC output", pick: PickKind.SaveFile, suggestedName: "playgo-chunk.sha");
        Run("Build chunk CRC", BuildChunkCrc);
    }

    private void BuildChunk(Action<string> log)
    {
        byte[] data = ProsperoPlayGo.BuildChunkDat(_contentId.Value.Trim());
        File.WriteAllBytes(_chunkOutput.Value.Trim(), data);
        log($"Output: {_chunkOutput.Value.Trim()} ({data.Length} bytes)");
    }

    private void WriteModule(Action<string> log)
    {
        byte[]? module = ProsperoPlayGo.GetRightSprx();
        if (module is null)
        {
            log("No module is available.");
            return;
        }

        File.WriteAllBytes(_moduleOutput.Value.Trim(), module);
        log($"Output: {_moduleOutput.Value.Trim()} ({module.Length} bytes)");
    }

    private void BuildChunkCrc(Action<string> log)
    {
        byte[] crc = ProsperoPlayGo.BuildChunkCrc(File.ReadAllBytes(_mountImage.Value.Trim()));
        File.WriteAllBytes(_crcOutput.Value.Trim(), crc);
        log($"Output: {_crcOutput.Value.Trim()} ({crc.Length} bytes)");
    }
}
