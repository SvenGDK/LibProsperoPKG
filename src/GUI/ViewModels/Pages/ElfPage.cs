using LibProsperoPkg.Content;
using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using System;
using System.IO;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class ElfPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _path;
    private readonly TextFieldViewModel _normalizeIn;
    private readonly TextFieldViewModel _normalizeOut;

    public ElfPage(IAppHost host)
        : base(host, "ELF", "Read an ELF header, or normalize an ELF for use as a module.")
    {
        _path = Text("ELF file", pick: PickKind.OpenFile);
        Run("Read header", ReadHeader, primary: true);

        _normalizeIn = Text("Input ELF", pick: PickKind.OpenFile);
        _normalizeOut = Text("Output ELF", pick: PickKind.SaveFile);
        Run("Normalize module", Normalize);
    }

    private void ReadHeader(Action<string> log)
    {
        var header = ProsperoElfHeader.ReadFile(_path.Value.Trim());
        log($"Class: {header.Class}  Data: {header.Data}  OS ABI: {header.OsAbi}  ABI version: {header.AbiVersion}");
        log($"Type: {header.Type}  Machine: {header.Machine}  Entry: 0x{header.Entry:X}");
        log($"Program headers: {header.ProgramHeaderCount}  Flags: 0x{header.Flags:X}");
        log($"Executable: {header.IsExecutable}  Dynamic: {header.IsDynamic}  Module: {header.IsModuleType}  Module ready: {header.IsModuleReady}");
    }

    private void Normalize(Action<string> log)
    {
        byte[] elf = File.ReadAllBytes(_normalizeIn.Value.Trim());
        ElfNormalizeResult result = ProsperoElfHeader.NormalizeForModule(elf);
        File.WriteAllBytes(_normalizeOut.Value.Trim(), elf);
        log("Changed: " + (result.Changed ? "yes" : "no"));
        log("Output: " + _normalizeOut.Value.Trim());
    }
}
