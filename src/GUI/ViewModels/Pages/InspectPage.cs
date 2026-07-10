using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.NpDrm;
using LibProsperoPkg.PKG;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class InspectPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _path;

    public InspectPage(IAppHost host)
        : base(host, "Inspect package", "Read the package type, header fields, entries and content info.")
    {
        _path = Text("Package file", pick: PickKind.OpenFile, filterName: "Package", extensions: ["pkg"]);

        Run("Detect type", DetectType, primary: true);
        Run("Summary", Summary);
        Run("List entries", ListEntries);
        Run("Content info", ContentInfo);
    }

    private string PkgPath => _path.Value.Trim();

    private void DetectType(Action<string> log)
    {
        ProsperoPkgType? type = ProsperoPkgReader.DetectType(PkgPath);
        log(type is null ? "Not a recognized package." : "Type: " + type.Value);
    }

    private void Summary(Action<string> log)
    {
        ProsperoPackageExtractionInfo info = ProsperoPackageExtractor.Inspect(PkgPath);
        log("Package type: " + info.PackageType);
        log("Retail: " + (info.IsRetail ? "yes" : "no"));
        log("Outer encrypted: " + (info.OuterEncrypted ? "yes" : "no"));
        log("Requires supplied key: " + (info.RequiresSuppliedKey ? "yes" : "no"));
        log("Content id: " + info.ContentId);
        log($"Inner image: offset={info.PfsImageOffset}, size={info.PfsImageSize}");

        ProsperoPkg pkg = ProsperoPkgReader.Read(PkgPath);
        log("Entry count: " + pkg.Entries.Count);
    }

    private void ListEntries(Action<string> log)
    {
        ProsperoPkg pkg = ProsperoPkgReader.Read(PkgPath);
        log("Entries: " + pkg.Entries.Count);
        foreach (ProsperoPkgEntry entry in pkg.Entries)
            log($"  {entry.Id}  offset=0x{entry.DataOffset:X}  size={entry.DataSize}  encrypted={(entry.Encrypted ? 1 : 0)}  {entry.Name}");
    }

    private void ContentInfo(Action<string> log)
    {
        var info = ProsperoNpDrmContentInfo.Read(PkgPath);
        log("Content id: " + info.ContentId);
        log("Title id: " + info.TitleId);
        log($"DRM type: {info.DrmType}  Content type: {info.ContentType}  Flags: 0x{info.ContentFlags:X}");
        log($"Patch: {info.IsPatch}  Nested: {info.IsNestedImage}  Finalized: {info.IsFinalized}");
        log("Container offset: " + info.ContainerOffset);
    }
}
