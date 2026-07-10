using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.License;
using System;
using System.IO;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class RifPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _contentId;
    private readonly TextFieldViewModel _output;
    private readonly TextFieldViewModel _expiry;

    private readonly TextFieldViewModel _readPath;
    private readonly TextFieldViewModel _appTitleId;

    public RifPage(IAppHost host)
        : base(host, "License records", "Create a structural license record, or summarize a license file.")
    {
        _contentId = Text("Content id");
        _output = Text("Output file", pick: PickKind.SaveFile, suggestedName: "license.rif");
        _expiry = Text("Expiry", watermark: "Optional Unix time; blank for none");
        Run("Create", Create, primary: true);

        _readPath = Text("License file", pick: PickKind.OpenFile);
        _appTitleId = Text("Application title id", watermark: "Optional; matched when set");
        Run("Summarize", Summarize);
    }

    private void Create(Action<string> log)
    {
        string expiryText = _expiry.Value.Trim();
        long expiry = expiryText.Length == 0 ? ProsperoRif.NeverExpires : long.Parse(expiryText);
        var rif = ProsperoRif.Create(_contentId.Value.Trim(), null, expiry);
        byte[] bytes = rif.ToBytes();
        File.WriteAllBytes(_output.Value.Trim(), bytes);
        log($"Output: {_output.Value.Trim()} ({bytes.Length} bytes)");
    }

    private void Summarize(Action<string> log)
    {
        string? title = _appTitleId.Value.Trim();
        if (title.Length == 0)
            title = null;

        var set = ProsperoRifSet.ReadFile(_readPath.Value.Trim());
        ProsperoRifSetSummary summary = set.Summarize(title);
        log($"Records: {summary.RecordCount}  Has app: {summary.HasApp}  Additional content: {summary.AdditionalContentCount}");
        log($"App content id: {summary.AppContentId}  Service id: {summary.ServiceId}");
        log($"Expected size: {summary.ExpectedSize}  Actual size: {summary.ActualSize}");
    }
}
