using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.PKG;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class ValidatePage : ToolPageViewModel
{
    private readonly TextFieldViewModel _path;
    private readonly TextFieldViewModel _expected;

    public ValidatePage(IAppHost host)
        : base(host, "Validate package", "Run structural checks and report pass, warning and fail counts.")
    {
        _path = Text("Package file", pick: PickKind.OpenFile, filterName: "Package", extensions: ["pkg"]);
        _expected = Text("Expected content id", watermark: "Optional; checked when set");

        Run("Validate", Validate, primary: true);
    }

    private void Validate(Action<string> log)
    {
        string? expected = _expected.Value.Trim();
        if (expected.Length == 0)
            expected = null;

        ProsperoAcceptanceReport report = ProsperoPkgValidator.Validate(_path.Value.Trim(), expected);

        int pass = 0, warn = 0, fail = 0;
        foreach (ProsperoAcceptanceCheck check in report.Checks)
        {
            string tag = check.Status switch
            {
                ProsperoCheckStatus.Pass => "pass",
                ProsperoCheckStatus.Warning => "warning",
                _ => "fail",
            };
            log($"[{tag}] {check.Name}: {check.Detail}");

            switch (check.Status)
            {
                case ProsperoCheckStatus.Pass: pass++; break;
                case ProsperoCheckStatus.Warning: warn++; break;
                case ProsperoCheckStatus.Fail: fail++; break;
            }
        }

        log($"Accepted: {(report.Accepted ? "yes" : "no")} (pass={pass}, warning={warn}, fail={fail})");
    }
}
