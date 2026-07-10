using LibProsperoPkg.Content;
using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class LaunchReadinessPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _root;

    public LaunchReadinessPage(IAppHost host)
        : base(host, "Launch readiness", "Inspect an application root for launch readiness.")
    {
        _root = Text("Application root", pick: PickKind.OpenFolder);
        Run("Inspect", Inspect, primary: true);
    }

    private void Inspect(Action<string> log)
    {
        ProsperoLaunchReadinessReport report = ProsperoLaunchReadiness.InspectAppRoot(_root.Value.Trim());
        log("Launch ready: " + (report.IsLaunchReady ? "yes" : "no"));
        log($"Main module: {report.HasEboot}  param.json: {report.HasParamJson}  param.sfo: {report.HasParamSfo}");
        log("Requires debug console: " + report.RequiresDebugConsole);
        log($"Modules: {report.Modules.Count}  Issues: {report.Issues.Count}");
        foreach (string issue in report.Issues)
            log("issue: " + issue);
    }
}
