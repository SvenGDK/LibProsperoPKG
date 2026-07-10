using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using System;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class IdHelpersPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _publisher;
    private readonly TextFieldViewModel _titleId;
    private readonly TextFieldViewModel _label;

    private readonly TextFieldViewModel _contentIdCheck;
    private readonly TextFieldViewModel _titleIdCheck;

    private readonly ChoiceFieldViewModel _applicationType;
    private readonly TextFieldViewModel _typeName;

    public IdHelpersPage(IAppHost host)
        : base(host, "Id helpers", "Compose and validate ids, and inspect application types.")
    {
        _publisher = Text("Publisher", watermark: "Publisher prefix");
        _titleId = Text("Title id");
        _label = Text("Label");
        Run("Compose content id", Compose, primary: true);

        _contentIdCheck = Text("Content id to check");
        Run("Check content id", CheckContentId);
        _titleIdCheck = Text("Title id to check");
        Run("Check title id", CheckTitleId);

        _applicationType = EnumChoice("Application type", ProsperoApplicationType.PaidStandaloneFullApp);
        Run("Describe type", DescribeType);
        _typeName = Text("Type name to parse");
        Run("Parse type", ParseType);
    }

    private void Compose(Action<string> log)
    {
        string id = ProsperoPackageBuilder.ComposeContentId(_publisher.Value.Trim(), _titleId.Value.Trim(), _label.Value.Trim());
        log("Content id: " + id);
    }

    private void CheckContentId(Action<string> log)
        => log("Valid content id: " + (ProsperoPackageBuilder.IsValidContentId(_contentIdCheck.Value.Trim()) ? "yes" : "no"));

    private void CheckTitleId(Action<string> log)
        => log("Valid title id: " + (ProsperoPackageBuilder.IsValidTitleId(_titleIdCheck.Value.Trim()) ? "yes" : "no"));

    private void DescribeType(Action<string> log)
    {
        ProsperoApplicationType type = _applicationType.SelectedAs<ProsperoApplicationType>();
        log("Name: " + ProsperoApplicationTypes.DisplayName(type));
        log("DRM token: " + ProsperoApplicationTypes.ApplicationDrmType(type));
    }

    private void ParseType(Action<string> log)
    {
        ProsperoApplicationType type = ProsperoApplicationTypes.Parse(_typeName.Value.Trim());
        log("Parsed: " + type);
    }
}
