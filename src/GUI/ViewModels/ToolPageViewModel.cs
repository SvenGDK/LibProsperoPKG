using LibProsperoPkg.Gui.Mvvm;
using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;

namespace LibProsperoPkg.Gui.ViewModels;

public abstract class ToolPageViewModel(IAppHost host, string title, string description) : ViewModelBase
{
    private readonly IAppHost _host = host;

    public string Title { get; } = title;

    public string Description { get; } = description;

    public ObservableCollection<FieldViewModel> Fields { get; } = [];

    public ObservableCollection<ActionViewModel> Actions { get; } = [];

    protected TextFieldViewModel Text(
        string label,
        string value = "",
        string? description = null,
        string? watermark = null,
        PickKind pick = PickKind.None,
        bool multiline = false,
        string? filterName = null,
        IReadOnlyList<string>? extensions = null,
        string? suggestedName = null)
    {
        var field = new TextFieldViewModel(_host.Storage)
        {
            Label = label,
            Description = description,
            Watermark = watermark,
            Multiline = multiline,
            Pick = pick,
            FileFilterName = filterName,
            FileExtensions = extensions,
            SuggestedFileName = suggestedName,
            Value = value,
        };
        Fields.Add(field);
        return field;
    }

    protected CheckFieldViewModel Check(string label, bool value = false, string? description = null)
    {
        var field = new CheckFieldViewModel { Label = label, Description = description, Value = value };
        Fields.Add(field);
        return field;
    }

    protected ChoiceFieldViewModel Choice(string label, IReadOnlyList<ChoiceOption> options, string? description = null)
    {
        var field = new ChoiceFieldViewModel(options) { Label = label, Description = description };
        Fields.Add(field);
        return field;
    }

    protected ChoiceFieldViewModel EnumChoice<TEnum>(string label, TEnum selected = default, string? description = null)
        where TEnum : struct, Enum
    {
        var options = new List<ChoiceOption>();
        ChoiceOption? preselected = null;
        foreach (TEnum value in Enum.GetValues<TEnum>())
        {
            var option = new ChoiceOption(Humanize(value.ToString() ?? ""), value);
            options.Add(option);
            if (EqualityComparer<TEnum>.Default.Equals(value, selected))
                preselected = option;
        }

        var field = new ChoiceFieldViewModel(options, preselected) { Label = label, Description = description };
        Fields.Add(field);
        return field;
    }

    protected void Run(string name, Action<Action<string>> operation, bool primary = false)
        => Actions.Add(new ActionViewModel(name, () => _host.RunAsync(name, operation), primary));

    private static string Humanize(string value)
    {
        var builder = new StringBuilder(value.Length + 4);
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (i > 0 && char.IsUpper(c) && !char.IsUpper(value[i - 1]))
                builder.Append(' ');
            builder.Append(c);
        }

        return builder.ToString();
    }
}
