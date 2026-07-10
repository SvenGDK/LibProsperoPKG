using System.Collections.Generic;

namespace LibProsperoPkg.Gui.ViewModels.Fields;

public sealed class ChoiceFieldViewModel(IReadOnlyList<ChoiceOption> options, ChoiceOption? selected = null) : FieldViewModel
{
    private ChoiceOption? _selected = selected ?? (options.Count > 0 ? options[0] : null);

    public IReadOnlyList<ChoiceOption> Options { get; } = options;

    public ChoiceOption? Selected
    {
        get => _selected;
        set => SetProperty(ref _selected, value);
    }

    public object? SelectedValue => Selected?.Value;

    public T SelectedAs<T>() => (T)Selected!.Value;
}
