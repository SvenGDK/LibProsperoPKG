namespace LibProsperoPkg.Gui.ViewModels.Fields;

public sealed class ChoiceOption(string label, object value)
{
    public string Label { get; } = label;

    public object Value { get; } = value;

    public override string ToString() => Label;
}
