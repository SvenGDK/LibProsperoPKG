using LibProsperoPkg.Gui.Mvvm;

namespace LibProsperoPkg.Gui.ViewModels.Fields;

public abstract class FieldViewModel : ViewModelBase
{
    public string Label { get; init; } = "";

    public string? Description { get; init; }

    public bool HasDescription => !string.IsNullOrWhiteSpace(Description);
}
