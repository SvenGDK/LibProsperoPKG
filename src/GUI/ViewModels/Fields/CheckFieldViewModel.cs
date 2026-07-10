namespace LibProsperoPkg.Gui.ViewModels.Fields;

public sealed class CheckFieldViewModel : FieldViewModel
{
    private bool _value;

    public bool Value
    {
        get => _value;
        set => SetProperty(ref _value, value);
    }
}
