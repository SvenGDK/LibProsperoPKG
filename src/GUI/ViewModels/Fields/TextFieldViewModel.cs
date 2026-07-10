using LibProsperoPkg.Gui.Mvvm;
using LibProsperoPkg.Gui.Services;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace LibProsperoPkg.Gui.ViewModels.Fields;

public sealed class TextFieldViewModel : FieldViewModel
{
    private readonly IStorageService _storage;
    private string _value = "";

    public TextFieldViewModel(IStorageService storage)
    {
        _storage = storage;
        BrowseCommand = new AsyncRelayCommand(BrowseAsync);
    }

    public string Value
    {
        get => _value;
        set => SetProperty(ref _value, value);
    }

    public string? Watermark { get; init; }

    public bool Multiline { get; init; }

    public double InputHeight => Multiline ? 120 : double.NaN;

    public PickKind Pick { get; init; } = PickKind.None;

    public string? FileFilterName { get; init; }

    public IReadOnlyList<string>? FileExtensions { get; init; }

    public string? SuggestedFileName { get; init; }

    public bool ShowBrowse => Pick != PickKind.None;

    public AsyncRelayCommand BrowseCommand { get; }

    private async Task BrowseAsync()
    {
        string? picked = Pick switch
        {
            PickKind.OpenFile => await _storage.OpenFileAsync(Label, FileFilterName, FileExtensions),
            PickKind.OpenFolder => await _storage.OpenFolderAsync(Label),
            PickKind.SaveFile => await _storage.SaveFileAsync(Label, SuggestedFileName, FileFilterName, FileExtensions),
            _ => null,
        };

        if (!string.IsNullOrEmpty(picked))
            Value = picked;
    }
}
