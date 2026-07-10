using Avalonia.Controls;
using Avalonia.Platform.Storage;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LibProsperoPkg.Gui.Services;

public sealed class StorageService : IStorageService
{
    public TopLevel? Owner { get; set; }

    public async Task<string?> OpenFileAsync(string title, string? filterName = null, IReadOnlyList<string>? extensions = null)
    {
        if (Owner is null)
            return null;

        var options = new FilePickerOpenOptions { Title = title, AllowMultiple = false };
        if (extensions is { Count: > 0 })
        {
            options.FileTypeFilter =
            [
                new FilePickerFileType(filterName ?? "Files")
                {
                    Patterns = [.. extensions.Select(e => "*." + e.TrimStart('.'))],
                },
            ];
        }

        var result = await Owner.StorageProvider.OpenFilePickerAsync(options);
        return result.Count > 0 ? result[0].TryGetLocalPath() : null;
    }

    public async Task<string?> OpenFolderAsync(string title)
    {
        if (Owner is null)
            return null;

        var result = await Owner.StorageProvider.OpenFolderPickerAsync(
            new FolderPickerOpenOptions { Title = title, AllowMultiple = false });
        return result.Count > 0 ? result[0].TryGetLocalPath() : null;
    }

    public async Task<string?> SaveFileAsync(string title, string? suggestedName = null, string? filterName = null, IReadOnlyList<string>? extensions = null)
    {
        if (Owner is null)
            return null;

        var options = new FilePickerSaveOptions { Title = title, SuggestedFileName = suggestedName };
        if (extensions is { Count: > 0 })
        {
            options.DefaultExtension = extensions[0].TrimStart('.');
            options.FileTypeChoices =
            [
                new FilePickerFileType(filterName ?? "Files")
                {
                    Patterns = [.. extensions.Select(e => "*." + e.TrimStart('.'))],
                },
            ];
        }

        var result = await Owner.StorageProvider.SaveFilePickerAsync(options);
        return result?.TryGetLocalPath();
    }
}
