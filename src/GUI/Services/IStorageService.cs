using System.Collections.Generic;
using System.Threading.Tasks;

namespace LibProsperoPkg.Gui.Services;

public interface IStorageService
{
    Task<string?> OpenFileAsync(string title, string? filterName = null, IReadOnlyList<string>? extensions = null);

    Task<string?> OpenFolderAsync(string title);

    Task<string?> SaveFileAsync(string title, string? suggestedName = null, string? filterName = null, IReadOnlyList<string>? extensions = null);
}
