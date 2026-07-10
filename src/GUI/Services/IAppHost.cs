using System;
using System.Threading.Tasks;

namespace LibProsperoPkg.Gui.Services;

public interface IAppHost
{
    IStorageService Storage { get; }

    Task RunAsync(string label, Action<Action<string>> operation);
}
