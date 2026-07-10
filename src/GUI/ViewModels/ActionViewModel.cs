using LibProsperoPkg.Gui.Mvvm;
using System;
using System.Threading.Tasks;
using System.Windows.Input;

namespace LibProsperoPkg.Gui.ViewModels;

public sealed class ActionViewModel(string name, Func<Task> execute, bool primary = false) : ViewModelBase
{
    public string Name { get; } = name;

    public bool IsPrimary { get; } = primary;

    public ICommand Command { get; } = new AsyncRelayCommand(execute);
}
