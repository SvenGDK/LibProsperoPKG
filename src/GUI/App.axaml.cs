using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels;
using LibProsperoPkg.Gui.Views;

namespace LibProsperoPkg.Gui;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var storage = new StorageService();
            var model = new MainWindowViewModel(storage);
            var window = new MainWindow { DataContext = model };
            storage.Owner = window;
            desktop.MainWindow = window;
        }

        base.OnFrameworkInitializationCompleted();
    }
}
