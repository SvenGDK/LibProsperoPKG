using Avalonia.Threading;
using LibProsperoPkg.Gui.Mvvm;
using LibProsperoPkg.Gui.Services;
using System;
using System.Collections.ObjectModel;
using System.Text;
using System.Threading.Tasks;

namespace LibProsperoPkg.Gui.ViewModels;

public sealed class MainWindowViewModel : ViewModelBase, IAppHost
{
    private readonly StringBuilder _log = new();
    private ToolPageViewModel? _selectedPage;
    private bool _isBusy;
    private string _status = "Ready";
    private string _logText = "";

    public MainWindowViewModel(IStorageService storage)
    {
        Storage = storage;
        Pages = new ObservableCollection<ToolPageViewModel>(PageCatalog.Create(this));
        _selectedPage = Pages.Count > 0 ? Pages[0] : null;
        ClearLogCommand = new RelayCommand(ClearLog);
    }

    public static string Title => "LibProsperoPKG GUI by SvenGDK";

    public IStorageService Storage { get; }

    public ObservableCollection<ToolPageViewModel> Pages { get; }

    public ToolPageViewModel? SelectedPage
    {
        get => _selectedPage;
        set => SetProperty(ref _selectedPage, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set => SetProperty(ref _isBusy, value);
    }

    public string Status
    {
        get => _status;
        private set => SetProperty(ref _status, value);
    }

    public string LogText
    {
        get => _logText;
        private set => SetProperty(ref _logText, value);
    }

    public RelayCommand ClearLogCommand { get; }

    public async Task RunAsync(string label, Action<Action<string>> operation)
    {
        if (IsBusy)
            return;

        IsBusy = true;
        Status = label + " running";
        Append("> " + label);

        void Log(string message) => Dispatcher.UIThread.Post(() => Append(message));

        try
        {
            await Task.Run(() => operation(Log));
            Status = label + " complete";
            Append(label + ": done");
        }
        catch (Exception ex)
        {
            Status = label + " failed";
            Append(label + ": error - " + ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }

    // The retained log is bounded so a long-running operation does not turn each appended line into a
    // full re-stringify of an ever-growing buffer (which is quadratic over the run).
    private const int MaxLogChars = 64 * 1024;

    private void Append(string message)
    {
        _log.AppendLine(message);
        if (_log.Length > MaxLogChars)
            _log.Remove(0, _log.Length - MaxLogChars);
        LogText = _log.ToString();
    }

    private void ClearLog()
    {
        _log.Clear();
        LogText = "";
    }
}
