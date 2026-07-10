using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Pages;
using System.Collections.Generic;

namespace LibProsperoPkg.Gui.ViewModels;

internal static class PageCatalog
{
    public static IReadOnlyList<ToolPageViewModel> Create(IAppHost host) =>
    [
        new BuildPage(host),
        new HomebrewPage(host),
        new BackupConvertPage(host),
        new InspectPage(host),
        new ExtractPage(host),
        new ValidatePage(host),
        new MergePage(host),
        new ComparePage(host),
        new InnerImagePage(host),
        new PfsImagePage(host),
        new PfscPage(host),
        new FselfPage(host),
        new ElfPage(host),
        new AuthInfoPage(host),
        new LaunchReadinessPage(host),
        new RifPage(host),
        new EntitlementPage(host),
        new DiscBackupPage(host),
        new UcpPage(host),
        new DdsPage(host),
        new PlayGoPage(host),
        new MetadataPage(host),
        new IdHelpersPage(host),
    ];
}
