# LibProsperoPkg

A .NET class library for building **PS5** packages. It turns a prepared
application folder into a complete, signed PS5 package in-process, with no external
command-line tool to install.

The library is written in **C# 14** and targets **.NET 10**. It is self-contained and
exposes a small, documented public API so any .NET developer can consume it from their own
application.

---

## Highlights

- **In-process pipeline.** Folder -> inner PFS layout -> AES-XTS encryption -> outer PFS ->
  `\x7FCNT` metadata container -> finalized `\x7FFIH` debug image, end to end.
- **Self-contained.** The GP5 project model, the PFS image builder, AES-XTS encryption,
  RSA-3072 metadata signing and the finalized debug image are produced by the library itself.
- **Reader and writer.** Parse and inspect existing PS5 packages (`\x7FCNT` / `\x7FFIH`) and
  build new ones.
- **Extraction.** Extract the application filesystem from a finalized debug/keyed image with
  `ProsperoPackageExtractor`, or from any image whose 32-byte image key is supplied.
- **Disc-backup packages.** Open a split disc-backup (`app_0.pkg` + `app_sc.pkg`) through its
  `app.json` manifest, reassemble it on the fly, and verify the package digest and 64 KiB chunk CRCs.
- **License (`rif`).** Read, write and create the per-title license record — including multi-title
  files — through `LibProsperoPkg.License`.
- **Acceptance checks.** Validate a package against the structural gate the console mount path
  enforces (`ProsperoPkgValidator`).
- **Fake-signed packages (fPKG).** Optionally fake-sign raw ELF modules (`eboot.bin`, `*.elf`,
  `*.prx`, `*.sprx`) to fake-self before packing, producing an installable fake package. The
  conversion is non-destructive: source modules are restored after the build.
- **Application type.** `ProsperoApplicationType` selects the generated `param.json`
  `applicationDrmType` (`free` / `standard` / `freemium`), covering paid, upgradable, demo and
  freemium apps.
- **Texture generation.** The `sce_sys` icon/picture DDS (BC7) re-encoder is backed by Magick.NET.

---

## Requirements

| | |
|---|---|
| Toolchain | .NET 10 SDK or newer |
| Language | C# 14 |
| Dependency | `Magick.NET-Q8-AnyCPU` |

---

## Building

```bash
cd LibProsperoPKG/src/LibProsperoPkg
dotnet build -c Release
```

This produces `LibProsperoPkg.dll`.

---

## Quick start

Add the project (or the built `LibProsperoPkg.dll`) to your build and create a
package from a prepared application folder:

```csharp
using LibProsperoPkg;

var options = new ProsperoBuildOptions
{
    Mode         = ProsperoPackageMode.Application,
    OutputFormat = ProsperoOutputFormat.DebugImage,   // installable on a debug-mode console
    SourceFolder = @"/path/to/prepared/app",          // must contain sce_sys/
    OutputFolder = @"/path/to/output",
    ContentId    = "UP9000-PPSA00000_00-PROSPERO00000000",
    TitleId      = "PPSA00000",
    Title        = "My PS5 Application",
    Version      = "01.00",
};

ProsperoBuildResult result = ProsperoPackageBuilder.Build(options, Console.WriteLine);

Console.WriteLine($"Package written to: {result.OutputPath}");
foreach (var warning in result.Warnings)
    Console.WriteLine($"Warning: {warning}");
```

### Fake-signing modules (fPKG)

Set `FakeSignSelfModules` to convert raw ELF modules in the source folder to fake-self before
packing. Use `ApplicationType` to control the generated `param.json` `applicationDrmType`:

```csharp
var options = new ProsperoBuildOptions
{
    Mode                = ProsperoPackageMode.Application,
    OutputFormat        = ProsperoOutputFormat.DebugImage,
    SourceFolder        = @"/path/to/prepared/app",
    OutputFolder        = @"/path/to/output",
    ContentId           = "UP9000-PPSA00000_00-PROSPERO00000000",
    TitleId             = "PPSA00000",
    Title               = "My PS5 Application",
    Version             = "01.00",
    ApplicationType     = ProsperoApplicationType.FreemiumApp,
    FakeSignSelfModules = true,
};
```

Files that are already SELF are left untouched, and the original module bytes are restored once
packing completes.

### Inspecting an existing package

```csharp
using LibProsperoPkg.PKG;

ProsperoPkg pkg = ProsperoPkgReader.Read(@"/path/to/some.pkg");
Console.WriteLine($"Type:       {pkg.Type}");
Console.WriteLine($"Content ID: {pkg.Header.ContentId}");
Console.WriteLine($"Entries:    {pkg.Entries.Count}");
```

---

## Public surface, at a glance

| Namespace | Key types |
|---|---|
| `LibProsperoPkg` | `ProsperoPackageBuilder`, `ProsperoBuildOptions`, `ProsperoBuildResult`, `ProsperoPackageMode`, `ProsperoOutputFormat`, `InnerImageForm`, `ProsperoApplicationType` |
| `LibProsperoPkg.PKG` | `ProsperoPkgBuilder`, `ProsperoPkgReader`, `ProsperoCntWriter`, `ProsperoFihBuilder`, `ProsperoPkgSigner`, `ProsperoDdsEncoder`, `ProsperoPackageExtractor`, `ProsperoExtractionKey`, `ProsperoPkgValidator`, `ProsperoPkg`, `ProsperoPkgHeader` |
| `LibProsperoPkg.PFS` | `ProsperoPfsLayout`, `ProsperoPfsImage`, `ProsperoPfsc`, `ProsperoPfsExtractor` |
| `LibProsperoPkg.License` | `ProsperoRif`, `ProsperoRifSet`, `ProsperoEntitlementKey` |
| `LibProsperoPkg.NpDrm` | `ProsperoNpDrmContentInfo` |
| `LibProsperoPkg.DiscBackup` | `ProsperoDiscBackup`, `ProsperoDiscBackupManifest`, `ProsperoPlaygoChunkCrc` |
| `LibProsperoPkg.GP5` | `Gp5Creator`, `Gp5Project` and its element model |
| `LibProsperoPkg.Keys` | `ProsperoKeys` |
| `LibProsperoPkg.PlayGo` | `ProsperoPlayGo` |
| `LibProsperoPkg.Content` | `ProsperoUcp`, `ProsperoFself`, `ProsperoSelfAuthInfo` |

See **[docs/](docs/)** for the full feature status and the PS5 package technical write-up.

---

## Documentation

- **[docs/README.md](docs/README.md)** - documentation index.
- **[docs/getting-started.md](docs/getting-started.md)** - install, build and first package.
- **[docs/api-overview.md](docs/api-overview.md)** - public API by namespace.
- **[docs/implementation-status.md](docs/implementation-status.md)** - what is implemented and
  what is still missing.
- **[docs/ps5-pkg-format.md](docs/ps5-pkg-format.md)** - technical write-up of the PS5 package
  format and the creation process.

---

## Limitations

LibProsperoPkg produces a complete, self-consistent package whose structure and embedded
metadata container round-trip through the reader. Two parts of a finalized image depend on
console-side finalization material and are filled best-effort rather than reproduced exactly:
the finalized-image digest table and the trailing install-metadata archive. A console running
in **debug mode**, which relaxes finalized-image verification, is the intended target.
On-console acceptance depends on the console's mode and firmware. See [docs/implementation-status.md](docs/implementation-status.md)
for the precise breakdown.

---

## License

LibProsperoPkg is licensed under the GNU General Public License v3.0 or later
(GPL-3.0-or-later). See [LICENSE](LICENSE). Third-party attributions are listed in [NOTICE](NOTICE).