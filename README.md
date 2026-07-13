# LibProsperoPkg

A .NET class library for building and inspecting **PS5** packages. It turns a prepared application
folder into a complete, installable debug package end to end, in-process, without an external
command-line tool.

The library is written in C# 14 and targets .NET 10. It is self-contained and exposes a small,
documented public API any .NET application can consume.

---

## Highlights

- **End-to-end pipeline.** Folder -> inner PFS layout -> AES-XTS encryption -> outer PFS ->
  `\x7FCNT` metadata container -> finalized `\x7FFIH` debug image, in one process.
- **Self-contained.** The GP5 project model, the PFS image builder, AES-XTS encryption,
  RSA-3072 metadata signing and the finalized debug image are produced by the library itself.
- **Reader and writer.** Parse and inspect existing PS5 packages (`\x7FCNT` / `\x7FFIH`) and build
  new ones.
- **Extraction.** Extract the application filesystem from a finalized debug/keyed image with
  `ProsperoPackageExtractor`, or from any image whose 32-byte image key is supplied.
- **Disc-backup packages.** Open a split disc backup (the ordered `app_0` / `app_sc` pieces)
  through its `app.json` manifest, reassemble it on the fly, and verify the package digest and
  64 KiB chunk CRCs.
- **License (`rif`).** Read, write and create the per-title license record — including multi-title
  files — through `LibProsperoPkg.License`.
- **Acceptance checks.** Validate a package against the structural gate the console mount path
  enforces (`ProsperoPkgValidator`).
- **Fake-signed packages (fPKG).** Optionally fake-sign raw ELF modules (`eboot.bin`, `*.elf`,
  `*.prx`, `*.sprx`) to fake-self before packing, producing an installable fake package. The
  conversion is non-destructive: source modules are restored after the build.
- **Backup conversion.** `ProsperoBackupConverter` repackages a decrypted application backup into a
  debug fPKG, substituting each executable with its decrypted ELF and fake-signing it, so the image
  mounts from the content id and passcode with no rif.
- **Launch-readiness inspection.** `ProsperoLaunchReadiness` inspects an assembled application root
  and reports whether it meets the debug-launch conditions: every executable module is a plaintext
  module the loader accepts, `eboot.bin` is present, and the metadata is a `param.json` rather than a
  PS4 `param.sfo`.
- **Homebrew packaging.** `ProsperoHomebrewPackager` turns a compiled homebrew folder into an
  installable debug fPKG: it assembles a clean source tree, builds a license-free debug image whose
  mount key derives from the content id and passcode, and checks launch-readiness. A worked sample
  lives in `src/HomebrewTest`.
- **Application type.** `ProsperoApplicationType` selects the generated `param.json`
  `applicationDrmType` (`free` / `standard` / `freemium`), covering paid, upgradable, demo and
  freemium apps.
- **Texture generation.** The `sce_sys` icon/picture DDS (BC7) encoder decodes the source PNG and
  block-compresses it to a DX10 BC7 texture in-process.

---

## Requirements

| | |
|---|---|
| Toolchain | .NET 10 SDK or newer |
| Language | C# 14 |

---

## Building

```bash
cd LibProsperoPKG/src/LibProsperoPkg
dotnet build -c Release
```

This produces `LibProsperoPkg.dll`.

---

## Quick start

Add the project (or the built `LibProsperoPkg.dll`) to your build and create a package from a
prepared application folder:

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

To build a DRM-free, license-free package in one step, set `LicenseFree`. It fake-signs modules and
derives the debug mount key from the content id and passcode, so no rif is written.
`ProsperoBuildResult.DebugLicense` reports the grant and `ProsperoBuildResult.LicenseFree` echoes the
option. The output is a debug finalized image for a debug-enabled console.

To repackage a decrypted application backup into a debug fPKG, call `ProsperoBackupConverter.Convert`.
It substitutes each signed executable with its decrypted raw ELF, fake-signs the modules, and builds
a debug image that mounts from the content id and passcode. The backup stays untouched; the converter
works from a staging copy.

```csharp
var result = ProsperoBackupConverter.Convert(new ProsperoBackupConversionOptions
{
    BackupFolder = @"/path/to/backup/PPSA00000-app0",
    OutputFolder = @"/path/to/output",
});
```

### Packaging a homebrew module

To package a compiled homebrew folder (a raw ELF `eboot.bin` plus an optional `sce_sys/` tree) into
an installable debug fPKG, call `ProsperoHomebrewPackager.Package`. It fake-signs the module and
derives the mount key from the content id and passcode, then checks launch-readiness. A worked sample
lives in `src/HomebrewTest`.

```csharp
var result = ProsperoHomebrewPackager.Package(new ProsperoHomebrewPackageOptions
{
    HomebrewFolder = @"/path/to/HomebrewTest",
    OutputFolder   = @"/path/to/output",
    ContentId      = "UP9000-PPSA99099_00-PROSPERO00000000",
    Title          = "LibProsperoPKG",
});
Console.WriteLine($"Launch ready: {result.LaunchReadiness.IsLaunchReady}");
```

Every build path stores the inner image as the data-first image.

### Inspecting an existing package

```csharp
using LibProsperoPkg.PKG;

ProsperoPkg pkg = ProsperoPkgReader.Read(@"/path/to/package.pkg");
Console.WriteLine($"Type:       {pkg.Type}");
Console.WriteLine($"Content ID: {pkg.Header?.ContentId}");
Console.WriteLine($"Entries:    {pkg.Entries.Count}");
```

---

## Public surface, at a glance

| Namespace | Key types |
|---|---|
| `LibProsperoPkg` | `ProsperoPackageBuilder`, `ProsperoBackupConverter`, `ProsperoHomebrewPackager`, `ProsperoBuildOptions`, `ProsperoBuildResult`, `ProsperoBackupConversionOptions`, `ProsperoBackupConversionResult`, `ProsperoHomebrewPackageOptions`, `ProsperoHomebrewPackageResult`, `ProsperoPackageMode`, `ProsperoOutputFormat`, `InnerImageForm`, `ProsperoApplicationType` |
| `LibProsperoPkg.PKG` | `ProsperoPkgBuilder`, `ProsperoPkgReader`, `ProsperoCntWriter`, `ProsperoFihBuilder`, `ProsperoPkgSigner`, `ProsperoDdsEncoder`, `ProsperoPackageExtractor`, `ProsperoExtractionKey`, `ProsperoPkgValidator`, `ProsperoPkg`, `ProsperoPkgHeader` |
| `LibProsperoPkg.PFS` | `ProsperoPfsLayout`, `ProsperoPfsImage`, `ProsperoPfsc`, `ProsperoPfsExtractor` |
| `LibProsperoPkg.License` | `ProsperoRif`, `ProsperoRifSet`, `ProsperoEntitlementKey` |
| `LibProsperoPkg.NpDrm` | `ProsperoNpDrmContentInfo` |
| `LibProsperoPkg.DiscBackup` | `ProsperoDiscBackup`, `ProsperoDiscBackupManifest`, `ProsperoPlaygoChunkCrc` |
| `LibProsperoPkg.GP5` | `Gp5Creator`, `Gp5Project` and its element model |
| `LibProsperoPkg.Keys` | `ProsperoKeys` |
| `LibProsperoPkg.PlayGo` | `ProsperoPlayGo` |
| `LibProsperoPkg.Content` | `ProsperoUcp`, `ProsperoFself`, `ProsperoSelfAuthInfo`, `ProsperoElfHeader`, `ProsperoLaunchReadiness` |

See **[docs/](docs/)** for the full feature status and the PS5 package technical write-up.

---

## Documentation

- **[docs/README.md](docs/README.md)** - documentation index.
- **[docs/getting-started.md](docs/getting-started.md)** - install, build and first package.
- **[docs/api-overview.md](docs/api-overview.md)** - public API by namespace.
- **[docs/implementation-status.md](docs/implementation-status.md)** - what is implemented and what
  is still missing.
- **[docs/ps5-pkg-format.md](docs/ps5-pkg-format.md)** - technical write-up of the PS5 package
  format and the creation process.

---

## Scope

LibProsperoPkg produces a complete debug package end to end: the finalized `\x7FFIH` image, the
`\x7FCNT` metadata container, the inner-image assembly, the layout/metric metadata and the trailing
install-metadata archive, all of which round-trip through the reader. A console running in **debug
mode**, which relaxes finalized-image verification, is the intended target. The retail (submitted)
image path and the per-console license and key material are gated on console-side material the
library does not have. On-console acceptance depends on the console's mode and firmware. See
[docs/implementation-status.md](docs/implementation-status.md) for the precise breakdown.

---

## License

LibProsperoPkg is licensed under the GNU General Public License v3.0 or later
(GPL-3.0-or-later). See [LICENSE](LICENSE). Third-party attributions are listed in [NOTICE](NOTICE).
