# Getting Started

## Prerequisites

- **.NET 10 SDK** or newer. Verify with:

  ```bash
  dotnet --version
  ```

- A C# 14 capable toolchain (included with the .NET 10 SDK).

## Project layout

```
LibProsperoPKG/
├── README.md
├── NOTICE
├── docs/
└── src/
    └── LibProsperoPkg/
        ├── LibProsperoPkg.csproj
        ├── ProsperoPackageBuilder.cs   high-level entry point
        ├── PKG/                         container build/read/write, signing, DDS, FIH, extraction
        ├── PFS/                         inner PFS layout, AES-XTS, PFSC/data-first compression, extraction
        ├── Content/                     UCP, fake-self, and auth-info content codecs
        ├── License/                     per-title license (rif) read/write/create
        ├── NpDrm/                       package content-info projection
        ├── DiscBackup/                  split disc-backup (app_0 / app_sc) open and verify
        ├── GP5/                         GP5 project model
        ├── Keys/                        signing key access
        ├── PlayGo/                      PlayGo / "about" helper file generators
        └── Util/                        crypto, keys, and shared helpers
```

## Building the library

```bash
cd LibProsperoPKG/src/LibProsperoPkg
dotnet build -c Release
```

The Release build is written under `bin/Release/net10.0/`.

## Using the library from another project

Point another project at either the compiled assembly or the `.csproj` directly:

```xml
<ItemGroup>
  <ProjectReference Include="..\LibProsperoPKG\src\LibProsperoPkg\LibProsperoPkg.csproj" />
</ItemGroup>
```

## Preparing an application folder

The builder consumes a folder that already contains the standard PS5 layout:

- `sce_sys/` — system metadata directory (must be present). When `param.json` is missing and
  `GenerateParamJsonIfMissing` is left `true`, a minimal one is generated from the build options.
- The application executable (`eboot.bin`) and any data files.

## Building your first package

```csharp
using LibProsperoPkg;

var options = new ProsperoBuildOptions
{
    Mode         = ProsperoPackageMode.Application,
    OutputFormat = ProsperoOutputFormat.DebugImage,
    SourceFolder = "/path/to/prepared/app",
    OutputFolder = "/path/to/output",
    ContentId    = "UP9000-PPSA00000_00-PROSPERO00000000",
    TitleId      = "PPSA00000",
    Title        = "My PS5 Application",
    Version      = "01.00",
};

var result = ProsperoPackageBuilder.Build(options, Console.WriteLine);
Console.WriteLine(result.OutputPath);
```

## Fake-signing modules and application type

To pack raw ELF modules that are not yet SELF, set `FakeSignSelfModules`. The builder converts
`eboot.bin` and any `*.elf` / `*.prx` / `*.sprx` in the source folder to fake-self before layout
and restores the original files afterward. Modules that are already SELF are skipped.

`ApplicationType` selects the `applicationDrmType` written to a generated `param.json`:

| `ProsperoApplicationType` | `applicationDrmType` |
|---|---|
| `PaidStandaloneFullApp` | `standard` |
| `UpgradableApp` | `standard` |
| `FreemiumApp` | `freemium` |
| `DemoApp` | `free` |
| `NotSpecified` | `free` |

```csharp
var options = new ProsperoBuildOptions
{
    Mode                = ProsperoPackageMode.Application,
    OutputFormat        = ProsperoOutputFormat.DebugImage,
    SourceFolder        = "/path/to/prepared/app",
    OutputFolder        = "/path/to/output",
    ContentId           = "UP9000-PPSA00000_00-PROSPERO00000000",
    TitleId             = "PPSA00000",
    Title               = "My PS5 Application",
    Version             = "01.00",
    ApplicationType     = ProsperoApplicationType.FreemiumApp,
    FakeSignSelfModules = true,
};
```

## DRM/license-free debug package

Set `LicenseFree` to build a single package that is DRM-free, license-free, fake-signed, and
runnable on a debug-enabled console. The flag fake-signs raw ELF modules (the same conversion as
`FakeSignSelfModules`) and constructs a debug grant whose mount key is recomputed from the content
id and passcode, so no rif or license file is written. The output stays a debug finalized image.
`param.json` `applicationDrmType` is descriptive metadata read by the installer, not a boot gate; a
generated `param.json` already carries the derived value and is not rewritten.

```csharp
var options = new ProsperoBuildOptions
{
    Mode         = ProsperoPackageMode.Application,
    OutputFormat = ProsperoOutputFormat.DebugImage,
    SourceFolder = "/path/to/prepared/app",
    OutputFolder = "/path/to/output",
    ContentId    = "UP9000-PPSA00000_00-PROSPERO00000000",
    TitleId      = "PPSA00000",
    Title        = "My PS5 Application",
    Version      = "01.00",
    LicenseFree  = true,
};

ProsperoBuildResult result = ProsperoPackageBuilder.Build(options);
// result.LicenseFree == true
// result.DebugLicense holds the content id + passcode grant (RequiresRif == false)
```

The source tree is unchanged after the build: the fake-sign step restores the original bytes when
the build finishes or throws.

Read an existing package's header and entries:

```csharp
using LibProsperoPkg.PKG;

ProsperoPkg pkg = ProsperoPkgReader.Read("/path/to/package.pkg");
Console.WriteLine($"{pkg.Type} {pkg.Header?.ContentId}");
```

Check a package against the structural acceptance gate the console mount path enforces:

```csharp
ProsperoAcceptanceReport report = ProsperoPkgValidator.Validate("/path/to/package.pkg");
Console.WriteLine(report.Accepted);
```

Extract the application filesystem from a finalized debug/keyed image. `Inspect` first reports
whether a supplied key is required, without needing one:

```csharp
ProsperoPackageExtractionInfo info = ProsperoPackageExtractor.Inspect("/path/to/package.pkg");
if (!info.RequiresSuppliedKey)
{
    ProsperoPackageManifest manifest = ProsperoPackageExtractor.Extract(
        "/path/to/package.pkg", "/path/to/output", new string('0', 32));
    Console.WriteLine(manifest.ExtractedFileCount);
}
```

A finalized retail image (signed byte `0x80`) reports `RequiresSuppliedKey = true`; its image key
is not derivable from public inputs, so extraction needs a supplied 32-byte key through
`ProsperoExtractionKey.FromEkpfs`.

## Opening a disc-backup

A split disc backup is a set of `app_0` / `app_sc` pieces described by an `app.json` manifest. Open
the directory, verify integrity, and read the reassembled package:

```csharp
using LibProsperoPkg.DiscBackup;

ProsperoDiscBackup backup = ProsperoDiscBackup.Open("/path/to/backup/dir");
Console.WriteLine(backup.VerifyPackageDigest());
ProsperoPkg pkg = backup.ReadPackage();
```

## Converting a decrypted backup to a debug fPKG

A decrypted backup carries the app tree plus a `decrypted/` subfolder that mirrors every executable
as raw ELF. `ProsperoBackupConverter` substitutes each signed executable with its decrypted
counterpart, fake-signs the modules, and builds a debug image that mounts from the content id and
passcode alone. No executable byte-patching and no `param.json` edit are involved.

```csharp
var options = new ProsperoBackupConversionOptions
{
    BackupFolder = "/path/to/backup/PPSA00000-app0",
    OutputFolder = "/path/to/output",
    // ContentId and Version fall back to the backup's param.json when omitted.
};

ProsperoBackupConversionResult result = ProsperoBackupConverter.Convert(options);
Console.WriteLine(result.OutputPath);
Console.WriteLine($"substituted {result.SubstitutedModules.Count} modules");
// result.DebugLicense.RequiresRif == false
```

The backup is never modified; the converter works from a staging copy. Every module in the output
is a fake-self, the image is debug (not retail), and extraction round-trips every file.

## Notes on content identifiers

- **Content ID** is 36 characters: `XXYYYY-XXXXYYYYY_00-ZZZZZZZZZZZZZZZZ`.
  Validate with `ProsperoPackageBuilder.IsValidContentId` or compose one with
  `ProsperoPackageBuilder.ComposeContentId(publisher, titleId, label)`.
- **Title ID** is 9 characters (for example `PPSA00000`). Validate with
  `ProsperoPackageBuilder.IsValidTitleId`.
- **Passcode** is exactly 32 characters and defaults to all zeroes.
