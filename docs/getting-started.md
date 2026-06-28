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
        ├── PKG/                         container build/read/write, signing, DDS, FIH
        ├── PFS/                         inner PFS layout, AES-XTS, PFSC compression
        ├── GP5/                         GP5 project model
        ├── Keys/                        publishing key access
        ├── PlayGo/                      PlayGo / "about" helper file generators
        └── Util/                        crypto, keys, and shared helpers
```

## Building the library

```bash
cd LibProsperoPKG/src/LibProsperoPkg
dotnet build -c Release
```

The output is `bin/Release/net10.0/LibProsperoPkg.dll`.

To produce a NuGet package:

```bash
dotnet pack -c Release
```

## Referencing the library

From another project, reference either the compiled assembly, the NuGet package, or the
project directly:

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

## Notes on content identifiers

- **Content ID** is 36 characters: `XXYYYY-XXXXYYYYY_00-ZZZZZZZZZZZZZZZZ`.
  Validate with `ProsperoPackageBuilder.IsValidContentId` or compose one with
  `ProsperoPackageBuilder.ComposeContentId(publisher, titleId, label)`.
- **Title ID** is 9 characters (for example `PPSA00000`). Validate with
  `ProsperoPackageBuilder.IsValidTitleId`.
- **Passcode** is exactly 32 characters and defaults to all zeroes.
