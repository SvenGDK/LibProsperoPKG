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
- **Texture generation.** The `sce_sys` icon/picture DDS (BC7) re-encoder is backed by Magick.NET.

---

## Requirements

| | |
|---|---|
| Toolchain | .NET 10 SDK or newer |
| Language | C# 14 |
| NuGet dependency | `Magick.NET-Q8-AnyCPU` |

---

## Building

```bash
cd LibProsperoPKG/src/LibProsperoPkg
dotnet build -c Release
```

This produces `LibProsperoPkg.dll`. To create a NuGet package:

```bash
dotnet pack -c Release
```

---

## Quick start

Add a reference to the project (or the built `LibProsperoPkg.dll` / NuGet package) and build a
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
| `LibProsperoPkg` | `ProsperoPackageBuilder`, `ProsperoBuildOptions`, `ProsperoBuildResult`, `ProsperoPackageMode`, `ProsperoOutputFormat`, `InnerImageForm` |
| `LibProsperoPkg.PKG` | `ProsperoPkgBuilder`, `ProsperoPkgReader`, `ProsperoPkgWriter`, `ProsperoFihBuilder`, `ProsperoPkgSigner`, `ProsperoDdsEncoder`, `ProsperoPkg`, `ProsperoPkgHeader` |
| `LibProsperoPkg.PFS` | `ProsperoPfsLayout`, `ProsperoPfsImage`, `ProsperoPfsc` |
| `LibProsperoPkg.GP5` | `Gp5Creator`, `Gp5Project` and its element model |
| `LibProsperoPkg.Keys` | `ProsperoKeys` |
| `LibProsperoPkg.PlayGo` | `ProsperoPlayGo` |

See **[docs/](docs/)** for the full feature status and the PS5 package technical write-up.

---

## Documentation

- **[docs/README.md](docs/README.md)** - documentation index.
- **[docs/getting-started.md](docs/getting-started.md)** - install, build and first package.
- **[docs/api-overview.md](docs/api-overview.md)** - public API reference by namespace.
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
On-console acceptance is hardware-gated. See [docs/implementation-status.md](docs/implementation-status.md)
for the precise breakdown.

---

## License

LibProsperoPkg is licensed under the GNU General Public License v3.0 or later
(GPL-3.0-or-later). See [LICENSE](LICENSE). Third-party attributions are listed in [NOTICE](NOTICE).