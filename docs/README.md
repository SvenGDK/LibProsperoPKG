# LibProsperoPkg Documentation

This folder contains the developer documentation for **LibProsperoPkg**, a
.NET 10 / C# 14 library for building PS5 packages.

## Contents

| Document | Description |
|---|---|
| [getting-started.md](getting-started.md) | Install the SDK, build the library, and produce your first package. |
| [api-overview.md](api-overview.md) | The public API, organized by namespace, with usage notes. |
| [implementation-status.md](implementation-status.md) | A precise breakdown of what is implemented and what is still missing. |
| [ps5-pkg-format.md](ps5-pkg-format.md) | A technical write-up of the PS5 package format and the end-to-end creation process. |

## At a glance

LibProsperoPkg turns a prepared PS5 application folder into a complete, signed package
in-process. The pipeline is:

```
prepared folder (sce_sys/ + eboot + data)
        │
        ▼  optional fake-sign of raw ELF modules (FakeSignSelfModules)
        │
        ▼  inner PFS layout (ProsperoPfsLayout)
   plaintext inner PFS image
        │
        ▼  AES-XTS encryption (ProsperoPfsImage)  ── optional PFSC compression (ProsperoPfsc)
   encrypted inner PFS image
        │
        ▼  outer PFS + metadata (ProsperoPkgBuilder)
   \x7FCNT metadata container
        │
        ▼  finalize (ProsperoFihBuilder)
   \x7FFIH debug image  ──►  installable on a debug-mode console
```

The library also has a read side. `ProsperoPackageExtractor` inspects and unpacks debug packages,
`ProsperoDiscBackup` reassembles split `app_0.pkg` / `app_sc.pkg` backups from an `app.json`
manifest, and the `License` and `NpDrm` namespaces read `rif` licences and project package
content-info. See [api-overview.md](api-overview.md) for the full surface and
[ps5-pkg-format.md](ps5-pkg-format.md) §9–§11 for the RIF, disc-backup and extraction formats.

