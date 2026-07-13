# API Overview

This document summarizes the public surface of LibProsperoPkg, grouped by namespace. Every
public type and member carries XML documentation, so IntelliSense and the generated
documentation file give the authoritative detail; this page is the orientation map.

---

## `LibProsperoPkg` — high-level builder

### `ProsperoPackageBuilder` (static)

The primary entry point.

| Member | Purpose |
|---|---|
| `Build(ProsperoBuildOptions, Action<string>?)` | Build a package from a prepared folder. Returns `ProsperoBuildResult`. |
| `BuildInnerPfsLayout(...)` | Lay a folder out into a plaintext inner-PFS image. Returns `ProsperoPfsLayoutResult`. |
| `BuildInnerImage(...)` | Run the full inner-image pipeline (plaintext / encrypted / zlib-compressed / Kraken-compressed). Returns the written image path. |
| `EncryptPfsImage(...)` | AES-XTS-encrypt a prepared plaintext inner-PFS image in place. Returns `ProsperoPfsImageResult`. |
| `CompareContainers(...)` | Compare two packages field by field. Returns the list of differences. |
| `ComposeContentId(publisher, titleId, label)` | Build a well-formed 36-char content id. |
| `IsValidContentId` / `IsValidTitleId` | Validate identifiers. |
| `VolumeTypeForMode(mode)` | Map a `ProsperoPackageMode` to the GP5 `Gp5VolumeType`. |
| `ProsperoVolumeTypeForMode(mode)` | Map a `ProsperoPackageMode` to the container `ProsperoVolumeType`. |
| `IsDlcMode(mode)` | Report whether a mode is additional-content. |
| `KeysAvailable` | Reports whether the built-in signing key material is available. |

### Supporting types

- **`ProsperoBuildOptions`** — the build description: `Mode`, `OutputFormat`, `SourceFolder`,
  `OutputFolder`, `ContentId`, `Passcode`, `Title`, `TitleId`, `Version`,
  `GenerateParamJsonIfMissing`, `ApplicationType`, `ApplicationDrmType`, `ContentBadgeType`,
  `FakeSignSelfModules`, `FselfOptions`, `LicenseFree`.
- **`ProsperoApplicationType`** — the application type: `NotSpecified`,
  `PaidStandaloneFullApp`, `UpgradableApp`, `DemoApp`, `FreemiumApp`. `ProsperoApplicationTypes`
  maps it to the generated `param.json` `applicationDrmType` (`free` / `standard` / `freemium`)
  and provides `DisplayName` and `Parse`.
- **`ProsperoBuildResult`** — `OutputPath`, a list of non-fatal `Warnings`, `LicenseFree` (echoes
  the option), and `DebugLicense` (the constructed `ProsperoDebugLicense` when `LicenseFree` is set,
  otherwise null).
- **`ProsperoPackageMode`** — `Application`, `Homebrew`, `AdditionalContentData`,
  `AdditionalContentNoData`.
- **`ProsperoOutputFormat`** — `MetadataContainer` (`\x7FCNT` only, not installable) or
  `DebugImage` (`\x7FFIH`, the default, installable on a debug-mode console).
- **`InnerImageForm`** — `Plaintext`, `Encrypted`, `Compressed` (zlib PFSC),
  `KrakenCompressed` (PFSv3 Kraken). Selects how `BuildInnerImage` renders a laid-out inner image.

The package build path always stores the inner `pfs_image.dat` as the data-first image: a raw
concatenation of per-file payloads (raw or headerless Kraken) with the geometry described by a
generated `naps_pkg_layout.dat`.

### `ProsperoBackupConverter` (static)

Repackages a decrypted application backup into a debug fPKG that mounts and launches without a rif
or a console secret.

| Member | Purpose |
|---|---|
| `Convert(ProsperoBackupConversionOptions, Action<string>?)` | Assemble a staging tree from the backup, substitute each signed executable with its decrypted counterpart, fake-sign, and build a debug image. Returns `ProsperoBackupConversionResult`. |

- **`ProsperoBackupConversionOptions`** — `BackupFolder`, `OutputFolder`, `DecryptedSubfolder`
  (default `decrypted`), `ContentId`, `Passcode`, `Version`, `StagingFolder`, `KeepStaging`,
  `UseEmbeddedRightSprx`, `FselfOptions`. Content id and version fall back to the backup's
  `param.json` when not supplied.
- **`ProsperoBackupConversionResult`** — `OutputPath`, `DebugLicense`, `SubstitutedModules`,
  `PlaintextModules`, `UnresolvedModules`, `Warnings`, `LaunchReadiness`, `StagingFolder`.
  `LaunchReadiness` is a `ProsperoLaunchReadinessReport` (below) over the assembled tree.

### `ProsperoHomebrewPackager` (static)

Packages a compiled homebrew module into an installable debug fPKG. It assembles a clean source tree
from the module folder (the module lands as `eboot.bin`, the `sce_sys/` tree is copied) and builds a
finalized debug image with the license-free path enabled, so the module is fake-signed and the mount
key derives from the content id and passcode.

| Member | Purpose |
|---|---|
| `Package(ProsperoHomebrewPackageOptions, Action<string>?)` | Assemble the source tree and build a debug image. Returns `ProsperoHomebrewPackageResult`. |

- **`ProsperoHomebrewPackageOptions`** — `HomebrewFolder`, `OutputFolder` (both required), `ModuleName`
  (default `eboot.bin`), `ContentId`, `Passcode`, `Title`, `Version`, `StagingFolder`, `KeepStaging`,
  `FselfOptions`. Content id and version fall back to the homebrew's `param.json` when not supplied.
- **`ProsperoHomebrewPackageResult`** — `OutputPath`, `DebugLicense` (`RequiresRif` always false),
  `ModulePath` (`eboot.bin`), `LaunchReadiness`, `Warnings`, `StagingFolder`.

### `ProsperoLaunchReadiness` (static, `LibProsperoPkg.Content`)

Inspects an assembled application root and reports whether it meets the debug-launch conditions:
every executable module is a plaintext module the loader accepts, `eboot.bin` is present, and the
metadata is a `param.json` rather than the older `param.sfo`. It inspects only — it never signs, mounts,
or launches.

| Member | Purpose |
|---|---|
| `InspectModule(string path, ReadOnlySpan<byte> data)` | Classify one module. Returns `ModuleLaunchReadiness`. |
| `InspectAppRoot(string root)` | Scan `eboot.bin` + `*.prx` / `*.sprx`, check `param.json` / `param.sfo`, aggregate issues. Returns `ProsperoLaunchReadinessReport`. |

- **`ModuleAuthorityKind`** — `NotExecutable`, `RawElf`, `FakeAuthoritySelf`, `GenuineAuthoritySelf`,
  `UnknownAuthoritySelf`, `SignedEncrypted`.
- **`ModuleLaunchReadiness`** — `Path`, `Kind`, `AuthorityId`, `WillRunOnDebugConsole`, `Note`.
- **`ProsperoLaunchReadinessReport`** — `AppRoot`, `Modules`, `HasEboot`, `HasParamJson`,
  `HasParamSfo`, `RequiresDebugConsole`, `Issues`, `IsLaunchReady`.

---

## `LibProsperoPkg.PKG` — container, signing, finalization

| Type | Purpose |
|---|---|
| `ProsperoPkgBuilder` | Build the outer PFS + `\x7FCNT` metadata container. |
| `ProsperoPkgReader` | `DetectType(path/stream)` and `Read(path/stream)` for existing packages. |
| `ProsperoCntWriter` | Low-level `\x7FCNT` container writer over the `ProsperoCnt` model (`ProsperoCntEntry`, `ProsperoCntHeader`, `ProsperoCntEntryNames`, entry-id enums). |
| `ProsperoFihBuilder` | Wrap a `\x7FCNT` into a finalized `\x7FFIH` image. `BuildFromCnt(cntPath, fihOutputPath, ProsperoFihVariant)`. |
| `ProsperoPkgSigner` | RSA-3072 metadata signing and EKPFS derivation. |
| `ProsperoNapsLayout` | PS5 `naps_pkg_layout.dat` decoder and serializer for the `nwonly` streaming layout. `Parse`/`DecodeHeader` (returning a `NapsLayoutDocument` over the `Naps*` record types), `BuildLayout` (decoder and serializer are mutually consistent, including zero padding), the per-section `Encode*`/`Decode*` helpers, `SectionMap`. Record values are data-dependent on the inner-image compression run. The data-first build path generates a valid layout for its assembled inner image through `ProsperoNwonlyNapsGenerator`. |
| `ProsperoImageDigests` | PS5 finalized-image / CNT digest algorithms (single primitive: **SHA3-256**). Computes digests for all documented formulas. `ComputeSblockDigest`/`ComputeGameDigest` (`SHA3-256(plaintext outer superblock, 0x10000)` = FIH `0x30/0x70/0xD0`), `ComputeFixedInfoDigest` (`SHA3-256(FIH block)`), `ComputeBodyDigest` (`SHA3-256(CNT body)`), `ComputeEntryDigest` + `BuildEntryDigestTable` (CNT entry `0x0001`; self-slot zeroed), `ComputePackageDigest` (`SHA3-256(CNT[0:0xFE0])` = CNT `+0xFE0` = `<package-digest>`), `ComputeCntHeaderRollupDigest` (`SHA3-256(CNT[off:off+size])` = CNT `+0x100`), `ComputeContentDigest` / `ComputeHeaderDigest` / `ComputeConcatDigest` / `ForceFihRelativeImageOffset` (the GeneralDigests block — content/header/system/playgo/target, wired via `ProsperoPkgBuilder.ComputeGeneralDigests`), `LocateSuperblock`/`ComputeSblockDigestFromImage` (scan `version 2` + magic `0x0b2a3301`), `Sha3_256`. The FIH `0xB0` nested-image-content slot is computed from the uncompressed inner PFS image during finalization. |
| `ProsperoDdsEncoder` | Re-encode `sce_sys` icon/picture images to BC7 DDS. |
| `ProsperoFihVariant` | Finalized-image variant for `ProsperoFihBuilder`: `Debug`, `Official`. |
| `ProsperoNapsMeta` | Build the `naps_meta_*` install-metadata descriptors. `BuildMeta300` / `BuildMeta300FromInnerImageSize` produce the 48-byte `naps_meta_300/301/302/308` descriptor from the inner-image geometry; `BuildMeta18` builds the AES-128-XTS TLV metric blob (`naps_meta_18.dat`) over the finalized image and its content-file table. |
| `ProsperoSystemFiles` | Validate backend-signed `sce_sys` files before packing. `Validate`, `ValidateNpbind`, `ValidateNptitle`, `ValidateLicenseDat`, `ValidateLicenseInfo`. |
| `ProsperoSiArchive` | Build the trailing `sce_suppl` install archive: `pfsimage.xml`, the `naps_meta_*` descriptors, and the copied PlayGo files. `BuildDebugSiSegment`, `BuildPfsImageXml`, `WriteZip`, with `ProsperoSiMember` and `ProsperoPfsImageXmlOptions`. |
| `ProsperoChunkInfoModel` | Chunk/scenario model threaded from the GP5 project into the install archive. |

### Read model

- **`ProsperoPkg`** — `Type` (`ProsperoPkgType`), `Header` (`ProsperoPkgHeader?`), `Entries`
  (`IReadOnlyList<ProsperoPkgEntry>`), `Fih` (`ProsperoFihHeader?`).
- **`ProsperoPkgHeader`** — `Magic`, `Flags`, `EntryCount`, `EntryTableOffset`, `BodyOffset`,
  `BodySize`, `ContentId`, `DrmType`, `ContentType`.
- **`ProsperoPkgEntry`** — `Id` (`ProsperoEntryId`), `DataOffset`, `DataSize`, `Name`, and the
  raw header fields.
- **`ProsperoFihHeader`** — `SignedByte` (0x00 debug / 0x80 retail), `PfsImageOffset`,
  `PfsImageSize`, `EmbeddedCntOffset`.

### Build properties

- **`ProsperoPkgBuildProperties`** and **`ProsperoVolumeType`** drive the low-level builder.
- **`ProsperoPkgLayout`** and **`ProsperoEntryId`** describe the container layout and entry ids.

### Reading and extracting existing packages

| Type | Purpose |
|---|---|
| `ProsperoPackageExtractor` (static) | Extract the application filesystem from a finalized image end to end (finalized image → outer PFS → `pfs_image.dat` PFSC → inner PFS → files). `Inspect(path)` reports type, retail flag, outer-PFS offset/size, whether the outer PFS is encrypted, and whether a supplied key is required — without a key. `ListFiles(path, key)` enumerates the inner filesystem without writing. `Extract(...)` (two overloads) writes the files and returns a `ProsperoPackageManifest`. Supporting records: `ProsperoExtractionOptions`, `ProsperoPackageExtractionInfo`, `ProsperoPackageManifest`. |
| `ProsperoExtractionKey` (sealed) | Key material for the outer PFS. `FromPasscode(passcode)` / `FromPasscode(contentId, passcode)` derive the outer EKPFS from public inputs (SHA-256 and SHA3-256 candidates; the extractor auto-selects whichever opens the image), `FromEkpfs(bytes)` takes a supplied 32-byte image key, `None` attempts a plaintext outer PFS. `ResolveEkpfsCandidates`, `Kind` (`ProsperoExtractionKeyKind`), `ContentId`, `Passcode`, `Ekpfs`. |
| `ProsperoPkgValidator` (static) | Check a package against the structural acceptance gate the mount path enforces. `Validate(path, expectedContentId=null)` / `Validate(ProsperoPkg, expectedContentId=null)` return a `ProsperoAcceptanceReport` of named `Pass` / `Warning` / `Fail` checks (`ProsperoAcceptanceCheck`, `ProsperoCheckStatus`) with `Accepted` and `HasWarnings` roll-ups. |

A finalized retail image (signed byte `0x80`) encrypts the whole outer PFS including its
superblock; its image key arrives through the console entitlement path and is not derivable from
public inputs. `Inspect` reports this (`RequiresSuppliedKey = true`) and `Extract` refuses with a
clear message rather than returning a fabricated result.

---

## `LibProsperoPkg.PFS` — filesystem image

| Type | Purpose |
|---|---|
| `ProsperoPfsLayout` | Build a plaintext inner-PFS image from a folder. `BuildFromFolder`, `VerifyRoundTrip`. |
| `ProsperoPfsImage` | AES-XTS encrypt/decrypt a PFS image. `EncryptInPlace`, `VerifyRoundTrip`. |
| `ProsperoOuterPfsImage` | AES-XTS encrypt/decrypt the PS5 nwonly **outer** finalized-image PFS (whole 0x10000 block = one XTS unit; sector = block index, or `0x800000000000 | index` for signed blocks; superblock block left plaintext). `Transform` (block-index or `ProsperoOuterBlockKind[]` overload), `EncryptInPlace`/`DecryptInPlace` (key- or content-id/passcode-driven), `MetadataBlockIndex`. Decrypt and re-encrypt round-trips. |
| `ProsperoOuterPfsSignature` | PS5 nwonly outer-PFS signing primitives. `ComputeBlockHash` (plain SHA3-256 per-block/dinode hash), `ComputeSuperblockIcv`/`WriteSuperblockIcv` (`SHA3-256(superblock[0:0x5a0])` with the `icv` field zeroed), `BlockSector(index, signed)` (the bit-47 signed-block sector flag). |
| `ProsperoOuterPfsBuilder` | PS5 nwonly outer-PFS **structure generator**: assembles the data-first 11-block plaintext outer image from its outer files (`pfs_image.dat`, `naps_pkg_layout.dat`) — inode table with per-block SHA3 hashes, super-root/uroot dirents, the `\x7fFLT` inode_flat_path_table (custom reduced-Keccak path hash), and the signed superblock (+`icv`). `BuildPlaintext`, `Encrypt`, `BuildEncrypted`. Types: `ProsperoOuterFile`, `ProsperoOuterPfsBuildParameters`, `ProsperoOuterPfsBuildResult`. |
| `ProsperoPfsKeys` | PFS-image key derivation using SHA3-256. `DeriveEkpfs(contentId, passcode)`, `DeriveImageEncryptionKeys(ekpfs, seed)` → `(tweakKey, dataKey)`, overload `DeriveImageEncryptionKeys(contentId, passcode, seed)` → `(tweakKey, dataKey)`, `DeriveImageSignKey(ekpfs, seed)`. |
| `ProsperoPfsc` | High-level PFSC block compression. `PackFile`, `Unpack`, `IsPfsc`. |
| `ProsperoPfscEncoder` | Lower-level PFSC container encoder. `Encode` (buffer or stream), `HeaderSize`, `ShouldSkipExecutableCompression`, with `ProsperoPfscEncoderOptions` / `ProsperoPfscEncodeStats`. |
| `ProsperoPfscReader` | Random-access reader over a PFSC container. `Read`, `ReadSector`, `SectorSize`, `DataLength`. |
| `ProsperoPfsExtractor` (static) | Write every file of an opened (and, if encrypted, decrypted) `ProsperoPfsReader` to a directory, PFSC-decompressing per file, confined to the output directory. `Extract(reader, outputDirectory, logger=null)`, `ListEntries(reader)`; owns `ProsperoExtractedEntry` and `ProsperoExtractionException`. This is the single-image half that `ProsperoPackageExtractor` composes twice around the middle PFSC decode. |

Each high-level entry carries an options/result record pair (`ProsperoPfsLayoutOptions`/`Result`,
`ProsperoPfsImageOptions`/`Result`, `ProsperoPfscOptions`/`Result`).

The namespace also exposes the low-level filesystem model that the builder and reader operate on:
`ProsperoPfsBuilder`, `ProsperoPfsReader`, `ProsperoPfsHeader`, `ProsperoInode`, the on-disk dinode
records (`ProsperoDinodeD32`, `ProsperoDinodeS32`, `ProsperoDinodeS64`), `ProsperoFlatPathTable`,
`ProsperoPfsDirent`, the filesystem-tree nodes (`ProsperoFsNode`, `ProsperoFsDir`, `ProsperoFsFile`),
`ProsperoXtsDecryptReader`, `ProsperoPfscWriter` (low-level PFSC header writer), and the supporting
enums (`ProsperoDirentType`, `ProsperoInodeFlags`,
`ProsperoInodeMode`, `ProsperoPfsMode`, `ProsperoOuterBlockKind`).

### `LibProsperoPkg.PFS.Compression` — PS5 PFSv3 Kraken codec

The PS5 compression-file (`PFSC` v3) codec used by the `nwonly` path.

| Type | Purpose |
|---|---|
| `ProsperoCompressedPfsImage` | Public façade for the inner-image use of the codec — packs/unpacks a whole PFS image as a self-describing `PFSC` v3 container. `Pack`/`PackStored`/`PackFile`, `Unpack`/`UnpackFile`, detection helpers, `ValidateRoundTrip`; returns `ProsperoCompressedPfsImageResult` (raw/encoded sizes, block + stored counts, gain %). Used to compress the inner metadata block and by the standalone PFSC pack/unpack tool. |
| `ProsperoCompressedPfsFileWriter` | Produce a PFSv3 `PFSC` container. `WriteCompressed(payload, level, blockSize, useHuffmanArrays=true)` (Kraken with default-on Huffman entropy arrays, per-block stored fallback) / `WriteStored(payload)`. |
| `ProsperoCompressedPfsFile` | Parse a PFSv3 `PFSC` container. `Parse`, detection helpers, `VerifyFileDigest`, and `Decompress()` for a full decode. |
| `ProsperoPfsDigest` | SHA3-256 helpers for the per-block hashes and the `@0x28` file digest. |
| `ProsperoPfsCompressionConstants` | The Kraken window-bits constant for the codec. |
| `ProsperoCompressionAlgorithm` / `ProsperoPfsCompressionFormat` | The codec (`QuickZ`, `Zlib`, `Kraken`) and container-format version (`Version0`..`Version3`) enums. `ProsperoPfsShufflePattern` names the pre-compression shuffle patterns. |

The newLZ (Kraken) decoder and the Huffman entropy-array encoder are internal implementation
details of these types and are not part of the public surface. `PfsBlock` and
`ProsperoCompressedPfsImageResult` describe a single block and the pack result.

---

## `LibProsperoPkg.GP5` — project model

- **`Gp5Creator`** — `FromFolder(...)` / `FromFolderExplicit(...)` build a `Gp5Project` from a
  folder.
- **`Gp5Project`** — the GP5 document model, with both the "normal" (`rootdir`-walked) and
  "flat" (`files`/`folders`-listed) layouts represented via `Gp5Layout`. Elements:
  `Gp5Volume`, `Gp5Package`, `Gp5ChunkInfo`, `Gp5Chunk`, `Gp5Scenarios`, `Gp5Scenario`,
  `Gp5RootDir`, `Gp5File`, `Gp5Dir`. `Gp5VolumeType` names the volume kind
  (`prospero_app`, `prospero_patch`, `prospero_ac`, `prospero_ac_nodata`).

---

## `LibProsperoPkg.Keys` — signing key access

- **`ProsperoKeys`** — exposes the wired-in PS5 signing key material (`IsAvailable` and the
  individual key accessors). Used by the signer and the package builder.

---

## `LibProsperoPkg.PlayGo` — auxiliary file generators

- **`ProsperoPlayGo`** — generates the auxiliary `sce_sys` files (`about/right.sprx`,
  `playgo-chunk.dat`, `playgo-manifest.xml`) that the builder injects into the inner PFS so the
  produced file set is complete.

---

## `LibProsperoPkg.Content` — content file codecs

- **`ProsperoUcp`** — reads, builds, validates, verifies, and repairs UCP archives
  (`trophy2/*.ucp`, `uds/*.ucp`). `IsUcp`, `Read`, `Build`, `BuildFromDirectory`, `Validate`,
  `VerifyDigest`, and `WithRepairedDigest`.
- **`ProsperoFself`** — parses SELF containers and generates a fake-self from a 64-bit ELF.
  `IsSelf`, `IsElf`, `Parse`, `Validate`, and `MakeFself` (with `FselfOptions` for app and firmware
  version and an optional authority id). The read model exposes `SelfImage`, `SelfSegment`, and
  `SelfExtInfo`. `MakeFself` normalizes the input module header by default (see
  `FselfOptions.NormalizeHeader`), working on a private copy so the caller's buffer is untouched. The
  high-level builder wires this in through `ProsperoBuildOptions.FakeSignSelfModules`,
  which fake-signs raw ELF modules in the source tree before packing (producing an fPKG) and restores
  the originals afterward.
- **`ProsperoSelfAuthInfo`** — reads, validates, builds, and round-trips the SELF authentication-info
  sidecar (`*.auth_info`), a fixed 0x88-byte record: program authority id (`paid`) at `0x00`, four
  64-bit capability words at `0x08`, four 64-bit attribute words at `0x28`, and a 0x40-byte reserved
  tail, all little-endian. `IsAuthInfo`, `Parse`, `Read`, `ReadFile`, `Create`, `ToBytes`, `Write`,
  `WriteFile`; `Paid` / `AuthorityId`, `Capabilities`, `Attributes`, `Reserved`, and `Category`
  (`ProsperoAuthorityCategory`, with `IsFakeAuthority` / `IsGenuineAuthority` / `IsPrivilegedSystem`).
  Grant words are copied verbatim.
- **`ProsperoElfHeader`** — reads and edits the 64-bit ELF header. `Read`, `ReadFile`, the typed
  header properties, and the `IsExecutable` / `IsDynamic` / `IsModuleType` / `IsModuleReady`
  predicates report its shape. `SetOsAbi`, `SetAbiVersion`, `SetType`, and `SetMachine` rewrite
  single fields in place; `NormalizeForModule` retargets a module ELF (machine to x86-64, OS/ABI to
  FreeBSD, placeholder type to executable) before `MakeFself`, returning an `ElfNormalizeResult`.
  `ElfType`, `ElfClass`, `ElfData`, `ElfOsAbi`, and `ElfMachine` name the value spaces.

---

## `LibProsperoPkg.License` — per-title license (`rif`)

| Type | Purpose |
|---|---|
| `ProsperoRif` (sealed) | The per-title license record (`license/rif`): a fixed `0x400`-byte structure with a big-endian header (magic `RIF\0`, version, flags, the `QPaC` format tag, expiry, a 36-byte content id) and a 448-byte encrypted key blob at `0x240`. `Parse` / `Read` decode one record; `ReadAll` / `WriteAll` handle a multi-title file (one record per sub-title); `Create(contentId, keyBlob=null, expiry)` builds a structural record (copying a supplied key blob verbatim or leaving it zero); `ToBytes` / `Write` serialize; `Validate`. Exposes `ContentId`, `TitleId`, `ServiceLabel`, `Expiry` / `IsNonExpiring`, `HasKeyBlob`. |
| `ProsperoRifSet` (sealed) | A whole license file as the ordered set of records. `ReadFile` / `Read` / `FromRecords`, `Validate` (non-empty, whole-file size a positive multiple of `0x400`, per-record validity), `Summarize(appTitleId)` → `ProsperoRifSetSummary` (`n_rif`, per-record `ServiceID`, `has_app`, `n_ac`, size), `Describe`. |
| `ProsperoEntitlementKey` (sealed) | The 128-bit content key (`entitlement_key`) the builder accepts as an alternative to a passcode. `FromBytes`, `ParseHex` / `ToHex`, `Value`, `IsZero`, `Validate`, and `ResolveMode(passcode, entitlementKey, out mode, out error)` (`ProsperoKeyMode`) enforcing the mutual-exclusivity rule. A validated carrier for supplied material; it never derives or forges a license key body. |
| `ProsperoDebugLicense` (sealed) | The debug grant for a content id + passcode, where the mount key is recomputed from public inputs rather than granted. `Create(contentId, passcode=null)` (passcode defaults to 32 zeros), `RequiresRif` (always false), `DeriveEkpfs`, `DeriveImageEncryptionKeys(seed)`, `DeriveImageSignKey(seed)`, and `DeriveKeySet(seed)` → `ProsperoDebugKeySet` (EKPFS + AES-XTS tweak/data + sign key) delegate to `ProsperoPfsKeys`; `ToStructuralRif(expiry)` emits a zero-blob record for pipelines that expect a license file present; `Validate`. Holds no device secret. |

The 448-byte key blob at `0x240` is encrypted with per-console material and cannot be produced
off-console. `Create` covers the structural / templated path only.

---

## `LibProsperoPkg.NpDrm` — content-info projection

| Type | Purpose |
|---|---|
| `ProsperoNpDrmContentInfo` (sealed) | Projects a package header into the compact classification the mount path consumes before it accepts an image: container offset, content id, derived title id, `DrmType` (`0x70`), `ContentType` (`0x74`), `ContentFlags` (`0x78`), `IsNestedImage`, `IsFinalized`, and the decoded `PatchKind` (`ProsperoPatchKind`: `None` / `First` / `Subsequent` / `Delta` / `Cumulative`) with an `IsPatch` roll-up. `Read(path)` / `Read(stream)` parse and project; `FromPackage` projects a parsed `ProsperoPkg`; `ResolveContainerOffset` mirrors the container-offset switch on magic and version; `DeriveTitleId(contentId)`. |

---

## `LibProsperoPkg.DiscBackup` — split disc-backup packages

| Type | Purpose |
|---|---|
| `ProsperoDiscBackup` (sealed) | Opens a split disc-backup package (the ordered `app_0` / `app_sc` pieces) described by an `app.json` manifest and presents it as one package. `Open(path)`, `OpenPackageStream` / `ReassembleTo(stream/path, progress)`, `ReadPackage`, `ReadContentInfo`, `ComputePackageDigest` / `VerifyPackageDigest`, `ReadChunkCrc` / `VerifyChunkCrcHash` / `VerifyChunkCrcs(out mismatchChunk, progress)`, `FindImageKeyEntry`, `ExtractEntry` / `ExtractEntryBytes`. Props: `Directory`, `Manifest`, `OriginalFileSize`. |
| `ProsperoDiscBackupManifest` (sealed) | Parses `app.json`: `NumberOfSplitFiles`, `OriginalFileSize`, `PackageDigest`, the ordered `Pieces` (`ProsperoDiscBackupPiece`: `DiscNumber`, `FileOffset`, `FileSize`, `Url`), `PlaygoChunkCrcHashValue`, `PlaygoChunkCrcUrl`. `Parse(json)`, `Read(path)`. |
| `ProsperoConcatStream` (sealed) | A read-only, seekable stream that concatenates the piece windows without materializing a temporary file. |
| `ProsperoPlaygoChunkCrc` (sealed) | Parses the headerless little-endian CRC-32C array (one value per 64 KiB chunk, from `app.crc`). `Parse`, `Read(path)`, `VerifyPackage(stream, out mismatchChunk, progress)`. |

The EEKPFS key entry (id `0x20`) is returned as stored (encrypted); off-console key derivation from
it is not implemented.

---

## `LibProsperoPkg.Util` — low-level helpers

Building blocks shared across the library. Most consumers use the higher-level types above; these
are exposed for advanced use.

- **`Crypto`** — SHA-256 / SHA3-256, HMAC-SHA-256, AES-CBC/CFB, RSA (PKCS#1) key wrapping, the PFS
  key-generation primitives (`PfsGenCryptoKey`, `PfsGenEncKey`, `PfsGenSignKey`), `ComputeKeys`,
  `CreateKeystone`, and `Xor`.
- **`CryptoKeys`** — the key constants the signer and mount-key derivation use.
- **`ProsperoCrc32C`** — CRC-32C (`Compute`, `Update`).
- **`XtsBlockTransform`** — AES-XTS sector encrypt/decrypt.
- Stream helpers: `OffsetStream`, `SubStream`, `StreamReader`, `WriterBase`, and the
  `IMemoryReader` / `IMemoryAccessor` accessors with `MemoryMappedViewAccessor_`.

---

## Shared library (C ABI)

The library can be built with a flat C export surface and a matching `libprosperopkg.h` header.
The committed project stays unchanged; build properties are injected at build time. Each build
checks the exported symbol table and packages the library, header, license text, and a
`SHA256SUMS` manifest as an artifact.

| Function | Purpose |
|---|---|
| `lpp_version` | Return the library version string. |
| `lpp_abi_version` | Return the numeric ABI version of the export surface (`LPP_ABI_VERSION`). |
| `lpp_last_error` | Return the last error message on the calling thread. |
| `lpp_is_valid_content_id` / `lpp_is_valid_title_id` | Validate identifiers. |
| `lpp_compose_content_id` | Compose a 36-char content id. |
| `lpp_build_package` | Run the full build from a prepared folder. |
| `lpp_build_package_ex` | Run the full build with the complete option set (`lpp_build_options`). |
| `lpp_detect_package_type` | Return the package type of a file (`LPP_TYPE_*`). |
| `lpp_build_inner_image` | Lay a folder out into an inner-PFS image (`LPP_FORM_*`). |
| `lpp_encrypt_pfs_image` | AES-XTS-encrypt a plaintext inner-PFS image in place. |
| `lpp_pack_pfs_image` / `lpp_unpack_pfs_image` | Pack / unpack a PFSv3 PFSC container. |
| `lpp_is_self` / `lpp_is_elf` / `lpp_is_ucp` | Detect a SELF, a 64-bit ELF, or a UCP archive. |
| `lpp_read_self_info` | Read the extended info and segment count from a SELF module. |
| `lpp_make_fself` | Generate a fake-self from a 64-bit ELF. |
| `lpp_make_fself_ex` | Generate a fake-self with explicit version and authority-id options. |
| `lpp_make_fself_file` | Read an ELF from a path, fake-sign it, and write the result to a path. |
| `lpp_fake_sign_folder` | Fake-sign every raw ELF module under a folder in place. |
| `lpp_application_type_name` | Return the display name of an application type (`LPP_APP_TYPE_*`). |
| `lpp_application_drm_type` | Return the generated `applicationDrmType` token for an application type. |
| `lpp_parse_application_type` | Parse an application-type display name into its code. |
| `lpp_read_auth_info` / `lpp_write_auth_info` | Read / write a SELF authentication-info sidecar. |
| `lpp_read_npdrm_content_info` | Read the NpDrm content-info of a package (`lpp_npdrm_content_info`). |
| `lpp_inspect_package` | Inspect a package without a key (`lpp_package_info`). |
| `lpp_read_package_summary` | Read header and image-header fields (`lpp_package_summary`). |
| `lpp_package_entry_count` / `lpp_read_package_entry` | Count entries / read one entry (`lpp_package_entry`). |
| `lpp_list_package_files` / `lpp_list_package_files_ekpfs` | List the inner files by passcode or image key. |
| `lpp_compare_containers` | List the differences between two metadata containers. |
| `lpp_extract_package` / `lpp_extract_package_ekpfs` | Extract a package by passcode or image key. |
| `lpp_validate_package` | Run the acceptance checks on a package. |
| `lpp_merge_split_package_dir` | Merge split packages found in a directory. |
| `lpp_package_homebrew` | Build a package from a homebrew folder. |
| `lpp_inspect_launch_readiness` | Summarize the launch readiness of an application root (`lpp_launch_readiness`). |
| `lpp_build_pfs_layout` | Lay a folder out into a plaintext inner-PFS image. |
| `lpp_pfs_image_is_encrypted` / `lpp_decrypt_pfs_image` | Report encryption state / decrypt an inner image in place. |
| `lpp_read_elf_header` | Read an ELF header (`lpp_elf_info`). |
| `lpp_normalize_elf_module` | Normalize an ELF for use as a module. |
| `lpp_ucp_validate_file` / `lpp_ucp_verify_digest_file` | Validate a content protection file / verify its digest. |
| `lpp_ucp_build_from_directory` / `lpp_ucp_repair_digest_file` | Build a content protection file / repair its digest. |
| `lpp_rif_record_count` / `lpp_read_rif_content_id` / `lpp_read_rif_summary` | Read the record count, first content id, or a summary (`lpp_rif_summary`). |
| `lpp_rif_create` | Create a structural license record. |
| `lpp_derive_image_key` | Derive the 32-byte image key from a content id and passcode. |
| `lpp_entitlement_key_validate` | Validate a 32-hex-character entitlement key. |
| `lpp_disc_backup_reassemble` / `lpp_disc_backup_verify` | Reassemble / verify a split disc backup. |
| `lpp_disc_backup_content_info` / `lpp_disc_backup_verify_chunk_crcs` | Read a disc backup's content info / verify its chunk CRCs. |
| `lpp_convert_backup` | Convert a decrypted application backup into a debug package. |
| `lpp_encode_png_to_dds` | Encode a PNG file to a BC7 DDS texture. |
| `lpp_build_playgo_chunk_dat` | Build a chunk descriptor file for a content id. |
| `lpp_create_param_json` | Create a default param.json for a set of ids. |

`lpp_build_package_ex` takes a pointer to `lpp_build_options`, a zero-initialized struct whose
`struct_size` field is set to `sizeof(lpp_build_options)` before use. It carries the application
type, badge and DRM overrides, param.json generation, inner compression, and the fake-self settings
(version, firmware and authority-id) applied to raw ELF modules before packing. The trailing
`license_free` field builds a DRM/license-free debug package; it is appended, so a smaller
`struct_size` from an older caller leaves it disabled.

Strings cross the boundary as UTF-8. String-output functions return the number of bytes written, or
the negative of the required size (including the terminator) when the caller buffer is too small.
Status functions return 0 on success and a negative value on failure, with the message available
through `lpp_last_error`. Struct-output functions fill a caller-provided struct — `lpp_build_options`,
`lpp_npdrm_content_info`, `lpp_package_info`, `lpp_rif_summary`, `lpp_package_summary`,
`lpp_package_entry`, `lpp_elf_info`, and `lpp_launch_readiness` — whose `struct_size` field is set
before use. Enums pass as ints; the header defines the `LPP_ABI_VERSION`, `LPP_MODE_*`,
`LPP_OUTPUT_*`, `LPP_INNER_*`, `LPP_FORM_*`, `LPP_TYPE_*`, `LPP_APP_TYPE_*`, `LPP_PATCH_*`,
`LPP_AUTH_CATEGORY_*`, `LPP_PARAM_DRM_*`, `LPP_ELF_MACHINE_*`, and `LPP_ENTRY_*` values.
