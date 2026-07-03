# API Overview

This document summarizes the public surface of LibProsperoPkg, grouped by namespace. Every
public type and member carries XML documentation, so IntelliSense and the generated
documentation file are the authoritative reference; this page is the orientation map.

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
| `CompareContainers(referencePkg, candidatePkg)` | Compare two packages field by field. Returns the list of differences. |
| `ComposeContentId(publisher, titleId, label)` | Build a well-formed 36-char content id. |
| `IsValidContentId` / `IsValidTitleId` | Validate identifiers. |
| `VolumeTypeForMode(mode)` | Map a `ProsperoPackageMode` to the GP5 `Gp5VolumeType`. |
| `ProsperoVolumeTypeForMode(mode)` | Map a `ProsperoPackageMode` to the container `ProsperoVolumeType`. |
| `IsDlcMode(mode)` | Report whether a mode is additional-content. |
| `KeysAvailable` | Reports whether publishing key material is available. |

### Supporting types

- **`ProsperoBuildOptions`** — the build description: `Mode`, `OutputFormat`, `SourceFolder`,
  `OutputFolder`, `ContentId`, `Passcode`, `Title`, `TitleId`, `Version`,
  `GenerateParamJsonIfMissing`, `CompressInnerImage`, `InnerCompression`, `ApplicationType`,
  `ApplicationDrmType`, `ContentBadgeType`, `FakeSignSelfModules`, `FselfOptions`.
- **`ProsperoApplicationType`** — the application type: `NotSpecified`,
  `PaidStandaloneFullApp`, `UpgradableApp`, `DemoApp`, `FreemiumApp`. `ProsperoApplicationTypes`
  maps it to the generated `param.json` `applicationDrmType` (`free` / `standard` / `freemium`)
  and provides `DisplayName` and `Parse`.
- **`ProsperoBuildResult`** — `OutputPath` and a list of non-fatal `Warnings`.
- **`ProsperoPackageMode`** — `Application`, `Homebrew`, `AdditionalContentData`,
  `AdditionalContentNoData`.
- **`ProsperoOutputFormat`** — `MetadataContainer` (`\x7FCNT` only, not installable) or
  `DebugImage` (`\x7FFIH`, the default, installable on a debug-mode console).
- **`InnerImageForm`** — `Plaintext`, `Encrypted`, `Compressed` (zlib PFSC),
  `KrakenCompressed` (PFSv3 Kraken, the `nwonly` codec).
- **`ProsperoInnerCompression`** (in `LibProsperoPkg.PKG`) — `None`, `Zlib` (installable inner
  image), `Kraken` (`nwonly` inner image). Set on `ProsperoBuildOptions.InnerCompression`
  / `ProsperoPkgBuildProperties.InnerCompression`; takes precedence over the legacy
  `CompressInnerImage` bool when non-`None`.

---

## `LibProsperoPkg.PKG` — container, signing, finalization

| Type | Purpose |
|---|---|
| `ProsperoPkgBuilder` | Build the outer PFS + `\x7FCNT` metadata container. |
| `ProsperoPkgReader` | `DetectType(path/stream)` and `Read(path/stream)` for existing packages. |
| `ProsperoCntWriter` | Low-level `\x7FCNT` container writer over the `ProsperoCnt` model (`ProsperoCntEntry`, `ProsperoCntHeader`, `ProsperoCntEntryNames`, entry-id enums). |
| `ProsperoFihBuilder` | Wrap a `\x7FCNT` into a finalized `\x7FFIH` image. `BuildFromCnt(cntPath, fihOutputPath, ProsperoFihVariant)`. |
| `ProsperoPkgSigner` | RSA-3072 metadata signing and EKPFS/PFS key derivation. |
| `ProsperoNapsLayout` | PS5 `naps_pkg_layout.dat` decoder and serializer for the `nwonly` streaming layout. `Parse`/`DecodeHeader` (returning a `NapsLayoutDocument` over the `Naps*` record types), `BuildLayout` (decoder and serializer are mutually consistent, including zero padding), the per-section `Encode*`/`Decode*` helpers, `SectionMap`. Record values are data-dependent on the inner-image compression run. |
| `ProsperoImageDigests` | PS5 finalized-image / CNT digest algorithms (single primitive: **SHA3-256**). Computes byte-exact digests for all documented formulas. `ComputeSblockDigest`/`ComputeGameDigest` (`SHA3-256(plaintext outer superblock, 0x10000)` = FIH `0x30/0x70/0xD0`), `ComputeFixedInfoDigest` (`SHA3-256(FIH block)`), `ComputeBodyDigest` (`SHA3-256(CNT body)`), `ComputeEntryDigest` + `BuildEntryDigestTable` (CNT entry `0x0001`; self-slot zeroed), `ComputePackageDigest` (`SHA3-256(CNT[0:0xFE0])` = CNT `+0xFE0` = `<package-digest>`), `ComputeCntHeaderRollupDigest` (`SHA3-256(CNT[off:off+size])` = CNT `+0x100`), `ComputeContentDigest` / `ComputeHeaderDigest` / `ComputeConcatDigest` / `ForceFihRelativeImageOffset` (the GeneralDigests block — content/header/system/playgo/target, wired via `ProsperoPkgBuilder.ComputeGeneralDigests`), `LocateSuperblock`/`ComputeSblockDigestFromImage` (scan `version 2` + magic `0x0b2a3301`), `Sha3_256`. The FIH `0xB0` nested-image-content slot is computed from the uncompressed inner PFS image during finalization. |
| `ProsperoDdsEncoder` | Re-encode `sce_sys` icon/picture images to BC7 DDS. |
| `ProsperoInnerCompression` | Inner-image codec selector: `None`, `Zlib`, `Kraken`. Set on `ProsperoBuildOptions.InnerCompression` / `ProsperoPkgBuildProperties.InnerCompression`. |
| `ProsperoFihVariant` | Finalized-image variant for `ProsperoFihBuilder`: `Debug`, `Official`. |
| `ProsperoNapsMeta` | Build the `naps_meta_300` install-metadata descriptor from the inner-image geometry. `BuildMeta300`, `BuildMeta300FromInnerImageSize`. |
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

---

## `LibProsperoPkg.PFS` — filesystem image

| Type | Purpose |
|---|---|
| `ProsperoPfsLayout` | Build a plaintext inner-PFS image from a folder. `BuildFromFolder`, `VerifyRoundTrip`. |
| `ProsperoPfsImage` | AES-XTS encrypt/decrypt a PFS image. `EncryptInPlace`, `VerifyRoundTrip`. |
| `ProsperoOuterPfsImage` | AES-XTS encrypt/decrypt the PS5 nwonly **outer** finalized-image PFS (whole 0x10000 block = one XTS unit; sector = block index, or `0x800000000000 | index` for signed blocks; superblock block left plaintext). `Transform` (block-index or `ProsperoOuterBlockKind[]` overload), `EncryptInPlace`/`DecryptInPlace` (key- or content-id/passcode-driven), `MetadataBlockIndex`. Decrypt and re-encrypt round-trips byte-for-byte. |
| `ProsperoOuterPfsSignature` | PS5 nwonly outer-PFS signing primitives. `ComputeBlockHash` (plain SHA3-256 per-block/dinode hash), `ComputeSuperblockIcv`/`WriteSuperblockIcv` (`SHA3-256(superblock[0:0x5a0])` with the `icv` field zeroed), `BlockSector(index, signed)` (the bit-47 signed-block sector flag). |
| `ProsperoOuterPfsBuilder` | PS5 nwonly outer-PFS **structure generator**: assembles the data-first 11-block plaintext outer image from its outer files (`pfs_image.dat`, `naps_pkg_layout.dat`) — inode table with per-block SHA3 hashes, super-root/uroot dirents, the `\x7fFLT` inode_flat_path_table (custom reduced-Keccak path hash), and the signed superblock (+`icv`). `BuildPlaintext`, `Encrypt`, `BuildEncrypted`. Produces byte-exact plaintext and ciphertext output. Types: `ProsperoOuterFile`, `ProsperoOuterPfsBuildParameters`, `ProsperoOuterPfsBuildResult`. |
| `ProsperoPfsKeys` | PFS-image key derivation using SHA3-256. `DeriveEkpfs(contentId, passcode)`, `DeriveImageEncryptionKeys(ekpfs, seed)` → `(tweakKey, dataKey)`, overload `DeriveImageEncryptionKeys(contentId, passcode, seed)` → `(tweakKey, dataKey)`, `DeriveImageSignKey(ekpfs, seed)`. |
| `ProsperoPfsc` | High-level PFSC block compression. `PackFile`, `Unpack`, `IsPfsc`. |
| `ProsperoPfscEncoder` | Lower-level PFSC container encoder. `Encode` (buffer or stream), `HeaderSize`, `ShouldSkipExecutableCompression`, with `ProsperoPfscEncoderOptions` / `ProsperoPfscEncodeStats`. |
| `ProsperoPfscReader` | Random-access reader over a PFSC container. `Read`, `ReadSector`, `SectorSize`, `DataLength`. |

Each high-level entry carries an options/result record pair (`ProsperoPfsLayoutOptions`/`Result`,
`ProsperoPfsImageOptions`/`Result`, `ProsperoPfscOptions`/`Result`).

The namespace also exposes the low-level filesystem model that the builder and reader operate on:
`ProsperoPfsBuilder`, `ProsperoPfsReader`, `ProsperoPfsHeader`, `ProsperoInode`, the on-disk dinode
records (`ProsperoDinodeD32`, `ProsperoDinodeS32`, `ProsperoDinodeS64`), `ProsperoFlatPathTable`,
`ProsperoPfsDirent`, the filesystem-tree nodes (`ProsperoFsNode`, `ProsperoFsDir`, `ProsperoFsFile`),
`ProsperoXtsDecryptReader`, and the supporting enums (`ProsperoDirentType`, `ProsperoInodeFlags`,
`ProsperoInodeMode`, `ProsperoPfsMode`, `ProsperoOuterBlockKind`).

### `LibProsperoPkg.PFS.Compression` — PS5 PFSv3 Kraken codec

The PS5 compression-file (`PFSC` v3) codec used by the `nwonly` path.

| Type | Purpose |
|---|---|
| `ProsperoCompressedPfsImage` | Public façade for the inner-image use of the codec — packs/unpacks a whole PFS image as a self-describing `PFSC` v3 container. `Pack`/`PackStored`/`PackFile`, `Unpack`/`UnpackFile`, detection helpers, `ValidateRoundTrip`; returns `ProsperoCompressedPfsImageResult` (raw/encoded sizes, block + stored counts, gain %). The codec the builder's `ProsperoInnerCompression.Kraken` option uses. |
| `ProsperoCompressedPfsFileWriter` | Produce a PFSv3 `PFSC` container. `WriteCompressed(payload, level, blockSize, useHuffmanArrays=true)` (Kraken with default-on Huffman entropy arrays, per-block stored fallback) / `WriteStored(payload)`. |
| `ProsperoCompressedPfsFile` | Parse a PFSv3 `PFSC` container. `Parse`, detection helpers, `VerifyFileDigest`, and `Decompress()` for a full byte-exact decode. |
| `ProsperoPfsDigest` | SHA3-256 helpers for the per-block hashes and the `@0x28` file digest. |
| `ProsperoPfsShuffle` | The pre-compression de-interleave (shuffle/deshuffle) transforms. `ProsperoPfsShufflePattern` names each pattern. |
| `ProsperoPfsCompressionConstants` | Block size, level and format constants for the codec. |
| `ProsperoCompressionAlgorithm` / `ProsperoPfsCompressionFormat` | The codec (`QuickZ`, `Zlib`, `Kraken`) and container-format version (`Version0`..`Version3`) enums. |

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

## `LibProsperoPkg.Keys` — publishing key access

- **`ProsperoKeys`** — exposes the wired-in PS5 publishing key material (`IsAvailable` and the
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
  `SelfExtInfo`. The high-level builder wires this in through `ProsperoBuildOptions.FakeSignSelfModules`,
  which fake-signs raw ELF modules in the source tree before packing (producing an fPKG) and restores
  the originals afterward.

---

## `LibProsperoPkg.Util` — low-level helpers

Building blocks shared across the library. Most consumers use the higher-level types above; these
are exposed for advanced use.

- **`Crypto`** — SHA-256 / SHA3-256, HMAC-SHA-256, AES-CBC/CFB, RSA-2048, the PFS key-generation
  primitives (`PfsGenCryptoKey`, `PfsGenEncKey`, `PfsGenSignKey`), `ComputeKeys`, `CreateKeystone`,
  and `Xor`.
- **`CryptoKeys`** and **`RSAKeyset`** — the key constants and the RSA key-set model the signer uses.
- **`ProsperoCrc32C`** — CRC-32C (`Compute`, `Update`).
- **`XtsBlockTransform`** — AES-XTS sector encrypt/decrypt.
- **`MersenneTwister`** — the seed generator.
- Stream helpers: `OffsetStream`, `SubStream`, `StreamReader`, `WriterBase`, and the
  `IMemoryReader` / `IMemoryAccessor` accessors with `MemoryMappedViewAccessor_`.

---

## Native shared library (C ABI)

The library can be published as a shared library (`.so` / `.dylib`) with a flat C export surface,
built by the `native-linux` and `native-macos` workflows. The export source and the matching
`libprosperopkg.h` header live in the repository under `.github/native/`. The committed project is
unchanged; the workflow injects the NativeAOT build properties at build time. Each build verifies
the exported symbol table and packages the library, header, license text and a `SHA256SUMS`
manifest as an artifact.

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

`lpp_build_package_ex` takes a pointer to `lpp_build_options`, a zero-initialized struct whose
`struct_size` field is set to `sizeof(lpp_build_options)` before use. It carries the application
type, badge and DRM overrides, param.json generation, inner compression, and the fake-self settings
(version, firmware and authority-id) applied to raw ELF modules before packing.

Strings cross the boundary as UTF-8. String-output functions return the number of bytes written, or
the negative of the required size (including the terminator) when the caller buffer is too small.
Status functions return 0 on success and a negative value on failure, with the message available
through `lpp_last_error`. Enums pass as ints; the header defines the `LPP_ABI_VERSION`,
`LPP_MODE_*`, `LPP_OUTPUT_*`, `LPP_INNER_*`, `LPP_FORM_*`, `LPP_TYPE_*`, and `LPP_APP_TYPE_*`
values.
