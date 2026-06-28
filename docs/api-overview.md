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
| `BuildInnerPfsLayout(...)` | Lay a folder out into a plaintext inner-PFS image. |
| `BuildInnerImage(...)` | Run the full inner-image pipeline (plaintext / encrypted / zlib-compressed / Kraken-compressed). |
| `EncryptPfsImage(...)` | AES-XTS-encrypt a prepared plaintext inner-PFS image in place. |
| `IsValidContentId` / `IsValidTitleId` | Validate identifiers. |
| `ComposeContentId(publisher, titleId, label)` | Build a well-formed 36-char content id. |
| `VolumeTypeForMode` / `IsDlcMode` | Map a `ProsperoPackageMode` to volume metadata. |
| `KeysAvailable` | Reports whether publishing key material is available. |

### Supporting types

- **`ProsperoBuildOptions`** — the build description: `Mode`, `OutputFormat`, `SourceFolder`,
  `OutputFolder`, `ContentId`, `Passcode`, `Title`, `TitleId`, `Version`,
  `GenerateParamJsonIfMissing`, `CompressInnerImage`, `InnerCompression`.
- **`ProsperoBuildResult`** — `OutputPath` and a list of non-fatal `Warnings`.
- **`ProsperoPackageMode`** — `Application`, `Homebrew`, `AdditionalContentData`,
  `AdditionalContentNoData`.
- **`ProsperoOutputFormat`** — `MetadataContainer` (`\x7FCNT` only, not installable) or
  `DebugImage` (`\x7FFIH`, the default, installable on a debug-mode console).
- **`InnerImageForm`** — `Plaintext`, `Encrypted`, `Compressed` (zlib PFSC),
  `KrakenCompressed` (PFSv3 Oodle Kraken, the `--oformat nwonly` codec).
- **`ProsperoInnerCompression`** (in `LibProsperoPkg.PKG`) — `None`, `Zlib` (installable inner
  image), `Kraken` (`--oformat nwonly` inner image). Set on `ProsperoBuildOptions.InnerCompression`
  / `ProsperoPkgBuildProperties.InnerCompression`; takes precedence over the legacy
  `CompressInnerImage` bool when non-`None`.

---

## `LibProsperoPkg.PKG` — container, signing, finalization

| Type | Purpose |
|---|---|
| `ProsperoPkgBuilder` | Build the outer PFS + `\x7FCNT` metadata container. |
| `ProsperoPkgReader` | `DetectType(path/stream)` and `Read(path/stream)` for existing packages. |
| `ProsperoPkgWriter` | Low-level container writer (`ProsperoPkgWriterEntry`, `ProsperoPkgWriterOptions`). |
| `ProsperoFihBuilder` | Wrap a `\x7FCNT` into a finalized `\x7FFIH` debug image. |
| `ProsperoPkgSigner` | RSA-3072 metadata signing and EKPFS/PFS key derivation. |
| `ProsperoNapsLayout` | PS5 `naps_pkg_layout.dat` (`PackageLayout_NAPS`) decoder and serializer for the `--oformat nwonly` streaming layout. `Parse`/`DecodeHeader`, `BuildLayout` (decoder and serializer are mutually consistent, including zero padding), the per-section `Encode*`/`Decode*` helpers, `SectionMap`. Record values are data-dependent on the inner-image compression run. |
| `ProsperoImageDigests` | PS5 finalized-image / CNT digest algorithms (single primitive: **SHA3-256**). Computes byte-exact digests for all documented formulas. `ComputeSblockDigest`/`ComputeGameDigest` (`SHA3-256(plaintext outer superblock, 0x10000)` = FIH `0x30/0x70/0xD0`), `ComputeFixedInfoDigest` (`SHA3-256(FIH block)`), `ComputeBodyDigest` (`SHA3-256(CNT body)`), `ComputeEntryDigest` + `BuildEntryDigestTable` (CNT entry `0x0001`; self-slot zeroed), `ComputePackageDigest` (`SHA3-256(CNT[0:0xFE0])` = CNT `+0xFE0` = `<package-digest>`), `ComputeCntHeaderRollupDigest` (`SHA3-256(CNT[off:off+size])` = CNT `+0x100`), `ComputeContentDigest` / `ComputeHeaderDigest` / `ComputeConcatDigest` / `ForceFihRelativeImageOffset` (the GeneralDigests block — content/header/system/playgo/target, wired via `ProsperoPkgBuilder.ComputeGeneralDigests`), `LocateSuperblock`/`ComputeSblockDigestFromImage` (scan `version 2` + magic `0x0b2a3301`), `Sha3_256`. The FIH `0xB0` nested-image-content slot is console-gated. |
| `ProsperoDdsEncoder` | Re-encode `sce_sys` icon/picture images to BC7 DDS. |

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
| `ProsperoPfsc` | PFSC block compression. `PackFile`, `Unpack`, `IsPfsc`. |

Each carries an options/result record pair (`ProsperoPfsLayoutOptions`/`Result`,
`ProsperoPfsImageOptions`/`Result`, `ProsperoPfscOptions`/`Result`).

### `LibProsperoPkg.PFS.Compression` — PS5 PFSv3 + Oodle Kraken codec

The PS5 compression-file (`PFSC` v3) codec used by
the `--oformat nwonly` path.

| Type | Purpose |
|---|---|
| `ProsperoCompressedPfsImage` | Public façade for the inner-image use of the codec — packs/unpacks a whole PFS image as a self-describing `PFSC` v3 container. `Pack`/`PackStored`/`PackFile`, `Unpack`/`UnpackFile`, detection helpers, `ValidateRoundTrip`; returns `ProsperoCompressedPfsImageResult` (raw/encoded sizes, block + stored counts, gain %). The codec the builder's `ProsperoInnerCompression.Kraken` option uses. |
| `CompressedPfsFileWriter` | Produce a PFSv3 `PFSC` container. `WriteCompressed(payload, level, blockSize, useHuffmanArrays=true)` (Kraken with default-on Huffman entropy arrays, per-block stored fallback) / `WriteStored(payload)`. |
| `CompressedPfsFile` | Parse a PFSv3 `PFSC` container. `Parse`, detection helpers, `VerifyFileDigest`, and `Decompress()` (drives `KrakenDecoder` for a full byte-exact decode). |
| `Oodle.KrakenDecoder` | Internal Oodle 2.8.0 newLZ (Kraken) decoder: raw + Huffman literal/cmd/offset/length arrays, post-seed excess framing with length escapes, both literal models, multi-chunk and multi-block. Decodes two embedded reference vectors and checks SHA3-256. |
| `Oodle.KrakenHuffmanArrayEncoder` | Internal Huffman entropy-array encoder (chunk type 2, 3-stream split, K.3 length-limit) — the inverse of the decoder's array path; Huffman-codes each chunk's literal/command/length streams. Output round-trips through `KrakenDecoder` byte-for-byte. |
| `PfsDigest` | SHA3-256 helpers for the per-block hashes and the `@0x28` file digest. |
| `PfsShuffle` | The 13 pre-compression SoA de-interleave (shuffle/deshuffle) transforms. |

---

## `LibProsperoPkg.GP5` — project model

- **`Gp5Creator`** — `FromFolder(...)` / `FromFolderExplicit(...)` build a `Gp5Project` from a
  folder.
- **`Gp5Project`** — the GP5 document model, with both the "normal" (`rootdir`-walked) and
  "flat" (`files`/`folders`-listed) layouts represented via `Gp5Layout`. Elements:
  `Gp5Volume`, `Gp5Package`, `Gp5ChunkInfo`, `Gp5Chunk`, `Gp5Scenarios`, `Gp5Scenario`,
  `Gp5RootDir`, `Gp5File`, `Gp5Dir`.

---

## `LibProsperoPkg.Keys` — publishing key access

- **`ProsperoKeys`** — exposes the wired-in PS5 publishing key material (`IsAvailable` and the
  individual key accessors). Used by the signer and the package builder.

---

## `LibProsperoPkg.PlayGo` — auxiliary file generators

- **`ProsperoPlayGo`** — generates the auxiliary `sce_sys` files (`about/right.sprx`,
  `playgo-chunk.dat`, `playgo-manifest.xml`) that the builder injects into the inner PFS so the
  produced file set is complete.
