# Implementation Status

This document describes the current LibProsperoPkg package-building and reading capabilities. It is a public technical status file: it lists implemented behavior, known limits, and remaining work without process notes.

## Implemented

### Container format

- Builds the outer PFS plus the `\x7FCNT` metadata container with big-endian header, entry table, and entry-name table.
- Reads `\x7FCNT` and finalized `\x7FFIH` packages through `ProsperoPkgReader`, including header fields, content id, entry table, and entry names.
- Produces containers that parse back with the expected PS5 stamping.
- `ProsperoPackageBuilder.Build` runs end to end from a source folder through inner PFS image creation, inner-image codec selection, AES-XTS outer PFS, `\x7FCNT`, metadata signature, and `\x7FFIH` finalization for all three inner codecs: `Kraken` (`nwonly`), `Zlib`, and raw `None`.

### Inner PFS image

- Lays out a prepared folder into a plaintext inner PFS image that reads back byte-for-byte. The superblock version is always 2 (PS5).
- Supports AES-XTS encryption over 0x1000-byte sectors using SHA3-256 EKPFS derivation. Tweak and data keys are derived from EKPFS plus the image header seed. The header block remains plaintext, and encrypted images decrypt byte-for-byte.
- Supports optional PFSC compression for `pfs_image.dat`. Compressed images are smaller when possible, carry the compressed flag, and decompress to a valid inner PFS. Incompressible images fall back to the raw wrapper.
- Supports zlib PFSC for installable-package inner images.
- Supports Kraken PFSC v3 for `nwonly` inner images through `ProsperoInnerCompression.Kraken`. The public facade is `LibProsperoPkg.PFS.Compression.ProsperoCompressedPfsImage` with pack, unpack, format-check, and validation helpers.
- `ProsperoPkgBuilder` selects the inner codec through `ProsperoInnerCompression` (`None`, `Zlib`, `Kraken`). The older `CompressInnerImage` boolean still maps to `Zlib`. `BuildInnerImage(..., InnerImageForm.KrakenCompressed)` stores `pfs_image.dat` as a self-describing PFSC v3 file inside the outer PFS.
- Before using a Kraken-compressed inner image, the builder validates an in-process round-trip with `KrakenDecoder`. If compression does not shrink the image or validation fails, it falls back to a raw wrapper.
- A real loose-source-folder build compressed the Kraken inner image to `0x80000` versus `0x160000` raw, confirming the codec is active in the package build path.

### Outer PFS encryption and signing

- Implements the PS5 finalized-image key schedule for `nwonly`: SHA3-256 EKPFS plus `new_crypt` tweak/data keys over 0x10000-byte sectors numbered by image block. Public API: `PFS.ProsperoPfsKeys.DeriveEkpfs`, `DeriveImageEncryptionKeys`, and `DeriveImageSignKey`.
- Decrypts an outer image to coherent plaintext and re-encrypts it to byte-identical ciphertext across the encrypted blocks.
- Uses AES-128-XTS with one 0x10000-byte block per XTS unit. File-data blocks use the block index as the sector number; signed metadata blocks use the bit-47 sector flag; the superblock block remains plaintext.
- Implements per-block and dinode integrity hashes as `SHA3-256(plaintext block)`. Dinodes store the 32-byte hash and owning block index; the super-root inode stores the same shape for the inode-table block.
- Implements the superblock `icv` as `SHA3-256(superblock[0:0x5a0])` with the 32-byte `icv` field zeroed during the computation.
- Implements the data-first outer-PFS structure generator in `PFS/ProsperoOuterPfsBuilder.cs`. It builds file-data blocks, a plaintext superblock, inode table, super-root directory entries, `\x7fFLT` flat-path table, and `uroot` directory entries.
- The generated plaintext and encrypted output match the 11-block layout byte-for-byte.

### Metadata signing

- Signs package metadata with RSA-3072, PKCS#1 v1.5, and SHA-256.
- Performs EKPFS and PFS key derivation as part of signing.
- Verifies the published key fingerprint and a sign/verify round-trip.

### Finalized debug image and FIH

- Wraps a `\x7FCNT` container into a finalized debug `\x7FFIH` image with signed byte `0x00`.
- Reproduces the structural fields: magic, signed byte, PFS image offset and size, embedded CNT offset and size.
- Produces a reader-round-trippable `FullDebug` image with signed byte `0x00`, PFS image offset `0x10000`, block-aligned PFS image size, and embedded CNT offset inside the file.
- Supports the PS5 data-first finalized layout: FIH header, outer PFS image, plaintext superblock at a non-zero image block, CNT body, and optional install-metadata archive.
- Uses the trailing metadata archive as optional debug install metadata. The debug variant is a plain ZIP with stored entries; the encrypted retail variant is not produced.

### Digests

- Uses `SHA3-256` for finalized-image and CNT digest values listed here.
- Computes the `game-digest` / inner `sblock-digest` as `SHA3-256` of the plaintext outer superblock block at the offset stored in FIH. Implemented, byte-exact.
- Computes `package-digest` as `SHA3-256(CNT[0:0xFE0])` and writes it at `CNT+0xFE0`.
- Computes the CNT-header rollup as `SHA3-256(CNT[off:off+size])`, where `off = BE64(CNT+0x20)` and `size = BE32(CNT+0x1c)`.
- Computes `body-digest` as `SHA3-256(CNT body)` and `fixed-info-digest` as `SHA3-256(FIH block)`.
- Builds the per-entry digest table (entry `0x0001`) as `SHA3-256(entry payload)` for each entry, with the digest table's own slot left all-zero. This covers all 13 entries.
- Computes the CNT GeneralDigests block (entry `0x0080`, `set_digests = 0x10DE`, length `0x1E0`):
    - `content-digest = SHA3-256(CNT[0x40:0x78] || game-digest || major-param(32 zeros))`.
    - `header-digest = SHA3-256(CNT[0:0x40] || CNT[0x400:0x480])`, with `CNT+0x410` forced to the FIH-relative `0x10000` value.
    - `system-digest` and `playgo-digest` as `SHA3-256` of concatenated per-entry digests for the matching CNT entries in ascending id order.
    - `param-digest = SHA3-256(param.json payload)`.
    - `target` as a copy of `game-digest`.
- Computes FIH `0xB0` nested-image-content digest as `SHA3-256` of the uncompressed inner PFS image at its logical size. The CNT build path threads this preimage through finalization, so the FIH value and CNT `pfs_signed_digest` are mutually consistent. The standalone finalization path without an inner image falls back to an outer-image hash.
- Computes `imagedigs.dat` (CNT entry `0x040A`, unnamed) as an `N * 32` byte table, one digest per 64 KiB outer-image block. It is stored as an outer-CNT body entry, not as an inner `sce_sys` file. Each stored 32-byte digest is written in byte-reversed order. The build patches the captured per-block descriptor digests after `WriteImage`.
- All populated digest slots are generated from finished on-disk CNT and image data. A from-scratch build remains internally self-consistent even when its bytes differ from a specific pre-existing package because compressed inner-image bytes can differ.

### sce\_sys files

- Injects `about/right.sprx` into the inner PFS. A `right.sprx` supplied in the source tree is packed verbatim; an embedded debug module is injected only when the source provides none. `ProsperoPkgBuilder.EnsureAboutRightSprx`.
- Reads and produces UCP archives (`trophy2/trophyNN.ucp`, `uds/udsNN.ucp`) through `Content.ProsperoUcp`. The codec parses and rebuilds both archive kinds byte-for-byte, including the SHA-1 integrity digest. Public API covers reading, building from entries, building from a directory, structural validation, digest verification, and digest repair. During a build, `ProsperoPkgBuilder.EnsureUcpArchives` repairs a stale digest on a supplied `.ucp` file but never synthesizes archive contents.
- Validates backend-signed system files before packing them, through `PKG.ProsperoSystemFiles`. `npbind.dat` (532 bytes, magic `0xD294A018`) is checked and its communication id extracted from the TLV chain; `nptitle.dat` (160 bytes, magic `NPTD`) is checked and its title id extracted; `license.dat` / `license.info` require a non-empty payload. Invalid inputs stop the build with a descriptive error.
- Emits `playgo-chunk.dat` (CNT entry `0x1001`), `playgo-hash-table.dat` (`0x2010`), and `playgo-ficm.dat` (`0x2011`) as outer-CNT body entries.
- Builds `playgo-hash-table.dat` as a content-independent constant structure with size `0x38 + n * 8`, where `n = ficmCount / 2`. Implemented, byte-exact.
- Generates `icon0.dds`, `pic0.dds`, `pic1.dds`, and `pic2.dds` next to source icon/picture images as valid BC7 DX10 DDS textures.
- Packs any backend-authored system file supplied under `sce_sys/` whose relative path maps to a known CNT id as an outer-CNT body entry: `license.dat`/`license.info` (`0x0400`/`0x0401`), `nptitle.dat` (`0x0402`), `npbind.dat` (`0x0403`), `selfinfo.dat` (`0x0404`), `origin-deltainfo.dat`/`target-deltainfo.dat` (`0x0408`/`0x0407`), `pubtoolinfo.dat` (`0x1007`), `pronunciation.xml`/`.sig` (`0x1004`/`0x1005`), `changeinfo/changeinfo*.xml` (`0x1260`+), the `keymap_rp/` image set (`0x1600`+), and `trophy/` archives. These files are excluded from the inner PFS and stored verbatim; the library never fabricates them. `CollectMediaEntries` in `ProsperoPkgBuilder`.

### Application type and generated param.json

- Models the application type through `ProsperoApplicationType` (`NotSpecified` = 0, `PaidStandaloneFullApp` = 1, `UpgradableApp` = 2, `DemoApp` = 3, `FreemiumApp` = 4). `ProsperoApplicationTypes` maps each type onto the PS5 `sce_sys/param.json` `applicationDrmType` bucket (`free` / `standard` / `freemium`) and exposes `DisplayName` and a case-insensitive `Parse`.
- When the builder generates a minimal `param.json` (source folder has none), `ProsperoBuildOptions.ApplicationType` selects the emitted `applicationDrmType`; `ApplicationDrmType` and `ContentBadgeType` allow explicit overrides. An existing `sce_sys/param.json` is always used verbatim. The `pfsimage.xml` `<application-type>` mirrors the resolved `applicationDrmType`.

### SELF container

- Parses the SELF (Signed ELF) container through `Content.ProsperoFself`: header, segment table, embedded ELF header and program headers, and the extended-info block (authority id, program type, app and firmware version, digest).
- Generates a fake-self from any 64-bit ELF with `MakeFself`. A digest/data segment pair is emitted for each program header whose file size is non-zero and whose type is `PT_LOAD`, module-data (`0x61000000`), relro (`0x61000010`), or comment (`0x6FFFFF00`), in program-header index order. Header size, metadata size, segment layout, and 16-byte data padding reproduce the source module's field layout.
- Sets the extended-info digest to `SHA-256` of the input ELF and derives the authority id and program type from the ELF type and the byte at file offset `0x3f00`. Digest and signature slots on the fake path are zero-filled.
- Round-trips through the container parser: the type-based segment selection reproduces each module's content-segment set, and every data segment matches the source program-header payload.
- `IsSelf`, `IsElf`, `Parse`, `Validate`, and `MakeFself` form the public API. Package builds continue to embed a fixed `right.sprx` asset when the source provides none; the generator is a standalone capability for arbitrary ELF input.
- The build pipeline can fake-sign the source tree before packing, producing an installable fake package (fPKG). `ProsperoBuildOptions.FakeSignSelfModules` converts every raw 64-bit ELF module in the source folder (`eboot.bin` and `*.elf` / `*.prx` / `*.sprx`) to a debug fake-self through `MakeFself`, driven by an optional `FselfOptions` (app/firmware version, authority-id override). Files that are already SELF are left untouched. The conversion is non-destructive: the original module bytes are saved and restored after packing (in a `finally` block), so the source tree is unchanged when the build finishes or throws. `ProsperoPackageBuilder.PrepareFakeSelfModules` / `RestoreFakeSelfModules`.

### SELF authentication-info sidecar

- Parses the SELF authentication-info sidecar (`*.auth_info`) through `Content.ProsperoSelfAuthInfo`: a fixed 0x88-byte record holding the program authority id (`paid`, offset `0x00`), four 64-bit capability words (`0x08`), four 64-bit attribute words (`0x28`), and a 0x40-byte reserved tail (`0x48`), all little-endian. This is the on-disk form of the record that the privileged auth-info query fills at runtime; it is separate from the authority id in the SELF extended-info block.
- `Parse` / `Read` / `ReadFile` decode a record and reject any buffer shorter than 0x88. `Paid` / `AuthorityId`, `Capabilities`, `Attributes`, and `Reserved` expose the decoded fields. `Category` (with `IsFakeAuthority` / `IsGenuineAuthority` / `IsPrivilegedSystem`) reads the top-byte category (`0x31` fake, `0x45` genuine, `0x48` privileged) consistent with the authority-id model.
- `Create(paid, capabilities, attributes, reserved)` builds a record from supplied material, zero-extending short inputs; `ToBytes` / `Write` / `WriteFile` serialize back to the 0x88-byte form. Grant words are copied verbatim — the builder never fabricates capability or attribute bits.
- Every sidecar record round-trips byte-identical, and a record rebuilt from decoded fields via `Create` reproduces the original bytes.

### Keystone

- Reproduces the 96-byte `sce_sys/keystone` byte-for-byte from the passcode for version 2 and version 3.
- Uses deterministic chained HMAC-SHA256: `KeyBlock1 = HMAC-SHA256(seed1, passcode_ascii)` at `0x20`, then `KeyBlock2 = HMAC-SHA256(seed2, keystone[0x00:0x40])` at `0x40`, with seed pairs selected by version.
- The version-3 seed pair differs from the version-2 seed pair.

### PlayGo

- Generates PlayGo and about-file outputs used by package builds.
- Builds `playgo-chunk.crc` as CRC-32C (Castagnoli), reflected polynomial `0x82F63B78`, init/xorout `0xFFFFFFFF`, over each 64 KiB block of the finalized image from offset 0. Each checksum is serialized as little-endian `uint32` in block order. The trailing partial block containing the metadata archive and CRC file is excluded, avoiding self-dependency. Implemented by `ProsperoCrc32C` and `ProsperoPlayGo.BuildChunkCrc`.

### NAPS streaming and Kraken inner compression

- Implements `ProsperoNapsLayout` as a parser and byte-exact serializer for `naps_pkg_layout.dat`.
- The layout serializer round-trips a 544-byte record: 533 bytes of section content plus 11 trailing zero pad bytes.
- Implements the 16-byte layout header bit packing: file count, compression type, key count, shuffle-pattern count, uncompressed-block count, outer-block count, and compressed-block-info count.
- Implements the section order and strides: outer block digest (8 bytes), shuffle pattern (8 bytes), uncompressed offset by file index (6 bytes), compressed-info offset by uncompressed-block index (10 bytes), and compressed-block info (9 bytes).
- Implements both 9-byte compressed-block-info record formats and all bit offsets used by the 45-record layout.
- `BuildLayout` defaults to 16-byte alignment.
- Data-dependent NAPS record value generation is only self-consistent for the library's own inner-image compressor output. Byte-identical reproduction of a specific package requires byte-identical Kraken-compressed block sizes.
- Implements a Kraken encoder and `KrakenDecoder` under `PFS/Compression/Oodle`, plus `ProsperoCompressedPfsFileWriter` and `ProsperoCompressedPfsFile` for the PFSC container.
- `ProsperoCompressedPfsFileWriter.WriteCompressed(payload)` output is accepted by a conformant decoder and round-trips byte-for-byte for the covered cases: single chunk, multi-block payloads over 256 KiB, the exact 0x40000 boundary, two internal chunks per block with cross-chunk back-matches, and stored fallback for incompressible chunks.
- `ProsperoCompressedPfsFile.Parse(pfs).Decompress()` reconstructs the original payload byte-for-byte in process for the same cases.
- The encoder implements the excess mode for single long matches, including the control byte high bit and forward excess substream. Periodic-tile cases are byte-identical to the expected output, while chunks with multiple over-long matches split them into valid shorter matches.
- The encoder enforces the newLZ rule that a match may not start in the last 16 bytes of a chunk. It caps match starts at `chunkEnd - 16`, flushes the remainder as trailing literals, and falls back to stored chunks if needed.
- Huffman entropy arrays are implemented and enabled by default through `KrakenHuffmanArrayEncoder`. The literal, command, length, and offset streams are each Huffman-coded as type-2 arrays with the internal three-stream split, and fall back to raw when the Huffman form is not smaller. The offset array is written in single-table offset mode.
- `KrakenDecoder` reads raw and Huffman-coded literal/command/offset/length arrays, both code-length encodings, the 3-stream split, excess framing, both literal models, multi-chunk and multi-block payloads, and stored fallback. It decodes the embedded verification vectors and checks SHA3-256 of the decoded payloads.
- Kraken `nwonly` inner compression is implemented and produces valid output that a conformant decoder accepts. It does not bit-match the original compressed bytes at compression level 7. Therefore a from-scratch package is internally self-consistent, but it will not bit-match a specific pre-existing package when downstream bytes depend on exact compressed block sizes.

### Reader and writer support

- `ProsperoPkgReader` detects both `\x7FCNT` and `\x7FFIH`, resolves embedded CNT data, and reports finalized debug images.
- `ProsperoPkgReader` reads the finalized-image format-version field (FIH offset `0x06`, little-endian) and exposes it as `ProsperoFihHeader.FormatVersion`, with `IsSupportedFormatVersion` testing the value the mount path requires (`3`).
- `ProsperoCntWriter`, `ProsperoPkgBuilder`, `ProsperoFihBuilder`, and related builders write the package structures described above.
- `ProsperoSiArchive` generates the debug install-metadata ZIP container with stored entries, member paths, `playgo-chunk.dat`, structural `pfsimage.xml` fields, and `playgo-chunk.crc`.
- The SI segment (the trailing `sce_suppl` ZIP) is emitted automatically by the `nwonly` build. `ProsperoPkgBuilder` captures the reproducible `pfsimage.xml` options, the CNT `playgo-chunk.dat`, and the block-aligned inner-image size during the CNT build; `ProsperoPackageBuilder` then passes them to `ProsperoFihBuilder.BuildFromCnt` through an `siArchiveFactory` that calls `ProsperoSiArchive.BuildDebugSiSegment` on the finalized mount image. The produced segment carries `pfsimage.xml` (with the build's own self-consistent digests, entries and geometry), the four `naps_meta_300/301/302/308.dat` records (`R = alignUp(pfs_image.dat) - 0x10000`, captured at build time), the copied `playgo-chunk.dat`, and a reproducible `config/<content-id>/playgo-chunk.crc` (CRC-32C). The keyed `naps_meta_18.dat` metric blob is omitted (never fabricated).
- `ProsperoSiArchive.BuildPfsImageXml` reproduces the descriptor structure through `<config>`, `<digests>` framing, `<params>`, `<container>`, `<mount-image>`, and `<entries>`. It includes derived long name, version constants, container geometry, extended mount-image fields, the `pfs-image-seed` block, and CNT entries. Keyed digest rows that are not supplied remain zero placeholders with warnings.
- `BuildPfsImageXml` also emits the deep introspection trees `<chunkinfo>`, `<pfs-image>` (outer PFS), and `<nested-image>` (inner PFS). `ProsperoPkgBuilder` captures the outer and inner inode layouts and the chunk geometry during the CNT build (`ProsperoPfsBuilder.CaptureImageTree`) and passes them into the SI options. The walk reflects only inodes actually materialized into each image: inner `sce_sys` files that are packed as outer CNT entries (for example `icon0.png`) receive no inner inode and are correctly excluded from the `<nested-image>` tree.
- The GP5 project model is parsed and emitted for both root-directory-walked and flat files/folders layouts.

### License (rif)

- Reads, writes, and creates the per-title license file (`license/rif`) through `License.ProsperoRif`. Each record is a fixed `0x400`-byte structure with a big-endian header (magic `RIF\0`, version `0x0002`, flags, the `QPaC` format tag, expiry, a 36-byte content id, an 8-byte format descriptor, an entry-count field) and a 448-byte encrypted key blob at offset `0x240`. See `Reversed/rif-format.md` for the decoded layout.
- `Parse` / `Read` decode a single record; `ReadAll` decodes a multi-title file (one record per sub-title) and `WriteAll` re-emits it. `ToBytes` / `Write` serialize a record, and `Create` builds a structural record for a content id, copying a supplied 448-byte key blob verbatim or leaving it zero.
- Exposes `ContentId`, `TitleId` (parsed from the content id), `Expiry` / `IsNonExpiring`, `HasKeyBlob`, and a structural `Validate`.
- Single-title records and multi-title files parse, validate, and round-trip through `ToBytes` byte-for-byte.
- The 448-byte key blob is encrypted with per-console material and cannot be produced off-console, so `Create` covers the fake/debug path or templating from an existing blob; an existing entitlement blob is copied verbatim, never synthesized.
- `ProsperoRif.ServiceLabel` exposes the per-record service token — the content-id prefix before the first `-` — the value the console verify path reports as each record's `ServiceID`.

### Content key and multi-content license set

- `License.ProsperoEntitlementKey` models the 128-bit content key (`entitlement_key`) that the builder accepts as an alternative to a passcode. It carries the 16-byte value with hex parse/format (`ParseHex` / `ToHex`, optional `0x` prefix), a zero check, and `Validate`. It is a validated carrier for supplied material and never derives or forges a license key body. See `Reversed/retail-drm-material.md`.
- `ProsperoEntitlementKey.ResolveMode(passcode, entitlementKey, out mode, out error)` reproduces the builder's mutual-exclusivity rule: exactly one of a 32-character passcode or a content key must be supplied. Supplying both is rejected (`entitlement_key must not be specified when a passcode is used`), supplying neither is rejected, and a wrong-length passcode is rejected. The result selects the fake/debug schedule (passcode) or the finalized/keyed schedule (content key).
- `License.ProsperoRifSet` models a whole license file as the ordered set of `0x400` records (one per sub-title, concatenated with no container header) and reproduces the console verify-path report: the record count (`n_rif`), the per-record `ServiceID`, the distinct service labels / title ids / content ids, and the whole-file-size rule (a positive multiple of `0x400`, guarded by `unexpected ac_rif_file_size`). `ReadFile` / `Read` decode a file or buffer, `FromRecords` wraps an existing list, and `Validate` enforces a non-empty count, the size rule, and per-record validity.
- `Summarize(appTitleId)` produces the compact `ServiceID / rif_size(exp/act) / has_app / n_ac / n_rif` projection. Because the app-versus-additional-content split (`n_ac`) is not derivable from RIF fixed fields alone, the caller supplies the application title id (from `app.json` / `param.json`); records matching it count as the app and the remainder as additional content.
- Single-title files report `n_rif=1` / `has_app=true` / `n_ac=0`, and a three-record multi-title file reports `n_rif=3` / `has_app=true` / `n_ac=2` at exactly `3 × 0x400 = 3072` bytes.

### Disc-backup packages (`app_0.pkg` / `app_sc.pkg`)

- Opens a split disc-backup package described by an `app.json` manifest through `DiscBackup.ProsperoDiscBackup`. `DiscBackup.ProsperoDiscBackupManifest` parses the manifest (`numberOfSplitFiles`, `originalFileSize`, `packageDigest`, the ordered `pieces[]` with `fileOffset` / `fileSize` / `url`, and the PlayGo chunk-CRC pointer). See `Reversed/disc-backup-format.md` for the decoded structure.
- Reassembles the pieces on the fly with `DiscBackup.ProsperoConcatStream`, a read-only seekable stream that concatenates the piece windows without materializing a temporary file. `OpenPackageStream` presents the whole package as one stream; `ReassembleTo` writes it to a file or stream.
- Reads the reassembled finalized (`\x7FFIH`) image and its embedded `\x7FCNT` through the existing `ProsperoPkgReader` over the concat stream, including entries that straddle the split boundary. `FindImageKeyEntry` locates the EEKPFS key entry (id `0x20`), and `ExtractEntry` / `ExtractEntryBytes` copy any entry's stored bytes (encrypted entries stay encrypted).
- Verifies integrity three ways: `VerifyPackageDigest` recomputes the reassembled `SHA-256` and compares it to `packageDigest`; `VerifyChunkCrcHash` checks the `SHA-256` of the chunk-CRC file against `playgoChunkCrcHashValue`; `VerifyChunkCrcs` recomputes every 64 KiB CRC-32C and reports the first mismatch. `DiscBackup.ProsperoPlaygoChunkCrc` parses the headerless little-endian CRC-32C array (one value per 64 KiB chunk).
- On split disc-backup packages, the reassembled length equals `originalFileSize`, the image begins with `\x7FFIH`, the embedded `\x7FCNT` is found across the piece split, the EEKPFS key entry is present and extractable, the chunk-CRC file hash matches the manifest, the chunk count equals `ceil(originalFileSize / 64 KiB)`, and recomputed chunk CRC-32C values match the table.

### Acceptance-gate validation

- `PKG.ProsperoPkgValidator` checks a parsed package against the structural preconditions the console mount path enforces (see `Reversed/acceptance-gate.md`). It returns a `ProsperoAcceptanceReport` of named `Pass` / `Warning` / `Fail` checks with an `Accepted` roll-up and a `HasWarnings` flag.
- Checks: a finalized (`\x7FFIH`) image is present (a bare `\x7FCNT` is not mountable), the FIH format version is `3` (the value the key-derivation path requires), the shared PFS image begins at `0x10000` and is non-empty, the embedded `\x7FCNT` parses, the EEKPFS key entry (`0x20`) is present, and the content id is present and — when an expected value such as a `rif` or `param.json` content id is supplied — matches.
- This validates the structural gate only; it does not reproduce the console's cryptographic checks. Reports `Accepted` for split disc-backup packages, with the embedded content id matching the corresponding `rif` content id.
- The report also includes a `Content-info` line projected through `NpDrm.ProsperoNpDrmContentInfo` (see below): the derived title id, drm/content type, content flags, patch kind, and nested-image flag.

### NpDrm content-info

- `NpDrm.ProsperoNpDrmContentInfo` projects a package header into the compact classification the mount path consumes before it accepts an image (see `Reversed/npdrm-content-info.md`). It exposes the container offset, content id, derived title id, `DrmType` (`0x70`), `ContentType` (`0x74`), `ContentFlags` (`0x78`), `IsNestedImage`, `IsFinalized`, and the decoded `PatchKind` (`None` / `First` / `Subsequent` / `Delta` / `Cumulative`) with an `IsPatch` roll-up.
- `Read(path)` / `Read(stream)` parse and project in one call; `FromPackage` projects an already-parsed `ProsperoPkg`. `ResolveContainerOffset` mirrors the console's container-offset switch on the raw magic and version (`\x7FCNT` → `0`, `\x7FLIH` → u64 `0x30`, `\x7FFIH` → u64 `0x58`), and `DeriveTitleId` extracts the title id from a content id.
- `ProsperoPkgReader` now reads `ContentFlags` (`0x78`, big-endian) into `ProsperoPkgHeader`, and `DiscBackup.ProsperoDiscBackup.ReadContentInfo` projects the content-info from the reassembled image (the CNT metadata is carried by the tail piece, so this uses the full reassembled stream).
- For every reassembled image the projected content id and title id match the manifest, the container offset equals the embedded-CNT offset, `IsNestedImage` is set, and the patch kind is decoded from the content flags (base images report `None`; images carrying the subsequent-patch flag report `Subsequent`).

### Package extraction

- `PKG.ProsperoPackageExtractor` extracts the application filesystem from a finalized image end to end (see `Reversed/pkg-decryption.md`). It reads the FIH header for the outer-PFS offset/size and signed byte, opens the AES-XTS outer PFS, locates the nested `pfs_image.dat`, PFSC-decodes it to the inner image, opens the inner PFS, and writes every file with per-file PFSC decompression, confining all writes inside the output directory.
- `PKG.ProsperoExtractionKey` models the key material: `FromPasscode(passcode)` / `FromPasscode(contentId, passcode)` derive the outer EKPFS from public inputs (it materializes both the SHA-256 and SHA3-256 candidates and the extractor auto-selects whichever opens the outer PFS), `FromEkpfs(bytes)` takes a supplied 32-byte image key directly, and `None` attempts a plaintext outer PFS. It never derives or forges a retail image key.
- `PFS.ProsperoPfsExtractor` is the reusable single-image half: given an already-opened (and, if encrypted, decrypted) `ProsperoPfsReader`, it walks the `uroot` tree and writes the files. The package extractor composes two of these around the middle PFSC decode.
- `Inspect(path)` reports the package type, retail flag, outer-PFS offset/size, whether the outer PFS is encrypted, and whether a supplied key is required — without needing any key. `ListFiles(path, key)` enumerates the inner filesystem without writing. `Extract(...)` returns a manifest (package type, retail flag, content id, EKPFS fingerprint, outer file count, inner-image-compressed flag, and the written entries).
- Verified by a byte-identical round trip: a debug image built from a known folder and extracted back produces SHA-256-identical files, and the auto-selected EKPFS fingerprint matches the fingerprint the build pipeline reports for the same content id + passcode.
- A finalized retail image (signed byte `0x80`) encrypts the whole outer PFS including block 0, so its superblock is unreadable without the console-provisioned image key. `Inspect` reports `IsRetail = true` / `RequiresSuppliedKey = true`, and `Extract` throws a clear message naming the supplied-key requirement rather than returning a fabricated result. Confirmed on a finalized retail `app_0.pkg`.

## Known gaps / not implemented

- Retail finalized images with signed byte `0x80` are not implemented. They require console-side finalization material that the library does not have.
- Retail install-metadata archives are not implemented. The retail variant is encrypted and is not produced by the library.
- On-console installation acceptance is not guaranteed. Library code verifies structure and round-tripping; acceptance depends on console mode and firmware.
- The `rif` key blob (offset `0x240`, 448 bytes) is encrypted with per-console material and cannot be produced off-console. `ProsperoRif.Create` builds a structural record and copies a supplied blob verbatim; it does not derive a retail entitlement blob.
- The finalized/keyed image-key schedule is not reproduced. The content key (`entitlement_key`) is modeled as a validated carrier and the finalize sc encryption is a standard AES-128-CBC pass (reproducible given key and IV), but the step that seals the content key into the 448-byte license key body and the retail image-key unwrap both use per-device material absent from any host binary. `ProsperoEntitlementKey` therefore carries supplied material only and never fabricates a seal.
- The EEKPFS key entry (`0x20`) extracted from a disc-backup package is returned as stored (encrypted). Off-console PFS key derivation from that entry is not implemented; extraction preserves the bytes for inspection only.
- Package extraction of a finalized retail image is console-gated. The outer PFS of a retail image is encrypted at block 0 with the image key delivered through the entitlement/kernel path, which is absent from any host binary and is neither derivable from public inputs nor brute-forceable (AES-128 / RSA-2048 wrap). `ProsperoPackageExtractor` therefore extracts debug/keyed images and any image whose 32-byte image key is supplied, and refuses a retail image without a supplied key with a clear message.
- The full NAPS streaming outer producer is not complete. Remaining pieces include rolling/weak/strong deduplication, block shuffle, per-outer-block encryption/CRC/digest integration, complete `naps_meta_*.dat` generation, full `pfsimage.xml` named-digest population for all package shapes, and final `\x7FFIH` assembly for enforced streaming use.
- NAPS layout record values are not fully generated from arbitrary input. The format parser and serializer are implemented, but values derived from exact compression bookkeeping are only self-consistent for this library's own compressor output.
- `naps_meta_300/301/302/308.dat` (the 48-byte records) are reproduced byte-exact by `ProsperoNapsMeta` from the build's own inner-image size and emitted in the SI segment automatically. The keyed `naps_meta_18.dat` metric blob has no off-console producer: it is accepted as an input and emitted verbatim when supplied, otherwise omitted — never fabricated.
- The `pfsimage.xml` `<chunkinfo>`, `<pfs-image>`, and `<nested-image>` introspection trees are emitted from the build's own captured outer/inner-PFS inode layout, so they are self-consistent snapshots of this library's image rather than byte matches of a specific pre-existing package. The outer superblock `<icv>` is the real captured superblock HMAC and the `<seed>` is all-zero; because this library writes a superblock-first outer PFS while a data-first layout places the superblock last, the reported block indices and metadata offsets differ from a data-first package. The nested `<metadata>` pseudo-element and per-file `poffset` are intentionally omitted (not stably derivable for compressed inner content). These sections live in the supplemental `sce_suppl` ZIP that the console loader does not read, so they do not affect installability.
- Keyed or console-produced `pfsimage.xml` digest members in the install-metadata archive are supplied by the caller or left as placeholders; they are not fabricated.
- Byte-identical reproduction of a specific `nwonly` package remains limited by exact Kraken encoder choices at compression level 7. The generated package is valid and internally consistent, but downstream NAPS layout values and digests that depend on exact compressed bytes can differ.
- Automatic emission of `naps_pkg_layout.dat` for package builds is not complete; the implemented component is the parser and serializer. The file was absent from the `nwonly` packages examined, so the builder does not claim package-emission coverage.

## Summary table

| Capability | Status |
| --- | --- |
| `\\x7FCNT` build | Implemented |
| `\\x7FCNT` / `\\x7FFIH` read | Implemented |
| End-to-end debug package build | Implemented |
| Inner PFS layout | Implemented |
| Inner PFS AES-XTS encryption | Implemented |
| zlib PFSC inner compression | Implemented |
| Kraken PFSC v3 inner compression for `nwonly` | Implemented; valid output, does not bit-match the original level-7 compressed bytes |
| Kraken decoder | Implemented, byte-exact for the covered blocks |
| Kraken Huffman encoder arrays | Implemented |
| PS5 outer-image key derivation | Implemented |
| PS5 outer-image AES-XTS encryption | Implemented, byte-exact |
| PS5 outer-PFS signing hashes and `icv` | Implemented, byte-exact |
| PS5 outer-PFS data-first structure generator | Implemented, byte-exact |
| Metadata signing | Implemented |
| Finalized debug image (`\\x7FFIH`) | Implemented |
| Finalized digest table: `game-digest` / superblock digest | Implemented, byte-exact |
| CNT per-entry, body, fixed-info, param, package, and header-rollup digests | Implemented, byte-exact |
| CNT GeneralDigests block | Implemented, byte-exact and self-consistent |
| FIH `0xB0` nested-image-content digest | Implemented; self-consistent, exact value depends on exact inner compression bytes |
| `imagedigs.dat` CNT entry | Implemented |
| Fake-self generation (`MakeFself`) | Implemented |
| SELF authentication-info sidecar (`ProsperoSelfAuthInfo`: read / validate / build / write `*.auth_info`) | Implemented; byte-exact round-trip, grant words supplied verbatim |
| Fake-sign build option (`FakeSignSelfModules`, fPKG) | Implemented; non-destructive in-place conversion |
| Application type / generated `param.json` app-type | Implemented; `ProsperoApplicationType` maps to `applicationDrmType` |
| Supplied `sce_sys` system files (license, np, self, delta-info, keymap_rp, changeinfo, pronunciation, trophy) | Implemented; packed verbatim as outer CNT entries when present |
| `playgo-chunk.dat`, `playgo-hash-table.dat`, `playgo-ficm.dat` | Implemented |
| UCP archives (`trophy2/*.ucp`, `uds/*.ucp`) | Implemented, byte-exact round-trip and digest |
| `npbind.dat` / `nptitle.dat` structural validation | Implemented; validated and identifiers extracted, packed verbatim |
| `playgo-chunk.crc` | Implemented, byte-exact |
| Debug install-metadata ZIP container | Implemented; caller supplies remaining console-produced members |
| `pfsimage.xml` structural descriptor | Implemented, including `<chunkinfo>`/`<pfs-image>`/`<nested-image>` trees; self-consistent (not byte-identical to a specific pre-existing package), supplied keyed digest rows remain placeholders |
| Keystone (`sce_sys/keystone`) | Implemented, byte-exact from passcode for version 2 and version 3 |
| DDS BC7 texture generation | Implemented |
| GP5 project model | Implemented |
| NAPS layout parser and serializer | Implemented; automatic package emission incomplete |
| NAPS streaming outer producer | Not implemented |
| Retail install-metadata archive | Not implemented |
| Retail finalized image (`0x80`) | Not implemented |
| On-console acceptance guarantee | Not implemented; depends on console mode and firmware |
| License (`rif`) read / write / create | Implemented; validated and byte-exact round-trip for single- and multi-title files |
| Disc-backup open / reassemble (`app_0.pkg` + `app_sc.pkg`) | Implemented; confirmed on split disc-backup packages |
| Disc-backup digest and chunk-CRC verification | Implemented; `SHA-256` package digest, chunk-CRC file hash, and 64 KiB CRC-32C recompute |
| Disc-backup embedded-CNT entry extraction | Implemented; stored bytes copied, encrypted entries stay encrypted |
| FIH format-version read (`ProsperoFihHeader.FormatVersion`) | Implemented |
| NpDrm content-info projection (`ProsperoNpDrmContentInfo`) | Implemented; confirmed on split disc-backup packages |
| Content-flags read (`ProsperoPkgHeader.ContentFlags`, `0x78`) | Implemented |
| Patch-kind classification (`None` / `First` / `Subsequent` / `Delta` / `Cumulative`) | Implemented |
| Acceptance-gate structural validation (`ProsperoPkgValidator`) | Implemented; structural gate only, not console cryptographic checks |
| Content key model (`ProsperoEntitlementKey`) + passcode/entitlement-key mode rule | Implemented; validated carrier for supplied material, never forged |
| Multi-content license set (`ProsperoRifSet`: `n_rif` / `ServiceID` / `has_app` / `n_ac` / size) | Implemented; confirmed on split disc-backup packages |
| Per-record service label (`ProsperoRif.ServiceLabel`) | Implemented |
| Finalized/keyed license key-body seal + retail image-key unwrap | Not implemented; console-gated, supply verbatim |
| Package extraction (debug/keyed image → outer PFS → `pfs_image.dat` PFSC → inner PFS → files) | Implemented; verified byte-identical by build → extract round trip |
| Package extraction key model (`ProsperoExtractionKey`: passcode / supplied EKPFS / none) | Implemented; derives debug EKPFS from public inputs, never forges a retail key |
| Package inspection without a key (`ProsperoPackageExtractor.Inspect`) | Implemented; type / retail flag / outer-PFS offset+size / encrypted / key-required |
| Package extraction of a finalized retail image (block-0 encrypted) | Not implemented; console-gated, refused cleanly unless the image key is supplied |


