# PS5 Package Format — Technical Write-up

This document describes the structure of a PS5 package and the end-to-end
process LibProsperoPkg follows to create one. It is a technical reference for developers working
with the format; the offsets and field names below match the library's own reader, builder and
finalizer.

> Endianness is mixed: the outer container (`\x7FCNT`) header is **big-endian**, while the
> finalized-image (`\x7FFIH`) header fields are **little-endian**. This is called out per section.

---

## 1. Overview

A complete, installable PS5 package is a **finalized image** with the magic `\x7FFIH`. It wraps
a **metadata container** with the magic `\x7FCNT`,
together with a shared, encrypted **PFS** image holding the actual
application files.

At the highest level a finished package is four consecutive segments:

```
┌──────────────────────────────────────────────────────────────┐
│ FIH   header + finalization digest table   (0x00000–0x10000)  │  little-endian
├──────────────────────────────────────────────────────────────┤
│ PFS   shared AES-XTS-encrypted outer PFS image                │
├──────────────────────────────────────────────────────────────┤
│ SC    embedded \x7FCNT metadata container                     │  big-endian header
├──────────────────────────────────────────────────────────────┤
│ SI    install-metadata archive                                │
└──────────────────────────────────────────────────────────────┘
```

The console reports these segments as **FIH / PFS / SC / SI**.

---

## 2. The metadata container (`\x7FCNT`)

The `\x7FCNT` container holds the package metadata: the entry table, the content id, and the
descriptor entries (param.json, icons, PlayGo data, license, digests, keys, …). It is metadata
only — by itself it is **not** an installable package.

### 2.1 Header (big-endian)

| Field | Notes |
|---|---|
| Magic | `0x7F 'C' 'N' 'T'` |
| Flags | Container flags |
| Entry count | Number of records in the entry table |
| Entry-table offset | File offset of the first entry-meta record |
| Body offset / size | Region holding the entry payloads |
| Content ID | 36-character ASCII identifier, stored in a `0x30`-byte field |
| DRM type / content type | Package classification |

The container header region is `0x5A0` bytes.

### 2.2 Entry table

The entry table is an array of fixed-size **`0x20`-byte** records. Each record describes one
entry:

| Field | Notes |
|---|---|
| Id | A well-known entry id (see below) |
| Name-table offset | Offset of the entry's name within the `EntryNames` (`0x0200`) table |
| Flags | Includes the encrypted-entry flag (`0x80000000` in `Flags1`) |
| Data offset / size | Location and length of the entry payload |

Entry names are resolved from the `ENTRY_NAMES` table (entry id `0x0200`).

### 2.3 Well-known entry ids

The subset relevant to inspection and
creation:

| Id | Entry |
|---|---|
| `0x0001` | Digests |
| `0x0010` | Entry keys |
| `0x0020` | Image key |
| `0x0080` | General digests |
| `0x0100` | Metas |
| `0x0200` | Entry names |
| `0x0400` / `0x0401` | License data / license info |
| `0x040A` | `imagedigs.dat` (**unnamed** entry) — `N × 32` outer-block digest table |
| `0x1001` | `playgo-chunk.dat` |
| `0x1200` / `0x1220` / `0x1240` | `icon0.png` / `pic0.png` / `snd0.at9` |
| `0x1280` / `0x12A0` / `0x12C0` / `0x2060` | `icon0.dds` / `pic0.dds` / `pic1.dds` / `pic2.dds` |
| `0x2000` | `param.json` |
| `0x2010` / `0x2011` | `playgo-hash-table.dat` / `playgo-ficm.dat` |

> A `--oformat nwonly` debug CNT carries 13 entries:
> `0x0001 0x0010 0x0020 0x0080 0x0100 0x0200 0x040A 0x1001 0x1200 0x1280 0x2000 0x2010 0x2011`
> (no license entries). `imagedigs.dat` (`0x040A`) is the only **unnamed** body entry.

---

## 3. The PFS image

The application's files live inside a **PFS** image. There are two
nested images:

- The **inner image** holds the actual file tree (`uroot`): `sce_sys/`, `eboot.bin`, data, etc.
- The **outer image** wraps the inner image (optionally compressed) plus the metadata, and is
  the segment that the finalized image references.

### 3.1 Layout

The inner PFS image is laid out from the prepared folder:

1. The folder tree is walked and turned into PFS directory and file inodes.
2. Inode tables, the directory structure and the data region are written.
3. A superblock records the image geometry and the format version (always 2 for PS5).

The resulting plaintext image reads back byte-for-byte through the PFS reader.

### 3.2 Merkle integrity

PFS protects its data with a **SHA-256 Merkle** hash tree: each block's hash rolls up through
parent levels to a root, so any tampering is detectable. This is built as part of the image.

### 3.3 Encryption (AES-XTS)

The image is encrypted with **AES-XTS** over **`0x1000`-byte (4 KiB) sectors**:

1. The **EKPFS** (encrypted-key PFS) roots the key schedule. For the **inner PFS image**, the
   EKPFS is derived from the content id and passcode using SHA3-256. For the **shared outer
   finalized-image PFS**, the EKPFS is the `pfs-image-key` stored in the package metadata (it
   is *not* the passcode-derived inner key) and is consumed directly.
2. From the EKPFS and the 16-byte superblock **seed**, the per-image key material (tweak key,
   data key, sign key) is derived using the SHA3-256-based `new_crypt` key schedule.

   The XTS sector number is the **image-relative** sector index (the first encrypted sector is
   tweak 0), with a `0x1000` sector size.
3. Every sector except the plaintext header block is encrypted; the encryption flag and the
   seed are stamped in the superblock.

`Util/Crypto.cs` (`PfsGenCryptoKey`/`PfsGenEncKey`/`PfsGenSignKey`) implements this
schedule.

The header (block 0) stays plaintext because the kernel needs to read the superblock before it
has the keys. The encrypted image decrypts back byte-for-byte.

### 3.4 Compression (PFSC)

The inner image can optionally be stored as a **PFSC** container — a block-compressed form that
substantially reduces the dominant size driver (`pfs_image.dat`). Each block is compressed
independently; incompressible blocks (and incompressible images as a whole) fall back to a raw
wrapper. A PFSC image decompresses back to a valid, mountable inner PFS.

---

## 4. Metadata signing

The package metadata is signed with **RSA-3072, PKCS#1 v1.5, SHA-256**. The same key material
drives the EKPFS/PFS key derivation used for the inner-image encryption. The signer verifies the
published key fingerprint and performs a sign/verify round-trip before use.

---

## 5. The finalized image (`\x7FFIH`)

Finalization wraps the `\x7FCNT` container and the shared PFS image into the installable
`\x7FFIH` image.

### 5.1 Header (little-endian)

| Offset | Field | Notes |
|---|---|---|
| `0x00` | Magic | `0x7F 'F' 'I' 'H'` |
| `0x05` | Signed byte | `0x00` = debug, `0x80` = retail/submitted |
| `0x10` | PFS image offset | u64; always `0x10000` |
| `0x18` | PFS image size | u64 |
| `0x58` | Embedded CNT (SC) offset | u64 |
| `0xA0` | Embedded CNT (SC) size | u64 |

The header + digest-table region is always **`0x10000`** bytes, and the PFS segment always
begins at `0x10000`. The FIH offset (`0`) and FIH size (`0x10000`) are constant; only the
segment sizes vary.

### 5.2 The signed byte

The single byte at offset `0x05` is what distinguishes a **debug** finalized image (`0x00`)
from a **retail/submitted** one (`0x80`). A console in debug mode relaxes finalized-image
verification and accepts the debug variant.

### 5.3 Finalization digest table

The remainder of the FIH region holds the finalized digests. The `game-digest` (`0x30`/`0x70`/`0xD0`)
is `SHA3-256` of the plaintext outer superblock, and the embedded CNT carries the package-digest
self-seal, the CNT-header rollup, the per-entry digest table and the GeneralDigests block
(content/header/system/param/playgo/target). LibProsperoPkg reproduces **all of these byte-exact**
(verified against four real debug packages). The FIH `0xB0` slot — `SHA3-256` of the **uncompressed
inner PFS image** at its plain size — is implemented and threaded through
the build path; like every digest its value bit-matches a specific reference package only once the inner
Kraken encoder is byte-identical, but the formula is exact and gated self-consistent.
See [implementation-status.md](implementation-status.md).

### 5.4 The SI segment

The image ends with a trailing **STORED ZIP** archive of install-time metadata. Verified
member order against reference debug packages (every member uncompressed / `STORED`):

| Path | Notes |
|---|---|
| `common/etc/naps_meta_18.dat` | per-package metric blob; size varies (e.g. 3440 / 7936 B) |
| `common/etc/naps_meta_300.dat` | 48 B |
| `common/etc/naps_meta_301.dat` | 48 B, byte-identical to `_300` |
| `common/etc/naps_meta_302.dat` | 48 B, byte-identical to `_300` |
| `common/etc/naps_meta_308.dat` | 48 B, byte-identical to `_300` |
| `common/etc/pfsimage.xml` | machine-readable image descriptor (see below) |
| `common/etc/playgo-chunk.dat` | 416 B; identical to the `sce_sys` copy |
| `config/<content-id>/playgo-chunk.crc` | CRC-32C per 64 KiB block of the mount image |

`LibProsperoPkg.PKG.ProsperoSiArchive` builds this archive (`BuildMembers` → `WriteZip`); the
order, paths, `STORED` framing and `naps_meta_30x` identity are reproduced exactly. The
`playgo-chunk.crc` is recomputed from the finalized mount image.

`pfsimage.xml` is reproduced faithfully through its `<config>`, `<digests>`, `<params>`,
`<container>`, `<mount-image>` and `<entries>` sections — including the toolchain constants
`<version-date>0x20200722</version-date>` / `<version-hash>0x01fe52e9</version-hash>`, the derived
`<longname>`, the full container/mount geometry and the CNT entry table. The keyed `*-digest`
fields are console-finalization products and are emitted as zero placeholders (each reported as a
warning), and the deep `<chunkinfo>`/`<pfs-image>`/`<nested-image>` introspection trees (which
require the full inner-PFS inode walk) are not implemented. The `naps_meta_*` blobs are supplied
verbatim — never fabricated. See [implementation-status.md](implementation-status.md).

---

## 6. End-to-end creation process

Putting the pieces together, the library builds a package as follows:

1. **Validate inputs** — content id (36 chars), title id, and passcode (32 chars). Optionally generate a minimal `param.json` if the source folder
   lacks one.
2. **Generate auxiliary `sce_sys` files** — `about/right.sprx`, `playgo-chunk.dat`,
   `playgo-manifest.xml`, and the BC7 DDS siblings of the icon/picture images — so the file set
   is complete.
3. **Lay out the inner PFS** — walk the folder into a plaintext inner-PFS image with the SHA-256
   Merkle tree and the correct (PS5) superblock version.
4. **Render the inner image** — leave it plaintext, **AES-XTS-encrypt** it with the EKPFS
   (the `pfs-image-key`; §3.3), or **PFSC-compress** it.
5. **Build the outer PFS + `\x7FCNT`** — assemble the metadata container, the entry table and
   the entry-name table around the inner image.
6. **Sign the metadata** — RSA-3072 / SHA-256.
7. **Finalize** — wrap the container and shared PFS image into a `\x7FFIH` **debug** image
   (signed byte `0x00`), writing the FIH header and the segment offsets/sizes.

The result round-trips through `ProsperoPkgReader` as a full debug image whose embedded
container and shared PFS image are intact.

---

## 7. Glossary

| Term | Meaning |
|---|---|
| **CNT** | The `\x7FCNT` metadata container. |
| **FIH** | The `\x7FFIH` finalized image — the installable package wrapper. |
| **PFS** | Package file system — the encrypted, integrity-protected image holding the files. |
| **PFSC** | The block-compressed form of a PFS image. |
| **EKPFS** | The encrypted-key PFS, the root of the PFS key schedule. The shared outer image uses the tool's `pfs-image-key`; inner images use a passcode/content-id-derived key. |
| **AES-XTS** | The sector-based block-cipher mode used to encrypt the PFS image. |
| **Merkle tree** | The SHA-256 hash tree that protects PFS block integrity. |
| **SC / SI** | The embedded metadata container segment and the trailing install-metadata archive within a finalized image. |

---

## 8. `sce_sys` / `sce_suppl` metadata files

These auxiliary files fall into two groups. `imagedigs.dat` and the PlayGo files (`playgo-chunk.dat`,
`playgo-hash-table.dat`, `playgo-ficm.dat`) are **outer-CNT body entries** — they live in the `\x7FCNT`
container metadata, NOT inside the inner PFS image. (An extractor presents them under a `sce_sys/` view,
which historically caused them to be modelled as inner-PFS files; they are not.) The `sce_suppl/common/etc`
SI archive (`naps_meta_*`, the second `playgo-chunk.dat` copy, `pfsimage.xml`) is a separate supplemental
stream. CNT-entry placement for each file is described below.

| File | Location | Description |
|---|---|---|
| `imagedigs.dat` | CNT entry `0x040A` (unnamed) | `N × 32` byte digest table, one entry per 64 KiB **outer** image block (e.g. 11 blocks = 352 B). **Now computed end-to-end:** the outer-PFS builder captures the per-block descriptor digests of the finalized outer image (`CaptureImageDigests`), and the builder patches them into the entry after `WriteImage`. Each stored 32-byte digest is written in reverse byte order. Because it digests the outer image but does **not** live in it, there is no self-reference / fixpoint — the build is single-pass and the entry size (`outerBlocks × 32`) is known up front. Self-consistent with this encoder's actual block content (byte-identity to a specific reference package is still gated on Kraken byte-identity). |
| `playgo-chunk.dat` | CNT entry `0x1001` **and** `sce_suppl/common/etc` (SI) | 416-byte PlayGo chunk descriptor. The two copies are **byte-identical**. Generated by `PlayGo.ProsperoPlayGo.BuildChunkDat`. |
| `playgo-hash-table.dat` | CNT entry `0x2010` | PlayGo file hash table; `0x38 + n × 8` bytes (n = `ficmCount / 2`). A content-independent constant structure (version=1, `\x7FFLT` magic at `0x18`, fixed 16-byte prefix + `n × 8` constant table entries). `PlayGo.ProsperoPlayGo.BuildHashTable`. |
| `playgo-ficm.dat` | CNT entry `0x2011` | PlayGo file-in-chunk map; 16-byte header + `fileCount` bytes. `PlayGo.ProsperoPlayGo.BuildFicm`. |
| `playgo-chunk.crc` | `config/<content-id>/` (SI) | CRC-32C over each 64 KiB block of the finalized mount image. `ProsperoPlayGo.BuildChunkCrc`. |
| `naps_meta_18.dat` | `sce_suppl/common/etc` (SI) | Per-package NAPS metric blob; size varies per package (e.g. 3440 / 7936 B). Supplied verbatim. |
| `naps_meta_300/301/302/308.dat` | `sce_suppl/common/etc` (SI) | 48-byte NAPS records; `301/302/308` are byte-identical to `300`. Reproduced byte-exact (`ProsperoNapsMeta`). |
| `pfsimage.xml` | `sce_suppl/common/etc` (SI) | Machine-readable image descriptor; reproduced through `<entries>` (see §5.4). |

> **`naps_pkg_layout.dat` is NOT present in `--oformat nwonly` debug packages.** LibProsperoPkg includes a round-trip serializer/parser (`ProsperoNapsLayout`) for completeness but never fabricates the file.

> **Reproducibility boundary.** The keyed digests (`content/game/header/system/param/package/body/sblock/fixed-info` digests, the superblock `icv`, the FIH finalization table) require console finalization material the library does not have. LibProsperoPkg computes the SHA3-256 CNT-region and entry digests and derives `imagedigs.dat` from its own finalized outer image; the remaining console-only finalization fields are emitted as structurally valid placeholders (reported as warnings). Byte-identity to a specific reference `.pkg` additionally requires the Kraken inner encoder to produce identical compressed output.
