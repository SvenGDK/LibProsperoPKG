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
- Supports Oodle Kraken PFSC v3 for `nwonly` inner images through `ProsperoInnerCompression.Kraken`. The public facade is `LibProsperoPkg.PFS.Compression.ProsperoCompressedPfsImage` with pack, unpack, format-check, and validation helpers.
- `ProsperoPkgBuilder` selects the inner codec through `ProsperoInnerCompression` (`None`, `Zlib`, `Kraken`). The older `CompressInnerImage` boolean still maps to `Zlib`. `BuildInnerImage(..., InnerImageForm.KrakenCompressed)` stores `pfs_image.dat` as a self-describing PFSC v3 file inside the outer PFS.
- Before using a Kraken-compressed inner image, the builder validates an in-process round-trip with `KrakenDecoder`. If compression does not shrink the image or validation fails, it falls back to a raw wrapper.
- A real loose-source-folder build compressed the Kraken inner image to `0x80000` versus `0x160000` raw, confirming the codec is active in the package build path.

### Outer PFS encryption and signing

- Implements the PS5 finalized-image key schedule for `nwonly`: SHA3-256 EKPFS plus `new_crypt` tweak/data keys over 0x10000-byte sectors numbered by image block. Public API: `PFS.ProsperoPfsKeys.DeriveEkpfs`, `DeriveImageEncryptionKeys`, and `DeriveImageSignKey`.
- Decrypts a reference outer image to coherent plaintext and re-encrypts it to byte-identical ciphertext across the encrypted blocks.
- Uses AES-128-XTS with one 0x10000-byte block per XTS unit. File-data blocks use the block index as the sector number; signed metadata blocks use the bit-47 sector flag; the superblock block remains plaintext.
- Implements per-block and dinode integrity hashes as `SHA3-256(plaintext block)`. Dinodes store the 32-byte hash and owning block index; the super-root inode stores the same shape for the inode-table block.
- Implements the superblock `icv` as `SHA3-256(superblock[0:0x5a0])` with the 32-byte `icv` field zeroed during the computation.
- Implements the data-first outer-PFS structure generator in `PFS/ProsperoOuterPfsBuilder.cs`. It builds file-data blocks, a plaintext superblock, inode table, super-root directory entries, `\x7fFLT` flat-path table, and `uroot` directory entries.
- The generated plaintext and encrypted output match the tested 11-block reference layout byte-for-byte.

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
- Computes the `game-digest` / inner `sblock-digest` as `SHA3-256` of the plaintext outer superblock block at the offset stored in FIH. Implemented, byte-exact for the tested debug packages.
- Computes `package-digest` as `SHA3-256(CNT[0:0xFE0])` and writes it at `CNT+0xFE0`.
- Computes the CNT-header rollup as `SHA3-256(CNT[off:off+size])`, where `off = BE64(CNT+0x20)` and `size = BE32(CNT+0x1c)`.
- Computes `body-digest` as `SHA3-256(CNT body)` and `fixed-info-digest` as `SHA3-256(FIH block)`.
- Builds the per-entry digest table (entry `0x0001`) as `SHA3-256(entry payload)` for each entry, with the digest table's own slot left all-zero. This covers all 13 entries in the tested samples.
- Computes the CNT GeneralDigests block (entry `0x0080`, `set_digests = 0x10DE`, length `0x1E0`):
    - `content-digest = SHA3-256(CNT[0x40:0x78] || game-digest || major-param(32 zeros))`.
    - `header-digest = SHA3-256(CNT[0:0x40] || CNT[0x400:0x480])`, with `CNT+0x410` forced to the FIH-relative `0x10000` value.
    - `system-digest` and `playgo-digest` as `SHA3-256` of concatenated per-entry digests for the matching CNT entries in ascending id order.
    - `param-digest = SHA3-256(param.json payload)`.
    - `target` as a copy of `game-digest`.
- Computes FIH `0xB0` nested-image-content digest as `SHA3-256` of the uncompressed inner PFS image at its logical size. The CNT build path threads this preimage through finalization, so the FIH value and CNT `pfs_signed_digest` are mutually consistent. The standalone finalization path without an inner image falls back to an outer-image hash.
- Computes `imagedigs.dat` (CNT entry `0x040A`, unnamed) as an `N * 32` byte table, one digest per 64 KiB outer-image block. It is stored as an outer-CNT body entry, not as an inner `sce_sys` file. Each stored 32-byte digest is written in reverse byte order. The build patches the captured per-block descriptor digests after `WriteImage`.
- All populated digest slots are generated from finished on-disk CNT and image data. A from-scratch build remains internally self-consistent even when its bytes differ from a specific reference package because compressed inner-image bytes can differ.

### sce\_sys files

- Generates `about/right.sprx` and injects it into the inner PFS.
- Emits `playgo-chunk.dat` (CNT entry `0x1001`), `playgo-hash-table.dat` (`0x2010`), and `playgo-ficm.dat` (`0x2011`) as outer-CNT body entries.
- Builds `playgo-hash-table.dat` as a content-independent constant structure with size `0x38 + n * 8`, where `n = ficmCount / 2`. Implemented, byte-exact.
- Generates `icon0.dds`, `pic0.dds`, `pic1.dds`, and `pic2.dds` next to source icon/picture images as valid BC7 DX10 DDS textures.

### Keystone

- Reproduces the 96-byte `sce_sys/keystone` byte-for-byte from the passcode for version 2 and version 3.
- Uses deterministic chained HMAC-SHA256: `KeyBlock1 = HMAC-SHA256(seed1, passcode_ascii)` at `0x20`, then `KeyBlock2 = HMAC-SHA256(seed2, keystone[0x00:0x40])` at `0x40`, with seed pairs selected by version.
- The version-3 seed pair differs from the version-2 seed pair.

### PlayGo

- Generates PlayGo and about-file outputs used by package builds.
- Builds `playgo-chunk.crc` as CRC-32C (Castagnoli), reflected polynomial `0x82F63B78`, init/xorout `0xFFFFFFFF`, over each 64 KiB block of the finalized image from offset 0. Each checksum is serialized as little-endian `uint32` in block order. The trailing partial block containing the metadata archive and CRC file is excluded, avoiding self-reference. Implemented by `ProsperoCrc32C` and `ProsperoPlayGo.BuildChunkCrc`.

### NAPS streaming and Kraken inner compression

- Implements `ProsperoNapsLayout` as a parser and byte-exact serializer for `naps_pkg_layout.dat`.
- The layout serializer round-trips the tested 544-byte sample: 533 bytes of section content plus 11 trailing zero pad bytes.
- Implements the 16-byte layout header bit packing: file count, compression type, key count, shuffle-pattern count, uncompressed-block count, outer-block count, and compressed-block-info count.
- Implements the section order and strides: outer block digest (8 bytes), shuffle pattern (8 bytes), uncompressed offset by file index (6 bytes), compressed-info offset by uncompressed-block index (10 bytes), and compressed-block info (9 bytes).
- Implements both 9-byte compressed-block-info record formats and all bit offsets used by the tested 45-record sample.
- `BuildLayout` defaults to 16-byte alignment, matching the tested sample.
- Data-dependent NAPS record value generation is only self-consistent for the library's own inner-image compressor output. Byte-identical reproduction of a specific package requires byte-identical Kraken-compressed block sizes.
- Implements an Oodle Kraken encoder and `KrakenDecoder` under `PFS/Compression/Oodle`, plus `CompressedPfsFileWriter` and `CompressedPfsFile` for the PFSC container.
- `CompressedPfsFileWriter.WriteCompressed(payload)` output is accepted by the reference decompressor and round-trips byte-for-byte for the covered cases: single chunk, multi-block payloads over 256 KiB, the exact 0x40000 boundary, two internal chunks per block with cross-chunk back-references, and stored fallback for incompressible chunks.
- `CompressedPfsFile.Parse(pfs).Decompress()` reconstructs the original payload byte-for-byte in process for the same cases.
- The encoder implements Oodle 2.8.0 excess mode for single long matches, including the control byte high bit and forward excess substream. Periodic-tile test classes are byte-identical to the tested reference output, while chunks with multiple over-long matches split them into valid shorter matches.
- The encoder enforces the newLZ rule that a match may not start in the last 16 bytes of a chunk. It caps match starts at `chunkEnd - 16`, flushes the remainder as trailing literals, and falls back to stored chunks if needed.
- Huffman entropy arrays are implemented and enabled by default through `KrakenHuffmanArrayEncoder`. Literal, command, and length streams can be Huffman-coded as type-2 single 3-stream arrays with a raw fallback when Huffman is not smaller; the offset array remains raw.
- `KrakenDecoder` reads raw and Huffman-coded literal/command/offset/length arrays, both code-length encodings, the 3-stream split, excess framing, both literal models, multi-chunk and multi-block payloads, and stored fallback. It decodes the embedded reference vectors and checks SHA3-256 of the decoded payloads.
- Kraken `nwonly` inner compression is implemented and produces valid output that the reference decompressor accepts. It is not byte-identical to the reference encoder at compression level 7. Therefore a from-scratch package is internally self-consistent, but it will not bit-match a specific reference package when downstream bytes depend on exact compressed block sizes.

### Reader and writer support

- `ProsperoPkgReader` detects both `\x7FCNT` and `\x7FFIH`, resolves embedded CNT data, and reports finalized debug images.
- `ProsperoPkgWriter`, `ProsperoPkgBuilder`, `ProsperoFihBuilder`, and related builders write the package structures described above.
- `ProsperoSiArchive` generates the debug install-metadata ZIP container with stored entries, member paths, `playgo-chunk.dat`, structural `pfsimage.xml` fields, and `playgo-chunk.crc`.
- `ProsperoSiArchive.BuildPfsImageXml` reproduces the descriptor structure through `<config>`, `<digests>` framing, `<params>`, `<container>`, `<mount-image>`, and `<entries>`. It includes derived long name, version constants, container geometry, extended mount-image fields, the `pfs-image-seed` block, and CNT entries. Keyed digest rows that are not supplied remain zero placeholders with warnings.
- The GP5 project model is parsed and emitted for both root-directory-walked and flat files/folders layouts.

## Known gaps / not implemented

- Retail finalized images with signed byte `0x80` are not implemented. They require console-side finalization material that the library does not have.
- Retail install-metadata archives are not implemented. The retail variant is encrypted and is not produced by the library.
- On-console installation acceptance is not guaranteed. Library code verifies structure and round-tripping; acceptance depends on console mode and firmware.
- The full NAPS streaming outer producer is not complete. Remaining pieces include rolling/weak/strong deduplication, block shuffle, per-outer-block encryption/CRC/digest integration, complete `naps_meta_*.dat` generation, full `pfsimage.xml` named-digest population for all package shapes, and final `\x7FFIH` assembly for enforced streaming use.
- NAPS layout record values are not fully generated from arbitrary input. The format parser and serializer are implemented, but values derived from exact compression bookkeeping are only self-consistent for this library's own compressor output.
- `naps_meta_*.dat` metric blobs are accepted as inputs and emitted verbatim in the debug metadata archive; the library does not fabricate their final values.
- Deep `pfsimage.xml` `<chunkinfo>`, `<pfs-image>`, and `<nested-image>` introspection trees are not implemented because they require a full inner-PFS inode walk.
- Keyed or console-produced `pfsimage.xml` digest members in the install-metadata archive are supplied by the caller or left as placeholders; they are not fabricated.
- Byte-identical reproduction of a specific `nwonly` package remains limited by exact Kraken encoder choices at compression level 7. The generated package is valid and internally consistent, but downstream NAPS layout values and digests that depend on exact compressed bytes can differ.
- Automatic emission of `naps_pkg_layout.dat` for package builds is not complete; the implemented component is the parser and serializer. Existing package-level status data says this file was absent from all real `nwonly` samples used for emission checks, so the builder does not claim package-emission coverage.

## Summary table

| Capability | Status |
| --- | --- |
| `\\x7FCNT` build | Implemented |
| `\\x7FCNT` / `\\x7FFIH` read | Implemented |
| End-to-end debug package build | Implemented |
| Inner PFS layout | Implemented |
| Inner PFS AES-XTS encryption | Implemented |
| zlib PFSC inner compression | Implemented |
| Kraken PFSC v3 inner compression for `nwonly` | Implemented; valid output, not byte-identical to the level-7 reference encoder |
| Kraken decoder | Implemented, byte-exact for covered reference blocks |
| Kraken Huffman encoder arrays | Implemented |
| PS5 outer-image key derivation | Implemented |
| PS5 outer-image AES-XTS encryption | Implemented, byte-exact for the tested reference image |
| PS5 outer-PFS signing hashes and `icv` | Implemented, byte-exact for the tested reference image |
| PS5 outer-PFS data-first structure generator | Implemented, byte-exact for the tested reference image |
| Metadata signing | Implemented |
| Finalized debug image (`\\x7FFIH`) | Implemented |
| Finalized digest table: `game-digest` / superblock digest | Implemented, byte-exact for tested debug packages |
| CNT per-entry, body, fixed-info, param, package, and header-rollup digests | Implemented, byte-exact for tested debug packages |
| CNT GeneralDigests block | Implemented, byte-exact for tested debug packages and self-consistent builder output |
| FIH `0xB0` nested-image-content digest | Implemented; self-consistent, exact value depends on exact inner compression bytes |
| `imagedigs.dat` CNT entry | Implemented |
| `playgo-chunk.dat`, `playgo-hash-table.dat`, `playgo-ficm.dat` | Implemented |
| `playgo-chunk.crc` | Implemented, byte-exact for tested debug samples |
| Debug install-metadata ZIP container | Implemented; caller supplies remaining console-produced members |
| `pfsimage.xml` structural descriptor | Implemented; deep introspection and supplied digest rows remain incomplete |
| Keystone (`sce_sys/keystone`) | Implemented, byte-exact from passcode for version 2 and version 3 |
| DDS BC7 texture generation | Implemented |
| GP5 project model | Implemented |
| NAPS layout parser and serializer | Implemented; automatic package emission incomplete |
| NAPS streaming outer producer | Not implemented |
| Retail install-metadata archive | Not implemented |
| Retail finalized image (`0x80`) | Not implemented |
| On-console acceptance guarantee | Not implemented; console-gated |


