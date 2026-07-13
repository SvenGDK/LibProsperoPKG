/*
 * libprosperopkg.h - C interface for the LibProsperoPkg shared library.
 *
 * The shared library (libprosperopkg.so / libprosperopkg.dylib) is produced by the build
 * workflows. All strings are UTF-8 and NUL-terminated. Output strings are written into
 * caller-provided buffers; the library allocates no memory the caller must free.
 *
 * String-output functions return the number of bytes written (excluding the terminator) on
 * success. When the buffer is too small they return the negative of the required size
 * (including the terminator), so a caller can size a buffer and retry. Status functions return
 * 0 on success and a negative value on failure; call lpp_last_error for a description. Detection
 * predicates (lpp_is_*) return 1 or 0 and never fail. Struct-output functions fill a
 * caller-provided struct (fixed char arrays inside are UTF-8 and NUL-terminated) and return 0 on
 * success or a negative value on failure.
 */

#ifndef LIBPROSPEROPKG_H
#define LIBPROSPEROPKG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ABI version of the exported surface (see lpp_abi_version). Bumped when exports change. */
#define LPP_ABI_VERSION 7

/* Build mode (build `mode`). */
#define LPP_MODE_APPLICATION                 0
#define LPP_MODE_HOMEBREW                    1
#define LPP_MODE_ADDITIONAL_CONTENT_DATA     2
#define LPP_MODE_ADDITIONAL_CONTENT_NO_DATA  3

/* Output container format (build `output_format`). */
#define LPP_OUTPUT_METADATA_CONTAINER  0
#define LPP_OUTPUT_DEBUG_IMAGE         1

/* Inner-image codec (build `inner_compression`). */
#define LPP_INNER_NONE               0
#define LPP_INNER_ZLIB               1
#define LPP_INNER_KRAKEN             2
/* Installable data-first inner image: raw-concatenated per-file payloads described by a generated
 * naps_pkg_layout.dat. This is the recommended codec for installable homebrew packages. */
#define LPP_INNER_NWONLY_DATA_FIRST  3

/* Inner-image form (lpp_build_inner_image `form`). */
#define LPP_FORM_PLAINTEXT         0
#define LPP_FORM_ENCRYPTED         1
#define LPP_FORM_COMPRESSED        2
#define LPP_FORM_KRAKEN_COMPRESSED 3

/* Package type (lpp_detect_package_type return value). */
#define LPP_TYPE_META         0
#define LPP_TYPE_FULL_RETAIL  1
#define LPP_TYPE_FULL_DEBUG   2

/* Application type (build `application_type`, and the app-type helper functions). */
#define LPP_APP_TYPE_NOT_SPECIFIED         0
#define LPP_APP_TYPE_PAID_STANDALONE_FULL  1
#define LPP_APP_TYPE_UPGRADABLE            2
#define LPP_APP_TYPE_DEMO                  3
#define LPP_APP_TYPE_FREEMIUM              4

/* Patch kind (lpp_npdrm_content_info.patch_kind). */
#define LPP_PATCH_NONE        0
#define LPP_PATCH_FIRST       1
#define LPP_PATCH_SUBSEQUENT  2
#define LPP_PATCH_DELTA       3
#define LPP_PATCH_CUMULATIVE  4

/* Authentication-info authority category (lpp_read_auth_info `category`). */
#define LPP_AUTH_CATEGORY_UNKNOWN     0x00
#define LPP_AUTH_CATEGORY_FAKE        0x31
#define LPP_AUTH_CATEGORY_GENUINE     0x45
#define LPP_AUTH_CATEGORY_PRIVILEGED  0x48

/* param.json DRM type (lpp_create_param_json `drm_type`). */
#define LPP_PARAM_DRM_STANDARD  0
#define LPP_PARAM_DRM_FREE      1
#define LPP_PARAM_DRM_FREEMIUM  2

/* GP5 volume type (lpp_create_gp5 `volume_type`). */
#define LPP_GP5_VOLUME_APP         0
#define LPP_GP5_VOLUME_PATCH       1
#define LPP_GP5_VOLUME_AC          2
#define LPP_GP5_VOLUME_AC_NODATA   3

/* ELF machine (lpp_elf_info.machine). */
#define LPP_ELF_MACHINE_X86_64   0x3E
#define LPP_ELF_MACHINE_AARCH64  0xB7

/* Package entry id (lpp_package_entry.id). */
#define LPP_ENTRY_UNKNOWN               0x0000
#define LPP_ENTRY_DIGESTS               0x0001
#define LPP_ENTRY_ENTRY_KEYS            0x0010
#define LPP_ENTRY_IMAGE_KEY             0x0020
#define LPP_ENTRY_GENERAL_DIGESTS       0x0080
#define LPP_ENTRY_METAS                 0x0100
#define LPP_ENTRY_ENTRY_NAMES           0x0200
#define LPP_ENTRY_LICENSE_DAT           0x0400
#define LPP_ENTRY_LICENSE_INFO          0x0401
#define LPP_ENTRY_PARAM_JSON            0x1000
#define LPP_ENTRY_PARAM_SFO             0x1001
#define LPP_ENTRY_ICON0_PNG             0x1200
#define LPP_ENTRY_PIC0_PNG              0x1220
#define LPP_ENTRY_SND0_AT9              0x1240
#define LPP_ENTRY_ICON0_DDS             0x1280
#define LPP_ENTRY_PIC0_DDS              0x12A0
#define LPP_ENTRY_PIC1_DDS              0x12C0
#define LPP_ENTRY_PLAYGO_CHUNK_DAT      0x1300
#define LPP_ENTRY_PLAYGO_CHUNK_SHA      0x1301
#define LPP_ENTRY_PLAYGO_MANIFEST_XML   0x1302
#define LPP_ENTRY_PIC2_DDS              0x2060

/*
 * Full option set for lpp_build_package_ex. Zero-initialize the whole struct, set struct_size to
 * sizeof(lpp_build_options), then fill the fields you need. Any string pointer may be NULL; a NULL
 * or empty `passcode` uses the 32-zero default, and a NULL or empty `version` uses "01.00". Set
 * `content_badge_type` to a negative value to omit it. Set `has_authority_id` to 1 to apply
 * `authority_id`; otherwise it is derived from the ELF during fake-signing. Set `license_free`
 * to 1 to produce a DRM/license-free debug package (fake-signs modules and forces the free DRM
 * bucket). `license_free` is an appended field: a smaller `struct_size` leaves it disabled.
 */
typedef struct lpp_build_options {
    int32_t struct_size;            /* sizeof(lpp_build_options) */
    int32_t mode;                   /* LPP_MODE_* */
    int32_t output_format;          /* LPP_OUTPUT_* */
    int32_t inner_compression;      /* LPP_INNER_* */
    int32_t application_type;       /* LPP_APP_TYPE_* */
    int32_t content_badge_type;     /* < 0 to omit */
    int32_t generate_param_json;    /* 0/1 (generate param.json when the source lacks one) */
    int32_t compress_inner_image;   /* 0/1 (zlib PFSC inner image) */
    int32_t fake_sign_self;         /* 0/1 (fake-sign raw ELF modules before packing) */
    int32_t has_authority_id;       /* 0/1 (apply authority_id below) */

    uint64_t app_version;           /* fake-self application version */
    uint64_t firmware_version;      /* fake-self firmware version */
    uint64_t authority_id;          /* fake-self authority-id override (see has_authority_id) */

    const char* source_folder;
    const char* output_folder;
    const char* content_id;
    const char* passcode;           /* NULL/empty -> 32 zeroes */
    const char* title;
    const char* title_id;
    const char* version;            /* NULL/empty -> "01.00" */
    const char* application_drm_type; /* NULL -> derived from application_type */

    int32_t license_free;           /* 0/1 (DRM/license-free debug package: fake-sign + free bucket) */
} lpp_build_options;

/*
 * Projected NpDrm content-info filled by lpp_read_npdrm_content_info. Zero-initialize before the
 * call; on return content_id and title_id are UTF-8, NUL-terminated.
 */
typedef struct lpp_npdrm_content_info {
    int32_t  struct_size;       /* sizeof(lpp_npdrm_content_info) */
    uint32_t drm_type;
    uint32_t content_type;
    uint32_t content_flags;
    int32_t  patch_kind;        /* LPP_PATCH_* */
    int32_t  is_patch;          /* 0/1 */
    int32_t  is_nested;         /* 0/1 */
    int32_t  is_finalized;      /* 0/1 */
    int64_t  container_offset;
    char     content_id[64];
    char     title_id[16];
} lpp_npdrm_content_info;

/*
 * Package inspection result filled by lpp_inspect_package. Zero-initialize before the call; on
 * return content_id is UTF-8, NUL-terminated (empty when the package carries no content id).
 */
typedef struct lpp_package_info {
    int32_t struct_size;        /* sizeof(lpp_package_info) */
    int32_t package_type;       /* LPP_TYPE_* */
    int32_t is_retail;          /* 0/1 */
    int32_t outer_encrypted;    /* 0/1 */
    int32_t requires_key;       /* 0/1 (a supplied key is required to extract) */
    int32_t reserved;
    int64_t pfs_image_offset;
    int64_t pfs_image_size;
    char    content_id[64];
} lpp_package_info;

/*
 * Multi-content RIF summary filled by lpp_read_rif_summary. Zero-initialize before the call; on
 * return app_content_id and service_id are UTF-8, NUL-terminated.
 */
typedef struct lpp_rif_summary {
    int32_t struct_size;        /* sizeof(lpp_rif_summary) */
    int32_t record_count;       /* n_rif */
    int32_t has_app;            /* 0/1 */
    int32_t additional_count;   /* n_ac */
    int64_t expected_size;
    int64_t actual_size;
    char    app_content_id[64];
    char    service_id[16];
} lpp_rif_summary;

/*
 * Package header/image-header summary filled by lpp_read_package_summary. Zero-initialize before
 * the call; on return content_id is UTF-8, NUL-terminated.
 */
typedef struct lpp_package_summary {
    int32_t  struct_size;         /* sizeof(lpp_package_summary) */
    int32_t  package_type;        /* LPP_TYPE_* */
    int32_t  is_official;         /* 0/1 */
    int32_t  fih_format_version;
    uint32_t flags;
    uint32_t entry_count;
    uint32_t sc_entry_count;
    uint32_t drm_type;
    uint32_t content_type;
    uint32_t content_flags;
    int64_t  pfs_image_offset;
    int64_t  pfs_image_size;
    int64_t  embedded_cnt_offset;
    char     content_id[64];
} lpp_package_summary;

/*
 * Single package entry filled by lpp_read_package_entry. Zero-initialize before the call; on
 * return name is UTF-8, NUL-terminated (empty when the entry is unnamed).
 */
typedef struct lpp_package_entry {
    int32_t  struct_size;         /* sizeof(lpp_package_entry) */
    uint32_t raw_id;
    int32_t  id;                  /* LPP_ENTRY_* */
    uint32_t flags1;
    uint32_t flags2;
    uint32_t data_offset;
    uint32_t data_size;
    int32_t  encrypted;           /* 0/1 */
    uint32_t key_index;
    char     name[64];
} lpp_package_entry;

/*
 * ELF header fields filled by lpp_read_elf_header. Zero-initialize before the call.
 */
typedef struct lpp_elf_info {
    int32_t  struct_size;         /* sizeof(lpp_elf_info) */
    int32_t  elf_class;
    int32_t  data;
    int32_t  os_abi;
    int32_t  abi_version;
    int32_t  type;
    int32_t  machine;             /* LPP_ELF_MACHINE_* */
    uint64_t entry;
    uint32_t flags;
    int32_t  program_header_count;
    int32_t  is_executable;       /* 0/1 */
    int32_t  is_dynamic;          /* 0/1 */
    int32_t  is_module_type;      /* 0/1 */
    int32_t  is_module_ready;     /* 0/1 */
} lpp_elf_info;

/*
 * Launch-readiness summary filled by lpp_inspect_launch_readiness and, optionally, by
 * lpp_package_homebrew. Zero-initialize before the call.
 */
typedef struct lpp_launch_readiness {
    int32_t struct_size;              /* sizeof(lpp_launch_readiness) */
    int32_t has_eboot;                /* 0/1 */
    int32_t has_param_json;           /* 0/1 */
    int32_t has_param_sfo;            /* 0/1 */
    int32_t requires_debug_console;   /* 0/1 */
    int32_t is_launch_ready;          /* 0/1 */
    int32_t module_count;
    int32_t issue_count;
} lpp_launch_readiness;

/* Returns a pointer to a static, NUL-terminated version string. */
const char* lpp_version(void);

/* Returns the numeric ABI version of this library (compare against LPP_ABI_VERSION). */
int lpp_abi_version(void);

/*
 * Returns 1 when the wired-in publishing key material is present (the build path can sign the
 * package), or 0 when it is absent and signing is skipped. Never fails.
 */
int lpp_keys_available(void);

/* Copies the current thread's most recent error message into `buffer`. */
int lpp_last_error(char* buffer, int capacity);

/* Returns 1 when `content_id` is a valid 36-character content id, otherwise 0. */
int lpp_is_valid_content_id(const char* content_id);

/* Returns 1 when `title_id` looks like a PPSAxxxxx title id, otherwise 0. */
int lpp_is_valid_title_id(const char* title_id);

/*
 * Composes a 36-character content id from a publisher prefix, a title id and a label.
 * Any argument may be NULL to accept the default for that field. Writes the result into
 * `out_buffer` as UTF-8.
 */
int lpp_compose_content_id(const char* publisher, const char* title_id, const char* label,
                           char* out_buffer, int capacity);

/*
 * Builds a package from a prepared source folder. `passcode` and `version` may be NULL/empty
 * to accept their defaults (a 32-zero passcode and "01.00"). On success the output path is
 * written to `out_path` and the function returns 0. On failure it returns a negative value;
 * call lpp_last_error for a description.
 */
int lpp_build_package(const char* source_folder,
                      const char* output_folder,
                      const char* content_id,
                      const char* passcode,
                      const char* title,
                      const char* title_id,
                      const char* version,
                      int mode,
                      int output_format,
                      int inner_compression,
                      char* out_path,
                      int out_path_capacity);

/*
 * Builds a package using the full option set in `options` (application type, fake-signing,
 * param.json generation, inner compression, badge and DRM overrides). Zero-initialize the struct
 * and set struct_size = sizeof(lpp_build_options). On success writes the output path to `out_path`
 * and returns 0; on failure returns a negative value (call lpp_last_error).
 */
int lpp_build_package_ex(const lpp_build_options* options,
                         char* out_path, int out_path_capacity);

/*
 * Detects the package type of the file at `path`. Returns the package type (LPP_TYPE_*), or -1
 * when the file is not a recognized package or cannot be read (call lpp_last_error).
 */
int lpp_detect_package_type(const char* path);

/*
 * Lays a prepared folder out into an inner-PFS image. `form` selects the image form (LPP_FORM_*).
 * `passcode` may be NULL/empty to accept the 32-zero default. The written image path is copied
 * into `out_path`. Returns 0 on success; a negative value on failure (call lpp_last_error).
 */
int lpp_build_inner_image(const char* source_folder,
                          const char* output_path,
                          const char* content_id,
                          const char* passcode,
                          int form,
                          char* out_path,
                          int out_path_capacity);

/*
 * AES-XTS-encrypts a plaintext inner-PFS image in place, using keys derived from the content id
 * and passcode. `passcode` may be NULL/empty to accept the 32-zero default. Returns 0 on success;
 * a negative value on failure (call lpp_last_error).
 */
int lpp_encrypt_pfs_image(const char* pfs_image_path, const char* content_id, const char* passcode);

/*
 * Packs a plaintext PFS image into a PFSv3 PFSC (Kraken) container. A non-positive `level` or
 * `block_size` selects the default (7 / 262144). Returns 0 on success; a negative value on
 * failure (call lpp_last_error).
 */
int lpp_pack_pfs_image(const char* input_image_path, const char* output_path,
                       int level, int block_size);

/*
 * Unpacks a PFSv3 PFSC container back into a plaintext PFS image. Returns the number of bytes
 * written on success, or -1 on failure (call lpp_last_error).
 */
long long lpp_unpack_pfs_image(const char* input_path, const char* output_path);

/* Returns 1 when `data` (`length` bytes) holds a SELF container, otherwise 0. */
int lpp_is_self(const unsigned char* data, int length);

/* Returns 1 when `data` (`length` bytes) holds a 64-bit ELF, otherwise 0. */
int lpp_is_elf(const unsigned char* data, int length);

/* Returns 1 when `data` (`length` bytes) holds a UCP archive, otherwise 0. */
int lpp_is_ucp(const unsigned char* data, int length);

/*
 * Reads the SELF extended-info and segment count from an in-memory SELF module. Any output
 * pointer may be NULL to skip that field; `digest32` must point to 32 bytes when non-NULL. When
 * the module carries no extended-info block the ext-info outputs are zero-filled and the call
 * still returns 0. Returns -1 when the buffer is not a valid SELF (call lpp_last_error).
 */
int lpp_read_self_info(const unsigned char* data, int length,
                       uint64_t* authority_id, uint64_t* program_type,
                       uint64_t* app_version, uint64_t* firmware_version,
                       unsigned char* digest32, int* segment_count);

/*
 * Generates a fake-self from a 64-bit ELF. Pass out_buffer=NULL or capacity=0 to query the
 * required size (returned positive, nothing written). On success returns the number of bytes
 * written. Returns -1 and sets lpp_last_error on failure or when a non-zero buffer is too small.
 */
int lpp_make_fself(const unsigned char* elf, int elf_length,
                   unsigned char* out_buffer, int capacity);

/*
 * Like lpp_make_fself, with explicit fake-self options: `app_version` and `firmware_version` are
 * written to the extended info, and `authority_id` overrides the derived id when `has_authority_id`
 * is non-zero. The size-query and buffer semantics match lpp_make_fself.
 */
int lpp_make_fself_ex(const unsigned char* elf, int elf_length,
                      uint64_t app_version, uint64_t firmware_version,
                      uint64_t authority_id, int has_authority_id,
                      unsigned char* out_buffer, int capacity);

/*
 * Reads a 64-bit ELF from `elf_path`, generates a fake-self and writes it to `out_path`. The
 * version/authority arguments match lpp_make_fself_ex. Returns the number of bytes written on
 * success, or -1 on failure (call lpp_last_error).
 */
int lpp_make_fself_file(const char* elf_path, const char* out_path,
                        uint64_t app_version, uint64_t firmware_version,
                        uint64_t authority_id, int has_authority_id);

/*
 * Fake-signs every raw ELF module under `source_folder` in place (eboot.bin, *.elf, *.prx,
 * *.sprx). Files already SELF, or that are not a 64-bit ELF, are skipped. The version/authority
 * arguments match lpp_make_fself_ex. Returns the number of modules converted, or -1 on failure
 * (call lpp_last_error).
 */
int lpp_fake_sign_folder(const char* source_folder,
                         uint64_t app_version, uint64_t firmware_version,
                         uint64_t authority_id, int has_authority_id);

/*
 * Copies the display name of an application type (LPP_APP_TYPE_*) into `out_buffer` as UTF-8.
 * Returns the number of bytes written, or a negative value (call lpp_last_error).
 */
int lpp_application_type_name(int application_type, char* out_buffer, int capacity);

/*
 * Copies the generated param.json applicationDrmType token ("free" / "standard" / "freemium") for
 * an application type (LPP_APP_TYPE_*) into `out_buffer`. Returns the number of bytes written, or a
 * negative value (call lpp_last_error).
 */
int lpp_application_drm_type(int application_type, char* out_buffer, int capacity);

/*
 * Parses an application-type display name (case-insensitive) into its code (LPP_APP_TYPE_*).
 * Unknown or empty input yields LPP_APP_TYPE_NOT_SPECIFIED (0).
 */
int lpp_parse_application_type(const char* name);

/*
 * Reads a SELF authentication-info sidecar (a 0x88-byte *.auth_info record). Any output pointer
 * may be NULL; `capabilities4` and `attributes4` each point to four 64-bit words, and `category`
 * receives the authority category (LPP_AUTH_CATEGORY_*). Returns 0 on success, or -1 on failure
 * (call lpp_last_error).
 */
int lpp_read_auth_info(const char* path, uint64_t* paid,
                       uint64_t* capabilities4, uint64_t* attributes4, int* category);

/*
 * Builds a SELF authentication-info sidecar from supplied fields and writes it to `path`.
 * `capabilities4` and `attributes4` each point to four 64-bit words, or may be NULL to write
 * zeroes. Returns 0 on success, or -1 on failure (call lpp_last_error).
 */
int lpp_write_auth_info(const char* path, uint64_t paid,
                        const uint64_t* capabilities4, const uint64_t* attributes4);

/*
 * Reads and projects the NpDrm content-info of the package at `path` into `out_info`. Returns 0
 * on success, or -1 on failure (call lpp_last_error).
 */
int lpp_read_npdrm_content_info(const char* path, lpp_npdrm_content_info* out_info);

/*
 * Inspects the package at `path` without a key, filling `out_info` (package type, retail flag,
 * outer-PFS offset and size, encryption state, whether a supplied key is required, and the content
 * id when present). Returns 0 on success, or -1 on failure (call lpp_last_error).
 */
int lpp_inspect_package(const char* path, lpp_package_info* out_info);

/*
 * Extracts a package to `output_directory`, deriving the outer key from `passcode` (and the
 * package's own content id). A NULL or empty passcode uses the 32-zero default. Set `extract_outer`
 * non-zero to also write the outer metadata files. Returns the number of extracted files on
 * success, or -1 on failure (call lpp_last_error).
 */
int lpp_extract_package(const char* path, const char* output_directory,
                        const char* passcode, int extract_outer);

/*
 * Extracts a package to `output_directory` using a supplied 32-byte outer key (`ekpfs32`). Set
 * `extract_outer` non-zero to also write the outer metadata files. Returns the number of extracted
 * files on success, or -1 on failure (call lpp_last_error).
 */
int lpp_extract_package_ekpfs(const char* path, const char* output_directory,
                              const unsigned char* ekpfs32, int extract_outer);

/*
 * Counts the records in a RIF license file (n_rif). Returns the record count on success, or -1 on
 * failure (call lpp_last_error).
 */
int lpp_rif_record_count(const char* path);

/*
 * Copies the content id of the first record in a RIF file into `out_buffer` as UTF-8. Returns the
 * number of bytes written, or a negative value (call lpp_last_error).
 */
int lpp_read_rif_content_id(const char* path, char* out_buffer, int capacity);

/*
 * Summarizes a multi-content RIF file into `out_summary`. `app_title_id` may be NULL to skip the
 * application match. Returns 0 on success, or -1 on failure (call lpp_last_error).
 */
int lpp_read_rif_summary(const char* path, const char* app_title_id, lpp_rif_summary* out_summary);

/*
 * Runs the structural acceptance-gate checks on the package at `path`. `expected_content_id` may be
 * NULL to skip the content-id match. The pass, warning and fail counts are written to the output
 * pointers when non-NULL. Returns 1 when accepted (no failing check), 0 when rejected, or -1 on
 * error (call lpp_last_error).
 */
int lpp_validate_package(const char* path, const char* expected_content_id,
                         int* pass_count, int* warn_count, int* fail_count);

/*
 * Runs the structural acceptance-gate checks on the package at `path` and writes each check as one
 * line ("[Status] Name: Detail") into `out_buffer`. `expected_content_id` may be NULL to skip the
 * content-id match. Follows the string-output convention (bytes written, or the negative required
 * size).
 */
int lpp_validate_package_report(const char* path, const char* expected_content_id,
                                char* out_buffer, int capacity);

/*
 * Reassembles a split disc-backup package (from an app.json path or a directory that contains one)
 * into a single package file at `output_path`. Returns the number of bytes written on success, or
 * -1 on failure (call lpp_last_error).
 */
long long lpp_disc_backup_reassemble(const char* manifest_path, const char* output_path);

/*
 * Verifies a split disc-backup package. The package-digest and chunk-CRC results are written to the
 * output pointers (1 = match, 0 = mismatch) when non-NULL. Returns 0 on success, or -1 on failure
 * (call lpp_last_error).
 */
int lpp_disc_backup_verify(const char* manifest_path, int* digest_ok, int* chunk_crc_ok);

/*
 * Converts a decrypted application backup into a debug package. Substitutes each signed executable
 * with its raw ELF from the decrypted subtree, fake-signs the modules, and builds a debug image whose
 * mount key derives from the content id and passcode. `content_id` and `version` may be NULL/empty to
 * take them from the backup's param.json; `passcode` may be NULL/empty for the all-zero default. The
 * substituted-module count is written to `substituted_count` when non-NULL. The output path is written
 * into `out_path` as UTF-8. Returns 0 on success, or -1 on failure (call lpp_last_error).
 */
int lpp_convert_backup(const char* backup_folder, const char* output_folder, const char* content_id,
                       const char* passcode, const char* version, int* substituted_count,
                       char* out_path, int out_path_capacity);

/*
 * Converts a decrypted application backup into a debug package with the full option set. Extends
 * lpp_convert_backup with the name of the decrypted-module subtree (`decrypted_subfolder`, NULL/empty
 * for "decrypted"), a flag to drop the backup's own right.sprx so the embedded debug module is
 * injected instead (`use_embedded_right_sprx`), and the inner-image codec (`inner_compression`,
 * LPP_INNER_*). The substituted, plaintext and unresolved module counts are written to the output
 * pointers when non-NULL. The output path is written to `out_path`. Returns 0 on success, or -1 on
 * failure (call lpp_last_error).
 */
int lpp_convert_backup_ex(const char* backup_folder, const char* output_folder, const char* content_id,
                          const char* passcode, const char* version, const char* decrypted_subfolder,
                          int use_embedded_right_sprx, int inner_compression, int* substituted_count,
                          int* plaintext_count, int* unresolved_count,
                          char* out_path, int out_path_capacity);

/*
 * Reads the package at `path` and fills `out_info` with header and image-header fields (package
 * type, entry counts, DRM/content type and flags, content id, PFS image offset/size, embedded
 * container offset). Returns 0 on success, or -1 on failure (call lpp_last_error).
 */
int lpp_read_package_summary(const char* path, lpp_package_summary* out_info);

/*
 * Returns the entry count of the package at `path`, or -1 on failure (call lpp_last_error).
 */
int lpp_package_entry_count(const char* path);

/*
 * Fills `out_entry` with the entry at zero-based `index` in the package at `path`. Returns 0 on
 * success, or -1 on failure or an out-of-range index (call lpp_last_error).
 */
int lpp_read_package_entry(const char* path, int index, lpp_package_entry* out_entry);

/*
 * Lists the inner files of the package at `path` (newline-separated relative paths) using a
 * passcode. `passcode` may be NULL/empty for the 32-zero default. Follows the string-output
 * convention (bytes written, or the negative required size).
 */
int lpp_list_package_files(const char* path, const char* passcode, char* out_buffer, int capacity);

/*
 * Lists the inner files of the package at `path` (newline-separated relative paths) using a
 * supplied 32-byte image key (`ekpfs32`). Follows the string-output convention.
 */
int lpp_list_package_files_ekpfs(const char* path, const unsigned char* ekpfs32,
                                 char* out_buffer, int capacity);

/*
 * Compares two metadata containers and writes the differences (newline-separated) into
 * `out_buffer`; an empty result means the containers match. Follows the string-output convention.
 */
int lpp_compare_containers(const char* reference_path, const char* candidate_path,
                           char* out_buffer, int capacity);

/*
 * Merges every split package found in `input_dir` and writes the resulting output paths
 * (newline-separated) into `out_buffer`. `output_dir` may be NULL to write beside the input; set
 * `compute_digest` non-zero to compute a SHA-256 per merged package. Follows the string-output
 * convention.
 */
int lpp_merge_split_package_dir(const char* input_dir, const char* output_dir, int compute_digest,
                                char* out_buffer, int capacity);

/*
 * Builds a package from a homebrew folder. `content_id`, `title` and `version` may be NULL/empty to
 * take defaults; `passcode` may be NULL/empty for the 32-zero default; `module_name` may be
 * NULL/empty for "eboot.bin". When non-NULL, `out_readiness` receives the launch-readiness summary.
 * Writes the output path to `out_path`. Returns 0 on success, or -1 on failure (call lpp_last_error).
 */
int lpp_package_homebrew(const char* homebrew_folder, const char* output_folder, const char* content_id,
                         const char* passcode, const char* title, const char* version,
                         const char* module_name, int inner_compression,
                         lpp_launch_readiness* out_readiness, char* out_path, int out_path_capacity);

/*
 * Inspects an application root and fills `out_readiness` with its launch-readiness summary. Returns
 * 0 on success, or -1 on failure (call lpp_last_error).
 */
int lpp_inspect_launch_readiness(const char* app_root, lpp_launch_readiness* out_readiness);

/*
 * Inspects an application root and writes its blocking launch-readiness reasons (newline-separated)
 * into `out_buffer`; an empty result means the tree is launch-ready. Pairs with
 * lpp_inspect_launch_readiness, which reports the issue count. Follows the string-output convention.
 */
int lpp_launch_readiness_issues(const char* app_root, char* out_buffer, int capacity);

/*
 * Lays a source folder out into a plaintext inner-PFS image. The file and directory counts are
 * written to `file_count` and `directory_count` when non-NULL; the output path is written to
 * `out_path`. Returns 0 on success, or -1 on failure (call lpp_last_error).
 */
int lpp_build_pfs_layout(const char* source_folder, const char* output_path, int* file_count,
                         int* directory_count, char* out_path, int out_path_capacity);

/*
 * Reports whether the inner image at `path` is encrypted. Returns 1 when encrypted, 0 when
 * plaintext, or -1 on failure (call lpp_last_error).
 */
int lpp_pfs_image_is_encrypted(const char* path);

/*
 * Decrypts the inner image at `pfs_image_path` in place, deriving the image key from `content_id`
 * and `passcode` (NULL/empty passcode uses the 32-zero default). Returns 0 on success, or -1 on
 * failure (call lpp_last_error).
 */
int lpp_decrypt_pfs_image(const char* pfs_image_path, const char* content_id, const char* passcode);

/*
 * Reads the ELF header at `path` into `out_info`. Returns 0 on success, or -1 on failure (call
 * lpp_last_error).
 */
int lpp_read_elf_header(const char* path, lpp_elf_info* out_info);

/*
 * Normalizes the ELF at `in_path` for use as a module and writes the result to `out_path`. When
 * non-NULL, `changed` receives 1 if any header field changed, otherwise 0. Returns 0 on success, or
 * -1 on failure (call lpp_last_error).
 */
int lpp_normalize_elf_module(const char* in_path, const char* out_path, int* changed);

/*
 * Validates the content protection file at `path`. When non-NULL, `error_buffer` receives a
 * description when the file is invalid. Returns 1 when valid, 0 when invalid, or -1 on failure
 * (call lpp_last_error).
 */
int lpp_ucp_validate_file(const char* path, char* error_buffer, int error_capacity);

/*
 * Verifies the digest of the content protection file at `path`. Returns 1 when the digest matches,
 * 0 when it does not, or -1 on failure (call lpp_last_error).
 */
int lpp_ucp_verify_digest_file(const char* path);

/*
 * Builds a content protection file from `directory` and writes it to `output_path`. Returns the
 * number of bytes written, or -1 on failure (call lpp_last_error).
 */
long long lpp_ucp_build_from_directory(const char* directory, const char* output_path);

/*
 * Reads the content protection file at `in_path`, repairs its digest, and writes it to `out_path`.
 * Returns the number of bytes written, or -1 on failure (call lpp_last_error).
 */
long long lpp_ucp_repair_digest_file(const char* in_path, const char* out_path);

/*
 * Creates a structural license record for `content_id` and writes it to `out_path`. Pass 0 for
 * `expiry` to create a non-expiring record. Returns the number of bytes written, or -1 on failure
 * (call lpp_last_error).
 */
long long lpp_rif_create(const char* content_id, long long expiry, const char* out_path);

/*
 * Derives the 32-byte image key from `content_id` and `passcode` (NULL/empty passcode uses the
 * 32-zero default) and writes it to `out32`. Returns 0 on success, or -1 on failure (call
 * lpp_last_error).
 */
int lpp_derive_image_key(const char* content_id, const char* passcode, unsigned char* out32);

/*
 * Validates a 32-hex-character entitlement key. Returns 1 when valid, 0 when invalid, or -1 on
 * failure (call lpp_last_error).
 */
int lpp_entitlement_key_validate(const char* hex);

/*
 * Opens a disc backup from its manifest and fills `out_info` with the content info of the
 * reassembled package. Returns 0 on success, or -1 on failure (call lpp_last_error).
 */
int lpp_disc_backup_content_info(const char* manifest_path, lpp_npdrm_content_info* out_info);

/*
 * Verifies the chunk CRCs of a disc backup. When non-NULL, `mismatch_chunk` receives the index of
 * the first mismatch (or -1 when all match). Returns 1 when all chunks match, 0 on mismatch, or -1
 * on failure (call lpp_last_error).
 */
int lpp_disc_backup_verify_chunk_crcs(const char* manifest_path, int* mismatch_chunk);

/*
 * Encodes the PNG file at `png_path` to a BC7 DDS texture and writes it to `dds_path`. Returns the
 * number of bytes written, or -1 on failure (call lpp_last_error).
 */
long long lpp_encode_png_to_dds(const char* png_path, const char* dds_path);

/*
 * Builds a chunk descriptor file for `content_id` and writes it to `out_path`. Returns the number
 * of bytes written, or -1 on failure (call lpp_last_error).
 */
long long lpp_build_playgo_chunk_dat(const char* content_id, const char* out_path);

/*
 * Creates a default param.json for the given ids (`drm_type` is LPP_PARAM_DRM_*) and writes it to
 * `out_path`. Returns the number of bytes written, or -1 on failure (call lpp_last_error).
 */
long long lpp_create_param_json(const char* content_id, const char* title_id, const char* title_name,
                                int drm_type, const char* out_path);

/*
 * Builds a GP5 project referencing `source_folder` and writes it to `out_path`. `volume_type` is one of
 * LPP_GP5_VOLUME_* and `passcode` may be NULL/empty for the all-zero default. Returns the number of bytes
 * written, or -1 on failure (call lpp_last_error).
 */
long long lpp_create_gp5(const char* source_folder, const char* out_path, int volume_type,
                         const char* passcode);

#ifdef __cplusplus
}
#endif

#endif /* LIBPROSPEROPKG_H */
