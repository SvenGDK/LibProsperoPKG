/*
 * libprosperopkg.h - C interface for the LibProsperoPkg shared library.
 *
 * The shared library (libprosperopkg.so / libprosperopkg.dylib) is produced by the native
 * build workflows. All strings are UTF-8 and NUL-terminated. Output strings are written into
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
#define LPP_ABI_VERSION 3

/* Build mode (build `mode`). */
#define LPP_MODE_APPLICATION                 0
#define LPP_MODE_HOMEBREW                    1
#define LPP_MODE_ADDITIONAL_CONTENT_DATA     2
#define LPP_MODE_ADDITIONAL_CONTENT_NO_DATA  3

/* Output container format (build `output_format`). */
#define LPP_OUTPUT_METADATA_CONTAINER  0
#define LPP_OUTPUT_DEBUG_IMAGE         1

/* Inner-image codec (build `inner_compression`). */
#define LPP_INNER_NONE    0
#define LPP_INNER_ZLIB    1
#define LPP_INNER_KRAKEN  2

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

/*
 * Full option set for lpp_build_package_ex. Zero-initialize the whole struct, set struct_size to
 * sizeof(lpp_build_options), then fill the fields you need. Any string pointer may be NULL; a NULL
 * or empty `passcode` uses the 32-zero default, and a NULL or empty `version` uses "01.00". Set
 * `content_badge_type` to a negative value to omit it. Set `has_authority_id` to 1 to apply
 * `authority_id`; otherwise it is derived from the ELF during fake-signing.
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

/* Returns a pointer to a static, NUL-terminated version string. */
const char* lpp_version(void);

/* Returns the numeric ABI version of this library (compare against LPP_ABI_VERSION). */
int lpp_abi_version(void);

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

#ifdef __cplusplus
}
#endif

#endif /* LIBPROSPEROPKG_H */
