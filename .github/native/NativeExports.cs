// C ABI surface for the shared-library builds produced by the native workflows.
//
// This file is NOT part of the normal managed build. It lives outside the project
// directory so the SDK never compiles it into the class library or its package. The
// native workflows copy it into the project directory and enable AOT/shared-library
// output before publishing, so the exported entry points only exist in the .so/.dylib
// artifacts.
//
// Every export uses UnmanagedCallersOnly so the AOT compiler emits a plain C symbol.
// Strings cross the boundary as UTF-8 (NUL-terminated `const char*`); output strings are
// copied into caller-provided buffers, so the caller owns all memory. Enum arguments are
// passed as 32-bit integers whose values are documented in libprosperopkg.h.
//
// String-output functions return the number of bytes written (excluding the terminator) on
// success, or the negative of the required size (including the terminator) when the buffer is
// too small, so a caller can size a buffer and retry. Status functions return 0 on success and
// a negative value on failure; call lpp_last_error for a description. Struct-output functions
// fill a caller-provided struct (fixed char arrays inside are UTF-8 and NUL-terminated) and
// return 0 on success or a negative value on failure.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using LibProsperoPkg;
using LibProsperoPkg.Content;
using LibProsperoPkg.DiscBackup;
using LibProsperoPkg.License;
using LibProsperoPkg.NpDrm;
using LibProsperoPkg.PFS.Compression;
using LibProsperoPkg.PKG;

namespace LibProsperoPkg.Native;

/// <summary>
/// Blittable mirror of the C <c>lpp_build_options</c> struct. Passed by pointer to
/// <see cref="NativeExports.BuildPackageEx"/>. The layout must match libprosperopkg.h exactly:
/// ten 32-bit integers, three 64-bit integers, then the UTF-8 string pointers.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct LppBuildOptions
{
    public int StructSize;
    public int Mode;
    public int OutputFormat;
    public int InnerCompression;
    public int ApplicationType;
    public int ContentBadgeType;   // negative to omit
    public int GenerateParamJson;  // 0/1
    public int CompressInnerImage; // 0/1
    public int FakeSignSelf;       // 0/1
    public int HasAuthorityId;     // 0/1

    public ulong AppVersion;
    public ulong FirmwareVersion;
    public ulong AuthorityId;

    public byte* SourceFolder;
    public byte* OutputFolder;
    public byte* ContentId;
    public byte* Passcode;
    public byte* Title;
    public byte* TitleId;
    public byte* Version;
    public byte* ApplicationDrmType;
}

/// <summary>
/// Blittable mirror of the C <c>lpp_npdrm_content_info</c> struct filled by
/// <see cref="NativeExports.ReadNpDrmContentInfo"/>. Fixed char arrays are UTF-8, NUL-terminated.
/// The layout must match libprosperopkg.h exactly.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct LppNpDrmContentInfo
{
    public int StructSize;
    public uint DrmType;
    public uint ContentType;
    public uint ContentFlags;
    public int PatchKind;      // LPP_PATCH_*
    public int IsPatch;        // 0/1
    public int IsNested;       // 0/1
    public int IsFinalized;    // 0/1
    public long ContainerOffset;
    public fixed byte ContentId[64];
    public fixed byte TitleId[16];
}

/// <summary>
/// Blittable mirror of the C <c>lpp_package_info</c> struct filled by
/// <see cref="NativeExports.InspectPackage"/>. The layout must match libprosperopkg.h exactly.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct LppPackageInfo
{
    public int StructSize;
    public int PackageType;    // LPP_TYPE_*
    public int IsRetail;       // 0/1
    public int OuterEncrypted; // 0/1
    public int RequiresKey;    // 0/1
    public int Reserved;
    public long PfsImageOffset;
    public long PfsImageSize;
    public fixed byte ContentId[64];
}

/// <summary>
/// Blittable mirror of the C <c>lpp_rif_summary</c> struct filled by
/// <see cref="NativeExports.ReadRifSummary"/>. The layout must match libprosperopkg.h exactly.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct LppRifSummary
{
    public int StructSize;
    public int RecordCount;     // n_rif
    public int HasApp;          // 0/1
    public int AdditionalCount; // n_ac
    public long ExpectedSize;
    public long ActualSize;
    public fixed byte AppContentId[64];
    public fixed byte ServiceId[16];
}

internal static unsafe class NativeExports
{
    // Bump when the exported surface changes in a way consumers can gate on.
    private const int AbiVersionValue = 3;

    [ThreadStatic]
    private static string? _lastError;

    private static readonly byte* VersionPtr = AllocUtf8("LibProsperoPkg 1.3.0");

    /// <summary>Returns a pointer to a static, NUL-terminated version string.</summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_version")]
    public static byte* Version() => VersionPtr;

    /// <summary>Returns the numeric ABI version of the exported surface.</summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_abi_version")]
    public static int AbiVersion() => AbiVersionValue;

    /// <summary>Copies the most recent error message for the current thread into a caller buffer.</summary>
    /// <returns>The number of UTF-8 bytes written (excluding the terminator), or a negative value on error.</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_last_error")]
    public static int LastError(byte* buffer, int capacity)
        => WriteUtf8(_lastError ?? "", buffer, capacity);

    /// <summary>Returns 1 when the argument is a valid 36-character content id, otherwise 0.</summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_is_valid_content_id")]
    public static int IsValidContentId(byte* contentId)
        => ProsperoPackageBuilder.IsValidContentId(Utf8ToString(contentId)) ? 1 : 0;

    /// <summary>Returns 1 when the argument looks like a PPSAxxxxx title id, otherwise 0.</summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_is_valid_title_id")]
    public static int IsValidTitleId(byte* titleId)
        => ProsperoPackageBuilder.IsValidTitleId(Utf8ToString(titleId)) ? 1 : 0;

    /// <summary>
    /// Composes a 36-character content id from a publisher prefix, a title id and a label,
    /// writing the result into a caller buffer as UTF-8.
    /// </summary>
    /// <returns>The number of bytes written, or a negative value on error (see lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_compose_content_id")]
    public static int ComposeContentId(byte* publisher, byte* titleId, byte* label, byte* outBuffer, int capacity)
    {
        try
        {
            string id = ProsperoPackageBuilder.ComposeContentId(
                Utf8ToString(publisher), Utf8ToString(titleId), Utf8ToString(label));
            return WriteUtf8(id, outBuffer, capacity);
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Builds a package from a prepared source folder. The integer arguments select the build
    /// mode, output format and inner-image codec (values documented in libprosperopkg.h). The
    /// output path is written into <paramref name="outPath"/> as UTF-8.
    /// </summary>
    /// <returns>0 on success; a negative value on failure (call lpp_last_error for the message).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_build_package")]
    public static int BuildPackage(
        byte* sourceFolder,
        byte* outputFolder,
        byte* contentId,
        byte* passcode,
        byte* title,
        byte* titleId,
        byte* version,
        int mode,
        int outputFormat,
        int innerCompression,
        byte* outPath,
        int outPathCapacity)
    {
        try
        {
            var options = new ProsperoBuildOptions
            {
                SourceFolder = Utf8ToString(sourceFolder) ?? "",
                OutputFolder = Utf8ToString(outputFolder) ?? "",
                ContentId = Utf8ToString(contentId) ?? "",
                Passcode = Fallback(Utf8ToString(passcode), new string('0', 32)),
                Title = Utf8ToString(title) ?? "",
                TitleId = Utf8ToString(titleId) ?? "",
                Version = Fallback(Utf8ToString(version), "01.00"),
                Mode = ToEnum<ProsperoPackageMode>(mode),
                OutputFormat = ToEnum<ProsperoOutputFormat>(outputFormat),
                InnerCompression = ToEnum<ProsperoInnerCompression>(innerCompression),
            };

            ProsperoBuildResult result = ProsperoPackageBuilder.Build(options);
            int written = WriteUtf8(result.OutputPath, outPath, outPathCapacity);
            return written < 0 ? written : 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Builds a package from a prepared source folder using the full option set carried by
    /// <paramref name="options"/> (application type, fake-signing, param.json generation, inner
    /// compression, badge and DRM overrides). The output path is written into
    /// <paramref name="outPath"/> as UTF-8.
    /// </summary>
    /// <returns>0 on success; a negative value on failure (call lpp_last_error for the message).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_build_package_ex")]
    public static int BuildPackageEx(LppBuildOptions* options, byte* outPath, int outPathCapacity)
    {
        try
        {
            if (options is null)
            {
                _lastError = "options pointer is null";
                return -1;
            }

            LppBuildOptions o = *options;
            var build = new ProsperoBuildOptions
            {
                SourceFolder = Utf8ToString(o.SourceFolder) ?? "",
                OutputFolder = Utf8ToString(o.OutputFolder) ?? "",
                ContentId = Utf8ToString(o.ContentId) ?? "",
                Passcode = Fallback(Utf8ToString(o.Passcode), new string('0', 32)),
                Title = Utf8ToString(o.Title) ?? "",
                TitleId = Utf8ToString(o.TitleId) ?? "",
                Version = Fallback(Utf8ToString(o.Version), "01.00"),
                Mode = ToEnum<ProsperoPackageMode>(o.Mode),
                OutputFormat = ToEnum<ProsperoOutputFormat>(o.OutputFormat),
                InnerCompression = ToEnum<ProsperoInnerCompression>(o.InnerCompression),
                ApplicationType = ToEnum<ProsperoApplicationType>(o.ApplicationType),
                GenerateParamJsonIfMissing = o.GenerateParamJson != 0,
                CompressInnerImage = o.CompressInnerImage != 0,
                FakeSignSelfModules = o.FakeSignSelf != 0,
            };

            string? drm = Utf8ToString(o.ApplicationDrmType);
            if (!string.IsNullOrEmpty(drm))
                build.ApplicationDrmType = drm;

            if (o.ContentBadgeType >= 0)
                build.ContentBadgeType = o.ContentBadgeType;

            if (o.FakeSignSelf != 0)
                build.FselfOptions = FselfOptionsFrom(o.AppVersion, o.FirmwareVersion, o.AuthorityId, o.HasAuthorityId);

            ProsperoBuildResult result = ProsperoPackageBuilder.Build(build);
            int written = WriteUtf8(result.OutputPath, outPath, outPathCapacity);
            return written < 0 ? written : 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Detects the package type of the file at <paramref name="path"/>.
    /// </summary>
    /// <returns>
    /// The package type as an integer (0 = Meta, 1 = FullRetail, 2 = FullDebug), or -1 when the
    /// file is not a recognized package or cannot be read (call lpp_last_error for details).
    /// </returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_detect_package_type")]
    public static int DetectPackageType(byte* path)
    {
        try
        {
            ProsperoPkgType? type = ProsperoPkgReader.DetectType(Utf8ToString(path) ?? "");
            return type is null ? -1 : (int)type.Value;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Lays a prepared folder out into an inner-PFS image. <paramref name="form"/> selects the
    /// image form (0 = Plaintext, 1 = Encrypted, 2 = Compressed zlib, 3 = KrakenCompressed). The
    /// written image path is copied into <paramref name="outPath"/> as UTF-8.
    /// </summary>
    /// <returns>0 on success; a negative value on failure (call lpp_last_error for the message).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_build_inner_image")]
    public static int BuildInnerImage(
        byte* sourceFolder,
        byte* outputPath,
        byte* contentId,
        byte* passcode,
        int form,
        byte* outPath,
        int outPathCapacity)
    {
        try
        {
            string result = ProsperoPackageBuilder.BuildInnerImage(
                Utf8ToString(sourceFolder) ?? "",
                Utf8ToString(outputPath) ?? "",
                Utf8ToString(contentId) ?? "",
                Fallback(Utf8ToString(passcode), new string('0', 32)),
                ToEnum<InnerImageForm>(form));
            int written = WriteUtf8(result, outPath, outPathCapacity);
            return written < 0 ? written : 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// AES-XTS-encrypts a prepared plaintext inner-PFS image in place, using keys derived from the
    /// content id and passcode.
    /// </summary>
    /// <returns>0 on success; a negative value on failure (call lpp_last_error for the message).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_encrypt_pfs_image")]
    public static int EncryptPfsImage(byte* pfsImagePath, byte* contentId, byte* passcode)
    {
        try
        {
            ProsperoPackageBuilder.EncryptPfsImage(
                Utf8ToString(pfsImagePath) ?? "",
                Utf8ToString(contentId) ?? "",
                Fallback(Utf8ToString(passcode), new string('0', 32)));
            return 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Packs a plaintext PFS image into a PFSv3 PFSC container using Kraken. A non-positive
    /// <paramref name="level"/> or <paramref name="blockSize"/> selects the default (7 / 262144).
    /// </summary>
    /// <returns>0 on success; a negative value on failure (call lpp_last_error for the message).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_pack_pfs_image")]
    public static int PackPfsImage(byte* inputImagePath, byte* outputPath, int level, int blockSize)
    {
        try
        {
            ProsperoCompressedPfsImage.PackFile(
                Utf8ToString(inputImagePath) ?? "",
                Utf8ToString(outputPath) ?? "",
                level > 0 ? level : ProsperoCompressedPfsImage.DefaultLevel,
                blockSize > 0 ? blockSize : ProsperoCompressedPfsImage.DefaultBlockSize);
            return 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Unpacks a PFSv3 PFSC container back into a plaintext PFS image.
    /// </summary>
    /// <returns>The number of bytes written on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_unpack_pfs_image")]
    public static long UnpackPfsImage(byte* inputPath, byte* outputPath)
    {
        try
        {
            return ProsperoCompressedPfsImage.UnpackFile(
                Utf8ToString(inputPath) ?? "",
                Utf8ToString(outputPath) ?? "");
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>Returns 1 when the buffer holds a SELF container, otherwise 0.</summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_is_self")]
    public static int IsSelf(byte* data, int length)
        => ProsperoFself.IsSelf(AsSpan(data, length)) ? 1 : 0;

    /// <summary>Returns 1 when the buffer holds a 64-bit ELF, otherwise 0.</summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_is_elf")]
    public static int IsElf(byte* data, int length)
        => ProsperoFself.IsElf(AsSpan(data, length)) ? 1 : 0;

    /// <summary>Returns 1 when the buffer holds a UCP archive, otherwise 0.</summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_is_ucp")]
    public static int IsUcp(byte* data, int length)
        => ProsperoUcp.IsUcp(AsSpan(data, length)) ? 1 : 0;

    /// <summary>
    /// Reads the SELF extended-info and segment count from an in-memory SELF module. Any output
    /// pointer may be NULL. When the module carries no extended-info block, the ext-info outputs
    /// are zero-filled and the call still succeeds.
    /// </summary>
    /// <returns>0 on success; -1 when the buffer is not a valid SELF (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_read_self_info")]
    public static int ReadSelfInfo(
        byte* data,
        int length,
        ulong* authorityId,
        ulong* programType,
        ulong* appVersion,
        ulong* firmwareVersion,
        byte* digest32,
        int* segmentCount)
    {
        try
        {
            if (data is null || length <= 0)
            {
                _lastError = "empty SELF input";
                return -1;
            }

            SelfImage image = ProsperoFself.Parse(new ReadOnlySpan<byte>(data, length));
            SelfExtInfo? ext = image.ExtInfo;

            if (authorityId is not null) *authorityId = ext?.AuthorityId ?? 0;
            if (programType is not null) *programType = ext?.ProgramType ?? 0;
            if (appVersion is not null) *appVersion = ext?.AppVersion ?? 0;
            if (firmwareVersion is not null) *firmwareVersion = ext?.FirmwareVersion ?? 0;
            if (segmentCount is not null) *segmentCount = image.Segments.Count;

            if (digest32 is not null)
            {
                var dst = new Span<byte>(digest32, 32);
                dst.Clear();
                ext?.Digest.AsSpan(0, Math.Min(32, ext.Digest.Length)).CopyTo(dst);
            }

            return 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Generates a fake-self from a 64-bit ELF. Pass <paramref name="outBuffer"/> = NULL or
    /// <paramref name="capacity"/> = 0 to query the required size (returned as a positive value
    /// without writing).
    /// </summary>
    /// <returns>
    /// The number of bytes written (or required, in query mode); -1 on failure or when a non-zero
    /// buffer is too small (call lpp_last_error for the message).
    /// </returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_make_fself")]
    public static int MakeFself(byte* elf, int elfLength, byte* outBuffer, int capacity)
        => MakeFselfCore(elf, elfLength, null, outBuffer, capacity);

    /// <summary>
    /// Generates a fake-self from a 64-bit ELF with explicit fake-self options (application and
    /// firmware version, and an optional authority-id override). The size-query and buffer
    /// semantics match <see cref="MakeFself"/>.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_make_fself_ex")]
    public static int MakeFselfEx(
        byte* elf,
        int elfLength,
        ulong appVersion,
        ulong firmwareVersion,
        ulong authorityId,
        int hasAuthorityId,
        byte* outBuffer,
        int capacity)
        => MakeFselfCore(elf, elfLength, FselfOptionsFrom(appVersion, firmwareVersion, authorityId, hasAuthorityId), outBuffer, capacity);

    /// <summary>
    /// Reads a 64-bit ELF from <paramref name="elfPath"/>, generates a fake-self and writes it to
    /// <paramref name="outPath"/>. Fake-self options are taken from the version/authority arguments.
    /// </summary>
    /// <returns>The number of bytes written on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_make_fself_file")]
    public static int MakeFselfFile(
        byte* elfPath,
        byte* outPath,
        ulong appVersion,
        ulong firmwareVersion,
        ulong authorityId,
        int hasAuthorityId)
    {
        try
        {
            string? inPath = Utf8ToString(elfPath);
            string? dstPath = Utf8ToString(outPath);
            if (string.IsNullOrEmpty(inPath) || string.IsNullOrEmpty(dstPath))
            {
                _lastError = "elf_path and out_path are required";
                return -1;
            }

            byte[] elf = File.ReadAllBytes(inPath);
            byte[] fself = ProsperoFself.MakeFself(elf, FselfOptionsFrom(appVersion, firmwareVersion, authorityId, hasAuthorityId));
            File.WriteAllBytes(dstPath, fself);
            return fself.Length;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Fake-signs every raw ELF module under <paramref name="sourceFolder"/> in place
    /// (<c>eboot.bin</c>, <c>*.elf</c>, <c>*.prx</c>, <c>*.sprx</c>). Files already SELF are
    /// skipped. This is the standalone form of the build-time fake-sign step.
    /// </summary>
    /// <returns>The number of modules converted; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_fake_sign_folder")]
    public static int FakeSignFolder(
        byte* sourceFolder,
        ulong appVersion,
        ulong firmwareVersion,
        ulong authorityId,
        int hasAuthorityId)
    {
        try
        {
            return ProsperoPackageBuilder.FakeSignModulesInPlace(
                Utf8ToString(sourceFolder) ?? "",
                FselfOptionsFrom(appVersion, firmwareVersion, authorityId, hasAuthorityId));
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>Copies the display name of an application type (LPP_APP_TYPE_*) into a caller buffer.</summary>
    /// <returns>The number of bytes written, or a negative value (see lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_application_type_name")]
    public static int ApplicationTypeName(int applicationType, byte* outBuffer, int capacity)
    {
        try
        {
            string name = ProsperoApplicationTypes.DisplayName(ToEnum<ProsperoApplicationType>(applicationType));
            return WriteUtf8(name, outBuffer, capacity);
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Copies the generated param.json <c>applicationDrmType</c> token (<c>free</c> / <c>standard</c>
    /// / <c>freemium</c>) for an application type (LPP_APP_TYPE_*) into a caller buffer.
    /// </summary>
    /// <returns>The number of bytes written, or a negative value (see lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_application_drm_type")]
    public static int ApplicationDrmType(int applicationType, byte* outBuffer, int capacity)
    {
        try
        {
            string token = ProsperoApplicationTypes.ApplicationDrmType(ToEnum<ProsperoApplicationType>(applicationType));
            return WriteUtf8(token, outBuffer, capacity);
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Parses an application-type display name (case-insensitive) into its code (LPP_APP_TYPE_*).
    /// Unknown or empty input yields <c>LPP_APP_TYPE_NOT_SPECIFIED</c> (0).
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_parse_application_type")]
    public static int ParseApplicationType(byte* name)
        => (int)ProsperoApplicationTypes.Parse(Utf8ToString(name));

    /// <summary>
    /// Reads a SELF authentication-info sidecar (0x88-byte <c>*.auth_info</c>). Any output pointer
    /// may be NULL; <paramref name="capabilities4"/> and <paramref name="attributes4"/> point to four
    /// 64-bit words each, and <paramref name="category"/> receives the authority category byte
    /// (0x31 fake, 0x45 genuine, 0x48 privileged, 0 unknown).
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_read_auth_info")]
    public static int ReadAuthInfo(byte* path, ulong* paid, ulong* capabilities4, ulong* attributes4, int* category)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            ProsperoSelfAuthInfo info = ProsperoSelfAuthInfo.ReadFile(p);
            if (paid is not null) *paid = info.Paid;
            if (capabilities4 is not null)
                for (int i = 0; i < ProsperoSelfAuthInfo.CapabilityWordCount; i++) capabilities4[i] = info.Capabilities[i];
            if (attributes4 is not null)
                for (int i = 0; i < ProsperoSelfAuthInfo.AttributeWordCount; i++) attributes4[i] = info.Attributes[i];
            if (category is not null) *category = (int)info.Category;
            return 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Builds a SELF authentication-info sidecar from supplied fields and writes it to
    /// <paramref name="path"/>. <paramref name="capabilities4"/> and <paramref name="attributes4"/>
    /// each point to four 64-bit words, or may be NULL to write zeroes.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_write_auth_info")]
    public static int WriteAuthInfo(byte* path, ulong paid, ulong* capabilities4, ulong* attributes4)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            Span<ulong> caps = stackalloc ulong[ProsperoSelfAuthInfo.CapabilityWordCount];
            Span<ulong> attrs = stackalloc ulong[ProsperoSelfAuthInfo.AttributeWordCount];
            if (capabilities4 is not null)
                for (int i = 0; i < caps.Length; i++) caps[i] = capabilities4[i];
            if (attributes4 is not null)
                for (int i = 0; i < attrs.Length; i++) attrs[i] = attributes4[i];

            ProsperoSelfAuthInfo.Create(paid, caps, attrs).WriteFile(p);
            return 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Reads and projects the NpDrm content-info of the package at <paramref name="path"/> into
    /// <paramref name="outInfo"/> (title/content id, DRM and content type, flags, patch kind, nested
    /// and finalized markers, and the metadata-container offset).
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_read_npdrm_content_info")]
    public static int ReadNpDrmContentInfo(byte* path, LppNpDrmContentInfo* outInfo)
    {
        try
        {
            if (outInfo is null) { _lastError = "output pointer is null"; return -1; }
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            ProsperoNpDrmContentInfo ci = ProsperoNpDrmContentInfo.Read(p);
            LppNpDrmContentInfo o = default;
            o.StructSize = sizeof(LppNpDrmContentInfo);
            o.DrmType = ci.DrmType;
            o.ContentType = ci.ContentType;
            o.ContentFlags = ci.ContentFlags;
            o.PatchKind = (int)ci.PatchKind;
            o.IsPatch = ci.IsPatch ? 1 : 0;
            o.IsNested = ci.IsNestedImage ? 1 : 0;
            o.IsFinalized = ci.IsFinalized ? 1 : 0;
            o.ContainerOffset = ci.ContainerOffset;
            *outInfo = o;
            WriteUtf8Fixed(ci.ContentId, outInfo->ContentId, 64);
            WriteUtf8Fixed(ci.TitleId, outInfo->TitleId, 16);
            return 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Inspects the package at <paramref name="path"/> without a key, filling <paramref name="outInfo"/>
    /// with the package type, retail flag, outer-PFS offset and size, encryption state, whether a
    /// supplied key is required, and the content id when present.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_inspect_package")]
    public static int InspectPackage(byte* path, LppPackageInfo* outInfo)
    {
        try
        {
            if (outInfo is null) { _lastError = "output pointer is null"; return -1; }
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            ProsperoPackageExtractionInfo info = ProsperoPackageExtractor.Inspect(p);
            LppPackageInfo o = default;
            o.StructSize = sizeof(LppPackageInfo);
            o.PackageType = (int)info.PackageType;
            o.IsRetail = info.IsRetail ? 1 : 0;
            o.OuterEncrypted = info.OuterEncrypted ? 1 : 0;
            o.RequiresKey = info.RequiresSuppliedKey ? 1 : 0;
            o.PfsImageOffset = info.PfsImageOffset;
            o.PfsImageSize = info.PfsImageSize;
            *outInfo = o;
            WriteUtf8Fixed(info.ContentId, outInfo->ContentId, 64);
            return 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Extracts a package to <paramref name="outputDirectory"/>, deriving the outer key from
    /// <paramref name="passcode"/> (and the package's own content id). A NULL or empty passcode uses
    /// the 32-zero default. Set <paramref name="extractOuter"/> non-zero to also write the outer
    /// metadata files.
    /// </summary>
    /// <returns>The number of extracted files on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_extract_package")]
    public static int ExtractPackage(byte* path, byte* outputDirectory, byte* passcode, int extractOuter)
    {
        try
        {
            string? p = Utf8ToString(path);
            string? dst = Utf8ToString(outputDirectory);
            if (string.IsNullOrEmpty(p) || string.IsNullOrEmpty(dst))
            {
                _lastError = "path and output_directory are required";
                return -1;
            }

            var key = ProsperoExtractionKey.FromPasscode(Fallback(Utf8ToString(passcode), new string('0', 32)));
            var options = new ProsperoExtractionOptions { ExtractOuterMetadata = extractOuter != 0 };
            ProsperoPackageManifest manifest = ProsperoPackageExtractor.Extract(p, dst, key, options);
            return manifest.ExtractedFileCount;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Extracts a package to <paramref name="outputDirectory"/> using a supplied 32-byte outer key
    /// (<paramref name="ekpfs32"/>). Set <paramref name="extractOuter"/> non-zero to also write the
    /// outer metadata files.
    /// </summary>
    /// <returns>The number of extracted files on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_extract_package_ekpfs")]
    public static int ExtractPackageEkpfs(byte* path, byte* outputDirectory, byte* ekpfs32, int extractOuter)
    {
        try
        {
            string? p = Utf8ToString(path);
            string? dst = Utf8ToString(outputDirectory);
            if (string.IsNullOrEmpty(p) || string.IsNullOrEmpty(dst))
            {
                _lastError = "path and output_directory are required";
                return -1;
            }
            if (ekpfs32 is null) { _lastError = "ekpfs pointer is null"; return -1; }

            var key = ProsperoExtractionKey.FromEkpfs(new ReadOnlySpan<byte>(ekpfs32, 32));
            var options = new ProsperoExtractionOptions { ExtractOuterMetadata = extractOuter != 0 };
            ProsperoPackageManifest manifest = ProsperoPackageExtractor.Extract(p, dst, key, options);
            return manifest.ExtractedFileCount;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>Counts the records in a RIF license file (<c>n_rif</c>).</summary>
    /// <returns>The record count on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_rif_record_count")]
    public static int RifRecordCount(byte* path)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }
            return ProsperoRif.ReadAll(p).Count;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>Copies the content id of the first record in a RIF file into a caller buffer.</summary>
    /// <returns>The number of bytes written, or a negative value (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_read_rif_content_id")]
    public static int ReadRifContentId(byte* path, byte* outBuffer, int capacity)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            var records = ProsperoRif.ReadAll(p);
            if (records.Count == 0) { _lastError = "no records in rif"; return -1; }
            return WriteUtf8(records[0].ContentId, outBuffer, capacity);
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Summarizes a multi-content RIF file into <paramref name="outSummary"/> (record count, the
    /// application record's presence/content id/service label, additional-content count, and the
    /// expected vs actual file size). <paramref name="appTitleId"/> may be NULL to skip the app match.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_read_rif_summary")]
    public static int ReadRifSummary(byte* path, byte* appTitleId, LppRifSummary* outSummary)
    {
        try
        {
            if (outSummary is null) { _lastError = "output pointer is null"; return -1; }
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            ProsperoRifSet set = ProsperoRifSet.ReadFile(p);
            ProsperoRifSetSummary s = set.Summarize(Utf8ToString(appTitleId));
            LppRifSummary o = default;
            o.StructSize = sizeof(LppRifSummary);
            o.RecordCount = s.RecordCount;
            o.HasApp = s.HasApp ? 1 : 0;
            o.AdditionalCount = s.AdditionalContentCount;
            o.ExpectedSize = s.ExpectedSize;
            o.ActualSize = s.ActualSize;
            *outSummary = o;
            WriteUtf8Fixed(s.AppContentId, outSummary->AppContentId, 64);
            WriteUtf8Fixed(s.ServiceId, outSummary->ServiceId, 16);
            return 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Runs the structural acceptance-gate checks on the package at <paramref name="path"/>.
    /// <paramref name="expectedContentId"/> may be NULL to skip the content-id match. The pass,
    /// warning and fail counts are written to the output pointers when non-NULL.
    /// </summary>
    /// <returns>1 when accepted (no failing check), 0 when rejected, -1 on error (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_validate_package")]
    public static int ValidatePackage(byte* path, byte* expectedContentId, int* passCount, int* warnCount, int* failCount)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            ProsperoAcceptanceReport report = ProsperoPkgValidator.Validate(p, Utf8ToString(expectedContentId));
            int pass = 0, warn = 0, fail = 0;
            foreach (ProsperoAcceptanceCheck c in report.Checks)
            {
                switch (c.Status)
                {
                    case ProsperoCheckStatus.Pass: pass++; break;
                    case ProsperoCheckStatus.Warning: warn++; break;
                    case ProsperoCheckStatus.Fail: fail++; break;
                }
            }
            if (passCount is not null) *passCount = pass;
            if (warnCount is not null) *warnCount = warn;
            if (failCount is not null) *failCount = fail;
            return report.Accepted ? 1 : 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Reassembles a split disc-backup package (from an <c>app.json</c> path or a directory that
    /// contains one) into a single package file at <paramref name="outputPath"/>.
    /// </summary>
    /// <returns>The number of bytes written on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_disc_backup_reassemble")]
    public static long DiscBackupReassemble(byte* manifestPath, byte* outputPath)
    {
        try
        {
            string? m = Utf8ToString(manifestPath);
            string? o = Utf8ToString(outputPath);
            if (string.IsNullOrEmpty(m) || string.IsNullOrEmpty(o))
            {
                _lastError = "manifest_path and output_path are required";
                return -1;
            }

            ProsperoDiscBackup backup = ProsperoDiscBackup.Open(m);
            return backup.ReassembleTo(o);
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    /// <summary>
    /// Verifies a split disc-backup package. The package-digest and chunk-CRC results are written to
    /// the output pointers (1 = match, 0 = mismatch) when non-NULL.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_disc_backup_verify")]
    public static int DiscBackupVerify(byte* manifestPath, int* digestOk, int* chunkCrcOk)
    {
        try
        {
            string? m = Utf8ToString(manifestPath);
            if (string.IsNullOrEmpty(m)) { _lastError = "manifest_path is required"; return -1; }

            ProsperoDiscBackup backup = ProsperoDiscBackup.Open(m);
            if (digestOk is not null) *digestOk = backup.VerifyPackageDigest() ? 1 : 0;
            if (chunkCrcOk is not null) *chunkCrcOk = backup.VerifyChunkCrcHash() ? 1 : 0;
            return 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    private static int MakeFselfCore(byte* elf, int elfLength, FselfOptions? options, byte* outBuffer, int capacity)
    {
        try
        {
            if (elf is null || elfLength <= 0)
            {
                _lastError = "empty ELF input";
                return -1;
            }

            byte[] result = ProsperoFself.MakeFself(new ReadOnlySpan<byte>(elf, elfLength).ToArray(), options);
            if (outBuffer is null || capacity <= 0)
                return result.Length;

            if (capacity < result.Length)
            {
                _lastError = $"buffer too small (need {result.Length})";
                return -1;
            }

            result.AsSpan().CopyTo(new Span<byte>(outBuffer, capacity));
            return result.Length;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    private static FselfOptions FselfOptionsFrom(ulong appVersion, ulong firmwareVersion, ulong authorityId, int hasAuthorityId)
        => new FselfOptions
        {
            AppVersion = appVersion,
            FirmwareVersion = firmwareVersion,
            AuthorityId = hasAuthorityId != 0 ? authorityId : null,
        };

    private static ReadOnlySpan<byte> AsSpan(byte* data, int length)
        => data is null || length <= 0 ? default : new ReadOnlySpan<byte>(data, length);

    private static string Fallback(string? value, string fallback)
        => string.IsNullOrEmpty(value) ? fallback : value;

    private static TEnum ToEnum<TEnum>(int value) where TEnum : struct, Enum
    {
        var result = (TEnum)Enum.ToObject(typeof(TEnum), value);
        if (!Enum.IsDefined(result))
            throw new ArgumentOutOfRangeException(nameof(value), value, $"Undefined {typeof(TEnum).Name} value.");
        return result;
    }

    private static string? Utf8ToString(byte* p)
        => p is null ? null : Marshal.PtrToStringUTF8((IntPtr)p);

    private static int WriteUtf8(string value, byte* buffer, int capacity)
    {
        if (buffer is null || capacity <= 0)
            return -1;

        int needed = Encoding.UTF8.GetByteCount(value);
        if (needed + 1 > capacity)
            return -(needed + 1); // caller must retry with at least this many bytes

        var span = new Span<byte>(buffer, capacity);
        int written = Encoding.UTF8.GetBytes(value, span);
        span[written] = 0;
        return written;
    }

    /// <summary>
    /// Writes a NUL-terminated UTF-8 string into a fixed-size buffer, clearing it first and
    /// truncating (leaving room for the terminator) when the value does not fit.
    /// </summary>
    private static void WriteUtf8Fixed(string? value, byte* destination, int size)
    {
        var span = new Span<byte>(destination, size);
        span.Clear();
        if (string.IsNullOrEmpty(value) || size <= 1)
            return;

        int needed = Encoding.UTF8.GetByteCount(value);
        if (needed + 1 <= size)
        {
            int written = Encoding.UTF8.GetBytes(value, span);
            span[written] = 0;
            return;
        }

        byte[] bytes = Encoding.UTF8.GetBytes(value);
        bytes.AsSpan(0, size - 1).CopyTo(span);
        span[size - 1] = 0;
    }

    private static byte* AllocUtf8(string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        byte* p = (byte*)NativeMemory.Alloc((nuint)(bytes.Length + 1));
        for (int i = 0; i < bytes.Length; i++)
            p[i] = bytes[i];
        p[bytes.Length] = 0;
        return p;
    }
}
