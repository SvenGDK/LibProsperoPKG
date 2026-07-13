// C ABI surface for the shared-library builds.
//
// This file is NOT part of the normal managed build. It lives outside the project
// directory so the SDK never compiles it into the class library or its package. The
// build workflows copy it into the project directory and enable shared-library
// output before publishing, so the exported entry points only exist in the .so/.dylib
// artifacts.
//
// Every export uses UnmanagedCallersOnly so the compiler emits a plain C symbol.
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
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using LibProsperoPkg;
using LibProsperoPkg.Content;
using LibProsperoPkg.DiscBackup;
using LibProsperoPkg.GP5;
using LibProsperoPkg.License;
using LibProsperoPkg.Metadata;
using LibProsperoPkg.NpDrm;
using LibProsperoPkg.PFS;
using LibProsperoPkg.PFS.Compression;
using LibProsperoPkg.PKG;
using LibProsperoPkg.PlayGo;

namespace LibProsperoPkg.Native;

/// <summary>
/// Blittable mirror of the C <c>lpp_build_options</c> struct. Passed by pointer to
/// <see cref="NativeExports.BuildPackageEx"/>. The layout must match libprosperopkg.h exactly:
/// ten 32-bit integers, three 64-bit integers, the UTF-8 string pointers, then a trailing
/// 32-bit integer. Fields are only appended, so an older caller's <c>StructSize</c> guards
/// access to newer trailing fields.
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

    public int LicenseFree;        // 0/1 (DRM/license-free debug package: fake-sign + free bucket)
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

/// <summary>
/// Blittable mirror of the C <c>lpp_package_summary</c> struct filled by
/// <see cref="NativeExports.ReadPackageSummary"/>. The layout must match libprosperopkg.h exactly.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct LppPackageSummary
{
    public int StructSize;
    public int PackageType;      // LPP_TYPE_*
    public int IsOfficial;       // 0/1
    public int FihFormatVersion;
    public uint Flags;
    public uint EntryCount;
    public uint ScEntryCount;
    public uint DrmType;
    public uint ContentType;
    public uint ContentFlags;
    public long PfsImageOffset;
    public long PfsImageSize;
    public long EmbeddedCntOffset;
    public fixed byte ContentId[64];
}

/// <summary>
/// Blittable mirror of the C <c>lpp_package_entry</c> struct filled by
/// <see cref="NativeExports.ReadPackageEntry"/>. The layout must match libprosperopkg.h exactly.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct LppPackageEntry
{
    public int StructSize;
    public uint RawId;
    public int Id;               // LPP_ENTRY_*
    public uint Flags1;
    public uint Flags2;
    public uint DataOffset;
    public uint DataSize;
    public int Encrypted;        // 0/1
    public uint KeyIndex;
    public fixed byte Name[64];
}

/// <summary>
/// Blittable mirror of the C <c>lpp_elf_info</c> struct filled by
/// <see cref="NativeExports.ReadElfHeader"/>. The layout must match libprosperopkg.h exactly.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct LppElfInfo
{
    public int StructSize;
    public int Class;
    public int Data;
    public int OsAbi;
    public int AbiVersion;
    public int Type;
    public int Machine;
    public ulong Entry;
    public uint Flags;
    public int ProgramHeaderCount;
    public int IsExecutable;     // 0/1
    public int IsDynamic;        // 0/1
    public int IsModuleType;     // 0/1
    public int IsModuleReady;    // 0/1
}

/// <summary>
/// Blittable mirror of the C <c>lpp_launch_readiness</c> struct filled by
/// <see cref="NativeExports.InspectLaunchReadiness"/>. The layout must match libprosperopkg.h exactly.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct LppLaunchReadiness
{
    public int StructSize;
    public int HasEboot;             // 0/1
    public int HasParamJson;         // 0/1
    public int HasParamSfo;          // 0/1
    public int RequiresDebugConsole; // 0/1
    public int IsLaunchReady;        // 0/1
    public int ModuleCount;
    public int IssueCount;
}

internal static unsafe class NativeExports
{
    // Bump when the exported surface changes in a way consumers can gate on.
    private const int AbiVersionValue = 7;

    [ThreadStatic]
    private static string? _lastError;

    private static readonly byte* VersionPtr = AllocUtf8("LibProsperoPkg 2.0.0");

    /// <summary>Returns a pointer to a static, NUL-terminated version string.</summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_version")]
    public static byte* Version() => VersionPtr;

    /// <summary>Returns the numeric ABI version of the exported surface.</summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_abi_version")]
    public static int AbiVersion() => AbiVersionValue;

    /// <summary>
    /// Returns 1 when the wired-in publishing key material is present, so the build path can sign the
    /// package; returns 0 when it is absent and signing is skipped. Never fails.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_keys_available")]
    public static int KeysAvailable() => ProsperoPackageBuilder.KeysAvailable ? 1 : 0;

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

            if (o.StructSize >= sizeof(LppBuildOptions) && o.LicenseFree != 0)
                build.LicenseFree = true;

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
    /// Runs the structural acceptance-gate checks on the package at <paramref name="path"/> and writes
    /// each check as one line (<c>[Status] Name: Detail</c>) into <paramref name="outBuffer"/>.
    /// <paramref name="expectedContentId"/> may be NULL to skip the content-id match.
    /// </summary>
    /// <returns>The number of bytes written, or a negative value (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_validate_package_report")]
    public static int ValidatePackageReport(byte* path, byte* expectedContentId, byte* outBuffer, int capacity)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            ProsperoAcceptanceReport report = ProsperoPkgValidator.Validate(p, Utf8ToString(expectedContentId));
            var sb = new StringBuilder();
            for (int i = 0; i < report.Checks.Count; i++)
            {
                ProsperoAcceptanceCheck c = report.Checks[i];
                if (i > 0) sb.Append('\n');
                sb.Append('[').Append(c.Status).Append("] ").Append(c.Name).Append(": ").Append(c.Detail);
            }
            return WriteUtf8(sb.ToString(), outBuffer, capacity);
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

    /// <summary>
    /// Converts a decrypted application backup into a debug package. Substitutes each signed
    /// executable with its raw ELF from the decrypted subtree, fake-signs the modules, and builds a
    /// debug image whose mount key derives from the content id and passcode. <paramref name="contentId"/>
    /// and <paramref name="version"/> may be NULL/empty to take them from the backup's param.json;
    /// <paramref name="passcode"/> may be NULL/empty for the all-zero default. The substituted-module
    /// count is written to <paramref name="substitutedCount"/> when non-NULL. The output path is
    /// written into <paramref name="outPath"/> as UTF-8.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_convert_backup")]
    public static int ConvertBackup(
        byte* backupFolder,
        byte* outputFolder,
        byte* contentId,
        byte* passcode,
        byte* version,
        int* substitutedCount,
        byte* outPath,
        int outPathCapacity)
    {
        try
        {
            string? b = Utf8ToString(backupFolder);
            string? o = Utf8ToString(outputFolder);
            if (string.IsNullOrEmpty(b) || string.IsNullOrEmpty(o))
            {
                _lastError = "backup_folder and output_folder are required";
                return -1;
            }

            var options = new ProsperoBackupConversionOptions
            {
                BackupFolder = b,
                OutputFolder = o,
                ContentId = Utf8ToString(contentId) ?? "",
                Passcode = Fallback(Utf8ToString(passcode), new string('0', 32)),
                Version = Utf8ToString(version) ?? "",
            };

            ProsperoBackupConversionResult result = ProsperoBackupConverter.Convert(options);
            if (substitutedCount is not null) *substitutedCount = result.SubstitutedModules.Count;
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
    /// Converts a decrypted application backup into a debug package with the full option set. Extends
    /// <see cref="ConvertBackup"/> with the name of the decrypted-module subtree
    /// (<paramref name="decryptedSubfolder"/>, NULL/empty for <c>decrypted</c>), a flag to drop the
    /// backup's own <c>right.sprx</c> so the embedded debug module is injected instead
    /// (<paramref name="useEmbeddedRightSprx"/>), and the inner-image codec
    /// (<paramref name="innerCompression"/>, LPP_INNER_*). The substituted, plaintext and unresolved
    /// module counts are written to the output pointers when non-NULL. The output path is written into
    /// <paramref name="outPath"/> as UTF-8.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_convert_backup_ex")]
    public static int ConvertBackupEx(
        byte* backupFolder,
        byte* outputFolder,
        byte* contentId,
        byte* passcode,
        byte* version,
        byte* decryptedSubfolder,
        int useEmbeddedRightSprx,
        int innerCompression,
        int* substitutedCount,
        int* plaintextCount,
        int* unresolvedCount,
        byte* outPath,
        int outPathCapacity)
    {
        try
        {
            string? b = Utf8ToString(backupFolder);
            string? o = Utf8ToString(outputFolder);
            if (string.IsNullOrEmpty(b) || string.IsNullOrEmpty(o))
            {
                _lastError = "backup_folder and output_folder are required";
                return -1;
            }

            var options = new ProsperoBackupConversionOptions
            {
                BackupFolder = b,
                OutputFolder = o,
                ContentId = Utf8ToString(contentId) ?? "",
                Passcode = Fallback(Utf8ToString(passcode), new string('0', 32)),
                Version = Utf8ToString(version) ?? "",
                UseEmbeddedRightSprx = useEmbeddedRightSprx != 0,
                InnerCompression = ToEnum<ProsperoInnerCompression>(innerCompression),
            };

            string? sub = Utf8ToString(decryptedSubfolder);
            if (!string.IsNullOrEmpty(sub))
                options.DecryptedSubfolder = sub;

            ProsperoBackupConversionResult result = ProsperoBackupConverter.Convert(options);
            if (substitutedCount is not null) *substitutedCount = result.SubstitutedModules.Count;
            if (plaintextCount is not null) *plaintextCount = result.PlaintextModules.Count;
            if (unresolvedCount is not null) *unresolvedCount = result.UnresolvedModules.Count;
            int written = WriteUtf8(result.OutputPath, outPath, outPathCapacity);
            return written < 0 ? written : 0;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return -1;
        }
    }

    // ---- Package read model -----------------------------------------------------------------

    /// <summary>
    /// Reads a package and fills <paramref name="outInfo"/> with header and image-header fields:
    /// package type, entry counts, DRM/content type and flags, content id, and PFS image offset,
    /// size, and embedded container offset.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_read_package_summary")]
    public static int ReadPackageSummary(byte* path, LppPackageSummary* outInfo)
    {
        try
        {
            if (outInfo is null) { _lastError = "output pointer is null"; return -1; }
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            ProsperoPkg pkg = ProsperoPkgReader.Read(p);
            LppPackageSummary o = default;
            o.StructSize = sizeof(LppPackageSummary);
            o.PackageType = (int)pkg.Type;
            o.IsOfficial = pkg.Fih?.IsOfficial == true ? 1 : 0;
            o.FihFormatVersion = pkg.Fih?.FormatVersion ?? 0;
            o.Flags = pkg.Header?.Flags ?? 0u;
            o.EntryCount = pkg.Header?.EntryCount ?? (uint)pkg.Entries.Count;
            o.ScEntryCount = (uint)(pkg.Header?.ScEntryCount ?? 0);
            o.DrmType = pkg.Header?.DrmType ?? 0u;
            o.ContentType = pkg.Header?.ContentType ?? 0u;
            o.ContentFlags = pkg.Header?.ContentFlags ?? 0u;
            o.PfsImageOffset = (long)(pkg.Fih?.PfsImageOffset ?? 0UL);
            o.PfsImageSize = (long)(pkg.Fih?.PfsImageSize ?? 0UL);
            o.EmbeddedCntOffset = (long)(pkg.Fih?.EmbeddedCntOffset ?? 0UL);
            *outInfo = o;
            WriteUtf8Fixed(pkg.Header?.ContentId ?? "", outInfo->ContentId, 64);
            return 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>Reads a package and returns its entry count.</summary>
    /// <returns>The number of entries, or -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_package_entry_count")]
    public static int PackageEntryCount(byte* path)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }
            return ProsperoPkgReader.Read(p).Entries.Count;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Reads a single entry (by zero-based index) into <paramref name="outEntry"/>: id, raw id,
    /// flags, data offset and size, encryption flag, key index, and name.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_read_package_entry")]
    public static int ReadPackageEntry(byte* path, int index, LppPackageEntry* outEntry)
    {
        try
        {
            if (outEntry is null) { _lastError = "output pointer is null"; return -1; }
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            ProsperoPkg pkg = ProsperoPkgReader.Read(p);
            if (index < 0 || index >= pkg.Entries.Count) { _lastError = "entry index out of range"; return -1; }

            ProsperoPkgEntry e = pkg.Entries[index];
            LppPackageEntry o = default;
            o.StructSize = sizeof(LppPackageEntry);
            o.RawId = e.RawId;
            o.Id = (int)e.Id;
            o.Flags1 = e.Flags1;
            o.Flags2 = e.Flags2;
            o.DataOffset = e.DataOffset;
            o.DataSize = e.DataSize;
            o.Encrypted = e.Encrypted ? 1 : 0;
            o.KeyIndex = e.KeyIndex;
            *outEntry = o;
            WriteUtf8Fixed(e.Name ?? "", outEntry->Name, 64);
            return 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Lists the inner files of a package (newline-separated relative paths) using a passcode.
    /// <paramref name="passcode"/> may be NULL/empty for the all-zero default.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_list_package_files")]
    public static int ListPackageFiles(byte* path, byte* passcode, byte* outBuffer, int capacity)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            ProsperoExtractionKey key = ProsperoExtractionKey.FromPasscode(Fallback(Utf8ToString(passcode), new string('0', 32)));
            return WriteUtf8(JoinRelativePaths(ProsperoPackageExtractor.ListFiles(p, key)), outBuffer, capacity);
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Lists the inner files of a package (newline-separated relative paths) using a 32-byte
    /// image key supplied at <paramref name="ekpfs32"/>.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_list_package_files_ekpfs")]
    public static int ListPackageFilesEkpfs(byte* path, byte* ekpfs32, byte* outBuffer, int capacity)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }
            if (ekpfs32 is null) { _lastError = "ekpfs pointer is null"; return -1; }

            ProsperoExtractionKey key = ProsperoExtractionKey.FromEkpfs(new ReadOnlySpan<byte>(ekpfs32, 32));
            return WriteUtf8(JoinRelativePaths(ProsperoPackageExtractor.ListFiles(p, key)), outBuffer, capacity);
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Compares two metadata containers and writes the differences (newline-separated) into
    /// <paramref name="outBuffer"/>. An empty result means the containers match.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_compare_containers")]
    public static int CompareContainers(byte* referencePath, byte* candidatePath, byte* outBuffer, int capacity)
    {
        try
        {
            string? r = Utf8ToString(referencePath);
            string? c = Utf8ToString(candidatePath);
            if (string.IsNullOrEmpty(r) || string.IsNullOrEmpty(c))
            { _lastError = "reference and candidate paths are required"; return -1; }

            IReadOnlyList<string> diffs = ProsperoPackageBuilder.CompareContainers(r, c);
            return WriteUtf8(string.Join('\n', diffs), outBuffer, capacity);
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Merges every split package found in <paramref name="inputDir"/> and writes the resulting
    /// output paths (newline-separated) into <paramref name="outBuffer"/>. Pass a non-zero
    /// <paramref name="computeDigest"/> to compute a SHA-256 for each merged package.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_merge_split_package_dir")]
    public static int MergeSplitPackageDir(byte* inputDir, byte* outputDir, int computeDigest, byte* outBuffer, int capacity)
    {
        try
        {
            string? inDir = Utf8ToString(inputDir);
            if (string.IsNullOrEmpty(inDir)) { _lastError = "input_dir is required"; return -1; }

            IReadOnlyList<ProsperoPkgMergeResult> results =
                ProsperoPkgMerger.MergeDirectory(inDir, Utf8ToString(outputDir), computeDigest != 0);

            var sb = new StringBuilder();
            for (int i = 0; i < results.Count; i++)
            {
                if (i > 0) sb.Append('\n');
                sb.Append(results[i].OutputPath);
            }
            return WriteUtf8(sb.ToString(), outBuffer, capacity);
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    // ---- Packaging and launch readiness -----------------------------------------------------

    /// <summary>
    /// Builds a package from a homebrew folder. <paramref name="contentId"/>, <paramref name="title"/>,
    /// and <paramref name="version"/> may be NULL/empty to take defaults; <paramref name="passcode"/>
    /// may be NULL/empty for the all-zero default; <paramref name="moduleName"/> may be NULL/empty
    /// for "eboot.bin". When non-NULL, <paramref name="outReadiness"/> receives the launch-readiness
    /// summary. The output path is written into <paramref name="outPath"/> as UTF-8.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_package_homebrew")]
    public static int PackageHomebrew(
        byte* homebrewFolder,
        byte* outputFolder,
        byte* contentId,
        byte* passcode,
        byte* title,
        byte* version,
        byte* moduleName,
        int innerCompression,
        LppLaunchReadiness* outReadiness,
        byte* outPath,
        int outPathCapacity)
    {
        try
        {
            string? hb = Utf8ToString(homebrewFolder);
            string? of = Utf8ToString(outputFolder);
            if (string.IsNullOrEmpty(hb) || string.IsNullOrEmpty(of))
            { _lastError = "homebrew_folder and output_folder are required"; return -1; }

            var options = new ProsperoHomebrewPackageOptions
            {
                HomebrewFolder = hb,
                OutputFolder = of,
                ContentId = Utf8ToString(contentId) ?? "",
                Passcode = Fallback(Utf8ToString(passcode), new string('0', 32)),
                Title = Utf8ToString(title) ?? "",
                Version = Utf8ToString(version) ?? "",
                InnerCompression = ToEnum<ProsperoInnerCompression>(innerCompression),
            };
            string? module = Utf8ToString(moduleName);
            if (!string.IsNullOrEmpty(module)) options.ModuleName = module;

            ProsperoHomebrewPackageResult result = ProsperoHomebrewPackager.Package(options);
            if (outReadiness is not null) FillLaunchReadiness(result.LaunchReadiness, outReadiness);
            int written = WriteUtf8(result.OutputPath, outPath, outPathCapacity);
            return written < 0 ? written : 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Inspects an application root and fills <paramref name="outReadiness"/> with its
    /// launch-readiness summary (eboot/param presence, module count, issue count, readiness flag).
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_inspect_launch_readiness")]
    public static int InspectLaunchReadiness(byte* appRoot, LppLaunchReadiness* outReadiness)
    {
        try
        {
            if (outReadiness is null) { _lastError = "output pointer is null"; return -1; }
            string? root = Utf8ToString(appRoot);
            if (string.IsNullOrEmpty(root)) { _lastError = "app_root is required"; return -1; }

            FillLaunchReadiness(ProsperoLaunchReadiness.InspectAppRoot(root), outReadiness);
            return 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Inspects an application root and writes its blocking launch-readiness reasons (newline-separated)
    /// into <paramref name="outBuffer"/>. An empty result means the tree is launch-ready. Pairs with
    /// <see cref="InspectLaunchReadiness"/>, which reports the issue count.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "lpp_launch_readiness_issues")]
    public static int LaunchReadinessIssues(byte* appRoot, byte* outBuffer, int capacity)
    {
        try
        {
            string? root = Utf8ToString(appRoot);
            if (string.IsNullOrEmpty(root)) { _lastError = "app_root is required"; return -1; }

            ProsperoLaunchReadinessReport report = ProsperoLaunchReadiness.InspectAppRoot(root);
            return WriteUtf8(string.Join('\n', report.Issues), outBuffer, capacity);
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    // ---- Inner image / PFS ------------------------------------------------------------------

    /// <summary>
    /// Builds a plaintext inner image layout from a source folder. The file and directory counts
    /// are written to <paramref name="fileCount"/> and <paramref name="directoryCount"/> when
    /// non-NULL; the output path is written into <paramref name="outPath"/> as UTF-8.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_build_pfs_layout")]
    public static int BuildPfsLayout(byte* sourceFolder, byte* outputPath, int* fileCount, int* directoryCount, byte* outPath, int outPathCapacity)
    {
        try
        {
            string? src = Utf8ToString(sourceFolder);
            string? outp = Utf8ToString(outputPath);
            if (string.IsNullOrEmpty(src) || string.IsNullOrEmpty(outp))
            { _lastError = "source_folder and output_path are required"; return -1; }

            ProsperoPfsLayoutResult result = ProsperoPfsLayout.BuildFromFolder(src, outp);
            if (fileCount is not null) *fileCount = result.FileCount;
            if (directoryCount is not null) *directoryCount = result.DirectoryCount;
            int written = WriteUtf8(result.OutputPath, outPath, outPathCapacity);
            return written < 0 ? written : 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>Reports whether an inner image is encrypted.</summary>
    /// <returns>1 when encrypted, 0 when plaintext, -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_pfs_image_is_encrypted")]
    public static int PfsImageIsEncrypted(byte* path)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }
            return ProsperoPfsImage.IsEncrypted(p) ? 1 : 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Decrypts an inner image in place. The image key derives from <paramref name="contentId"/> and
    /// <paramref name="passcode"/> (NULL/empty passcode uses the all-zero default).
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_decrypt_pfs_image")]
    public static int DecryptPfsImage(byte* pfsImagePath, byte* contentId, byte* passcode)
    {
        try
        {
            string? p = Utf8ToString(pfsImagePath);
            if (string.IsNullOrEmpty(p)) { _lastError = "pfs_image_path is required"; return -1; }

            byte[] ekpfs = ProsperoPfsKeys.DeriveEkpfs(Utf8ToString(contentId) ?? "", Fallback(Utf8ToString(passcode), new string('0', 32)));
            ProsperoPfsImage.DecryptInPlace(p, new ProsperoPfsImageOptions { Ekpfs = ekpfs });
            return 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    // ---- ELF --------------------------------------------------------------------------------

    /// <summary>
    /// Reads an ELF header into <paramref name="outInfo"/>: class, data, OS ABI, ABI version, type,
    /// machine, entry, flags, program-header count, and executable/dynamic/module flags.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_read_elf_header")]
    public static int ReadElfHeader(byte* path, LppElfInfo* outInfo)
    {
        try
        {
            if (outInfo is null) { _lastError = "output pointer is null"; return -1; }
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            ProsperoElfHeader h = ProsperoElfHeader.ReadFile(p);
            LppElfInfo o = default;
            o.StructSize = sizeof(LppElfInfo);
            o.Class = (int)h.Class;
            o.Data = (int)h.Data;
            o.OsAbi = h.OsAbi;
            o.AbiVersion = h.AbiVersion;
            o.Type = (int)h.Type;
            o.Machine = h.Machine;
            o.Entry = h.Entry;
            o.Flags = h.Flags;
            o.ProgramHeaderCount = h.ProgramHeaderCount;
            o.IsExecutable = h.IsExecutable ? 1 : 0;
            o.IsDynamic = h.IsDynamic ? 1 : 0;
            o.IsModuleType = h.IsModuleType ? 1 : 0;
            o.IsModuleReady = h.IsModuleReady ? 1 : 0;
            *outInfo = o;
            return 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Normalizes an ELF for use as a module and writes the result to <paramref name="outPath"/>.
    /// When non-NULL, <paramref name="changed"/> receives 1 if any header field changed, otherwise 0.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_normalize_elf_module")]
    public static int NormalizeElfModule(byte* inPath, byte* outPath, int* changed)
    {
        try
        {
            string? ip = Utf8ToString(inPath);
            string? op = Utf8ToString(outPath);
            if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(op))
            { _lastError = "in_path and out_path are required"; return -1; }

            byte[] elf = File.ReadAllBytes(ip);
            ElfNormalizeResult r = ProsperoElfHeader.NormalizeForModule(elf);
            File.WriteAllBytes(op, elf);
            if (changed is not null) *changed = r.Changed ? 1 : 0;
            return 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    // ---- Content protection files -----------------------------------------------------------

    /// <summary>
    /// Validates a content protection file. When non-NULL, <paramref name="errorBuffer"/> receives a
    /// description when the file is invalid.
    /// </summary>
    /// <returns>1 when valid, 0 when invalid, -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_ucp_validate_file")]
    public static int UcpValidateFile(byte* path, byte* errorBuffer, int errorCapacity)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }

            bool ok = ProsperoUcp.Validate(File.ReadAllBytes(p), out string? error);
            if (errorBuffer is not null && errorCapacity > 0)
                WriteUtf8(error ?? "", errorBuffer, errorCapacity);
            return ok ? 1 : 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>Verifies the digest of a content protection file.</summary>
    /// <returns>1 when the digest matches, 0 when it does not, -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_ucp_verify_digest_file")]
    public static int UcpVerifyDigestFile(byte* path)
    {
        try
        {
            string? p = Utf8ToString(path);
            if (string.IsNullOrEmpty(p)) { _lastError = "path is required"; return -1; }
            return ProsperoUcp.VerifyDigest(File.ReadAllBytes(p)) ? 1 : 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>Builds a content protection file from a directory and writes it to <paramref name="outputPath"/>.</summary>
    /// <returns>The number of bytes written, or -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_ucp_build_from_directory")]
    public static long UcpBuildFromDirectory(byte* directory, byte* outputPath)
    {
        try
        {
            string? dir = Utf8ToString(directory);
            string? op = Utf8ToString(outputPath);
            if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(op))
            { _lastError = "directory and output_path are required"; return -1; }

            byte[] ucp = ProsperoUcp.BuildFromDirectory(dir);
            File.WriteAllBytes(op, ucp);
            return ucp.Length;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>Reads a content protection file, repairs its digest, and writes it to <paramref name="outPath"/>.</summary>
    /// <returns>The number of bytes written, or -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_ucp_repair_digest_file")]
    public static long UcpRepairDigestFile(byte* inPath, byte* outPath)
    {
        try
        {
            string? ip = Utf8ToString(inPath);
            string? op = Utf8ToString(outPath);
            if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(op))
            { _lastError = "in_path and out_path are required"; return -1; }

            byte[] repaired = ProsperoUcp.WithRepairedDigest(File.ReadAllBytes(ip));
            File.WriteAllBytes(op, repaired);
            return repaired.Length;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    // ---- License and keys -------------------------------------------------------------------

    /// <summary>
    /// Creates a structural license record for <paramref name="contentId"/> and writes it to
    /// <paramref name="outPath"/>. Pass 0 for <paramref name="expiry"/> to create a non-expiring record.
    /// </summary>
    /// <returns>The number of bytes written, or -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_rif_create")]
    public static long RifCreate(byte* contentId, long expiry, byte* outPath)
    {
        try
        {
            string? cid = Utf8ToString(contentId);
            string? op = Utf8ToString(outPath);
            if (string.IsNullOrEmpty(cid) || string.IsNullOrEmpty(op))
            { _lastError = "content_id and out_path are required"; return -1; }

            ProsperoRif rif = ProsperoRif.Create(cid, null, expiry == 0 ? ProsperoRif.NeverExpires : expiry);
            byte[] bytes = rif.ToBytes();
            File.WriteAllBytes(op, bytes);
            return bytes.Length;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Derives the 32-byte image key from <paramref name="contentId"/> and <paramref name="passcode"/>
    /// (NULL/empty passcode uses the all-zero default) and writes it to <paramref name="out32"/>.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_derive_image_key")]
    public static int DeriveImageKey(byte* contentId, byte* passcode, byte* out32)
    {
        try
        {
            if (out32 is null) { _lastError = "output pointer is null"; return -1; }
            string? cid = Utf8ToString(contentId);
            if (string.IsNullOrEmpty(cid)) { _lastError = "content_id is required"; return -1; }

            byte[] ekpfs = ProsperoPfsKeys.DeriveEkpfs(cid, Fallback(Utf8ToString(passcode), new string('0', 32)));
            new ReadOnlySpan<byte>(ekpfs, 0, Math.Min(32, ekpfs.Length)).CopyTo(new Span<byte>(out32, 32));
            return 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>Validates a 32-hex-character entitlement key.</summary>
    /// <returns>1 when valid, 0 when invalid, -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_entitlement_key_validate")]
    public static int EntitlementKeyValidate(byte* hex)
    {
        try
        {
            string? h = Utf8ToString(hex);
            if (string.IsNullOrEmpty(h)) { _lastError = "hex is required"; return -1; }

            ProsperoEntitlementKey key = ProsperoEntitlementKey.ParseHex(h);
            return key.Validate(out _) ? 1 : 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    // ---- Disc backup ------------------------------------------------------------------------

    /// <summary>
    /// Opens a disc backup from its manifest and fills <paramref name="outInfo"/> with the content
    /// info drawn from the reassembled package.
    /// </summary>
    /// <returns>0 on success; -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_disc_backup_content_info")]
    public static int DiscBackupContentInfo(byte* manifestPath, LppNpDrmContentInfo* outInfo)
    {
        try
        {
            if (outInfo is null) { _lastError = "output pointer is null"; return -1; }
            string? m = Utf8ToString(manifestPath);
            if (string.IsNullOrEmpty(m)) { _lastError = "manifest_path is required"; return -1; }

            ProsperoDiscBackup backup = ProsperoDiscBackup.Open(m);
            ProsperoNpDrmContentInfo ci = backup.ReadContentInfo();
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
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>
    /// Verifies the chunk CRCs of a disc backup. When non-NULL, <paramref name="mismatchChunk"/>
    /// receives the index of the first mismatch (or -1 when all match).
    /// </summary>
    /// <returns>1 when all chunks match, 0 on mismatch, -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_disc_backup_verify_chunk_crcs")]
    public static int DiscBackupVerifyChunkCrcs(byte* manifestPath, int* mismatchChunk)
    {
        try
        {
            string? m = Utf8ToString(manifestPath);
            if (string.IsNullOrEmpty(m)) { _lastError = "manifest_path is required"; return -1; }

            ProsperoDiscBackup backup = ProsperoDiscBackup.Open(m);
            bool ok = backup.VerifyChunkCrcs(out int mismatch);
            if (mismatchChunk is not null) *mismatchChunk = mismatch;
            return ok ? 1 : 0;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    // ---- Auxiliary generators ---------------------------------------------------------------

    /// <summary>Encodes a PNG file to a BC7 DDS texture and writes it to <paramref name="ddsPath"/>.</summary>
    /// <returns>The number of bytes written, or -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_encode_png_to_dds")]
    public static long EncodePngToDds(byte* pngPath, byte* ddsPath)
    {
        try
        {
            string? ip = Utf8ToString(pngPath);
            string? op = Utf8ToString(ddsPath);
            if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(op))
            { _lastError = "png_path and dds_path are required"; return -1; }

            byte[] dds = ProsperoDdsEncoder.EncodePngToDds(File.ReadAllBytes(ip));
            File.WriteAllBytes(op, dds);
            return dds.Length;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>Builds a chunk descriptor file for <paramref name="contentId"/> and writes it to <paramref name="outPath"/>.</summary>
    /// <returns>The number of bytes written, or -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_build_playgo_chunk_dat")]
    public static long BuildPlaygoChunkDat(byte* contentId, byte* outPath)
    {
        try
        {
            string? cid = Utf8ToString(contentId);
            string? op = Utf8ToString(outPath);
            if (string.IsNullOrEmpty(cid) || string.IsNullOrEmpty(op))
            { _lastError = "content_id and out_path are required"; return -1; }

            byte[] data = ProsperoPlayGo.BuildChunkDat(cid);
            File.WriteAllBytes(op, data);
            return data.Length;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>Creates a default param.json for the given ids and writes it to <paramref name="outPath"/>.</summary>
    /// <returns>The number of bytes written, or -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_create_param_json")]
    public static long CreateParamJson(byte* contentId, byte* titleId, byte* titleName, int drmType, byte* outPath)
    {
        try
        {
            string? cid = Utf8ToString(contentId);
            string? tid = Utf8ToString(titleId);
            string? op = Utf8ToString(outPath);
            if (string.IsNullOrEmpty(cid) || string.IsNullOrEmpty(tid) || string.IsNullOrEmpty(op))
            { _lastError = "content_id, title_id and out_path are required"; return -1; }

            ProsperoParam param = ProsperoParam.CreateDefault(cid, tid, Utf8ToString(titleName) ?? "", ToEnum<ProsperoDrmType>(drmType));
            param.Save(op);
            return new FileInfo(op).Length;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    /// <summary>Builds a GP5 project referencing <paramref name="sourceFolder"/> and writes it to
    /// <paramref name="outPath"/>. <paramref name="volumeType"/> selects the volume kind
    /// (0 = application, 1 = patch, 2 = additional content, 3 = additional content without data);
    /// <paramref name="passcode"/> may be empty for the all-zero default.</summary>
    /// <returns>The number of bytes written, or -1 on failure (call lpp_last_error).</returns>
    [UnmanagedCallersOnly(EntryPoint = "lpp_create_gp5")]
    public static long CreateGp5(byte* sourceFolder, byte* outPath, int volumeType, byte* passcode)
    {
        try
        {
            string? src = Utf8ToString(sourceFolder);
            string? op = Utf8ToString(outPath);
            if (string.IsNullOrEmpty(src) || string.IsNullOrEmpty(op))
            { _lastError = "source_folder and out_path are required"; return -1; }

            string pass = Utf8ToString(passcode) is { Length: > 0 } p ? p : new string('0', 32);
            Gp5Project project = Gp5Creator.FromFolder(src, ToEnum<Gp5VolumeType>(volumeType), pass);
            Gp5Project.WriteTo(project, op);
            return new FileInfo(op).Length;
        }
        catch (Exception ex) { _lastError = ex.Message; return -1; }
    }

    private static string JoinRelativePaths(IReadOnlyList<ProsperoExtractedEntry> entries)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < entries.Count; i++)
        {
            if (i > 0) sb.Append('\n');
            sb.Append(entries[i].RelativePath);
        }
        return sb.ToString();
    }

    private static void FillLaunchReadiness(ProsperoLaunchReadinessReport report, LppLaunchReadiness* outReadiness)
    {
        LppLaunchReadiness o = default;
        o.StructSize = sizeof(LppLaunchReadiness);
        o.HasEboot = report.HasEboot ? 1 : 0;
        o.HasParamJson = report.HasParamJson ? 1 : 0;
        o.HasParamSfo = report.HasParamSfo ? 1 : 0;
        o.RequiresDebugConsole = report.RequiresDebugConsole ? 1 : 0;
        o.IsLaunchReady = report.IsLaunchReady ? 1 : 0;
        o.ModuleCount = report.Modules.Count;
        o.IssueCount = report.Issues.Count;
        *outReadiness = o;
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
