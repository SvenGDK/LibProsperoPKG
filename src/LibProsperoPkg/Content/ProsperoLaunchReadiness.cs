// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Launch-readiness inspection for a debug application tree. The console launch service prepares a
// title through a fixed chain: it mounts the application workspace, runs a path/directory check, then
// hands the process to the system-core daemon which loads and starts the modules. Two conditions
// decide whether that chain completes for a self-authored or converted title on a debug-mode console:
// every executable module must be a plaintext module the loader accepts (a fake-authority SELF, or a
// raw ELF the builder fake-signs), and the metadata must be a param.json rather than the older
// param.sfo, which the launch service refuses. This type reads an application root, classifies each
// executable module, and reports whether the tree meets those conditions. It never signs, mounts, or
// launches anything; it only inspects.

#nullable enable
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LibProsperoPkg.Content;

/// <summary>How an executable module presents to the module loader on a debug-mode console.</summary>
public enum ModuleAuthorityKind
{
    /// <summary>The file is neither an ELF nor a SELF container.</summary>
    NotExecutable = 0,

    /// <summary>A raw ELF module. The builder fake-signs it, so it starts on a debug-mode console.</summary>
    RawElf = 1,

    /// <summary>A plaintext SELF whose authority id carries the fake-authority prefix. Starts on a debug-mode console.</summary>
    FakeAuthoritySelf = 2,

    /// <summary>A plaintext SELF whose authority id is a genuine prefix. Relies on the console-provided module.</summary>
    GenuineAuthoritySelf = 3,

    /// <summary>A plaintext SELF whose authority prefix is neither fake nor a known genuine value.</summary>
    UnknownAuthoritySelf = 4,

    /// <summary>A signed and encrypted module. It needs the sealed key path and will not start on a debug-mode console.</summary>
    SignedEncrypted = 5,
}

/// <summary>Launch classification of a single executable module.</summary>
/// <param name="Path">Path of the module, relative to the inspected root.</param>
/// <param name="Kind">How the module presents to the loader.</param>
/// <param name="AuthorityId">The SELF authority id, or 0 when the module is not a SELF.</param>
/// <param name="WillRunOnDebugConsole">Whether the module starts on a debug-mode console as packaged.</param>
/// <param name="Note">A short description of the classification.</param>
public sealed record ModuleLaunchReadiness(
    string Path,
    ModuleAuthorityKind Kind,
    ulong AuthorityId,
    bool WillRunOnDebugConsole,
    string Note);

/// <summary>The launch-readiness report for an application root.</summary>
public sealed class ProsperoLaunchReadinessReport
{
    /// <summary>The inspected application root.</summary>
    public required string AppRoot { get; init; }

    /// <summary>Classification of every executable module found under the root.</summary>
    public required IReadOnlyList<ModuleLaunchReadiness> Modules { get; init; }

    /// <summary>Whether a main <c>eboot.bin</c> is present at the root.</summary>
    public required bool HasEboot { get; init; }

    /// <summary>Whether <c>sce_sys/param.json</c> is present.</summary>
    public required bool HasParamJson { get; init; }

    /// <summary>Whether a <c>sce_sys/param.sfo</c> is present. The launch service refuses this metadata form.</summary>
    public required bool HasParamSfo { get; init; }

    /// <summary>
    /// Whether the tree carries fake-authority or raw modules, which start only on a debug-mode console.
    /// A tree of solely genuine-authority modules does not set this.
    /// </summary>
    public required bool RequiresDebugConsole { get; init; }

    /// <summary>Blocking reasons that keep the tree from starting. Empty when the tree is launch-ready.</summary>
    public required IReadOnlyList<string> Issues { get; init; }

    /// <summary>Whether the tree meets every launch condition.</summary>
    public bool IsLaunchReady => Issues.Count == 0;
}

/// <summary>
/// Reads an application root and reports whether its executable modules and metadata satisfy the
/// console launch conditions for a debug-mode console. See the file header for the model.
/// </summary>
public static class ProsperoLaunchReadiness
{
    private const uint ElfMagic = 0x464C457FU;      // 0x7F 'E' 'L' 'F'
    private const uint SelfMagic = 0x1D3D154FU;     // SELF container magic on disk (fake and genuine alike)

    private const ulong AuthorityMask = 0xFF00000000000000UL;
    private const ulong FakeAuthorityPrefix = 0x3100000000000000UL;
    private const ulong GenuineAuthorityPrefix = 0x4500000000000000UL;

    // A 2 MiB window is larger than any real module header plus segment table, so a classification read
    // never needs the whole of a large module file.
    private const int HeaderWindow = 0x200000;

    // eboot.bin is inspected explicitly by name; the recursive scan looks for the module extensions.
    private static readonly string[] ModuleExtensions = { ".prx", ".sprx" };

    /// <summary>Classifies a single module from its bytes.</summary>
    /// <param name="path">Path recorded on the result.</param>
    /// <param name="data">The module bytes. Only the header region is read.</param>
    public static ModuleLaunchReadiness InspectModule(string path, ReadOnlySpan<byte> data)
    {
        if (data.Length < 4)
            return new ModuleLaunchReadiness(path, ModuleAuthorityKind.NotExecutable, 0, false, "File is too short to classify.");

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(data);

        if (magic == ElfMagic)
            return new ModuleLaunchReadiness(path, ModuleAuthorityKind.RawElf, 0, true,
                "Raw ELF module; the builder fake-signs it, so it starts on a debug-mode console.");

        // On disk a signed/encrypted module and a fake-self carry the same SELF magic; they are told
        // apart by the extended-info authority id, so both route through ClassifySelf. A genuine
        // (non-fake) authority or an unreadable encrypted header is reported as not launch-ready.
        if (magic == SelfMagic)
            return ClassifySelf(path, data);

        return new ModuleLaunchReadiness(path, ModuleAuthorityKind.NotExecutable, 0, false,
            "Not an ELF or SELF module.");
    }

    private static ModuleLaunchReadiness ClassifySelf(string path, ReadOnlySpan<byte> data)
    {
        SelfImage image;
        try
        {
            image = ProsperoFself.Parse(data);
        }
        catch (InvalidDataException ex)
        {
            return new ModuleLaunchReadiness(path, ModuleAuthorityKind.UnknownAuthoritySelf, 0, false,
                $"SELF header could not be parsed: {ex.Message}");
        }

        if (image.ExtInfo is null)
            return new ModuleLaunchReadiness(path, ModuleAuthorityKind.UnknownAuthoritySelf, 0, false,
                "SELF has no extended info; authority id is unavailable.");

        ulong authority = image.ExtInfo.AuthorityId;
        ulong prefix = authority & AuthorityMask;

        if (prefix == FakeAuthorityPrefix)
            return new ModuleLaunchReadiness(path, ModuleAuthorityKind.FakeAuthoritySelf, authority, true,
                "Fake-authority SELF; starts on a debug-mode console.");

        if (prefix == GenuineAuthorityPrefix)
            return new ModuleLaunchReadiness(path, ModuleAuthorityKind.GenuineAuthoritySelf, authority, false,
                "Genuine-authority SELF; relies on the console-provided module and does not start from this package on a debug-mode console.");

        return new ModuleLaunchReadiness(path, ModuleAuthorityKind.UnknownAuthoritySelf, authority, false,
            "SELF authority prefix is neither fake nor a known genuine value.");
    }

    /// <summary>
    /// Inspects an application root (the folder that holds <c>eboot.bin</c> and <c>sce_sys/</c>) and
    /// reports whether it meets the launch conditions for a debug-mode console.
    /// </summary>
    /// <param name="appRoot">The application root folder.</param>
    /// <exception cref="ArgumentException"><paramref name="appRoot"/> is empty or missing.</exception>
    public static ProsperoLaunchReadinessReport InspectAppRoot(string appRoot)
    {
        if (string.IsNullOrWhiteSpace(appRoot) || !Directory.Exists(appRoot))
            throw new ArgumentException("Application root does not exist.", nameof(appRoot));

        string root = Path.GetFullPath(appRoot);
        var modules = new List<ModuleLaunchReadiness>();
        var issues = new List<string>();

        string ebootPath = Path.Combine(root, "eboot.bin");
        bool hasEboot = File.Exists(ebootPath);

        var moduleFiles = new List<string>();
        if (hasEboot)
            moduleFiles.Add(ebootPath);
        moduleFiles.AddRange(Directory
            .EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(f => ModuleExtensions.Contains(Path.GetExtension(f).ToLowerInvariant()))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase));
        moduleFiles = moduleFiles
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (string file in moduleFiles)
        {
            string rel = Path.GetRelativePath(root, file).Replace('\\', '/');
            ModuleLaunchReadiness result = InspectModule(rel, ReadHeaderWindow(file));
            if (result.Kind == ModuleAuthorityKind.NotExecutable)
                continue;
            modules.Add(result);
        }

        bool hasParamJson = File.Exists(Path.Combine(root, "sce_sys", "param.json"));
        bool hasParamSfo = File.Exists(Path.Combine(root, "sce_sys", "param.sfo"));
        bool requiresDebugConsole = modules.Any(m =>
            m.Kind is ModuleAuthorityKind.FakeAuthoritySelf or ModuleAuthorityKind.RawElf);

        if (!hasEboot)
            issues.Add("No eboot.bin at the application root.");

        var mainModule = modules.FirstOrDefault(m => m.Path == "eboot.bin");
        if (hasEboot && mainModule is null)
            issues.Add("eboot.bin is present but is not a loadable ELF or SELF module; it will not start.");
        else if (hasEboot && mainModule is not null && !mainModule.WillRunOnDebugConsole)
            issues.Add($"eboot.bin will not start on a debug-mode console: {mainModule.Note}");

        var blocked = modules
            .Where(m => m.Kind == ModuleAuthorityKind.SignedEncrypted)
            .ToList();
        foreach (var m in blocked)
            issues.Add($"Module '{m.Path}' is signed and encrypted; it will not start on a debug-mode console.");

        if (!hasParamJson)
            issues.Add("No sce_sys/param.json; the launch service needs the param.json metadata form.");
        if (hasParamSfo)
            issues.Add("A sce_sys/param.sfo is present; the launch service refuses the param.sfo metadata form.");

        return new ProsperoLaunchReadinessReport
        {
            AppRoot = root,
            Modules = modules,
            HasEboot = hasEboot,
            HasParamJson = hasParamJson,
            HasParamSfo = hasParamSfo,
            RequiresDebugConsole = requiresDebugConsole,
            Issues = issues,
        };
    }

    private static byte[] ReadHeaderWindow(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        int length = (int)Math.Min(stream.Length, HeaderWindow);
        var buffer = new byte[length];
        int read = 0;
        while (read < length)
        {
            int n = stream.Read(buffer, read, length - read);
            if (n == 0) break;
            read += n;
        }
        return read == length ? buffer : buffer[..read];
    }
}
