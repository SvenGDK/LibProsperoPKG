// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ELF64 header reader and editor. A module that is fed to the fake-self builder must carry a
// correct ELF header: 64-bit class, little-endian data, the x86-64 machine, an OS/ABI the loader
// accepts, and an executable or dynamic type. This type reads those fields and edits them in place
// without touching segment content, so a plain homebrew ELF can be normalized before MakeFself.

#nullable enable
using System;
using System.Buffers.Binary;
using System.IO;

namespace LibProsperoPkg.Content;

/// <summary>ELF identification class byte (<c>e_ident[EI_CLASS]</c>).</summary>
public enum ElfClass : byte
{
    /// <summary>Invalid class.</summary>
    None = 0,

    /// <summary>32-bit objects.</summary>
    Elf32 = 1,

    /// <summary>64-bit objects.</summary>
    Elf64 = 2,
}

/// <summary>ELF identification data-encoding byte (<c>e_ident[EI_DATA]</c>).</summary>
public enum ElfData : byte
{
    /// <summary>Invalid encoding.</summary>
    None = 0,

    /// <summary>Two's-complement little-endian.</summary>
    LittleEndian = 1,

    /// <summary>Two's-complement big-endian.</summary>
    BigEndian = 2,
}

/// <summary>ELF object-file type (<c>e_type</c>), including the module-specific values.</summary>
public enum ElfType : ushort
{
    /// <summary>No file type.</summary>
    None = 0x0000,

    /// <summary>Relocatable file.</summary>
    Relocatable = 0x0001,

    /// <summary>Executable file.</summary>
    Executable = 0x0002,

    /// <summary>Shared object (dynamic) file.</summary>
    Dynamic = 0x0003,

    /// <summary>Core file.</summary>
    Core = 0x0004,

    /// <summary>Module executable.</summary>
    ModuleExecutable = 0xFE00,

    /// <summary>Replay executable.</summary>
    ModuleReplayExecutable = 0xFE01,

    /// <summary>Relocatable module executable.</summary>
    ModuleRelocatableExecutable = 0xFE04,

    /// <summary>Stub library.</summary>
    ModuleStubLibrary = 0xFE0C,

    /// <summary>Address-space-randomized executable.</summary>
    ModuleDynamicExecutable = 0xFE10,

    /// <summary>Dynamic shared library.</summary>
    ModuleDynamic = 0xFE18,
}

/// <summary>OS/ABI identification byte (<c>e_ident[EI_OSABI]</c>).</summary>
public static class ElfOsAbi
{
    /// <summary>System V (0x00).</summary>
    public const byte SystemV = 0x00;

    /// <summary>HP-UX (0x01).</summary>
    public const byte HpUx = 0x01;

    /// <summary>NetBSD (0x02).</summary>
    public const byte NetBsd = 0x02;

    /// <summary>GNU / Linux (0x03).</summary>
    public const byte Gnu = 0x03;

    /// <summary>Solaris (0x06).</summary>
    public const byte Solaris = 0x06;

    /// <summary>AIX (0x07).</summary>
    public const byte Aix = 0x07;

    /// <summary>IRIX (0x08).</summary>
    public const byte Irix = 0x08;

    /// <summary>FreeBSD (0x09). The value module SELF images carry.</summary>
    public const byte FreeBsd = 0x09;

    /// <summary>OpenBSD (0x0C).</summary>
    public const byte OpenBsd = 0x0C;

    /// <summary>OpenVMS (0x0D).</summary>
    public const byte OpenVms = 0x0D;

    /// <summary>FenixOS (0x10).</summary>
    public const byte FenixOs = 0x10;
}

/// <summary>Machine identifier (<c>e_machine</c>).</summary>
public static class ElfMachine
{
    /// <summary>No machine.</summary>
    public const ushort None = 0x0000;

    /// <summary>AMD x86-64 (0x3E). The machine module images use.</summary>
    public const ushort X86_64 = 0x003E;

    /// <summary>ARM AArch64 (0xB7).</summary>
    public const ushort AArch64 = 0x00B7;
}

/// <summary>
/// Reader and in-place editor for the 64-bit ELF header (the first 0x40 bytes of an ELF file).
/// </summary>
/// <remarks>
/// Field layout (little-endian scalars):
/// <list type="bullet">
/// <item><c>e_ident</c> at 0x00, 16 bytes: magic <c>7F 45 4C 46</c>, class (0x04), data (0x05),
/// header version (0x06), OS/ABI (0x07), ABI version (0x08), then padding.</item>
/// <item><c>e_type</c> (0x10, u16), <c>e_machine</c> (0x12, u16), <c>e_version</c> (0x14, u32).</item>
/// <item><c>e_entry</c> (0x18, u64), <c>e_phoff</c> (0x20, u64), <c>e_shoff</c> (0x28, u64).</item>
/// <item><c>e_flags</c> (0x30, u32), <c>e_ehsize</c> (0x34, u16), <c>e_phentsize</c> (0x36, u16),
/// <c>e_phnum</c> (0x38, u16), <c>e_shentsize</c> (0x3A, u16), <c>e_shnum</c> (0x3C, u16),
/// <c>e_shstrndx</c> (0x3E, u16).</item>
/// </list>
/// The editing methods change only the header bytes they name; program headers, section headers
/// and segment data are left untouched.
/// </remarks>
public sealed class ProsperoElfHeader
{
    /// <summary>Size in bytes of a 64-bit ELF header.</summary>
    public const int HeaderSize = 0x40;

    private const byte EiClass = 0x04;
    private const byte EiData = 0x05;
    private const byte EiVersion = 0x06;
    private const byte EiOsAbi = 0x07;
    private const byte EiAbiVersion = 0x08;
    private const int OffType = 0x10;
    private const int OffMachine = 0x12;
    private const int OffVersion = 0x14;
    private const int OffEntry = 0x18;
    private const int OffPhOff = 0x20;
    private const int OffShOff = 0x28;
    private const int OffFlags = 0x30;
    private const int OffEhSize = 0x34;
    private const int OffPhEntSize = 0x36;
    private const int OffPhNum = 0x38;
    private const int OffShEntSize = 0x3A;
    private const int OffShNum = 0x3C;
    private const int OffShStrNdx = 0x3E;

    private ProsperoElfHeader()
    {
    }

    /// <summary>Identification class byte.</summary>
    public ElfClass Class { get; private init; }

    /// <summary>Identification data-encoding byte.</summary>
    public ElfData Data { get; private init; }

    /// <summary>Identification header-version byte.</summary>
    public byte IdentVersion { get; private init; }

    /// <summary>OS/ABI byte. See <see cref="ElfOsAbi"/> for named values.</summary>
    public byte OsAbi { get; private init; }

    /// <summary>ABI-version byte.</summary>
    public byte AbiVersion { get; private init; }

    /// <summary>Object-file type.</summary>
    public ElfType Type { get; private init; }

    /// <summary>Machine identifier. See <see cref="ElfMachine"/> for named values.</summary>
    public ushort Machine { get; private init; }

    /// <summary>File version word.</summary>
    public uint Version { get; private init; }

    /// <summary>Entry-point virtual address.</summary>
    public ulong Entry { get; private init; }

    /// <summary>Program-header table file offset.</summary>
    public ulong ProgramHeaderOffset { get; private init; }

    /// <summary>Section-header table file offset.</summary>
    public ulong SectionHeaderOffset { get; private init; }

    /// <summary>Processor-specific flags.</summary>
    public uint Flags { get; private init; }

    /// <summary>ELF header size.</summary>
    public ushort HeaderSizeField { get; private init; }

    /// <summary>Program-header entry size.</summary>
    public ushort ProgramHeaderEntrySize { get; private init; }

    /// <summary>Program-header entry count.</summary>
    public ushort ProgramHeaderCount { get; private init; }

    /// <summary>Section-header entry size.</summary>
    public ushort SectionHeaderEntrySize { get; private init; }

    /// <summary>Section-header entry count.</summary>
    public ushort SectionHeaderCount { get; private init; }

    /// <summary>Section-name string-table index.</summary>
    public ushort SectionNameStringIndex { get; private init; }

    /// <summary>Whether the type is an executable or module-executable variant.</summary>
    public bool IsExecutable =>
        Type is ElfType.Executable or ElfType.ModuleExecutable or ElfType.ModuleReplayExecutable
             or ElfType.ModuleRelocatableExecutable or ElfType.ModuleDynamicExecutable;

    /// <summary>Whether the type is a dynamic/shared object or module-dynamic library.</summary>
    public bool IsDynamic =>
        Type is ElfType.Dynamic or ElfType.ModuleDynamic or ElfType.ModuleStubLibrary;

    /// <summary>Whether the type is one of the module-specific values.</summary>
    public bool IsModuleType => (ushort)Type >= 0xFE00 && (ushort)Type <= 0xFEFF;

    /// <summary>
    /// Whether the header is shaped the way a module the fake-self builder accepts expects it:
    /// 64-bit, little-endian, the x86-64 machine, an executable or dynamic type, and an OS/ABI of
    /// FreeBSD or System V.
    /// </summary>
    public bool IsModuleReady =>
        Class == ElfClass.Elf64 &&
        Data == ElfData.LittleEndian &&
        Machine == ElfMachine.X86_64 &&
        (IsExecutable || IsDynamic) &&
        OsAbi is ElfOsAbi.FreeBsd or ElfOsAbi.SystemV;

    /// <summary>Returns whether the buffer begins with the ELF magic and is large enough for a header.</summary>
    public static bool IsElf(ReadOnlySpan<byte> data) =>
        data.Length >= HeaderSize &&
        data[0] == 0x7F && data[1] == (byte)'E' && data[2] == (byte)'L' && data[3] == (byte)'F';

    /// <summary>Parses a 64-bit ELF header from the start of a buffer.</summary>
    /// <param name="data">A buffer beginning with an ELF header.</param>
    /// <exception cref="InvalidDataException">The buffer is not a 64-bit little-endian ELF header.</exception>
    public static ProsperoElfHeader Read(ReadOnlySpan<byte> data)
    {
        if (!IsElf(data))
            throw new InvalidDataException("Buffer does not begin with an ELF header.");
        if (data[EiClass] != (byte)ElfClass.Elf64)
            throw new InvalidDataException("Only 64-bit ELF files are supported.");
        if (data[EiData] != (byte)ElfData.LittleEndian)
            throw new InvalidDataException("Only little-endian ELF files are supported.");

        return new ProsperoElfHeader
        {
            Class = (ElfClass)data[EiClass],
            Data = (ElfData)data[EiData],
            IdentVersion = data[EiVersion],
            OsAbi = data[EiOsAbi],
            AbiVersion = data[EiAbiVersion],
            Type = (ElfType)BinaryPrimitives.ReadUInt16LittleEndian(data[OffType..]),
            Machine = BinaryPrimitives.ReadUInt16LittleEndian(data[OffMachine..]),
            Version = BinaryPrimitives.ReadUInt32LittleEndian(data[OffVersion..]),
            Entry = BinaryPrimitives.ReadUInt64LittleEndian(data[OffEntry..]),
            ProgramHeaderOffset = BinaryPrimitives.ReadUInt64LittleEndian(data[OffPhOff..]),
            SectionHeaderOffset = BinaryPrimitives.ReadUInt64LittleEndian(data[OffShOff..]),
            Flags = BinaryPrimitives.ReadUInt32LittleEndian(data[OffFlags..]),
            HeaderSizeField = BinaryPrimitives.ReadUInt16LittleEndian(data[OffEhSize..]),
            ProgramHeaderEntrySize = BinaryPrimitives.ReadUInt16LittleEndian(data[OffPhEntSize..]),
            ProgramHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(data[OffPhNum..]),
            SectionHeaderEntrySize = BinaryPrimitives.ReadUInt16LittleEndian(data[OffShEntSize..]),
            SectionHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(data[OffShNum..]),
            SectionNameStringIndex = BinaryPrimitives.ReadUInt16LittleEndian(data[OffShStrNdx..]),
        };
    }

    /// <summary>Reads the ELF header from a file.</summary>
    /// <param name="path">Path to an ELF file.</param>
    public static ProsperoElfHeader ReadFile(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        byte[] head = new byte[HeaderSize];
        using FileStream fs = File.OpenRead(path);
        int read = fs.ReadAtLeast(head, HeaderSize, throwOnEndOfStream: false);
        if (read < HeaderSize)
            throw new InvalidDataException("File is smaller than an ELF header.");
        return Read(head);
    }

    /// <summary>Writes the OS/ABI byte in place.</summary>
    /// <param name="elf">A buffer beginning with a 64-bit ELF header; modified in place.</param>
    /// <param name="osAbi">The OS/ABI value to write. See <see cref="ElfOsAbi"/>.</param>
    public static void SetOsAbi(byte[] elf, byte osAbi)
    {
        Require64BitElf(elf);
        elf[EiOsAbi] = osAbi;
    }

    /// <summary>Writes the ABI-version byte in place.</summary>
    /// <param name="elf">A buffer beginning with a 64-bit ELF header; modified in place.</param>
    /// <param name="abiVersion">The ABI-version value to write.</param>
    public static void SetAbiVersion(byte[] elf, byte abiVersion)
    {
        Require64BitElf(elf);
        elf[EiAbiVersion] = abiVersion;
    }

    /// <summary>Writes the object-file type in place.</summary>
    /// <param name="elf">A buffer beginning with a 64-bit ELF header; modified in place.</param>
    /// <param name="type">The type value to write.</param>
    public static void SetType(byte[] elf, ElfType type)
    {
        Require64BitElf(elf);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(OffType), (ushort)type);
    }

    /// <summary>Writes the machine identifier in place.</summary>
    /// <param name="elf">A buffer beginning with a 64-bit ELF header; modified in place.</param>
    /// <param name="machine">The machine value to write. See <see cref="ElfMachine"/>.</param>
    public static void SetMachine(byte[] elf, ushort machine)
    {
        Require64BitElf(elf);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(OffMachine), machine);
    }

    /// <summary>
    /// Normalizes an ELF header for the module loader without changing segment content: sets the
    /// machine to x86-64 and, when the current OS/ABI is System V or GNU, sets it to FreeBSD. A type
    /// that is already executable or dynamic (standard or module-specific) is kept; a
    /// <see cref="ElfType.None"/> type is set to <see cref="ElfType.Executable"/>. Returns the
    /// fields that changed.
    /// </summary>
    /// <param name="elf">A buffer beginning with a 64-bit ELF header; modified in place.</param>
    /// <returns>A summary of which fields were changed.</returns>
    public static ElfNormalizeResult NormalizeForModule(byte[] elf)
    {
        Require64BitElf(elf);
        var before = Read(elf);

        bool machineChanged = before.Machine != ElfMachine.X86_64;
        if (machineChanged)
            SetMachine(elf, ElfMachine.X86_64);

        bool osAbiChanged = before.OsAbi is ElfOsAbi.SystemV or ElfOsAbi.Gnu;
        if (osAbiChanged)
            SetOsAbi(elf, ElfOsAbi.FreeBsd);

        bool typeChanged = before.Type == ElfType.None;
        if (typeChanged)
            SetType(elf, ElfType.Executable);

        return new ElfNormalizeResult(machineChanged, osAbiChanged, typeChanged);
    }

    /// <summary>Returns a one-line description of the header for logging and inspection.</summary>
    public string Describe() =>
        $"ELF64 {Data} osabi=0x{OsAbi:X2} type={Type} machine=0x{Machine:X4} " +
        $"phnum={ProgramHeaderCount} entry=0x{Entry:X}";

    private static void Require64BitElf(byte[] elf)
    {
        ArgumentNullException.ThrowIfNull(elf);
        if (!IsElf(elf))
            throw new ArgumentException("Buffer does not begin with an ELF header.", nameof(elf));
        if (elf[EiClass] != (byte)ElfClass.Elf64)
            throw new ArgumentException("Only 64-bit ELF files are supported.", nameof(elf));
        if (elf[EiData] != (byte)ElfData.LittleEndian)
            throw new ArgumentException("Only little-endian ELF files are supported.", nameof(elf));
    }
}

/// <summary>Records which header fields <see cref="ProsperoElfHeader.NormalizeForModule"/> changed.</summary>
/// <param name="MachineChanged">Whether the machine field was set to x86-64.</param>
/// <param name="OsAbiChanged">Whether the OS/ABI byte was set to FreeBSD.</param>
/// <param name="TypeChanged">Whether the type field was set to executable.</param>
public readonly record struct ElfNormalizeResult(bool MachineChanged, bool OsAbiChanged, bool TypeChanged)
{
    /// <summary>Whether any field changed.</summary>
    public bool Changed => MachineChanged || OsAbiChanged || TypeChanged;
}
