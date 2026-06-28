// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2011-2026 SvenGDK
//
// PS5 PFS image AES-XTS encryption + decryption: a plaintext PFS
// image is turned into an encrypted one (and back) by XTS-encrypting every filesystem sector
// after the plaintext header block, deriving the (tweak, data) key pair from the EKPFS + the
// header seed.
//
// The inner-PFS image crypto scheme is AES-XTS-128 over 0x1000-byte
// sectors, key = PfsGenEncKey(EKPFS, seed) and the header block (block 0) left plaintext so the
// kernel can read the superblock's seed/mode. The transform and key derivation are reused from
// Util.Crypto.PfsGenEncKey + XtsBlockTransform, so this stays a single,
// round-trip-validated code path — the same way ProsperoPfsc reuses the
// internal PFSC encoder for compression.
#nullable enable
using System;
using System.IO;
using System.Security.Cryptography;
using LibProsperoPkg.PFS;
using LibProsperoPkg.Util;

namespace LibProsperoPkg.PFS;

/// <summary>The PFS superblock fields relevant to image encryption.</summary>
public sealed class ProsperoPfsImageInfo
{
    /// <summary>Superblock version (2 = PS5).</summary>
    public required long Version { get; init; }

    /// <summary>The raw PFS mode flag word from the superblock.</summary>
    public required ushort Mode { get; init; }

    /// <summary>Filesystem block size in bytes (typically 0x10000).</summary>
    public required uint BlockSize { get; init; }

    /// <summary>The 16-byte header crypto seed (all-zero when the image carries none).</summary>
    public required byte[] Seed { get; init; }

    /// <summary>True when the superblock declares the image AES-XTS encrypted.</summary>
    public bool Encrypted => (Mode & ProsperoPfsImage.EncryptedModeFlag) != 0;

    /// <summary>True when the superblock declares the image HMAC signed.</summary>
    public bool Signed => (Mode & ProsperoPfsImage.SignedModeFlag) != 0;
}

/// <summary>Options controlling a PFS image encrypt/decrypt operation.</summary>
public sealed class ProsperoPfsImageOptions
{
    /// <summary>
    /// The 32-byte EKPFS. When <c>null</c> the all-zero EKPFS is used — the standard
    /// package key that pairs with the all-zero passcode.
    /// </summary>
    public byte[]? Ekpfs { get; set; }

    /// <summary>
    /// The 16-byte header seed. When <c>null</c> the seed already present in the image
    /// header is used (encrypt of an already-prepared image); if the header has no seed a
    /// fresh cryptographically-random one is generated and written into the header.
    /// </summary>
    public byte[]? Seed { get; set; }

    /// <summary>
    /// When true, derive the encryption key from <c>HMAC(EKPFS, seed)</c> first (the
    /// <c>new_crypt</c> path / the <c>newCrypt</c> scheme). Defaults to the classic path.
    /// </summary>
    public bool NewCrypt { get; set; }
}

/// <summary>The outcome of an encrypt/decrypt operation.</summary>
public sealed class ProsperoPfsImageResult
{
    /// <summary>The path the image was written to.</summary>
    public required string OutputPath { get; init; }

    /// <summary>Total image size in bytes.</summary>
    public required long ImageSize { get; init; }

    /// <summary>Block size used (bytes).</summary>
    public required uint BlockSize { get; init; }

    /// <summary>Number of XTS sectors transformed.</summary>
    public required long SectorsTransformed { get; init; }

    /// <summary>The 16-byte seed the keys were derived from.</summary>
    public required byte[] Seed { get; init; }
}

/// <summary>
/// PFS image AES-XTS encryptor/decryptor for PS5. See the file header for the scheme.
/// </summary>
public static class ProsperoPfsImage
{
    /// <summary>AES-XTS sector size used by the PFS image crypto.</summary>
    public const int XtsSectorSize = 0x1000;

    /// <summary>The PFS mode bit that marks an image AES-XTS encrypted.</summary>
    public const ushort EncryptedModeFlag = 0x4;

    /// <summary>The PFS mode bit that marks an image HMAC signed.</summary>
    public const ushort SignedModeFlag = 0x1;

    // On-disk superblock field offsets (see LibProsperoPkg.PFS.PfsHeader).
    private const long ModeFieldOffset = 0x1C;       // ushort PFS mode word
    private const long UnknownIndexOffset = 0x36C;   // int written alongside the seed
    private const long SeedFieldOffset = 0x370;      // 16-byte header seed

    /// <summary>The all-zero EKPFS — the standard package key.</summary>
    public static byte[] ZeroEkpfs => new byte[32];

    /// <summary>
    /// Reads the PFS superblock of <paramref name="imagePath"/> and reports the fields
    /// relevant to encryption (version, mode, block size, seed).
    /// </summary>
    public static ProsperoPfsImageInfo Inspect(string imagePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(imagePath);
        if (!File.Exists(imagePath))
            throw new FileNotFoundException("PFS image was not found.", imagePath);

        using var fs = File.OpenRead(imagePath);
        var hdr = PfsHeader.ReadFromStream(fs);
        return new ProsperoPfsImageInfo
        {
            Version = hdr.Version,
            Mode = (ushort)hdr.Mode,
            BlockSize = hdr.BlockSize,
            Seed = hdr.Seed ?? new byte[16],
        };
    }

    /// <summary>
    /// Returns true when the PFS image at <paramref name="imagePath"/> has the encrypted
    /// mode flag set in its superblock (i.e. its filesystem sectors are AES-XTS encrypted).
    /// </summary>
    /// <param name="imagePath">Path to the PFS image to inspect.</param>
    /// <returns><c>true</c> if the superblock declares the image encrypted; otherwise <c>false</c>.</returns>
    public static bool IsEncrypted(string imagePath) => Inspect(imagePath).Encrypted;

    /// <summary>
    /// Encrypts a prepared (plaintext) PFS image in place: writes the encrypted-mode bit and
    /// the seed into the superblock, then AES-XTS-encrypts every filesystem sector after the
    /// header block.
    /// </summary>
    public static ProsperoPfsImageResult EncryptInPlace(
        string imagePath, ProsperoPfsImageOptions? options = null, Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(imagePath);
        return Transform(imagePath, imagePath, encrypt: true, options, logger);
    }

    /// <summary>
    /// Encrypts a prepared (plaintext) PFS image, writing the result to
    /// <paramref name="outputPath"/> (the input is left untouched).
    /// </summary>
    public static ProsperoPfsImageResult Encrypt(
        string inputImagePath, string outputPath, ProsperoPfsImageOptions? options = null, Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputImagePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        CopyTo(inputImagePath, outputPath);
        return Transform(outputPath, outputPath, encrypt: true, options, logger);
    }

    /// <summary>
    /// Decrypts an encrypted PFS image in place: AES-XTS-decrypts every filesystem sector
    /// after the header block and clears the encrypted-mode bit. Inverse of <see cref="EncryptInPlace"/>.
    /// </summary>
    public static ProsperoPfsImageResult DecryptInPlace(
        string imagePath, ProsperoPfsImageOptions? options = null, Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(imagePath);
        return Transform(imagePath, imagePath, encrypt: false, options, logger);
    }

    /// <summary>
    /// Decrypts an encrypted PFS image, writing the plaintext result to
    /// <paramref name="outputPath"/> (the input is left untouched).
    /// </summary>
    public static ProsperoPfsImageResult Decrypt(
        string inputImagePath, string outputPath, ProsperoPfsImageOptions? options = null, Action<string>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputImagePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        CopyTo(inputImagePath, outputPath);
        return Transform(outputPath, outputPath, encrypt: false, options, logger);
    }

    /// <summary>
    /// Proves the encrypt/decrypt pair is loss-less for a given image without leaving any
    /// artefacts: encrypts a temporary copy, decrypts it back and compares the filesystem
    /// data (every sector after the plaintext header block) to the original byte-for-byte.
    /// The header block legitimately gains the seed + encrypted-mode metadata, so it is
    /// excluded from the comparison. Used as the self-check that replaces on-hardware
    /// testing for the image crypto.
    /// </summary>
    public static bool VerifyRoundTrip(string plaintextImagePath, ProsperoPfsImageOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plaintextImagePath);
        string enc = Path.GetTempFileName();
        string dec = Path.GetTempFileName();
        try
        {
            var info = Inspect(plaintextImagePath);
            Encrypt(plaintextImagePath, enc, options);
            Decrypt(enc, dec, options);
            // Compare the filesystem data region (block 1 onward); the header block carries
            // the crypto metadata and is expected to differ.
            return FilesEqual(plaintextImagePath, dec, fromOffset: info.BlockSize);
        }
        finally
        {
            TryDelete(enc);
            TryDelete(dec);
        }
    }

    // The shared encrypt/decrypt engine. Operates on <paramref name="targetPath"/> in place;
    // callers that want a copy pre-copy the input to the target.
    private static ProsperoPfsImageResult Transform(
        string sourcePath, string targetPath, bool encrypt, ProsperoPfsImageOptions? options, Action<string>? logger)
    {
        if (!File.Exists(targetPath))
            throw new FileNotFoundException("PFS image was not found.", targetPath);

        options ??= new ProsperoPfsImageOptions();
        var log = logger ?? (_ => { });
        var ekpfs = ResolveEkpfs(options.Ekpfs);

        using var fs = new FileStream(targetPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        long length = fs.Length;

        fs.Position = 0;
        var hdr = PfsHeader.ReadFromStream(fs);

        uint blockSize = hdr.BlockSize;
        if (blockSize == 0 || (blockSize % XtsSectorSize) != 0)
            throw new InvalidDataException($"PFS block size {blockSize} is not a multiple of the XTS sector size {XtsSectorSize}.");
        if ((length % XtsSectorSize) != 0)
            throw new InvalidDataException($"PFS image length {length} is not a multiple of the XTS sector size {XtsSectorSize}.");

        // Decide on the seed: caller-provided > header-resident > freshly generated.
        byte[] headerSeed = hdr.Seed ?? new byte[16];
        byte[] seed = options.Seed ?? (IsAllZero(headerSeed) && encrypt ? RandomNumberGenerator.GetBytes(16) : headerSeed);
        if (seed.Length != 16)
            throw new ArgumentException("PFS header seed must be exactly 16 bytes.", nameof(options));

        bool alreadyEncrypted = ((ushort)hdr.Mode & EncryptedModeFlag) != 0;
        if (!encrypt && !alreadyEncrypted)
            throw new InvalidDataException("The image is not marked encrypted; nothing to decrypt.");

        // For encryption, stamp the seed + encrypted-mode bit into the plaintext superblock so
        // the kernel can derive the same keys when mounting. For decryption, clear the bit.
        ushort newMode = encrypt
            ? (ushort)((ushort)hdr.Mode | EncryptedModeFlag)
            : (ushort)((ushort)hdr.Mode & ~EncryptedModeFlag);
        PatchHeader(fs, newMode, encrypt ? seed : null);

        // Derive the AES-XTS (tweak, data) key pair.
        var (tweakKey, dataKey) = Crypto.PfsGenEncKey(ekpfs, seed, options.NewCrypt);
        var transform = new XtsBlockTransform(dataKey, tweakKey);

        long startSector = blockSize / XtsSectorSize; // header block (block 0) stays plaintext
        long totalSectors = length / XtsSectorSize;
        var buffer = new byte[XtsSectorSize];
        long transformed = 0;
        long reported = -1;

        log($"{(encrypt ? "Encrypting" : "Decrypting")} {Path.GetFileName(targetPath)} " +
            $"({length:N0} bytes, PFS, block size 0x{blockSize:X})...");

        for (long sector = startSector; sector < totalSectors; sector++)
        {
            long offset = sector * XtsSectorSize;
            fs.Position = offset;
            ReadExact(fs, buffer);
            transform.CryptSector(buffer, (ulong)sector, encrypt);
            fs.Position = offset;
            fs.Write(buffer, 0, buffer.Length);
            transformed++;

            long pct = totalSectors <= startSector ? 100 : (sector - startSector + 1) * 100 / (totalSectors - startSector);
            if (pct != reported) { reported = pct; log($"  {pct,3}%"); }
        }

        fs.Flush();
        log($"Done: {transformed:N0} sectors {(encrypt ? "encrypted" : "decrypted")} (seed {Convert.ToHexString(seed.AsSpan(0, 4))}...).");

        return new ProsperoPfsImageResult
        {
            OutputPath = targetPath,
            ImageSize = length,
            BlockSize = blockSize,
            SectorsTransformed = transformed,
            Seed = seed,
        };
    }

    // Writes the mode word (always) and, for encryption, the seed into the plaintext header
    // using the documented superblock field offsets. Only those bytes are touched.
    private static void PatchHeader(FileStream fs, ushort mode, byte[]? seed)
    {
        Span<byte> modeBytes = stackalloc byte[2];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(modeBytes, mode);
        fs.Position = ModeFieldOffset;
        fs.Write(modeBytes);

        if (seed != null)
        {
            // The seed is preceded by a 4-byte "unknown index" the writer sets to 0.
            Span<byte> idx = stackalloc byte[4];
            fs.Position = UnknownIndexOffset;
            fs.Write(idx);
            fs.Position = SeedFieldOffset;
            fs.Write(seed, 0, 16);
        }
    }

    private static byte[] ResolveEkpfs(byte[]? ekpfs)
    {
        if (ekpfs is null)
            return ZeroEkpfs;
        if (ekpfs.Length != 32)
            throw new ArgumentException($"EKPFS must be exactly 32 bytes (was {ekpfs.Length}).", nameof(ekpfs));
        return ekpfs;
    }

    private static bool IsAllZero(byte[] data)
    {
        foreach (var b in data)
            if (b != 0) return false;
        return true;
    }

    private static void CopyTo(string sourcePath, string outputPath)
    {
        if (!File.Exists(sourcePath))
            throw new FileNotFoundException("PFS image was not found.", sourcePath);

        var dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        if (!string.Equals(Path.GetFullPath(sourcePath), Path.GetFullPath(outputPath), StringComparison.Ordinal))
            File.Copy(sourcePath, outputPath, overwrite: true);
    }

    private static void ReadExact(Stream s, byte[] buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = s.Read(buffer, read, buffer.Length - read);
            if (n == 0) throw new EndOfStreamException("Unexpected end of PFS image while reading a sector.");
            read += n;
        }
    }

    private static bool FilesEqual(string a, string b, long fromOffset = 0)
    {
        var fa = new FileInfo(a);
        var fb = new FileInfo(b);
        if (fa.Length != fb.Length) return false;

        using var sa = fa.OpenRead();
        using var sb = fb.OpenRead();
        sa.Position = fromOffset;
        sb.Position = fromOffset;
        var ba = new byte[1 << 16];
        var bb = new byte[1 << 16];
        int na;
        while ((na = sa.Read(ba, 0, ba.Length)) > 0)
        {
            int off = 0;
            while (off < na)
            {
                int nb = sb.Read(bb, off, na - off);
                if (nb == 0) return false;
                off += nb;
            }
            if (!ba.AsSpan(0, na).SequenceEqual(bb.AsSpan(0, na)))
                return false;
        }
        return true;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* best-effort cleanup */ }
    }
}
