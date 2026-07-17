// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Shared utility primitives: crypto, binary IO and stream helpers.
#nullable disable
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LibProsperoPkg.Util;

public static class Crypto
{
    /// <summary>
    /// Key-derivation step:
    /// a common function to generate a final key for PFS
    /// </summary>
    public static byte[] PfsGenCryptoKey(byte[] ekpfs, byte[] seed, uint index)
    {
        byte[] d = new byte[4 + seed.Length];
        Array.Copy(BitConverter.GetBytes(index), d, 4);
        Array.Copy(seed, 0, d, 4, seed.Length);
        using (var hmac = new HMACSHA256(ekpfs))
        {
            return hmac.ComputeHash(d);
        }
    }

    /// <summary>
    /// Generates a (tweak, data) key pair for XTS
    /// </summary>
    public static Tuple<byte[], byte[]> PfsGenEncKey(byte[] ekpfs, byte[] seed, bool newCrypt = false)
    {
        var encKey = PfsGenCryptoKey(newCrypt ? HMACSHA256.HashData(ekpfs, seed) : ekpfs, seed, 1);
        var dataKey = new byte[16];
        var tweakKey = new byte[16];
        Buffer.BlockCopy(encKey, 0, tweakKey, 0, 16);
        Buffer.BlockCopy(encKey, 16, dataKey, 0, 16);
        return Tuple.Create(tweakKey, dataKey);
    }

    /// <summary>
    /// Key-derivation step:
    /// asigning key generator based on EKPFS and PFS header seed
    /// </summary>
    public static byte[] PfsGenSignKey(byte[] ekpfs, byte[] seed, bool newCrypt = false)
    {
        return PfsGenCryptoKey(newCrypt ? HMACSHA256.HashData(ekpfs, seed) : ekpfs, seed, 2);
    }

    /// <summary>
    /// Creates an AES-128-CBC engine (no padding) using the modern <see cref="Aes.Create()"/>
    /// factory in place of the obsolete <c>AesManaged</c> type.
    /// </summary>
    private static Aes CreateCbcAes(byte[] key, byte[] iv)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.KeySize = 128;
        aes.Key = key;
        aes.IV = iv;
        aes.Padding = PaddingMode.None;
        aes.BlockSize = 128;
        return aes;
    }

    /// <summary>
    /// Encrypts <paramref name="data"/> with an RSA public key — big-endian <paramref name="modulus"/>,
    /// public exponent 65537 — using EME-PKCS#1 v1.5 (type 2) padding. This is the PS5 CNT key-entry
    /// wrapping: the ciphertext length equals the modulus length (384 bytes = RSA-3072). The PKCS#1 pad
    /// is random, so successive calls are not byte-identical, but each decrypts to <paramref name="data"/>
    /// under the corresponding private key.
    /// </summary>
    public static byte[] RsaPkcs1EncryptKey(byte[] modulus, byte[] data)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = modulus,
            Exponent = [0x01, 0x00, 0x01],
        });
        return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
    }

    public static int AesCbcCfb128Encrypt(byte[] @out, byte[] @in, int size, byte[] key, byte[] iv)
    {
        using var cipher = CreateCbcAes(key, iv);
        var tmp = new byte[size];
        using (var pt_stream = new MemoryStream(@in))
        using (var ct_stream = new MemoryStream(tmp))
        using (var dec = cipher.CreateEncryptor(key, iv))
        using (var s = new CryptoStream(ct_stream, dec, CryptoStreamMode.Write))
        {
            pt_stream.CopyTo(s);
        }
        Buffer.BlockCopy(tmp, 0, @out, 0, tmp.Length);
        return 0;
    }
    /// <summary>
    /// Computes the SHA256 hash of the given data.
    /// </summary>
    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);
    public static byte[] Sha256(Stream data)
    {
        data.Position = 0;
        return SHA256.HashData(data);
    }
    /// <summary>
    /// Computes the SHA256 hash of the data in the stream between (start) and (start+length)
    /// </summary>
    public static byte[] Sha256(Stream data, long start, long length)
    {
        using (var s = new SubStream(data, start, length))
        {
            return Sha256(s);
        }
    }

    /// <summary>
    /// Computes the SHA3-256 hash of the given data. SHA3-256 is the digest primitive used by the
    /// PS5 PFS: outer-image EKPFS key derivation, the compressed-file 'PFSC' digests, and
    /// the per-block hashes. Requires a runtime/platform that provides SHA-3 (verified on .NET 10).
    /// </summary>
    public static byte[] Sha3_256(byte[] data)
    {
        if (!SHA3_256.IsSupported)
            throw new PlatformNotSupportedException(
                "SHA3-256 is required for PS5 PFS key derivation and digests but is not available on this platform/runtime.");
        return SHA3_256.HashData(data);
    }

    /// <summary>Computes the SHA3-256 hash over the whole stream (used for PS5 CNT body/entry digests).</summary>
    public static byte[] Sha3_256(Stream data)
    {
        if (!SHA3_256.IsSupported)
            throw new PlatformNotSupportedException(
                "SHA3-256 is required for PS5 PFS digests but is not available on this platform/runtime.");
        data.Position = 0;
        return SHA3_256.HashData(data);
    }

    /// <summary>
    /// Computes the SHA3-256 hash of the data in the stream between (start) and (start+length). This is
    /// the PS5 CNT digest primitive (per-entry table, body-digest, sc-entry rollups).
    /// </summary>
    public static byte[] Sha3_256(Stream data, long start, long length)
    {
        using (var s = new SubStream(data, start, length))
        {
            return Sha3_256(s);
        }
    }


    public static byte[] HmacSha256(byte[] key, byte[] data)
      => HMACSHA256.HashData(key, data);
    public static byte[] HmacSha256(byte[] key, Stream data)
    {
        data.Position = 0;
        return HMACSHA256.HashData(key, data);
    }
    public static byte[] HmacSha256(byte[] key, Stream data, long start, long length)
    {
        using (var s = new SubStream(data, start, length))
        {
            return HmacSha256(key, s);
        }
    }

    /// <summary>
    /// Computes keys for the package.
    /// The key is the result of a SHA256 hash of the concatenation of:
    ///  - The SHA256 hash of the index (4 bytes big-endian)
    ///  - The SHA256 hash of the Content ID (36 bytes padded to 48 with nulls)
    ///  - The passcode
    /// The EKPFS is Index 1. 
    /// </summary>
    public static byte[] ComputeKeys(string ContentId, string Passcode, uint Index)
        => ComputeKeys(ContentId, Passcode, Index, useSha3: false);

    /// <summary>
    /// Computes keys for the package, selecting the per-generation digest primitive.
    /// EKPFS (Index 1) = H( H(Index, 4 bytes big-endian) || H(ContentId padded to 48 with nulls) || Passcode ),
    /// where H = SHA3-256 (useSha3: true) or SHA-256 (useSha3: false).
    /// The SHA3 form yields the EKPFS used for the outer PFS image; combine it
    /// with <see cref="PfsGenEncKey"/>/<see cref="PfsGenSignKey"/> using <c>newCrypt: true</c>.
    /// </summary>
    public static byte[] ComputeKeys(string ContentId, string Passcode, uint Index, bool useSha3)
    {
        if (ContentId.Length != 36)
            throw new Exception("Content ID must be 36 characters long");
        if (Passcode.Length != 32)
            throw new Exception("Passcode must be 32 characters long");

        Func<byte[], byte[]> h = useSha3 ? Sha3_256 : Sha256;
        byte[] data = new byte[96];
        Buffer.BlockCopy(h(BitConverter.GetBytes(Index).Reverse().ToArray()), 0, data, 0, 32);
        Buffer.BlockCopy(h(Encoding.ASCII.GetBytes(ContentId.PadRight(48, '\0'))), 0, data, 32, 32);
        Buffer.BlockCopy(Encoding.ASCII.GetBytes(Passcode), 0, data, 64, 32);

        return h(data);
    }

    public static byte[] CreateKeystone(string passcode)
    {
        // Build the 0x20-byte keystone header block (the full keystone file is 0x60 bytes: header
        // 0x00-0x1F, then the two appended HMAC blocks at 0x20 and 0x40). The header is the ASCII tag
        // "keystone" (8 bytes), a little-endian uint16 version (3), the uint16 magic 0x0001, and zero
        // padding out to 0x20.
        const ushort version = 3;
        var keystoneHeader = new byte[0x20];
        Encoding.ASCII.GetBytes("keystone").CopyTo(keystoneHeader, 0);
        BitConverter.GetBytes(version).CopyTo(keystoneHeader, 8);
        keystoneHeader[10] = 0x01;

        var fingerprint = HmacSha256(CryptoKeys.keystone_hmac_key_ps5, Encoding.ASCII.GetBytes(passcode));
        var final = HmacSha256(CryptoKeys.keystone_mac_data_ps5, keystoneHeader.Concat(fingerprint).ToArray());
        return keystoneHeader.Concat(fingerprint).Concat(final).ToArray();
    }

    /// <summary>
    /// XORs a with b and stores the result in a
    /// </summary>
    public static byte[] Xor(this byte[] a, byte[] b)
    {
        for (var i = 0; i < a.Length; i++)
        {
            a[i] ^= b[i];
        }
        return a;
    }
}
