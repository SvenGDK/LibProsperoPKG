// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Shared utility primitives: crypto, binary IO and stream helpers.
#nullable disable
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace LibProsperoPkg.Util;

/// <summary>
/// AES-XTS-128 sector transform. The AES engines and their block transforms are created once and
/// reused across every sector, so the per-sector path allocates nothing. A single instance is not
/// thread-safe; give each thread its own instance.
/// </summary>
public sealed class XtsBlockTransform : IDisposable
{
    // Data-key engine (applied to the tweaked plaintext) and tweak-key engine (encrypts the tweak).
    private readonly Aes cipher;
    private readonly Aes tweakCipher;
    private readonly ICryptoTransform encryptor;
    private readonly ICryptoTransform decryptor;
    private readonly ICryptoTransform tweakEncryptor;

    private readonly byte[] tweak = new byte[16];
    private readonly byte[] xor = new byte[16];
    private readonly byte[] encryptedTweak = new byte[16];

    /// <summary>
    /// Creates an AES-XTS-128 transformer.
    /// </summary>
    public XtsBlockTransform(byte[] dataKey, byte[] tweakKey)
    {
        cipher = CreateEcbAes(dataKey);
        tweakCipher = CreateEcbAes(tweakKey);
        encryptor = cipher.CreateEncryptor();
        decryptor = cipher.CreateDecryptor();
        tweakEncryptor = tweakCipher.CreateEncryptor();
    }

    /// <summary>
    /// Creates a single-block AES-128-ECB engine (no padding) used as the primitive for
    /// the manual XTS transform.
    /// </summary>
    private static Aes CreateEcbAes(byte[] key)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.KeySize = 128;
        aes.Key = key;
        aes.Padding = PaddingMode.None;
        aes.BlockSize = 128;
        return aes;
    }

    public void EncryptSector(byte[] sector, ulong sectorNum) => CryptSector(sector, sectorNum, true);
    public void DecryptSector(byte[] sector, ulong sectorNum) => CryptSector(sector, sectorNum, false);

    /// <summary>
    /// Encrypts or decrypts the given sector using the XTS transform.
    /// </summary>
    /// <param name="sector">Sector plain/ciphertext</param>
    /// <param name="sectorNum">Sector index number</param>
    /// <param name="encrypt">If this is set to true, encrypt the sector</param>
    public void CryptSector(byte[] sector, ulong sectorNum, bool encrypt = false)
    {
        // Reset tweak to sector number (little-endian, high half zeroed).
        BinaryPrimitives.WriteUInt64LittleEndian(tweak, sectorNum);
        for (int x = 8; x < 16; x++)
            tweak[x] = 0;

        tweakEncryptor.TransformBlock(tweak, 0, 16, encryptedTweak, 0);
        ICryptoTransform cryptor = encrypt ? encryptor : decryptor;

        for (int destOffset = 0; destOffset < sector.Length; destOffset += 16)
        {
            for (var x = 0; x < 16; x++)
                xor[x] = (byte)(sector[x + destOffset] ^ encryptedTweak[x]);

            cryptor.TransformBlock(xor, 0, 16, xor, 0);

            for (var x = 0; x < 16; x++)
                sector[x + destOffset] = (byte)(xor[x] ^ encryptedTweak[x]);

            // GF-Multiply Tweak
            int feedback = 0;
            for (int k = 0; k < 16; k++)
            {
                byte tmp = encryptedTweak[k];
                encryptedTweak[k] = (byte)(2 * encryptedTweak[k] | feedback);
                feedback = (tmp & 0x80) >> 7;
            }
            if (feedback != 0)
                encryptedTweak[0] ^= 0x87;
        }
    }

    public void Dispose()
    {
        encryptor.Dispose();
        decryptor.Dispose();
        tweakEncryptor.Dispose();
        cipher.Dispose();
        tweakCipher.Dispose();
    }
}
