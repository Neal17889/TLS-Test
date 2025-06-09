// CryptoUtil.cs
using System;
using System.Security.Cryptography;
using Sodium;

public static class CryptoUtil
{
    // AEAD：加密（GCM模式） - 使用 libsodium 的 AES256-GCM
    public static byte[] EncryptAesGcm(byte[] key, byte[] nonce, byte[] plaintext, byte[]? aad = null)
    {
        if (!SecretAeadAes.IsAvailable)
            throw new PlatformNotSupportedException("AES256-GCM is not supported on this platform.");

        byte[] ciphertextWithTag = SecretAeadAes.Encrypt(
            message: plaintext,
            nonce: nonce,
            key: key,
            additionalData: aad ?? Array.Empty<byte>());

        return ciphertextWithTag;
    }

    // AEAD：解密（GCM模式） - 使用 libsodium 的 AES256-GCM
    public static byte[] DecryptAesGcm(byte[] key, byte[] nonce, byte[] encryptedData, byte[]? aad = null)
    {
        if (!SecretAeadAes.IsAvailable)
            throw new PlatformNotSupportedException("AES256-GCM is not supported on this platform.");

        try
        {
            return SecretAeadAes.Decrypt(
                cipher: encryptedData,
                nonce: nonce,
                key: key,
                additionalData: aad ?? Array.Empty<byte>());
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("AEAD decryption failed: invalid tag or corrupted data.");
        }
    }
}
