// CryptoUtil.cs
using System;
using System.Security.Cryptography;
using Sodium;

public static class CryptoUtil
{
    // AEAD：加密（ChaCha20-Poly1305） - 使用 libsodium
    public static byte[] EncryptChaCha20Poly1305(byte[] key, byte[] nonce, byte[] plaintext, byte[]? aad = null)
    {
        if (key.Length != 32)
            throw new ArgumentOutOfRangeException(nameof(key), "Key must be 32 bytes for ChaCha20-Poly1305.");

        byte[] ciphertextWithTag = SecretAeadChaCha20Poly1305.Encrypt(
            message: plaintext,
            additionalData: aad ?? Array.Empty<byte>(),
            nonce: nonce,
            key: key);

        return ciphertextWithTag;
    }

    // AEAD：解密（ChaCha20-Poly1305） - 使用 libsodium
    public static byte[] DecryptChaCha20Poly1305(byte[] key, byte[] nonce, byte[] encryptedData, byte[]? aad = null)
    {
        if (key.Length != 32)
            throw new ArgumentOutOfRangeException(nameof(key), "Key must be 32 bytes for ChaCha20-Poly1305.");

        try
        {
            return SecretAeadChaCha20Poly1305.Decrypt(
                cipher: encryptedData,
                additionalData: aad ?? Array.Empty<byte>(),
                nonce: nonce,
                key: key);
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("AEAD decryption failed: invalid tag or corrupted data.");
        }
    }
}
