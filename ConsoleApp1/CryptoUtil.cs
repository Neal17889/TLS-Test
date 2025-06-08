// CryptoUtil.cs
using System.Security.Cryptography;
using System.Text;

public static class CryptoUtil
{
    // AEAD：加密（GCM模式）
    public static byte[] EncryptAesGcm(byte[] key, byte[] nonce, byte[] plaintext, byte[]? aad = null)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16]; // 128-bit tag

        using var aesGcm = new AesGcm(key);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        // 拼接 ciphertext + tag
        byte[] result = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);
        return result;
    }

    // AEAD：解密（GCM模式）
    public static byte[] DecryptAesGcm(byte[] key, byte[] nonce, byte[] encryptedData, byte[]? aad = null)
    {
        int tagLength = 16;
        if (encryptedData.Length < tagLength)
            throw new CryptographicException("Encrypted data too short");

        int cipherLength = encryptedData.Length - tagLength;
        byte[] ciphertext = new byte[cipherLength];
        byte[] tag = new byte[tagLength];
        Buffer.BlockCopy(encryptedData, 0, ciphertext, 0, cipherLength);
        Buffer.BlockCopy(encryptedData, cipherLength, tag, 0, tagLength);

        byte[] plaintext = new byte[cipherLength];
        using var aesGcm = new AesGcm(key);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        return plaintext;
    }
}
