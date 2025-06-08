// CryptoUtil.cs
using System.Security.Cryptography;
using System.Text;

public static class CryptoUtil
{
    public static byte[] EncryptAes(byte[] key, byte[] plainBytes)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        byte[] result = new byte[aes.IV.Length + cipherBytes.Length];
        Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
        Buffer.BlockCopy(cipherBytes, 0, result, aes.IV.Length, cipherBytes.Length);
        return result;
    }

    public static byte[] DecryptAes(byte[] key, byte[] encryptedData)
    {
        using var aes = Aes.Create();
        aes.Key = key;

        byte[] iv = new byte[aes.BlockSize / 8];
        byte[] cipherBytes = new byte[encryptedData.Length - iv.Length];
        Buffer.BlockCopy(encryptedData, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(encryptedData, iv.Length, cipherBytes, 0, cipherBytes.Length);

        aes.IV = iv;
        using var decryptor = aes.CreateDecryptor();
        byte[] plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
        return /*Encoding.UTF8.GetString(*/plainBytes/*)*/;
    }
}
