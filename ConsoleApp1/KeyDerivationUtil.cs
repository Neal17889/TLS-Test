using System.Security.Cryptography;
using System.Text;

public static class KeyDerivationUtil
{
    // 生成最终对称密钥（输出为16字节）
    public static byte[] DeriveAesKey(
        byte[] sharedSecret,
        byte[] clientRandom,
        byte[] serverRandom,
        byte[] psk)
    {
        // 第一步：HMAC-SHA256 提取阶段
        byte[] salt = Combine(psk, clientRandom, serverRandom); // 可作为 HKDF salt
        byte[] prk = HmacSha256(salt, sharedSecret); // 伪随机密钥

        // 第二步：HMAC-SHA256 扩展阶段（用 info 参数导出 AES 密钥）
        byte[] info = Encoding.UTF8.GetBytes("TLS_AES_128_KEY_DERIVATION");
        byte[] okm = HmacSha256(prk, info);

        // 返回前16字节作为 AES 密钥
        byte[] aesKey = new byte[16];
        Buffer.BlockCopy(okm, 0, aesKey, 0, 16);
        return aesKey;
    }

    private static byte[] HmacSha256(byte[] key, byte[] data)
    {
        using HMACSHA256 hmac = new(key);
        return hmac.ComputeHash(data);
    }

    private static byte[] Combine(params byte[][] arrays)
    {
        int totalLength = 0;
        foreach (var arr in arrays)
            totalLength += arr.Length;

        byte[] result = new byte[totalLength];
        int offset = 0;
        foreach (var arr in arrays)
        {
            Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
            offset += arr.Length;
        }
        return result;
    }
}
