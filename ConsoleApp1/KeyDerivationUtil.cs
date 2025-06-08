// KeyDerivationUtil.cs
using System.Security.Cryptography;
using System.Text;

public static class KeyDerivationUtil
{
    // 输出结构体：包含 AES 密钥和 AEAD IV
    public record AeadKeyMaterial(byte[] AesKey, byte[] IvBase);

    // 生成最终 AEAD 密钥材料（AES-128 + 12字节 IV）
    public static AeadKeyMaterial DeriveAeadKey(
        byte[] sharedSecret,
        byte[] clientRandom,
        byte[] serverRandom,
        byte[] psk)
    {
        // 第一步：HMAC-SHA256 提取阶段
        byte[] salt = Combine(psk, clientRandom, serverRandom); // 可作为 HKDF salt
        byte[] prk = HmacSha256(salt, sharedSecret); // 伪随机密钥

        // 第二步：HMAC-SHA256 扩展阶段（用 info 参数导出密钥材料）
        byte[] info = Encoding.UTF8.GetBytes("TLS_AES_128_KEY_DERIVATION");
        byte[] okm = HmacSha256(prk, info);

        // 返回结构体：前16字节作为 AES 密钥，后12字节作为 IV Base
        byte[] aesKey = new byte[16];
        byte[] ivBase = new byte[12];
        Buffer.BlockCopy(okm, 0, aesKey, 0, 16);
        Buffer.BlockCopy(okm, 16, ivBase, 0, 12);

        return new AeadKeyMaterial(aesKey, ivBase);
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
