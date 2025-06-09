// KeyDerivationUtil.cs
using System;
using System.Security.Cryptography;
using System.Text;

public static class KeyDerivationUtil
{
    // 扩展返回类型，增加 finishedKey 字段
    public record AeadKeyMaterial(byte[] AesKey, byte[] IvBase, byte[] FinishedKey);

    public static AeadKeyMaterial DeriveAeadKey(
        byte[] sharedSecret,
        byte[] clientRandom,
        byte[] serverRandom,
        byte[] psk)
    {
        // 构造 salt: 结合 PSK、clientRandom 与 serverRandom
        Span<byte> salt = stackalloc byte[psk.Length + clientRandom.Length + serverRandom.Length];
        psk.CopyTo(salt);
        clientRandom.CopyTo(salt.Slice(psk.Length));
        serverRandom.CopyTo(salt.Slice(psk.Length + clientRandom.Length));

        // 计算伪随机密钥 prk = HMAC(salt, sharedSecret)
        Span<byte> prk = stackalloc byte[32];
        using (var hmac = new HMACSHA256(salt.ToArray()))
        {
            hmac.TryComputeHash(sharedSecret, prk, out _);
        }

        // 使用 info 字符串进行扩展，原先生成 40 字节，现在换成 72 字节（32+8+32）
        Span<byte> info = Encoding.UTF8.GetBytes("TLS_AES_128_KEY_DERIVATION");
        Span<byte> okm = stackalloc byte[72];
        using (var hmac = new HMACSHA256(prk.ToArray()))
        {
            hmac.TryComputeHash(info, okm, out _);
        }

        // 分区：取出 32 字节 AES 密钥，8 字节 IV 基础值，及 32 字节 finished_key
        byte[] aesKey = okm.Slice(0, 32).ToArray();
        byte[] ivBase = okm.Slice(32, 8).ToArray();
        byte[] finishedKey = okm.Slice(40, 32).ToArray();

        return new AeadKeyMaterial(aesKey, ivBase, finishedKey);
    }
}