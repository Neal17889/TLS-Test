// KeyDerivationUtil.cs
using System;
using System.Security.Cryptography;
using System.Text;

public static class KeyDerivationUtil
{
    public record AeadKeyMaterial(byte[] AesKey, byte[] IvBase);

    public static AeadKeyMaterial DeriveAeadKey(
        byte[] sharedSecret,
        byte[] clientRandom,
        byte[] serverRandom,
        byte[] psk)
    {
        Span<byte> salt = stackalloc byte[psk.Length + clientRandom.Length + serverRandom.Length];
        psk.CopyTo(salt);
        clientRandom.CopyTo(salt.Slice(psk.Length));
        serverRandom.CopyTo(salt.Slice(psk.Length + clientRandom.Length));

        Span<byte> prk = stackalloc byte[32];
        using (var hmac = new HMACSHA256(salt.ToArray()))
        {
            hmac.TryComputeHash(sharedSecret, prk, out _);
        }

        Span<byte> info = Encoding.UTF8.GetBytes("TLS_AES_128_KEY_DERIVATION");
        Span<byte> okm = stackalloc byte[44]; // 原 32 => 增加为 44
        using (var hmac = new HMACSHA256(prk.ToArray()))
        {
            hmac.TryComputeHash(info, okm, out _);
        }

        byte[] aesKey = okm.Slice(0, 32).ToArray();   // 取前 32 字节
        byte[] ivBase = okm.Slice(32, 12).ToArray();  // 取后 12 字节

        return new AeadKeyMaterial(aesKey, ivBase);
    }
}
