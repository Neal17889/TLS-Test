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

        // 生成符合 TLS1.3 HKDF-Expand-Label 格式的 info 数据
        // 这里设定输出长度为72，标签为 "key derivation"，上下文为空
        byte[] info = BuildHkdfLabel(72, "key derivation", Array.Empty<byte>());

        // 使用 info 数据进行密钥拓展，生成72字节 okm
        Span<byte> okm = stackalloc byte[72];
        using (var hmac = new HMACSHA256(prk.ToArray()))
        {
            hmac.TryComputeHash(info, okm, out _);
        }

        // 分区：32字节 AES 密钥，8字节 IV 基础值，32字节 finished_key
        byte[] aesKey = okm.Slice(0, 32).ToArray();
        byte[] ivBase = okm.Slice(32, 8).ToArray();
        byte[] finishedKey = okm.Slice(40, 32).ToArray();

        return new AeadKeyMaterial(aesKey, ivBase, finishedKey);
    }

    /// <summary>
    /// 生成符合 TLS 1.3 HKDF-Expand-Label 格式的 info 数据。
    /// 格式： [length(2 bytes)] [label length(1 byte)] [("tls13 " + label)] [context length(1 byte)] [context]
    /// </summary>
    /// <param name="length">期望输出的长度</param>
    /// <param name="label">标签字符串，例如 "key derivation"</param>
    /// <param name="context">上下文数据，通常为空</param>
    /// <returns>序列化后的 info 字节数组</returns>
    private static byte[] BuildHkdfLabel(int length, string label, byte[] context)
    {
        // "tls13 " 前缀
        byte[] prefix = Encoding.UTF8.GetBytes("tls13 ");
        byte[] labelBytes = Encoding.UTF8.GetBytes(label);
        byte[] fullLabel = new byte[prefix.Length + labelBytes.Length];
        Buffer.BlockCopy(prefix, 0, fullLabel, 0, prefix.Length);
        Buffer.BlockCopy(labelBytes, 0, fullLabel, prefix.Length, labelBytes.Length);

        // 计算 info 长度：2字节（length） +1字节(label长度)+ fullLabel.Length + 1字节(context长度)+context.Length
        int infoLength = 2 + 1 + fullLabel.Length + 1 + (context?.Length ?? 0);
        byte[] info = new byte[infoLength];

        // 2字节输出长度（大端）
        info[0] = (byte)(length >> 8);
        info[1] = (byte)(length & 0xFF);

        // 1字节 fullLabel 长度
        info[2] = (byte)fullLabel.Length;
        // 拷贝 fullLabel
        Buffer.BlockCopy(fullLabel, 0, info, 3, fullLabel.Length);

        // 1字节 context 长度（这里 context 为空时为0）
        int pos = 3 + fullLabel.Length;
        info[pos] = (byte)(context?.Length ?? 0);

        // 拷贝 context（如果有）
        if (context != null && context.Length > 0)
        {
            Buffer.BlockCopy(context, 0, info, pos + 1, context.Length);
        }

        return info;
    }
}