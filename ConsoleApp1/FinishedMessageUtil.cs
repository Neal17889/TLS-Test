// FinishedMessageUtil.cs
using System.Collections.Generic;
using System.Security.Cryptography;

public static class FinishedMessageUtil
{
    public static byte[] ComputeHandshakeHash(List<byte[]> messages)
    {
        using var sha256 = SHA256.Create();
        foreach (var msg in messages)
            sha256.TransformBlock(msg, 0, msg.Length, null, 0);
        sha256.TransformFinalBlock(System.Array.Empty<byte>(), 0, 0);
        return sha256.Hash!;
    }

    public static byte[] SignFinished(byte[] hash, ECDsa privateKey)
    {
        // 使用 ECDsa 对传入的 hash 进行签名（默认使用 SHA256 算法）
        return privateKey.SignHash(hash);
    }

    public static bool VerifyFinished(byte[] hash, byte[] signature, ECDsa publicKey)
    {
        // 使用 ECDsa 对 signature 进行验证
        return publicKey.VerifyHash(hash, signature);
    }
}