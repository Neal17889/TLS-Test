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

    public static byte[] SignFinished(byte[] hash, RSA privateKey)
    {
        return privateKey.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public static bool VerifyFinished(byte[] hash, byte[] signature, RSA publicKey)
    {
        return publicKey.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}