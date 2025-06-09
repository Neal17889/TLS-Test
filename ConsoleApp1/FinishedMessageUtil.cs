// FinishedMessageUtil.cs
using System.Collections.Generic;
using System.Security.Cryptography;

public static class FinishedMessageUtil
{
    // 计算所有握手消息的 Hash，作为验证握手完整性的基础数据
    public static byte[] ComputeHandshakeHash(List<byte[]> messages)
    {
        using var sha256 = SHA256.Create();
        foreach (var msg in messages)
        {
            sha256.TransformBlock(msg, 0, msg.Length, null, 0);
        }
        sha256.TransformFinalBlock(System.Array.Empty<byte>(), 0, 0);
        return sha256.Hash;
    }

    // 使用 finishedKey 计算 HMAC-SHA256 作为 Finished 消息的 MAC
    public static byte[] ComputeFinishedMAC(byte[] handshakeHash, byte[] finishedKey)
    {
        using var hmac = new HMACSHA256(finishedKey);
        return hmac.ComputeHash(handshakeHash);
    }

    // 验证接收到的 Finished 消息 MAC 是否正确（采用恒定时间比较）
    public static bool VerifyFinishedMAC(byte[] handshakeHash, byte[] finishedKey, byte[] receivedMAC)
    {
        byte[] computedMAC = ComputeFinishedMAC(handshakeHash, finishedKey);
        return CryptographicOperations.FixedTimeEquals(computedMAC, receivedMAC);
    }
}