// HandshakeMessageUtil.cs
using System.Security.Cryptography;
using System.Text;
/*
struct ClientHello
{
    byte[] random[32];             // 模拟客户端随机
}

struct ServerHello
{
    byte[] random[32];             // 模拟服务端随机
}*/

public static class HandshakeMessageUtil
{
    public static byte[] BuildClientHello()
    {
        byte[] random = RandomNumberGenerator.GetBytes(32);
        return random; // 直接发送随机数
    }

    public static byte[] BuildServerHello()
    {
        byte[] random = RandomNumberGenerator.GetBytes(32);
        return random; // 直接发送随机数
    }

    public static byte[] ExtractRandom(byte[] hello)
    {
        // 提取 hello 消息中的前32字节随机数
        if (hello.Length < 32)
            throw new ArgumentException("Handshake message too short to extract random");

        byte[] random = new byte[32];
        Buffer.BlockCopy(hello, 0, random, 0, 32);
        return random;
    }

    public static byte[] CombineRandoms(byte[] clientRandom, byte[] serverRandom)
    {
        if (clientRandom.Length != 32 || serverRandom.Length != 32)
            throw new ArgumentException("Randoms must be 32 bytes each");

        byte[] combined = new byte[64];
        Buffer.BlockCopy(clientRandom, 0, combined, 0, 32);
        Buffer.BlockCopy(serverRandom, 0, combined, 32, 32);
        return combined;
    }
}
