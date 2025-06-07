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
        return random; // 暂时只发随机数
    }

    public static byte[] BuildServerHello()
    {
        byte[] random = RandomNumberGenerator.GetBytes(32);
        return random; // 暂时只发随机数
    }
}
