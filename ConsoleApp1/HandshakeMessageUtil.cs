// HandshakeMessageUtil.cs
using System.Security.Cryptography;
using System.Text;
/*
struct ClientHello
{
    byte[] random[32];             // 模拟客户端随机
    byte[] clientPublicKey;
}

struct ServerHello
{
    byte[] random[32];             // 模拟服务端随机
    byte[] serverPublicKey
}*/

public static class HandshakeMessageUtil
{
    public static byte[] BuildClientHello(byte[] clientRandom, byte[] clientPublicKey)
    {
        byte[] hello = new byte[32 + clientPublicKey.Length];
        Buffer.BlockCopy(clientRandom, 0, hello, 0, 32);
        Buffer.BlockCopy(clientPublicKey, 0, hello, 32, clientPublicKey.Length);
        return hello;
    }

    public static byte[] BuildServerHello(byte[] serverRandom, byte[] serverPublicKey)
    {
        byte[] hello = new byte[32 + serverPublicKey.Length];
        Buffer.BlockCopy(serverRandom, 0, hello, 0, 32);
        Buffer.BlockCopy(serverPublicKey, 0, hello, 32, serverPublicKey.Length);
        return hello;
    }

    public static void ParseClientHello(byte[] hello, out byte[] clientRandom, out byte[] clientPublicKey)
    {
        clientRandom = new byte[32];
        Buffer.BlockCopy(hello, 0, clientRandom, 0, 32);
        clientPublicKey = new byte[hello.Length - 32];
        Buffer.BlockCopy(hello, 32, clientPublicKey, 0, clientPublicKey.Length);
    }

    public static void ParseServerHello(byte[] hello, out byte[] serverRandom, out byte[] serverPublicKey)
    {
        serverRandom = new byte[32];
        Buffer.BlockCopy(hello, 0, serverRandom, 0, 32);
        serverPublicKey = new byte[hello.Length - 32];
        Buffer.BlockCopy(hello, 32, serverPublicKey, 0, serverPublicKey.Length);
    }
}

