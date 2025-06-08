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
        if (clientRandom.Length != 32 || clientPublicKey.Length != 32)
            throw new ArgumentException("X25519 requires 32-byte clientRandom and publicKey");

        byte[] hello = new byte[64];
        Buffer.BlockCopy(clientRandom, 0, hello, 0, 32);
        Buffer.BlockCopy(clientPublicKey, 0, hello, 32, 32);
        return hello;
    }


    public static byte[] BuildServerHello(byte[] serverRandom, byte[] serverPublicKey)
    {
        if (serverRandom.Length != 32 || serverPublicKey.Length != 32)
            throw new ArgumentException("X25519 requires 32-byte serverRandom and publicKey");

        byte[] hello = new byte[64];
        Buffer.BlockCopy(serverRandom, 0, hello, 0, 32);
        Buffer.BlockCopy(serverPublicKey, 0, hello, 32, 32);
        return hello;
    }

    public static void ParseClientHello(byte[] hello, out byte[] clientRandom, out byte[] clientPublicKey)
    {
        if (hello.Length != 64)
            throw new InvalidOperationException("Invalid ClientHello length for X25519");

        clientRandom = new byte[32];
        clientPublicKey = new byte[32];
        Buffer.BlockCopy(hello, 0, clientRandom, 0, 32);
        Buffer.BlockCopy(hello, 32, clientPublicKey, 0, 32);
    }

    public static void ParseServerHello(byte[] hello, out byte[] serverRandom, out byte[] serverPublicKey)
    {
        if (hello.Length != 64)
            throw new InvalidOperationException("Invalid ServerHello length for X25519");

        serverRandom = new byte[32];
        serverPublicKey = new byte[32];
        Buffer.BlockCopy(hello, 0, serverRandom, 0, 32);
        Buffer.BlockCopy(hello, 32, serverPublicKey, 0, 32);
    }

}

