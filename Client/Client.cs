// ========================= Client.cs =========================
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class Client
{
    public static void Main()
    {
        List<byte[]> handshakeMessages = [];

        using TcpClient client = new("127.0.0.1", 4433);
        using NetworkStream stream = client.GetStream();

        // 1. 发送 ClientHello
        byte[] clientHello = HandshakeMessageUtil.BuildClientHello();
        handshakeMessages.Add(clientHello);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, clientHello);

        // 2. 接收 ServerHello
        var (_, serverHello) = TlsRecordUtil.ReceiveRecord(stream);
        handshakeMessages.Add(serverHello);

        // 3. 接收服务器证书并验证
        var (_, serverCertRaw) = TlsRecordUtil.ReceiveRecord(stream);
        handshakeMessages.Add(serverCertRaw);
        var serverCert = new X509Certificate2(serverCertRaw);
        var caCert = CertUtil.LoadCaCertificate("ca.crt");
        if (!CertUtil.VerifyCertificateChain(serverCert, caCert))
        {
            Console.WriteLine("Client: Server cert invalid");
            return;
        }

        // 4. 发送客户端证书
        var clientCert = CertUtil.LoadCertificate("client.pfx");
        handshakeMessages.Add(clientCert.RawData);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, clientCert.RawData);

        // 5. 使用双方random派生对称密钥
        byte[] clientRandom = HandshakeMessageUtil.ExtractRandom(clientHello);
        byte[] serverRandom = HandshakeMessageUtil.ExtractRandom(serverHello);
        byte[] combinedRandoms = HandshakeMessageUtil.CombineRandoms(clientRandom, serverRandom);
        byte[] aesKey = SHA256.HashData(combinedRandoms).Take(16).ToArray();


        // 6. 发送 Finished
        byte[] handshakeHash = FinishedMessageUtil.ComputeHandshakeHash(handshakeMessages);
        byte[] finishedSig = FinishedMessageUtil.SignFinished(handshakeHash, clientCert.GetRSAPrivateKey());
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, finishedSig);

        // 7. 接收并验证 Finished
        var (_, serverFinished) = TlsRecordUtil.ReceiveRecord(stream);
        if (!FinishedMessageUtil.VerifyFinished(handshakeHash, serverFinished, serverCert.GetRSAPublicKey()))
        {
            Console.WriteLine("Client: Server Finished verify failed");
            return;
        }
        Console.WriteLine("Client: Server Finished verified");

        // 8. 收发数据
        string message = "Hello from client!";
        byte[] encMsg = CryptoUtil.EncryptAes(aesKey, message);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.ApplicationData, encMsg);

        var (_, encResp) = TlsRecordUtil.ReceiveRecord(stream);
        string resp = CryptoUtil.DecryptAes(aesKey, encResp);
        Console.WriteLine("Client: Received - " + resp);

        Console.WriteLine("按任意键退出");
        Console.ReadLine();
    }
}