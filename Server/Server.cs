using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class Server
{
    public static void Main()
    {
        List<byte[]> handshakeMessages = [];

        TcpListener listener = new(IPAddress.Loopback, 4433);
        listener.Start();
        Console.WriteLine("Server: Listening on port 4433...");

        using TcpClient client = listener.AcceptTcpClient();
        using NetworkStream stream = client.GetStream();
        using EcdheUtil ecdhe = new();

        // 1. 接收 ClientHello
        var (_, clientHello) = TlsRecordUtil.ReceiveRecord(stream);
        HandshakeMessageUtil.ParseClientHello(clientHello, out var clientRandom, out var clientPubKey);
        handshakeMessages.Add(clientHello);
        Console.WriteLine("Server: Received ClientHello");

        // 2. 发送 ServerHello
        byte[] serverRandom = RandomNumberGenerator.GetBytes(32);
        byte[] serverHello = HandshakeMessageUtil.BuildServerHello(serverRandom, ecdhe.PublicKeyBytes);
        handshakeMessages.Add(serverHello);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, serverHello);
        Console.WriteLine("Server: Sent ServerHello");

        // 3. 发送服务器证书
        var serverCert = CertUtil.LoadCertificate("server.pfx");
        handshakeMessages.Add(serverCert.RawData);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, serverCert.RawData);

        // 4. 接收客户端证书
        var (_, clientCertRaw) = TlsRecordUtil.ReceiveRecord(stream);
        handshakeMessages.Add(clientCertRaw);
        var clientCert = new X509Certificate2(clientCertRaw);
        var caCert = CertUtil.LoadCaCertificate("ca.crt");
        if (!CertUtil.VerifyCertificateChain(clientCert, caCert))
        {
            Console.WriteLine("Server: Client certificate invalid");
            return;
        }

        // 5. 派生共享密钥
        byte[] sharedSecret = ecdhe.DeriveSharedSecret(clientPubKey);
        byte[] aesKey = KeyDerivationUtil.DeriveAesKey(sharedSecret, clientRandom, serverRandom, PSKUtil.GetPskBytes());

        // 6. 接收 Finished
        var (_, clientFinished) = TlsRecordUtil.ReceiveRecord(stream);
        byte[] handshakeHash = FinishedMessageUtil.ComputeHandshakeHash(handshakeMessages);
        if (!FinishedMessageUtil.VerifyFinished(handshakeHash, clientFinished, clientCert.GetRSAPublicKey()))
        {
            Console.WriteLine("Server: Client Finished verification failed");
            return;
        }
        Console.WriteLine("Server: Client Finished verified");

        // 7. 发送 Finished
        byte[] serverFinished = FinishedMessageUtil.SignFinished(handshakeHash, serverCert.GetRSAPrivateKey());
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, serverFinished);

        // 8. 收发数据
        var (_, encAppData) = TlsRecordUtil.ReceiveRecord(stream);
        string msg = CryptoUtil.DecryptAes(aesKey, encAppData);
        Console.WriteLine("Server: Received - " + msg);

        string response = "Hello from server!";
        var encResp = CryptoUtil.EncryptAes(aesKey, response);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.ApplicationData, encResp);
    }
}
