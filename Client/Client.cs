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

        using TcpClient client = new ("127.0.0.1", 4433);
        using NetworkStream stream = client.GetStream();

        // Send ClientHello
        byte[] clientHello = HandshakeMessageUtil.BuildClientHello();
        handshakeMessages.Add(clientHello);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, clientHello);
        Console.WriteLine("Client: Sent ClientHello");

        // Receive ServerHello
        var (type1, serverHello) = TlsRecordUtil.ReceiveRecord(stream);
        handshakeMessages.Add(serverHello);
        Console.WriteLine("Client: Received ServerHello");

        // Receive server cert and validate
        var caCert = CertUtil.LoadCaCertificate("ca.crt");
        var (type2, serverRaw) = TlsRecordUtil.ReceiveRecord(stream);
        handshakeMessages.Add(serverRaw);
        var serverCert = new X509Certificate2(serverRaw);
        if (!CertUtil.VerifyCertificateChain(serverCert, caCert))
        {
            Console.WriteLine("Client: Server certificate verification failed!");
            return;
        }
        Console.WriteLine("Client: Server certificate verified");

        // Send client cert
        X509Certificate2 clientCert = CertUtil.LoadCertificate("client.pfx");
        handshakeMessages.Add(clientCert.RawData);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, clientCert.RawData);
        Console.WriteLine("Client: Sent client certificate");

        // Generate and send AES key
        byte[] aesKey = RandomNumberGenerator.GetBytes(16);
        RSA? serverRsa = serverCert.GetRSAPublicKey();
        byte[] encKey = serverRsa.Encrypt(aesKey, RSAEncryptionPadding.Pkcs1);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, encKey);
        Console.WriteLine("Client: Sent encrypted AES key");

        // Send Finished
        byte[] handshakeHash = FinishedMessageUtil.ComputeHandshakeHash(handshakeMessages);
        byte[] finishedSig = FinishedMessageUtil.SignFinished(handshakeHash, clientCert.GetRSAPrivateKey());
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, finishedSig);
        Console.WriteLine("Client: Sent Finished message");

        // Receive and verify server Finished
        var (type3, serverFinished) = TlsRecordUtil.ReceiveRecord(stream);
        byte[] expectedHash = FinishedMessageUtil.ComputeHandshakeHash(handshakeMessages);
        if (!FinishedMessageUtil.VerifyFinished(expectedHash, serverFinished, serverCert.GetRSAPublicKey()))
        {
            Console.WriteLine("Client: Server Finished verification failed!");
            return;
        }
        Console.WriteLine("Client: Server Finished verified");

        // Send encrypted message
        string message = "Hello from client!";
        byte[] encMessage = CryptoUtil.EncryptAes(aesKey, message);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.ApplicationData, encMessage);
        Console.WriteLine("Client: Sent encrypted message");

        // Receive encrypted response
        var (type4, encResp) = TlsRecordUtil.ReceiveRecord(stream);
        string response = CryptoUtil.DecryptAes(aesKey, encResp);
        Console.WriteLine("Client: Decrypted response: " + response);

        Console.WriteLine("按任意键退出...");
        Console.ReadKey();
    }
}