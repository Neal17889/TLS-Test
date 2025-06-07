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

        TcpListener listener = new (IPAddress.Loopback, 4433);
        listener.Start();
        Console.WriteLine("Server: Listening on port 4433...");

        using TcpClient client = listener.AcceptTcpClient();
        using NetworkStream stream = client.GetStream();

        // Receive ClientHello
        var (type, clientHello) = TlsRecordUtil.ReceiveRecord(stream);
        handshakeMessages.Add(clientHello);
        Console.WriteLine("Server: Received ClientHello");

        // Send ServerHello
        byte[] serverHello = HandshakeMessageUtil.BuildServerHello();
        handshakeMessages.Add(serverHello);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, serverHello);
        Console.WriteLine("Server: Sent ServerHello");

        // Send server certificate
        X509Certificate2 serverCert = CertUtil.LoadCertificate("server.pfx");
        handshakeMessages.Add(serverCert.RawData);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, serverCert.RawData);
        Console.WriteLine("Server: Sent server certificate");

        // Receive client certificate
        var (type2, clientRaw) = TlsRecordUtil.ReceiveRecord(stream);
        handshakeMessages.Add(clientRaw);
        var clientCert = new X509Certificate2(clientRaw);
        var caCert = CertUtil.LoadCaCertificate("ca.crt");
        if (!CertUtil.VerifyCertificateChain(clientCert, caCert))
        {
            Console.WriteLine("Server: Client certificate verification failed!");
            return;
        }
        Console.WriteLine("Server: Client certificate verified");

        // Receive encrypted AES key
        var (type3, encKeyRecord) = TlsRecordUtil.ReceiveRecord(stream);
        RSA? serverRsa = serverCert.GetRSAPrivateKey();
        byte[] aesKey = serverRsa.Decrypt(encKeyRecord, RSAEncryptionPadding.Pkcs1);
        Console.WriteLine("Server: Received and decrypted AES key");

        // Receive client Finished
        var (type4, clientFinished) = TlsRecordUtil.ReceiveRecord(stream);
        byte[] expectedHash = FinishedMessageUtil.ComputeHandshakeHash(handshakeMessages);
        if (!FinishedMessageUtil.VerifyFinished(expectedHash, clientFinished, clientCert.GetRSAPublicKey()))
        {
            Console.WriteLine("Server: Client Finished verification failed!");
            return;
        }
        Console.WriteLine("Server: Client Finished verified");

        // Send server Finished
        byte[] serverHash = FinishedMessageUtil.ComputeHandshakeHash(handshakeMessages);
        byte[] serverFinished = FinishedMessageUtil.SignFinished(serverHash, serverCert.GetRSAPrivateKey());
        TlsRecordUtil.SendRecord(stream, TlsRecordType.Handshake, serverFinished);
        Console.WriteLine("Server: Sent Finished message");

        // Receive encrypted message
        var (type5, encAppData) = TlsRecordUtil.ReceiveRecord(stream);
        string message = CryptoUtil.DecryptAes(aesKey, encAppData);
        Console.WriteLine("Server: Decrypted message: " + message);

        // Send encrypted response
        string response = "Hello from server!";
        byte[] encResp = CryptoUtil.EncryptAes(aesKey, response);
        TlsRecordUtil.SendRecord(stream, TlsRecordType.ApplicationData, encResp);
        Console.WriteLine("Server: Sent encrypted response");
    }
}