// Server.cs
using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class AsyncServer
{
    public static async Task Main()
    {
        TcpListener listener = new(IPAddress.Loopback, 4433);
        listener.Start();
        Console.WriteLine("Server: Listening on port 4433...");

        using TcpClient client = await listener.AcceptTcpClientAsync();
        using NetworkStream netStream = client.GetStream();

        var serverCert = CertUtil.LoadCertificate("server.pfx");
        var caCert = CertUtil.LoadCaCertificate("ca.crt");

        var sslStream = new MySslStream(
            netStream,
            leaveInnerStreamOpen: false,
            certValidationCallback: (_, cert, chain, errors) =>
            {
                if (cert == null) return false;
                var cert2 = new X509Certificate2(cert);
                return CertUtil.VerifyCertificateChain(cert2, caCert) &&
                       errors == SslPolicyErrors.None;
            }
        );

        try
        {
            sslStream.AuthenticateAsServer(serverCert, caCert);
            Console.WriteLine("Server: TLS handshake completed");

            byte[] buffer = new byte[1024];
            int bytesRead = await sslStream.ReadAsync(buffer);
            string msg = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Server: Received - " + msg);

            string response = "Hello from server!";
            byte[] responseData = Encoding.UTF8.GetBytes(response);
            await sslStream.WriteAsync(responseData);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Server error: " + ex.Message);
        }
    }
}