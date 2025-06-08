using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class AsyncClient
{
    public static async Task Main()
    {
        try
        {
            var clientCert = CertUtil.LoadCertificate("client.pfx");
            var caCert = CertUtil.LoadCaCertificate("ca.crt");

            using TcpClient client = new("127.0.0.1", 4433);
            using NetworkStream netStream = client.GetStream();

            var sslStream = new MySslStream(
                netStream,
                leaveInnerStreamOpen: false,
                certValidationCallback: (_, cert, chain, errors) =>
                {
                    if (cert == null) return false;
                    var serverCert = new X509Certificate2(cert);
                    return CertUtil.VerifyCertificateChain(serverCert, caCert) &&
                           errors == SslPolicyErrors.None;
                }
            );

            sslStream.AuthenticateAsClient(clientCert, caCert);
            Console.WriteLine("Client: TLS handshake completed");

            string message = "Hello from client!";
            byte[] messageData = Encoding.UTF8.GetBytes(message);
            await sslStream.WriteAsync(messageData);

            byte[] buffer = new byte[1024];
            int bytesRead = await sslStream.ReadAsync(buffer);
            string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Client: Received - " + response);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Client error: " + ex.Message);
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadLine();
    }
}
