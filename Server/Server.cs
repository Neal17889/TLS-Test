using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

class Server
{
    public static void Main()
    {
        TcpListener listener = new(IPAddress.Loopback, 4433);
        listener.Start();
        Console.WriteLine("Server: Listening on port 4433...");

        using TcpClient client = listener.AcceptTcpClient();
        using NetworkStream netStream = client.GetStream();

        // 加载证书
        var serverCert = CertUtil.LoadCertificate("server.pfx");
        var caCert = CertUtil.LoadCaCertificate("ca.crt");

        // 创建自定义SSL流
        var sslStream = new MySslStream(
            netStream,
            leaveInnerStreamOpen: false,
            certValidationCallback: (_, cert, chain, errors) =>
            {
                // 将X509Certificate转换为X509Certificate2以便验证
                if (cert == null) return false;
                var cert2 = new X509Certificate2(cert);
                return CertUtil.VerifyCertificateChain(cert2, caCert) &&
                       errors == SslPolicyErrors.None;
            }
        );

        try
        {
            // 执行服务器认证
            sslStream.AuthenticateAsServer(serverCert, caCert);
            Console.WriteLine("Server: TLS handshake completed");

            // 接收加密数据
            byte[] buffer = new byte[1024];
            int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
            string msg = System.Text.Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Server: Received - " + msg);

            // 发送加密响应
            string response = "Hello from server!";
            byte[] responseData = System.Text.Encoding.UTF8.GetBytes(response);
            sslStream.Write(responseData, 0, responseData.Length);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Server error: " + ex.Message);
        }
    }
}