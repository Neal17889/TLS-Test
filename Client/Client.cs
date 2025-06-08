using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

class Client
{
    public static void Main()
    {
        try
        {
            // 加载证书
            var clientCert = CertUtil.LoadCertificate("client.pfx");
            var caCert = CertUtil.LoadCaCertificate("ca.crt");

            // 建立TCP连接
            using TcpClient client = new("127.0.0.1", 4433);
            using NetworkStream netStream = client.GetStream();

            // 创建自定义SSL流
            var sslStream = new MySslStream(
                netStream,
                leaveInnerStreamOpen: false,
                certValidationCallback: (_, cert, chain, errors) =>
                {
                    // 将X509Certificate转换为X509Certificate2以便验证
                    if (cert == null) return false;
                    var serverCert = new X509Certificate2(cert);
                    return CertUtil.VerifyCertificateChain(serverCert, caCert) &&
                       errors == SslPolicyErrors.None;
                }
            );

            // 执行客户端认证
            sslStream.AuthenticateAsClient(clientCert, caCert);
            Console.WriteLine("Client: TLS handshake completed");

            // 发送加密数据
            string message = "Hello from client!";
            byte[] messageData = System.Text.Encoding.UTF8.GetBytes(message);
            sslStream.Write(messageData, 0, messageData.Length);

            // 接收加密响应
            byte[] buffer = new byte[1024];
            int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
            string response = System.Text.Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Client: Received - " + response);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Client error: " + ex.Message);
        }

        Console.WriteLine("按任意键退出");
        Console.ReadLine();
    }
}