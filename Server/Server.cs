// Server.cs
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

class AsyncServer
{
    public static async Task Main()
    {
        int port = 4433;
        TcpListener listener = new(IPAddress.Loopback, port);
        listener.Start();
        Console.WriteLine($"Server: Listening on port {port}...");

        // 预加载证书（若使用证书认证则会使用，否则仍加载以便传入参数）
        var serverCert = CertUtil.LoadCertificate("server.pfx");
        var caCert = CertUtil.LoadCaCertificate("ca.crt");

        while (true)
        {
            try
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                Console.WriteLine("Server: Client connected.");
                _ = HandleClientAsync(client, serverCert, caCert);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Server error while accepting client: " + ex.Message);
            }
        }
    }

    private static async Task HandleClientAsync(TcpClient client, X509Certificate2 serverCert, X509Certificate2 caCert)
    {
        try
        {
            using (client)
            using (var netStream = client.GetStream())
            {
                // 构造 MySslStream，useCertAuth 设置为 false（不采用证书认证）
                var sslStream = new MySslStream(
                    netStream,
                    leaveInnerStreamOpen: false,
                    certValidationCallback: (_, cert, chain, errors) =>
                    {
                        if (cert == null)
                            return false;
                        var cert2 = new X509Certificate2(cert);
                        return CertUtil.VerifyCertificateChain(cert2, caCert) &&
                               errors == System.Net.Security.SslPolicyErrors.None;
                    },
                    useCertAuth: false
                );

                // 执行 TLS 握手
                sslStream.AuthenticateAsServer(serverCert, caCert);
                Console.WriteLine("Server: TLS handshake completed.");

                byte[] buffer = new byte[1024];
                while (true)
                {
                    int bytesRead = 0;
                    try
                    {
                        // 尝试读取数据，如果流已结束或数据不足将抛出异常
                        bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Server: Exception during reading: " + ex.Message);
                        break; // 读取异常时优雅退出循环
                    }

                    if (bytesRead <= 0)
                    {
                        // 当返回 0 时，意味着客户端已经关闭了连接
                        Console.WriteLine("Server: Client closed connection gracefully.");
                        break;
                    }

                    string msg = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Console.WriteLine("Server: Received - " + msg);

                    string response = "Hello from server!";
                    byte[] responseData = Encoding.UTF8.GetBytes(response);
                    await sslStream.WriteAsync(responseData, 0, responseData.Length);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Server error: " + ex.Message);
        }
    }
}