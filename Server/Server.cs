// Server.cs
using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
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

        // 预加载证书（服务器证书和 CA 证书）
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
                // 构造 SslStream，注意 leaveInnerStreamOpen 为 false
                // 由于不采用客户端证书认证，这里回调直接返回 true；如果需要验证客户端证书，可在此处添加验证逻辑
                var sslStream = new SslStream(netStream, false, new RemoteCertificateValidationCallback((sender, certificate, chain, sslPolicyErrors) =>
                {
                    // 若需要客户端证书认证，按需验证 certificate
                    return true;
                }));

                // 使用 SslStream 执行 TLS 握手
                // 参数说明：服务器证书、是否要求客户端证书（此处为 false）、使用 TLS 1.2、是否检查撤销状态（此处为 false）
                await sslStream.AuthenticateAsServerAsync(serverCert, clientCertificateRequired: false, enabledSslProtocols: SslProtocols.Tls12, checkCertificateRevocation: false);
                Console.WriteLine("Server: TLS handshake completed.");

                byte[] buffer = new byte[1024];
                while (true)
                {
                    int bytesRead = 0;
                    try
                    {
                        // 尝试从 SslStream 中读取数据
                        bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Server: Exception during reading: " + ex.Message);
                        break; // 发生异常时退出循环
                    }

                    if (bytesRead <= 0)
                    {
                        // 如果返回 0，表示客户端已关闭连接
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