// Client.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class PerformanceTestClient
{
    // --- 测试参数配置 ---
    const int TEST_DURATION = 60; // 测试总时长（秒）
    const int CONNECTIONS_PER_SECOND = 1; // 每秒发起的连接数
    const int MESSAGES_PER_CONNECTION = 1000; // 每个连接发送的消息数

    // --- 全局测试指标 ---
    static int totalConnections = 0;     // 总连接数
    static int successConnections = 0;   // 成功连接数（无错误完成消息往返的连接）
    static int errorConnections = 0;     // 出错连接数
    static int totalMessages = 0;        // 发送的总消息数
    static double totalResponseTime = 0.0;  // 累计响应时长（单位秒）
    static readonly object metricsLock = new object();

    public static async Task Main()
    {
        // 加载客户端证书和 CA 证书（请确保文件路径正确）
        var clientCert = CertUtil.LoadCertificate("client.pfx");
        var caCert = CertUtil.LoadCaCertificate("ca.crt");

        using CancellationTokenSource cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromSeconds(TEST_DURATION));

        List<Task> connectionTasks = new List<Task>();
        Stopwatch swGlobal = Stopwatch.StartNew();

        Console.WriteLine("Performance test starting...");

        // 在测试时长内，每秒发起 CONNECTIONS_PER_SECOND 个新连接
        while (!cts.IsCancellationRequested)
        {
            for (int i = 0; i < CONNECTIONS_PER_SECOND; i++)
            {
                connectionTasks.Add(RunConnection(clientCert, caCert));
            }
            await Task.Delay(1000);
        }

        // 等待所有连接任务完成
        await Task.WhenAll(connectionTasks);
        swGlobal.Stop();

        // 计算连接错误率和消息吞吐量（消息/秒）
        double errorRate = errorConnections > 0 ? (double)errorConnections / totalConnections * 100.0 : 0.0;
        double throughput = totalMessages / (double)TEST_DURATION;

        // 输出全局测试指标
        Console.WriteLine("---- Test Completed ----");
        Console.WriteLine($"Total Connections: {totalConnections}");
        Console.WriteLine($"Successful Connections: {successConnections}");
        Console.WriteLine($"Error Connections: {errorConnections}");
        Console.WriteLine($"Connection Error Rate: {errorRate:F2}%");
        Console.WriteLine($"Total Messages Sent: {totalMessages}");
        Console.WriteLine($"Total Response Time (s): {totalResponseTime:F3}");
        Console.WriteLine($"Throughput (messages/sec): {throughput:F2}");
        if (totalMessages > 0)
        {
            double avgRespTimeMs = (totalResponseTime / totalMessages) * 1000.0;
            Console.WriteLine($"Average Response Time (ms): {avgRespTimeMs:F3}");
        }
        Console.WriteLine("Press any key to exit...");
        Console.ReadLine();
    }

    private static async Task RunConnection(X509Certificate2 clientCert, X509Certificate2 caCert)
    {
        Interlocked.Increment(ref totalConnections);
        try
        {
            using TcpClient client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, 4433);
            using NetworkStream netStream = client.GetStream();

            // 构造 SslStream
            // 不进行客户端证书认证，因此 RemoteCertificateValidationCallback 中仅用于验证服务器证书
            var sslStream = new SslStream(netStream, false, new RemoteCertificateValidationCallback((sender, certificate, chain, sslPolicyErrors) =>
            {
                return true;
            }));

            // 进行 TLS 握手
            // targetHost 参数必须与服务器证书的 CN 一致，这里使用 "localhost"，如有需要请修改
            await sslStream.AuthenticateAsClientAsync("localhost", new X509CertificateCollection { clientCert }, SslProtocols.Tls12, false);
            Interlocked.Increment(ref successConnections);

            // 每个连接发送固定数量的消息
            for (int i = 0; i < MESSAGES_PER_CONNECTION; i++)
            {
                string message = "Hello from client!";
                byte[] messageData = Encoding.UTF8.GetBytes(message);

                Stopwatch sw = Stopwatch.StartNew();
                await sslStream.WriteAsync(messageData, 0, messageData.Length);
                byte[] buffer = new byte[1024];
                int bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length);
                sw.Stop();

                if (bytesRead <= 0)
                {
                    // 若服务器关闭连接，则退出循环
                    break;
                }

                Interlocked.Increment(ref totalMessages);
                lock (metricsLock)
                {
                    totalResponseTime += sw.Elapsed.TotalSeconds;
                }
            }
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref errorConnections);
            Console.WriteLine("Connection error: " + ex.Message);
        }
    }
}