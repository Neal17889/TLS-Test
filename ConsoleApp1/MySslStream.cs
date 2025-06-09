// MySslStream.cs
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

public class MySslStream : Stream
{
    private readonly NetworkStream _innerStream;
    private readonly bool _leaveInnerStreamOpen;
    private readonly RemoteCertificateValidationCallback _certValidationCallback;
    private readonly bool _useCertAuth; // 用于控制是否进行证书认证

    private TlsCryptoContext? _cryptoContext;
    private readonly List<byte[]> _handshakeMessages = new();

    public X509Certificate? LocalCertificate { get; private set; }
    public X509Certificate? RemoteCertificate { get; private set; }

    // 构造函数中增加 useCertAuth 参数
    public MySslStream(NetworkStream innerStream, bool leaveInnerStreamOpen, RemoteCertificateValidationCallback certValidationCallback, bool useCertAuth)
    {
        _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        _leaveInnerStreamOpen = leaveInnerStreamOpen;
        _certValidationCallback = certValidationCallback ?? throw new ArgumentNullException(nameof(certValidationCallback));
        _useCertAuth = useCertAuth;
    }

    private void SendHandshakeRecord(byte[] payload)
    {
        _innerStream.WriteByte((byte)TlsRecordType.Handshake);
        _innerStream.WriteByte(0x03); // TLS 1.2 major
        _innerStream.WriteByte(0x03); // TLS 1.2 minor
        _innerStream.WriteByte((byte)(payload.Length >> 8));
        _innerStream.WriteByte((byte)(payload.Length & 0xFF));
        _innerStream.Write(payload, 0, payload.Length);
    }

    private byte[] ReceiveHandshakeRecord()
    {
        Span<byte> header = stackalloc byte[5];
        _innerStream.ReadExactly(header);
        int length = (header[3] << 8) | header[4];
        byte[] payload = new byte[length];
        _innerStream.ReadExactly(payload);
        return payload;
    }

    // 客户端认证方法
    // 若 _useCertAuth 为 true，则要求双向证书认证，否则跳过证书交换流程
    public void AuthenticateAsClient(X509Certificate2 clientCert, X509Certificate2 caCert)
    {
        // 当使用证书认证时，参数不能为 null
        if (_useCertAuth)
        {
            ArgumentNullException.ThrowIfNull(clientCert);
            ArgumentNullException.ThrowIfNull(caCert);
        }

        using var ecdhe = new EcdheUtil();
        byte[] clientRandom = RandomNumberGenerator.GetBytes(32);
        byte[] clientHello = HandshakeMessageUtil.BuildClientHello(clientRandom, ecdhe.PublicKeyBytes);
        _handshakeMessages.Add(clientHello);
        SendHandshakeRecord(clientHello);

        byte[] serverHello = ReceiveHandshakeRecord();
        _handshakeMessages.Add(serverHello);
        HandshakeMessageUtil.ParseServerHello(serverHello, out byte[] serverRandom, out byte[] serverPubKey);

        if (_useCertAuth)
        {
            // 接收并处理服务器证书
            byte[] serverCertRaw = ReceiveHandshakeRecord();
            _handshakeMessages.Add(serverCertRaw);
            var serverCert = new X509Certificate2(serverCertRaw);
            RemoteCertificate = serverCert;
            if (!_certValidationCallback(this, serverCert, null, SslPolicyErrors.None))
                throw new Exception("Server certificate validation failed");

            // 发送客户端证书
            _handshakeMessages.Add(clientCert.RawData);
            SendHandshakeRecord(clientCert.RawData);
            LocalCertificate = clientCert;
        }
        else
        {
            // 若不采用证书认证，则不交换证书，确保相关成员为 null
            LocalCertificate = null;
            RemoteCertificate = null;
        }

        // 共享密钥及密钥派生（包含 finished_key）
        byte[] psk = PSKUtil.GetPskBytes();
        byte[] sharedSecret = ecdhe.DeriveSharedSecret(serverPubKey);
        var keys = KeyDerivationUtil.DeriveAeadKey(sharedSecret, clientRandom, serverRandom, psk);
        _cryptoContext = new TlsCryptoContext { Key = keys.AesKey, IvBase = keys.IvBase };

        // 使用 finished_key 和 HMAC 计算 Finished 消息
        byte[] handshakeHash = FinishedMessageUtil.ComputeHandshakeHash(_handshakeMessages);
        byte[] finished = FinishedMessageUtil.ComputeFinishedMAC(handshakeHash, keys.FinishedKey);
        SendHandshakeRecord(finished);

        // 客户端接收并验证服务端的 Finished 消息
        byte[] serverFinished = ReceiveHandshakeRecord();
        if (!FinishedMessageUtil.VerifyFinishedMAC(handshakeHash, keys.FinishedKey, serverFinished))
            throw new Exception("Server Finished verification failed");
    }

    // 服务器认证方法
    // 若 _useCertAuth 为 true，则要求双向证书认证，否则跳过证书交换流程
    public void AuthenticateAsServer(X509Certificate2 serverCert, X509Certificate2 caCert)
    {
        if (_useCertAuth)
        {
            ArgumentNullException.ThrowIfNull(serverCert);
            ArgumentNullException.ThrowIfNull(caCert);
        }

        using var ecdhe = new EcdheUtil();
        byte[] serverRandom = RandomNumberGenerator.GetBytes(32);

        byte[] clientHello = ReceiveHandshakeRecord();
        _handshakeMessages.Add(clientHello);
        HandshakeMessageUtil.ParseClientHello(clientHello, out byte[] clientRandom, out byte[] clientPubKey);

        byte[] serverHello = HandshakeMessageUtil.BuildServerHello(serverRandom, ecdhe.PublicKeyBytes);
        _handshakeMessages.Add(serverHello);
        SendHandshakeRecord(serverHello);

        if (_useCertAuth)
        {
            // 发送服务器证书
            _handshakeMessages.Add(serverCert.RawData);
            SendHandshakeRecord(serverCert.RawData);
            LocalCertificate = serverCert;

            // 接收并处理客户端证书
            byte[] clientCertRaw = ReceiveHandshakeRecord();
            _handshakeMessages.Add(clientCertRaw);
            var clientCert = new X509Certificate2(clientCertRaw);
            RemoteCertificate = clientCert;
            if (!_certValidationCallback(this, clientCert, null, SslPolicyErrors.None))
                throw new Exception("Client certificate validation failed");
        }
        else
        {
            LocalCertificate = null;
            RemoteCertificate = null;
        }

        // 共享密钥及密钥派生（包含 finished_key）
        byte[] psk = PSKUtil.GetPskBytes();
        byte[] sharedSecret = ecdhe.DeriveSharedSecret(clientPubKey);
        var keys = KeyDerivationUtil.DeriveAeadKey(sharedSecret, clientRandom, serverRandom, psk);
        _cryptoContext = new TlsCryptoContext { Key = keys.AesKey, IvBase = keys.IvBase };

        // 接收并验证客户端 Finished 消息
        byte[] clientFinished = ReceiveHandshakeRecord();
        byte[] handshakeHash = FinishedMessageUtil.ComputeHandshakeHash(_handshakeMessages);
        if (!FinishedMessageUtil.VerifyFinishedMAC(handshakeHash, keys.FinishedKey, clientFinished))
            throw new Exception("Client Finished verification failed");

        // 生成并发送服务器 Finished 消息
        byte[] serverFinished = FinishedMessageUtil.ComputeFinishedMAC(handshakeHash, keys.FinishedKey);
        SendHandshakeRecord(serverFinished);
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (_cryptoContext == null)
            throw new InvalidOperationException("TLS context not initialized");

        byte[] plain = new byte[count];
        Buffer.BlockCopy(buffer, offset, plain, 0, count);
        await TlsRecordUtil.SendRecordWithAeadAsync(_innerStream, TlsRecordType.ApplicationData, plain, _cryptoContext, cancellationToken);
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (_cryptoContext == null)
            throw new InvalidOperationException("TLS context not initialized");

        var (type, plain) = await TlsRecordUtil.ReceiveRecordWithAeadAsync(_innerStream, _cryptoContext, cancellationToken);
        int toCopy = Math.Min(plain.Length, count);
        Buffer.BlockCopy(plain, 0, buffer, offset, toCopy);
        return toCopy;
    }

    public override void Close()
    {
        if (!_leaveInnerStreamOpen)
            _innerStream.Close();
        base.Close();
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => _innerStream.Flush();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException("Use WriteAsync instead");
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException("Use ReadAsync instead");
}