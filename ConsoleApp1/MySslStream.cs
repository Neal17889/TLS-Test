using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

public class MySslStream(NetworkStream innerStream, bool leaveInnerStreamOpen, RemoteCertificateValidationCallback certValidationCallback) : Stream
{
    private readonly NetworkStream _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
    private readonly bool _leaveInnerStreamOpen = leaveInnerStreamOpen;
    private readonly RemoteCertificateValidationCallback _certValidationCallback = certValidationCallback ?? throw new ArgumentNullException(nameof(certValidationCallback));

    private Aes? _aes;
    private ICryptoTransform? _encryptor;
    private ICryptoTransform? _decryptor;
    private readonly List<byte[]> _handshakeMessages = [];

    public X509Certificate? LocalCertificate { get; private set; }
    public X509Certificate? RemoteCertificate { get; private set; }

    public void AuthenticateAsClient(X509Certificate2 clientCert, X509Certificate2 caCert)
    {
        ArgumentNullException.ThrowIfNull(clientCert);
        ArgumentNullException.ThrowIfNull(caCert);

        using var ecdhe = new EcdheUtil();
        byte[] clientRandom = RandomNumberGenerator.GetBytes(32);
        byte[] clientHello = HandshakeMessageUtil.BuildClientHello(clientRandom, ecdhe.PublicKeyBytes);
        _handshakeMessages.Add(clientHello);
        TlsRecordUtil.SendRecord(_innerStream, TlsRecordType.Handshake, clientHello);

        var (_, serverHello) = TlsRecordUtil.ReceiveRecord(_innerStream);
        _handshakeMessages.Add(serverHello);
        HandshakeMessageUtil.ParseServerHello(serverHello, out byte[] serverRandom, out byte[] serverPubKey);

        var (_, serverCertRaw) = TlsRecordUtil.ReceiveRecord(_innerStream);
        _handshakeMessages.Add(serverCertRaw);
        var serverCert = new X509Certificate2(serverCertRaw);
        RemoteCertificate = serverCert;
        if (!_certValidationCallback(this, serverCert, null, SslPolicyErrors.None))
            throw new Exception("Server certificate validation failed");

        _handshakeMessages.Add(clientCert.RawData);
        TlsRecordUtil.SendRecord(_innerStream, TlsRecordType.Handshake, clientCert.RawData);
        LocalCertificate = clientCert;

        byte[] psk = PSKUtil.GetPskBytes();
        byte[] sharedSecret = ecdhe.DeriveSharedSecret(serverPubKey);
        byte[] aesKey = KeyDerivationUtil.DeriveAesKey(psk, sharedSecret, clientRandom, serverRandom);
        InitAes(aesKey);

        byte[] handshakeHash = FinishedMessageUtil.ComputeHandshakeHash(_handshakeMessages);
        var privateKey = clientCert.GetRSAPrivateKey() ?? throw new InvalidOperationException("Client certificate has no private key");
        byte[] finished = FinishedMessageUtil.SignFinished(handshakeHash, privateKey);
        TlsRecordUtil.SendRecord(_innerStream, TlsRecordType.Handshake, finished);

        var (_, serverFinished) = TlsRecordUtil.ReceiveRecord(_innerStream);
        var publicKey = serverCert.GetRSAPublicKey() ?? throw new InvalidOperationException("Server certificate has no public key");
        if (!FinishedMessageUtil.VerifyFinished(handshakeHash, serverFinished, publicKey))
            throw new Exception("Server Finished verification failed");
    }

    public void AuthenticateAsServer(X509Certificate2 serverCert, X509Certificate2 caCert)
    {
        ArgumentNullException.ThrowIfNull(serverCert);
        ArgumentNullException.ThrowIfNull(caCert);

        using var ecdhe = new EcdheUtil();
        byte[] serverRandom = RandomNumberGenerator.GetBytes(32);

        var (_, clientHello) = TlsRecordUtil.ReceiveRecord(_innerStream);
        _handshakeMessages.Add(clientHello);
        HandshakeMessageUtil.ParseClientHello(clientHello, out byte[] clientRandom, out byte[] clientPubKey);

        byte[] serverHello = HandshakeMessageUtil.BuildServerHello(serverRandom, ecdhe.PublicKeyBytes);
        _handshakeMessages.Add(serverHello);
        TlsRecordUtil.SendRecord(_innerStream, TlsRecordType.Handshake, serverHello);

        _handshakeMessages.Add(serverCert.RawData);
        TlsRecordUtil.SendRecord(_innerStream, TlsRecordType.Handshake, serverCert.RawData);
        LocalCertificate = serverCert;

        var (_, clientCertRaw) = TlsRecordUtil.ReceiveRecord(_innerStream);
        _handshakeMessages.Add(clientCertRaw);
        var clientCert = new X509Certificate2(clientCertRaw);
        RemoteCertificate = clientCert;
        if (!_certValidationCallback(this, clientCert, null, SslPolicyErrors.None))
            throw new Exception("Client certificate validation failed");

        byte[] psk = PSKUtil.GetPskBytes();
        byte[] sharedSecret = ecdhe.DeriveSharedSecret(clientPubKey);
        byte[] aesKey = KeyDerivationUtil.DeriveAesKey(psk, sharedSecret, clientRandom, serverRandom);
        InitAes(aesKey);

        var (_, clientFinished) = TlsRecordUtil.ReceiveRecord(_innerStream);
        byte[] handshakeHash = FinishedMessageUtil.ComputeHandshakeHash(_handshakeMessages);
        var publicKey = clientCert.GetRSAPublicKey() ?? throw new InvalidOperationException("Client certificate has no public key");
        if (!FinishedMessageUtil.VerifyFinished(handshakeHash, clientFinished, publicKey))
            throw new Exception("Client Finished verification failed");

        var privateKey = serverCert.GetRSAPrivateKey() ?? throw new InvalidOperationException("Server certificate has no private key");
        byte[] serverFinished = FinishedMessageUtil.SignFinished(handshakeHash, privateKey);
        TlsRecordUtil.SendRecord(_innerStream, TlsRecordType.Handshake, serverFinished);
    }

    private void InitAes(byte[] aesKey)
    {
        _aes = Aes.Create();
        _aes.Mode = CipherMode.CBC;
        _aes.Padding = PaddingMode.PKCS7;
        _aes.Key = aesKey;
        _aes.GenerateIV();
        _encryptor = _aes.CreateEncryptor();
        _decryptor = _aes.CreateDecryptor();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (_aes == null || _encryptor == null)
            throw new InvalidOperationException("Stream not initialized for encryption");

        byte[] plain = new byte[count];
        Buffer.BlockCopy(buffer, offset, plain, 0, count);
        byte[] encrypted = CryptoUtil.EncryptAes(_aes.Key, plain);
        TlsRecordUtil.SendRecord(_innerStream, TlsRecordType.ApplicationData, encrypted);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_aes == null || _decryptor == null)
            throw new InvalidOperationException("Stream not initialized for decryption");

        var (_, encrypted) = TlsRecordUtil.ReceiveRecord(_innerStream);
        byte[] plain = CryptoUtil.DecryptAes(_aes.Key, encrypted);
        int toCopy = Math.Min(plain.Length, count);
        Buffer.BlockCopy(plain, 0, buffer, offset, toCopy);
        return toCopy;
    }

    public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback? callback, object? state)
    {
        return _innerStream.BeginRead(buffer, offset, count, ar =>
        {
            try
            {
                int bytesRead = _innerStream.EndRead(ar);
                byte[] encrypted = new byte[bytesRead];
                Buffer.BlockCopy(buffer, offset, encrypted, 0, bytesRead);
                byte[] plain = CryptoUtil.DecryptAes(_aes!.Key, encrypted);
                Buffer.BlockCopy(plain, 0, buffer, offset, Math.Min(plain.Length, count));
            }
            catch { }
            callback?.Invoke(ar);
        }, state);
    }

    public override int EndRead(IAsyncResult asyncResult)
    {
        return _innerStream.EndRead(asyncResult); // Return raw bytes read; app may have to recheck
    }

    public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback? callback, object? state)
    {
        if (_aes == null || _encryptor == null)
            throw new InvalidOperationException("Stream not initialized for encryption");

        byte[] plain = new byte[count];
        Buffer.BlockCopy(buffer, offset, plain, 0, count);
        byte[] encrypted = CryptoUtil.EncryptAes(_aes.Key, plain);
        return _innerStream.BeginWrite(encrypted, 0, encrypted.Length, callback, state);
    }

    public override void EndWrite(IAsyncResult asyncResult)
    {
        _innerStream.EndWrite(asyncResult);
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (_aes == null || _decryptor == null)
            throw new InvalidOperationException("Stream not initialized for decryption");

        var record = await TlsRecordUtil.ReceiveRecordAsync(_innerStream, cancellationToken);
        byte[] plain = CryptoUtil.DecryptAes(_aes.Key, record.Data);
        int toCopy = Math.Min(plain.Length, count);
        Buffer.BlockCopy(plain, 0, buffer, offset, toCopy);
        return toCopy;
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (_aes == null || _encryptor == null)
            throw new InvalidOperationException("Stream not initialized for encryption");

        byte[] plain = new byte[count];
        Buffer.BlockCopy(buffer, offset, plain, 0, count);
        byte[] encrypted = CryptoUtil.EncryptAes(_aes.Key, plain);
        await TlsRecordUtil.SendRecordAsync(_innerStream, TlsRecordType.ApplicationData, encrypted, cancellationToken);
    }


    public override void Close()
    {
        if (!_leaveInnerStreamOpen)
            _innerStream.Close();

        _encryptor?.Dispose();
        _decryptor?.Dispose();
        _aes?.Dispose();

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
}
