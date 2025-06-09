// TlsRecordUtil.cs
using System.Net.Sockets;
using System.Security.Cryptography;

/*
struct TLS Record Header (TLS 1.2/1.3 compatible)
{
    byte  contentType;        // 1 = handshake, 2 = application_data
    ushort legacy_version;    // always 0x0303 in TLS 1.3
    ushort length;            // payload length (ciphertext || tag)
}
*/

public enum TlsRecordType : byte
{
    Handshake = 1,
    ApplicationData = 2,
}

public class TlsCryptoContext
{
    public byte[] Key { get; init; } = null!;
    public byte[] IvBase { get; init; } = null!; // 12 bytes
    public ulong SendSequence { get; set; } = 0;
    public ulong ReceiveSequence { get; set; } = 0;
}

public static class TlsRecordUtil
{
    private const ushort TlsVersion = 0x0303;
    private const int AeadTagSize = 16;
    private const int NonceSize = 8;

    // Send AEAD record
    public static async Task SendRecordWithAeadAsync(Stream stream, TlsRecordType type, byte[] plaintext, TlsCryptoContext ctx, CancellationToken cancellationToken)
    {
        byte[] nonce = ComputeNonce(ctx.IvBase, ctx.SendSequence);
        byte[] header = BuildTlsHeader(type, plaintext.Length + AeadTagSize);

        byte[] encrypted = CryptoUtil.EncryptChaCha20Poly1305(ctx.Key, nonce, plaintext, header);

        byte[] record = new byte[header.Length + encrypted.Length];
        Buffer.BlockCopy(header, 0, record, 0, header.Length);
        Buffer.BlockCopy(encrypted, 0, record, header.Length, encrypted.Length);

        await stream.WriteAsync(record, cancellationToken);
        ctx.SendSequence++;
    }

    // Receive AEAD record
    public static async Task<(TlsRecordType type, byte[] plaintext)> ReceiveRecordWithAeadAsync(Stream stream, TlsCryptoContext ctx, CancellationToken cancellationToken)
    {
        byte[] header = new byte[5];
        await stream.ReadExactlyAsync(header, cancellationToken);

        TlsRecordType type = (TlsRecordType)header[0];
        int length = (header[3] << 8) | header[4];

        byte[] encrypted = new byte[length];
        await stream.ReadExactlyAsync(encrypted, cancellationToken);

        byte[] nonce = ComputeNonce(ctx.IvBase, ctx.ReceiveSequence);
        byte[] plaintext = CryptoUtil.DecryptChaCha20Poly1305(ctx.Key, nonce, encrypted, header);
        ctx.ReceiveSequence++;
        return (type, plaintext);
    }

    private static byte[] BuildTlsHeader(TlsRecordType type, int payloadLength)
    {
        return new byte[]
        {
            (byte)type,
            (byte)(TlsVersion >> 8),
            (byte)(TlsVersion & 0xFF),
            (byte)(payloadLength >> 8),
            (byte)(payloadLength & 0xFF)
        };
    }

    public static byte[] ComputeNonce(byte[] ivBase, ulong sequenceNumber)
    {
        if (ivBase.Length < NonceSize)
            throw new ArgumentException("IV base must be at least 8 bytes for ChaCha20");

        byte[] seqBytes = BitConverter.GetBytes(sequenceNumber);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(seqBytes); // network order

        byte[] nonce = new byte[NonceSize];
        for (int i = 0; i < NonceSize; i++)
        {
            nonce[i] = (byte)(ivBase[i] ^ seqBytes[seqBytes.Length - NonceSize + i]);
        }
        return nonce;
    }

}
