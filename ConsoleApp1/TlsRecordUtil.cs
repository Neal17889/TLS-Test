// TlsRecordUtil.cs
using System.Net.Sockets;
/*
struct TlsRecord
{
    byte recordType;       // 1 = handshake, 2 = data
    ushort payloadLength;  // 2 bytes
    byte[] payload;        // N bytes
}*/

public enum TlsRecordType : byte
{
    Handshake = 1,
    ApplicationData = 2,
}

public static class TlsRecordUtil
{
    public static void SendRecord(NetworkStream stream, TlsRecordType type, byte[] payload)
    {
        byte[] header = new byte[3];
        header[0] = (byte)type;
        ushort length = (ushort)payload.Length;
        header[1] = (byte)(length >> 8);
        header[2] = (byte)(length & 0xFF);

        byte[] record = new byte[header.Length + payload.Length];
        Buffer.BlockCopy(header, 0, record, 0, header.Length);
        Buffer.BlockCopy(payload, 0, record, header.Length, payload.Length);
        stream.Write(record, 0, record.Length);

    }

    public static (TlsRecordType type, byte[] payload) ReceiveRecord(NetworkStream stream)
    {
        byte[] header = new byte[3];
        stream.ReadExactly(header);  // .NET 8 内置方法

        var type = (TlsRecordType)header[0];
        int length = (header[1] << 8) | header[2];

        byte[] payload = new byte[length];
        stream.ReadExactly(payload);  // 同样使用内置方法

        return (type, payload);
    }



    public static async Task<(TlsRecordType Type, byte[] Data)> ReceiveRecordAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] header = new byte[5];
        await stream.ReadExactlyAsync(header, cancellationToken);  // .NET 8

        TlsRecordType type = (TlsRecordType)header[0];
        int length = (header[3] << 8) | header[4];
        byte[] data = new byte[length];
        await stream.ReadExactlyAsync(data, cancellationToken);    // 同样内置方法

        return (type, data);
    }


    public static async Task SendRecordAsync(Stream stream, TlsRecordType type, byte[] data, CancellationToken cancellationToken)
    {
        byte[] header =
        [
            (byte)type,
            3,
            3, // TLS version
            (byte)(data.Length >> 8),
            (byte)(data.Length & 0xff),
        ];
        byte[] record = new byte[header.Length + data.Length];
        Buffer.BlockCopy(header, 0, record, 0, header.Length);
        Buffer.BlockCopy(data, 0, record, header.Length, data.Length);
        await stream.WriteAsync(record.AsMemory(0, record.Length), cancellationToken);

    }
}
