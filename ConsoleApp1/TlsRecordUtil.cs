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

        stream.Write(header, 0, header.Length);
        stream.Write(payload, 0, payload.Length);
    }

    public static (TlsRecordType type, byte[] payload) ReceiveRecord(NetworkStream stream)
    {
        byte[] header = new byte[3];
        stream.Read(header, 0, 3);
        var type = (TlsRecordType)header[0];
        int length = (header[1] << 8) | header[2];

        byte[] payload = new byte[length];
        int read = 0;
        while (read < length)
            read += stream.Read(payload, read, length - read);

        return (type, payload);
    }
}
