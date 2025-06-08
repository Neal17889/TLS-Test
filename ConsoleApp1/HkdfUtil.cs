// HkdfUtil.cs
using System.Security.Cryptography;
using System.Text;

public static class HkdfUtil
{
    public static byte[] Extract(byte[] salt, byte[] inputKeyMaterial)
    {
        using var hmac = new HMACSHA256(salt);
        return hmac.ComputeHash(inputKeyMaterial);
    }

    public static byte[] Expand(byte[] prk, byte[] info, int length)
    {
        List<byte> output = new();
        byte[] previous = Array.Empty<byte>();
        byte counter = 1;

        while (output.Count < length)
        {
            using var hmac = new HMACSHA256(prk);
            byte[] input = previous.Concat(info).Append(counter).ToArray();
            previous = hmac.ComputeHash(input);
            output.AddRange(previous);
            counter++;
        }

        return output.Take(length).ToArray();
    }

    public static byte[] Hkdf(byte[] salt, byte[] ikm, byte[] info, int length)
    {
        var prk = Extract(salt, ikm);
        return Expand(prk, info, length);
    }
}
