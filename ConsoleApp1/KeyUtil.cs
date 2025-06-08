// KeyUtil.cs
using System.Security.Cryptography;
using System.Text;

public static class KeyUtil
{
    public static RSAParameters ServerPrivateKey;
    public static RSAParameters ServerPublicKey;

    public static void GenerateRsaKeys()
    {
        using var rsa = RSA.Create(2048);
        ServerPrivateKey = rsa.ExportParameters(true);
        ServerPublicKey = rsa.ExportParameters(false);
    }

    public static byte[] RsaEncrypt(byte[] data, RSAParameters publicKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(publicKey);
        return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
    }

    public static byte[] RsaDecrypt(byte[] data, RSAParameters privateKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(privateKey);
        return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
    }

    public static string ExportPublicKeyXml(RSAParameters publicKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(publicKey);
        return rsa.ToXmlString(false);
    }

    public static RSAParameters ImportPublicKeyXml(string xml)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(xml);
        return rsa.ExportParameters(false);
    }
}
