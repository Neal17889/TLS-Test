// CertUtil.cs
using System.Security.Cryptography.X509Certificates;

public static class CertUtil
{
    public static X509Certificate2 LoadCertificate(string pfxPath)
    {
        return new X509Certificate2(
            pfxPath,
            password: null as string,  // 使用null表示无密码
            X509KeyStorageFlags.Exportable |
            X509KeyStorageFlags.PersistKeySet
        );
    }

    public static X509Certificate2 LoadCaCertificate(string path)
    {
        return new X509Certificate2(File.ReadAllBytes(path));
    }

    public static bool VerifyCertificateChain(X509Certificate2 receivedCert, X509Certificate2 caCert)
    {
        var chain = new X509Chain();
        chain.ChainPolicy.ExtraStore.Add(caCert);
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        return chain.Build(receivedCert) &&
               chain.ChainElements[^1].Certificate.Thumbprint == caCert.Thumbprint;
    }
}
