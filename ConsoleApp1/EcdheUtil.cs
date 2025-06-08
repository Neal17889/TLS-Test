// EcdheUtil.cs
using System.Security.Cryptography;

public class EcdheUtil : IDisposable
{
    private readonly ECDiffieHellman _ecdh;
    // 使用 SubjectPublicKeyInfo 格式导出本地公钥
    public byte[] PublicKeyBytes { get; }

    public EcdheUtil()
    {
        _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        PublicKeyBytes = _ecdh.PublicKey.ExportSubjectPublicKeyInfo();
    }

    public byte[] DeriveSharedSecret(byte[] peerPublicKeyBytes)
    {
        int bytesRead;
        // 创建临时的 ECDiffieHellman 实例，并导入对方的公钥信息
        using (ECDiffieHellman peerEcdh = ECDiffieHellman.Create())
        {
            peerEcdh.ImportSubjectPublicKeyInfo(peerPublicKeyBytes, out bytesRead);
            return _ecdh.DeriveKeyMaterial(peerEcdh.PublicKey);
        }
    }

    public void Dispose()
    {
        _ecdh?.Dispose();
    }
}