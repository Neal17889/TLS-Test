// EcdheUtil.cs
using NSec.Cryptography;

public class EcdheUtil : IDisposable
{
    private static readonly KeyAgreementAlgorithm Algorithm = KeyAgreementAlgorithm.X25519;
    private readonly Key _privateKey;
    public byte[] PublicKeyBytes { get; }

    public EcdheUtil()
    {
        _privateKey = new Key(Algorithm);
        PublicKeyBytes = _privateKey.PublicKey.Export(KeyBlobFormat.RawPublicKey) ??
                         throw new InvalidOperationException("Failed to export public key");
    }

    public byte[] DeriveSharedSecret(byte[] peerPublicKeyBytes)
    {
        ArgumentNullException.ThrowIfNull(peerPublicKeyBytes);

        var peerPublicKey = PublicKey.Import(Algorithm, peerPublicKeyBytes, KeyBlobFormat.RawPublicKey) ??
                            throw new InvalidOperationException("Failed to import peer public key");

        var creationParams = new SharedSecretCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        using SharedSecret sharedSecret = Algorithm.Agree(_privateKey, peerPublicKey, in creationParams) ??
                                        throw new InvalidOperationException("Failed to derive shared secret");
        return sharedSecret.Export(SharedSecretBlobFormat.RawSharedSecret) ??
               throw new InvalidOperationException("Failed to export shared secret");
    }

    public void Dispose()
    {
        _privateKey?.Dispose();
    }
}