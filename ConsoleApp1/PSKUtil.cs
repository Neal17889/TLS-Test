// PSKUtil.cs
using System.Text;

public static class PSKUtil
{
    // 可以视需求替换为更安全的方式管理（比如从安全存储加载）
    private const string PreSharedKey = "SuperSecretPreSharedKey123!";

    public static byte[] GetPskBytes()
    {
        return Encoding.UTF8.GetBytes(PreSharedKey);
    }
}
