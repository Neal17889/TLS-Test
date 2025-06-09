// PSKUtil.cs
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class PSKUtil
{
    // 在 Credential Manager 中存储凭据时所用的目标名称
    private const string CredentialTarget = "MyApp_PSK";

    /// <summary>
    /// 从 Windows Credential Manager 中读取预共享密钥（PSK）字符串。
    /// 若找不到凭据或读取失败，则抛出异常。
    /// </summary>
    /// <returns>预共享密钥字符串</returns>
    public static string GetPskString()
    {
        IntPtr pCredentialPtr;
        bool read = CredRead(CredentialTarget, CRED_TYPE.GENERIC, 0, out pCredentialPtr);
        if (!read)
        {
            int errorCode = Marshal.GetLastWin32Error();
            throw new Exception($"CredRead failed. Error code: {errorCode}");
        }

        // 将指针转换为 CREDENTIAL 结构体
        CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(pCredentialPtr, typeof(CREDENTIAL));

        string password = "";
        if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
        {
            byte[] blob = new byte[cred.CredentialBlobSize];
            Marshal.Copy(cred.CredentialBlob, blob, 0, (int)cred.CredentialBlobSize);
            // 注意：通常 CredentialBlob 中以 Unicode 格式存储数据
            password = Encoding.Unicode.GetString(blob);
        }

        // 释放凭据内存
        CredFree(pCredentialPtr);
        return password;
    }

    /// <summary>
    /// 获取预共享密钥的字节数组，使用 UTF8 编码转换
    /// </summary>
    /// <returns>PSK 的字节数组</returns>
    public static byte[] GetPskBytes()
    {
        string psk = GetPskString();
        return Encoding.UTF8.GetBytes(psk);
    }

    #region P/Invoke 声明

    // 定义凭据类型，这里只使用 GENERIC 类型
    private enum CRED_TYPE : uint
    {
        GENERIC = 1,
    }

    // 定义 CREDENTIAL 结构体，与 Windows API 中的结构体对应
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public CRED_TYPE Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    // 从 Advapi32.dll 导入 CredRead 函数
    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredRead(string target, CRED_TYPE type, int reservedFlag, out IntPtr CredentialPtr);

    // 从 Advapi32.dll 导入 CredFree 函数
    [DllImport("Advapi32.dll", SetLastError = true)]
    private static extern bool CredFree([In] IntPtr buffer);

    #endregion
}