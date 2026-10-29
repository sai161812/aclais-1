if (-not ("AclaisA2CredentialNative" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;

public static class AclaisA2CredentialNative
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeCredential
    {
        public UInt32 Flags;
        public UInt32 Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
        [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public UInt32 CredentialBlobSize;
        public IntPtr CredentialBlob;
        public UInt32 Persist;
        public UInt32 AttributeCount;
        public IntPtr Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
    }

    public sealed class StoredCredential
    {
        public string UserName { get; set; }
        public SecureString Password { get; set; }
    }

    [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref NativeCredential credential, UInt32 flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, UInt32 type, UInt32 flags, out IntPtr credential);

    [DllImport("Advapi32.dll", EntryPoint = "CredFree")]
    private static extern void CredFree(IntPtr buffer);

    public static void WriteGeneric(string target, string userName, SecureString password)
    {
        if (String.IsNullOrWhiteSpace(target) || String.IsNullOrWhiteSpace(userName))
            throw new ArgumentException("Credential target and username are required.");
        if (password == null || password.Length < 1 || password.Length * 2 > 5120)
            throw new ArgumentException("Credential blob length is invalid.");

        IntPtr blob = Marshal.SecureStringToGlobalAllocUnicode(password);
        try
        {
            var credential = new NativeCredential
            {
                Type = 1,
                TargetName = target,
                UserName = userName,
                CredentialBlob = blob,
                CredentialBlobSize = checked((UInt32)(password.Length * 2)),
                Persist = 2
            };
            if (!CredWrite(ref credential, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CredWriteW failed.");
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(blob);
        }
    }

    public static StoredCredential ReadGeneric(string target)
    {
        IntPtr buffer;
        if (!CredRead(target, 1, 0, out buffer))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CredReadW failed.");

        try
        {
            var credential = (NativeCredential)Marshal.PtrToStructure(buffer, typeof(NativeCredential));
            if (credential.Type != 1 || credential.CredentialBlob == IntPtr.Zero ||
                credential.CredentialBlobSize < 2 || credential.CredentialBlobSize > 5120 ||
                credential.CredentialBlobSize % 2 != 0)
                throw new InvalidOperationException("Stored credential blob failed validation.");

            var password = new SecureString();
            int characterCount = checked((int)(credential.CredentialBlobSize / 2));
            for (int index = 0; index < characterCount; index++)
            {
                short value = Marshal.ReadInt16(credential.CredentialBlob, index * 2);
                if (value == 0)
                    throw new InvalidOperationException("Stored credential contains an unexpected terminator.");
                password.AppendChar((char)value);
            }
            password.MakeReadOnly();
            return new StoredCredential { UserName = credential.UserName, Password = password };
        }
        finally
        {
            CredFree(buffer);
        }
    }
}
'@
}
