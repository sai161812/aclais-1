[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StoreRoot,
    [switch]$AuditOnly,
    [string]$WorkerSid
)

$ErrorActionPreference = 'Stop'
if (-not ('ReceiverStoreAclNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class ReceiverStoreAclNative
{
    [DllImport("Advapi32.dll", EntryPoint = "SetFileSecurityW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetFileSecurity(string path, UInt32 securityInformation, byte[] descriptor);

    public static void ApplyDaclOnly(string path, byte[] descriptor)
    {
        const UInt32 DACL_SECURITY_INFORMATION = 0x00000004;
        const UInt32 PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
        if (!SetFileSecurity(path, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to apply the scoped receiver DACL.");
    }
}
'@
}
$rootPath = [System.IO.Path]::GetFullPath($StoreRoot)
$rootItem = Get-Item -LiteralPath $rootPath -Force
if (-not $rootItem.PSIsContainer -or $rootPath.TrimEnd('\') -eq [System.IO.Path]::GetPathRoot($rootPath).TrimEnd('\')) {
    throw 'Receiver store root must be a scoped directory.'
}

$ownerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowedSids = @($ownerSid, 'S-1-5-18', 'S-1-5-32-544')
if ($WorkerSid -and $WorkerSid -in $allowedSids) {
    throw 'The configured worker identity has receiver storage access.'
}
$items = [System.Collections.Generic.List[System.IO.FileSystemInfo]]::new()
$pending = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
$pending.Push([System.IO.DirectoryInfo]::new($rootPath))
while ($pending.Count -gt 0) {
    $directory = $pending.Pop()
    if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Receiver store cannot contain reparse points.'
    }
    $items.Add($directory)
    foreach ($child in $directory.EnumerateFileSystemInfos()) {
        if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Receiver store cannot contain reparse points.'
        }
        if (($child.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
            $pending.Push([System.IO.DirectoryInfo]$child)
        } else {
            $items.Add($child)
        }
    }
}

foreach ($item in $items) {
    if ($AuditOnly) {
        $security = $null
    } elseif (($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
        $security = [System.Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
    } else {
        $security = [System.Security.AccessControl.FileSecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
    }
    if (-not $AuditOnly) {
        foreach ($sidText in $allowedSids) {
            $sid = [System.Security.Principal.SecurityIdentifier]::new($sidText)
            if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $sid,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
            } else {
                $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $sid,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
            }
            [void]$security.AddAccessRule($rule)
        }
        [ReceiverStoreAclNative]::ApplyDaclOnly(
            $item.FullName,
            $security.GetSecurityDescriptorBinaryForm()
        )
    }
    $verified = Get-Acl -LiteralPath $item.FullName
    if (-not $verified.AreAccessRulesProtected -or -not $verified.AreAccessRulesCanonical) {
        throw 'Receiver store ACL did not verify.'
    }
    $rules = $verified.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    if ($rules.Count -ne 3) { throw 'Receiver store ACL contains an unexpected principal.' }
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin $allowedSids -or
            $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl) {
            throw 'Receiver store ACL contains an unexpected permission.'
        }
    }
}

[Console]::Out.WriteLine('RECEIVER_STORE_PROTECTED')
