if (-not ('AclaisA2AclNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;

public static class AclaisA2AclNative
{
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle OpenDirectory(string path, UInt32 access, UInt32 share,
        IntPtr security, UInt32 disposition, UInt32 flags, IntPtr template);

    public static SafeFileHandle HoldNamespace(string path)
    {
        var handle = OpenDirectory(path, 1, 3, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Namespace guard failed.");
        return handle;
    }

    public static void ProbeDeleteAccess(string path)
    {
        using (var handle = OpenDirectory(path, 0x10000, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero))
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "DELETE access refused.");
    }
    public static byte[] CanonicalDacl(byte[] descriptor)
    {
        var raw = new RawSecurityDescriptor(descriptor, 0);
        var ordered = new RawAcl(raw.DiscretionaryAcl.Revision, raw.DiscretionaryAcl.Count);
        // Preserve inherited ACE order and every ACE's original rights/flags.
        for (int group = 0; group < 3; group++)
            foreach (GenericAce ace in raw.DiscretionaryAcl)
            {
                var qualified = ace as QualifiedAce;
                if (qualified == null) throw new InvalidOperationException("Unsupported checkout ACE.");
                int category = (ace.AceFlags & AceFlags.Inherited) != 0 ? 2 :
                    qualified.AceQualifier == AceQualifier.AccessDenied ? 0 : 1;
                if (category == group) ordered.InsertAce(ordered.Count, ace);
            }
        raw.DiscretionaryAcl = ordered;
        var result = new byte[raw.BinaryLength];
        raw.GetBinaryForm(result, 0);
        return result;
    }
    [DllImport("Advapi32.dll", EntryPoint = "SetFileSecurityW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetFileSecurity(string path, UInt32 securityInformation, byte[] descriptor);

    public static void ApplyOwnerOnly(string path, byte[] descriptor)
    {
        const UInt32 OWNER_SECURITY_INFORMATION = 0x00000001;
        if (!SetFileSecurity(path, OWNER_SECURITY_INFORMATION, descriptor))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to change the scoped owner.");
    }

    public static void ApplyDaclOnly(string path, byte[] descriptor)
    {
        const UInt32 DACL_SECURITY_INFORMATION = 0x00000004;
        const UInt32 PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
        if (!SetFileSecurity(path, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to apply the scoped DACL.");
    }

    public static void ApplyDaclPreservingProtection(string path, byte[] descriptor)
    {
        const UInt32 DACL_SECURITY_INFORMATION = 0x00000004;
        if (!SetFileSecurity(path, DACL_SECURITY_INFORMATION, descriptor))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to update the scoped DACL.");
    }
}
'@
}

function Open-A2CheckoutNamespace {
    param([Parameter(Mandatory)][string]$Root)
    $handles = [Collections.Generic.List[IDisposable]]::new()
    try {
        $directory = [IO.DirectoryInfo]::new($Root)
        while ($directory.Parent) {
            $handles.Add([AclaisA2AclNative]::HoldNamespace($directory.FullName))
            $directory = $directory.Parent
        }
        return ,$handles
    }
    catch {
        foreach ($handle in $handles) { $handle.Dispose() }
        throw
    }
}

function New-A2ProtectedAcl {
    param(
        [Parameter(Mandatory)][bool]$IsDirectory,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][string]$WorkerSid,
        [ValidateSet('None', 'X', 'RX', 'M')][string]$WorkerRights = 'None',
        [bool]$InheritWorkerRights = $true
    )

    $acl = if ($IsDirectory) {
        [Security.AccessControl.DirectorySecurity]::new()
    }
    else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $acl.SetAccessRuleProtection($true, $false)
    $owner = [Security.Principal.SecurityIdentifier]::new($OwnerSid)
    $acl.SetOwner($owner)

    $principals = @(
        @{ Sid = $owner; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        @{ Sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18'); Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        @{ Sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'); Rights = [Security.AccessControl.FileSystemRights]::FullControl }
    )
    foreach ($entry in $principals) {
        $inheritance = if ($IsDirectory) {
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        }
        else { [Security.AccessControl.InheritanceFlags]::None }
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $entry.Sid,
            $entry.Rights,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }

    if ($WorkerRights -ne 'None') {
        $rights = switch ($WorkerRights) {
            'X' { [Security.AccessControl.FileSystemRights]::ExecuteFile }
            'RX' { [Security.AccessControl.FileSystemRights]::ReadAndExecute }
            'M' { [Security.AccessControl.FileSystemRights]::Modify }
        }
        $inheritance = if ($IsDirectory -and $InheritWorkerRights) {
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        }
        else { [Security.AccessControl.InheritanceFlags]::None }
        $worker = [Security.Principal.SecurityIdentifier]::new($WorkerSid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $worker,
            $rights,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    return $acl
}

function Set-A2AclItem {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][string]$WorkerSid,
        [ValidateSet('None', 'X', 'RX', 'M')][string]$WorkerRights = 'None',
        [bool]$InheritWorkerRights = $true,
        [switch]$DaclOnly
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Protected path does not exist: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse point found in a protected tree: $($item.FullName)"
    }
    $acl = New-A2ProtectedAcl -IsDirectory ([bool]$item.PSIsContainer) `
        -OwnerSid $OwnerSid -WorkerSid $WorkerSid -WorkerRights $WorkerRights `
        -InheritWorkerRights $InheritWorkerRights
    if ($DaclOnly) {
        [AclaisA2AclNative]::ApplyDaclOnly($item.FullName, $acl.GetSecurityDescriptorBinaryForm())
    }
    else {
        [AclaisA2AclNative]::ApplyDaclPreservingProtection(
            $item.FullName,
            $acl.GetSecurityDescriptorBinaryForm()
        )
    }
}

function Set-A2AclTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][string]$WorkerSid,
        [ValidateSet('None', 'X', 'RX', 'M')][string]$WorkerRights = 'None',
        [switch]$DaclOnly
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Protected path does not exist: $Path"
    }
    $items = @(Get-A2TreeItems -Path $Path)

    foreach ($item in $items) {
        Set-A2AclItem -Path $item.FullName -OwnerSid $OwnerSid -WorkerSid $WorkerSid `
            -WorkerRights $WorkerRights -DaclOnly:$DaclOnly | Out-Null
    }
}

function Get-A2TreeItems {
    param([Parameter(Mandatory)][string]$Path)
    $pending = [Collections.Generic.Stack[IO.FileSystemInfo]]::new()
    $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $pending.Push($root)
    $items = [Collections.Generic.List[IO.FileSystemInfo]]::new()
    while ($pending.Count -gt 0) {
        $item = $pending.Pop()
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point found in a protected tree: $($item.FullName)"
        }
        $items.Add($item)
        if ($item.PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop) {
                $pending.Push($child)
            }
        }
    }
    return $items.ToArray()
}

function Set-A2RootAcl {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$OwnerSid, [switch]$DaclOnly)
    Set-A2AclItem -Path $Path -OwnerSid $OwnerSid -WorkerSid 'S-1-0-0' -WorkerRights None -DaclOnly:$DaclOnly
}

function Set-A2WorkerDenyTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$WorkerSid,
        [switch]$Recursive
    )
    if (-not (Test-Path -LiteralPath $Path)) { throw "Workspace protection path does not exist: $Path" }
    $items = if ($Recursive) { @(Get-A2TreeItems -Path $Path) } else { @(Get-Item -LiteralPath $Path -Force) }
    $worker = [Security.Principal.SecurityIdentifier]::new($WorkerSid)
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point found in a workspace protection path: $($item.FullName)"
        }
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        if (-not $acl.AreAccessRulesCanonical) {
            $acl.SetSecurityDescriptorBinaryForm(
                [AclaisA2AclNative]::CanonicalDacl($acl.GetSecurityDescriptorBinaryForm()),
                [Security.AccessControl.AccessControlSections]::Access)
        }
        $inheritance = if ($item.PSIsContainer) {
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        }
        else { [Security.AccessControl.InheritanceFlags]::None }
        $deny = [Security.AccessControl.FileSystemAccessRule]::new(
            $worker,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Deny
        )
        $acl.SetAccessRule($deny)
        [AclaisA2AclNative]::ApplyDaclPreservingProtection($item.FullName, $acl.GetSecurityDescriptorBinaryForm())
    }
}

function Test-A2NoReparsePoints {
    param([Parameter(Mandatory)][string]$Path)

    $items = @(Get-A2TreeItems -Path $Path)
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point not permitted in A2 path: $($item.FullName)"
        }
    }
}

function Get-A2Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
