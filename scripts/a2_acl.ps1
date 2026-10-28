if (-not ('AclaisA2AclNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class AclaisA2AclNative
{
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
        Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
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
