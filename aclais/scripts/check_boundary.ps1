param([switch]$SkipFixtureHashes, [switch]$RequireIdle, [switch]$AllowRetiring)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$componentRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $componentRoot
$labRoot = 'C:\ACLAIS-Lab'
. (Join-Path $PSScriptRoot 'a2_acl.ps1')
$checks = [Collections.Generic.List[object]]::new()
function Check([string]$Name, [scriptblock]$Body) {
    try { & $Body; $checks.Add(@{id=$Name; status='pass'; summary='Verified local boundary check.'}) }
    catch { $checks.Add(@{id=$Name; status='fail'; summary='Local boundary check failed; launch is refused.'}) }
}
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $manifest = Get-Content -LiteralPath (Join-Path $labRoot 'state\installation.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $sentinel = Get-Content -LiteralPath (Join-Path $labRoot '.owner-sentinel.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.owner_sid -ne $identity.User.Value -or $sentinel.owner_sid -ne $identity.User.Value -or
        $manifest.root_id -ne $sentinel.root_id -or $manifest.root_path -ne $labRoot -or
        $manifest.machine -ne $env:COMPUTERNAME) { throw 'ownership' }
    $ownerSid = $identity.User.Value
    $workerSid = [string]$manifest.worker_sid
} catch { Write-Output '{"passed":false,"checks":[{"id":"owned_installation","status":"fail","summary":"Owned installation metadata is unavailable or inconsistent."}]}'; exit 1 }
Check 'owner_and_worker_identity' {
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'elevated' }
    $worker = Get-LocalUser -Name 'AclaisWorker'
    if (-not $worker.Enabled -or $worker.SID.Value -ne $workerSid -or $workerSid -eq $ownerSid) { throw 'identity' }
    if (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $workerSid }).Count) { throw 'administrator' }
}
function CheckAcl([string]$Path, [string]$Rights, [bool]$RootProtected=$true) {
    try { $item = Get-Item -LiteralPath $Path -Force }
    catch [System.Management.Automation.ItemNotFoundException] {
        if (-not $RootProtected) { return }
        throw
    }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse' }
    $acl = Get-Acl -LiteralPath $Path
    if ($RootProtected -and -not $acl.AreAccessRulesProtected) { throw 'inheritance' }
    $expected = New-A2ProtectedAcl -IsDirectory ([bool]$item.PSIsContainer) -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights $Rights -InheritWorkerRights ($Rights -ne 'X')
    $actualMap = @{}; $expectedMap = @{}
    foreach ($pair in @(@{Acl=$acl; Map=$actualMap}, @{Acl=$expected; Map=$expectedMap})) {
        foreach ($rule in $pair.Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { throw 'unexpected_deny' }
            $sid = $rule.IdentityReference.Value
            $pair.Map[$sid] = ([long]$pair.Map[$sid]) -bor ([long]$rule.FileSystemRights)
        }
    }
    if ($actualMap.Count -ne $expectedMap.Count) { throw 'unexpected_principal' }
    foreach ($sid in $expectedMap.Keys) {
        if (-not $actualMap.ContainsKey($sid) -or $actualMap[$sid] -ne $expectedMap[$sid]) { throw 'effective_rights' }
    }
}
Check 'effective_runtime_permissions' {
    foreach ($relative in @('', 'store', 'work')) { CheckAcl (Join-Path $labRoot $relative) 'X' }
    foreach ($relative in @('store\originals','state','evidence','baseline')) {
        $path = Join-Path $labRoot $relative
        CheckAcl $path 'None'
        foreach ($item in @(Get-A2TreeItems -Path $path)) { CheckAcl $item.FullName 'None' $false }
    }
    foreach ($pair in @(@{Path='code'; Rights='RX'},@{Path='store\selected'; Rights='RX'},@{Path='work\temporary-output'; Rights='M'})) {
        foreach ($item in @(Get-A2TreeItems -Path (Join-Path $labRoot $pair.Path))) { CheckAcl $item.FullName $pair.Rights $false }
    }
    foreach ($relative in @('work\selected-inputs','work\task-output','work\verified-output')) {
        $path = Join-Path $labRoot $relative
        if (Test-Path -LiteralPath $path) {
            $acl = Get-Acl -LiteralPath $path
            foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
                $sid=$rule.IdentityReference.Value
                if ($sid -notin @($ownerSid,'S-1-5-18','S-1-5-32-544',$workerSid)) { throw 'task_parent_principal' }
                if ($sid -eq $workerSid -and (([long]$rule.FileSystemRights -band (-bnot 1179808)) -ne 0 -or $relative -eq 'work\verified-output')) { throw 'task_parent_rights' }
            }
        }
    }
}
Check 'checkout_dependencies_and_commands' {
    foreach ($relative in @('.','.git','aclais\backend','aclais\frontend','aclais\scripts','aclais\tests','scripts','shared','evidence')) {
        $path = Join-Path $repoRoot $relative
        $acl = Get-Acl -LiteralPath $path
        $denied = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.IdentityReference.Value -eq $workerSid -and $_.AccessControlType -eq 'Deny' -and
            (([long]$_.FileSystemRights -band 2032127) -eq 2032127) -and
            ($_.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -and
            ($_.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit)
        })
        if (-not $denied.Count) { throw 'checkout_not_protected' }
    }
}
Check 'code_and_fixture_integrity' {
    Test-A2NoReparsePoints -Path $labRoot
    if ((-not $SkipFixtureHashes -and (Test-Path -LiteralPath (Join-Path $labRoot 'state\reset-in-progress.json'))) -or
        (-not $AllowRetiring -and (Test-Path -LiteralPath (Join-Path $labRoot 'state\retiring.json')))) { throw 'incomplete_operator_action' }
    foreach ($record in @($manifest.protected_code)) {
        if ($record.path -notmatch '^code/' -or $record.path -match '(^|/)\.\.(/|$)|:|\\') { throw 'unsafe_inventory' }
        $path = Join-Path $labRoot $record.path
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $record.sha256) { throw 'code_hash' }
    }
    if (@(Get-A2TreeItems -Path (Join-Path $labRoot 'code') | Where-Object { -not $_.PSIsContainer }).Count -ne @($manifest.protected_code).Count) { throw 'code_inventory_count' }
    if (-not $SkipFixtureHashes) {
        foreach ($record in @($manifest.fixtures)) {
            if ($record.path -notmatch '^store/(originals|selected)/[a-zA-Z0-9_.-]+$') { throw 'unsafe_fixture' }
            if ((Get-FileHash -LiteralPath (Join-Path $labRoot $record.path) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $record.sha256) { throw 'fixture_hash' }
        }
    }
}
if ($RequireIdle) {
    Check 'no_active_worker' {
        foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe' OR Name='powershell.exe' OR Name='pwsh.exe'")) {
            $result=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
            if ($result.ReturnValue -ne 0 -or $result.Sid -eq $workerSid) { throw 'active_or_unverified_worker' }
        }
    }
}
$passed = @($checks | Where-Object { $_.status -ne 'pass' }).Count -eq 0
@{passed=$passed; checks=@($checks)} | ConvertTo-Json -Depth 5 -Compress
if (-not $passed) { exit 1 }
