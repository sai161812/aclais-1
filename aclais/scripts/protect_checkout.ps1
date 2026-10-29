$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$componentRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $componentRoot
$labRoot = 'C:\ACLAIS-Lab'
. (Join-Path $PSScriptRoot 'a2_acl.ps1')
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$manifest = Get-Content -LiteralPath (Join-Path $labRoot 'state\installation.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$sentinel = Get-Content -LiteralPath (Join-Path $labRoot '.owner-sentinel.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.owner_sid -ne $identity.User.Value -or $sentinel.owner_sid -ne $identity.User.Value -or
    $manifest.root_id -ne $sentinel.root_id -or $manifest.root_path -ne $labRoot) {
    throw 'Checkout protection refused inconsistent ownership.'
}
$paths = @('aclais\backend', 'aclais\frontend', 'aclais\scripts', 'aclais\tests', 'scripts', 'shared', 'evidence', '.git')
$snapshotPath = Join-Path $labRoot 'state\checkout-acl-before.json'
if (-not (Test-Path -LiteralPath $snapshotPath)) {
    $records = @()
    foreach ($relative in $paths) {
        $target = Join-Path $repoRoot $relative
        Test-A2NoReparsePoints -Path $target
        foreach ($item in @(Get-A2TreeItems -Path $target)) {
            $records += [ordered]@{
                path = $item.FullName.Substring($repoRoot.Length + 1)
                dacl = (Get-Acl -LiteralPath $item.FullName).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
            }
        }
    }
    [IO.File]::WriteAllText($snapshotPath, (@{ schema_version=1; repo_root=$repoRoot; records=$records } | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}
$snapshot = Get-Content -LiteralPath $snapshotPath -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($relative in $paths) {
    if (-not @($snapshot.records | Where-Object { $_.path -eq $relative }).Count) {
        foreach ($item in @(Get-A2TreeItems -Path (Join-Path $repoRoot $relative))) {
            $snapshot.records = @($snapshot.records) + @(@{
                path=$item.FullName.Substring($repoRoot.Length + 1)
                dacl=(Get-Acl -LiteralPath $item.FullName).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
            })
        }
    }
}
if (-not @($snapshot.records | Where-Object { $_.path -eq '.' }).Count) {
    $snapshot.records = @($snapshot.records) + @(@{path='.'; dacl=(Get-Acl -LiteralPath $repoRoot).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)})
}
[IO.File]::WriteAllText($snapshotPath, ($snapshot | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
Set-A2WorkerDenyTree -Path $repoRoot -WorkerSid $manifest.worker_sid
foreach ($relative in $paths) {
    Set-A2WorkerDenyTree -Path (Join-Path $repoRoot $relative) -WorkerSid $manifest.worker_sid -Recursive
}
Write-Output '{"checkpoint":"checkout_protection","passed":true,"secret_values_recorded":false}'
