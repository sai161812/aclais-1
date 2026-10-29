$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$componentRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $componentRoot
$labRoot = 'C:\ACLAIS-Lab'
$manifestPath = Join-Path $labRoot 'state\installation.json'
$sentinelPath = Join-Path $labRoot '.owner-sentinel.json'
$destination = Join-Path $labRoot 'code\document-tools'
. (Join-Path $repoRoot 'aclais\scripts\a2_acl.ps1')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Document Tools installation must run in the ordinary owner session.'
}
foreach ($path in @($labRoot, $sentinelPath, (Join-Path $labRoot 'state'), $manifestPath, (Join-Path $labRoot 'code'))) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Document Tools installation refused a reparse point.' }
}
$sentinel = Get-Content -LiteralPath $sentinelPath -Raw -Encoding UTF8 | ConvertFrom-Json
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.checkpoint -ne 'A2' -or $manifest.owner_sid -ne $identity.User.Value -or
    $sentinel.owner_sid -ne $identity.User.Value -or $sentinel.root_id -ne $manifest.root_id -or
    $sentinel.root_path -ne $labRoot -or $sentinel.machine -ne $env:COMPUTERNAME -or
    $manifest.machine -ne $env:COMPUTERNAME -or $manifest.worker_name -ne 'AclaisWorker') {
    throw 'Document Tools installation requires the verified owned A2 lab.'
}

$sourceFiles = @(
    'src\document_tools\__init__.py',
    'src\document_tools\broker.py',
    'src\document_tools\worker.py',
    'workers\report_formatter\entrypoint.py'
)
$staging = Join-Path (Join-Path $labRoot 'code') ('.document-tools-staging-' + [guid]::NewGuid().ToString('N'))
$backup = Join-Path (Join-Path $labRoot 'state') ('.document-tools-backup-' + [guid]::NewGuid().ToString('N'))
$destinationExists = Test-Path -LiteralPath $destination
if ($destinationExists) {
    $destinationItem = Get-Item -LiteralPath $destination -Force -ErrorAction Stop
    if ($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'An installed Document Tools path is a reparse point; it was left untouched.'
    }
    $oldManifest = Join-Path $destination 'tool-manifest.json'
    if (-not (Test-Path -LiteralPath $oldManifest -PathType Leaf)) {
        throw 'An unrecognized Document Tools installation already exists; it was left untouched.'
    }
    $oldRecord = Get-Content -LiteralPath $oldManifest -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($oldRecord.root_id -ne $manifest.root_id) {
        throw 'The existing Document Tools install belongs to a different lab; it was left untouched.'
    }
}

try {
    New-Item -ItemType Directory -Path $staging -ErrorAction Stop | Out-Null
    $records = [Collections.Generic.List[object]]::new()
    foreach ($relative in $sourceFiles) {
        $source = Join-Path $componentRoot $relative
        $sourceItem = Get-Item -LiteralPath $source -Force -ErrorAction Stop
        if ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Worker source contains a reparse point.' }
        $target = Join-Path $staging $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $target -ErrorAction Stop
        $copied = Get-FileHash -LiteralPath $target -Algorithm SHA256
        $records.Add(@{
            path = $relative.Replace('\', '/')
            sha256 = $copied.Hash.ToLowerInvariant()
            length = (Get-Item -LiteralPath $target).Length
        })
    }
    $toolRecord = @{
        tool_id = 'report_formatter'
        document_id = 'doc-report'
        entrypoint = 'workers/report_formatter/entrypoint.py'
        files = @($records)
    }
    $toolManifest = @{
        schema_version = 1
        root_id = [string]$manifest.root_id
        tools = @($toolRecord)
    }
    [IO.File]::WriteAllText(
        (Join-Path $staging 'tool-manifest.json'),
        ($toolManifest | ConvertTo-Json -Depth 8) + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    if ($destinationExists) { Move-Item -LiteralPath $destination -Destination $backup -ErrorAction Stop }
    Move-Item -LiteralPath $staging -Destination $destination -ErrorAction Stop
    $installedItem = Get-Item -LiteralPath $destination -Force -ErrorAction Stop
    if ($installedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Document Tools installation produced a reparse point.'
    }
    Set-A2AclTree -Path $destination -OwnerSid $manifest.owner_sid -WorkerSid $manifest.worker_sid -WorkerRights RX

    $deployProbe = Join-Path $repoRoot 'aclais\scripts\deploy_a3_probe.ps1'
    & $deployProbe | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Protected ACLAIS source inventory update failed.' }
    if (Test-Path -LiteralPath $backup) {
        Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $backup) {
            Write-Warning 'The previous formatter copy remains in the owner-only state directory.'
        }
    }
}
catch {
    if (Test-Path -LiteralPath $backup) {
        if (Test-Path -LiteralPath $destination) {
            Remove-Item -LiteralPath $destination -Recurse -Force -ErrorAction SilentlyContinue
        }
        Move-Item -LiteralPath $backup -Destination $destination -ErrorAction SilentlyContinue
    } elseif (-not $destinationExists -and (Test-Path -LiteralPath $destination)) {
        Remove-Item -LiteralPath $destination -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Output ([ordered]@{
    checkpoint = 'G3 Report Formatter installation'
    passed = $true
    root_id = [string]$manifest.root_id
    worker_sid = [string]$manifest.worker_sid
    installed_source_files = $records.Count
    secrets_recorded = $false
} | ConvertTo-Json -Depth 4 -Compress)
