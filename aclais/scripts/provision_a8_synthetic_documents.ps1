$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$componentRoot = Split-Path -Parent $PSScriptRoot
$labRoot = 'C:\ACLAIS-Lab'
$stateRoot = Join-Path $labRoot 'state'
$sentinelPath = Join-Path $labRoot '.owner-sentinel.json'
$manifestPath = Join-Path $stateRoot 'installation.json'
$trustedPath = Join-Path $stateRoot 'trusted-state.json'
$originalsRoot = Join-Path $labRoot 'store\originals'

. (Join-Path $PSScriptRoot 'a2_acl.ps1')
. (Join-Path $PSScriptRoot 'a2_root_guard.ps1')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Synthetic document provisioning must run as the unelevated owner.'
}
if (-not (Test-Path -LiteralPath $sentinelPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $trustedPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $originalsRoot -PathType Container)) {
    throw 'The existing A2 sentinel, manifest, trusted state, or originals directory is unavailable.'
}

$listener = @(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)
if ($listener.Count -gt 0) {
    throw 'ACLAIS is listening; stop the controller before changing trusted fixture metadata.'
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$sentinel = Get-Content -LiteralPath $sentinelPath -Raw -Encoding UTF8 | ConvertFrom-Json
$trusted = Get-Content -LiteralPath $trustedPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.checkpoint -ne 'A2' -or $manifest.owner_sid -ne $identity.User.Value -or
    $sentinel.owner_sid -ne $identity.User.Value -or $manifest.root_id -ne $sentinel.root_id -or
    $manifest.machine -ne $env:COMPUTERNAME -or $sentinel.machine -ne $env:COMPUTERNAME -or
    $trusted.root_id -ne $manifest.root_id -or $trusted.owner_sid -ne $manifest.owner_sid -or
    $trusted.worker_sid -ne $manifest.worker_sid -or -not $manifest.worker_sid) {
    throw 'The current identity does not match the trusted A2 installation metadata.'
}

Test-A2NoReparsePoints -Path $labRoot
$templates = @(
    @{ Name = 'project-report.md'; Template = 'project-report.template.md' },
    @{ Name = 'meeting-notes.md'; Template = 'meeting-notes.template.md' },
    @{ Name = 'invoice.csv'; Template = 'invoice.template.csv' }
)
$sha256 = [Security.Cryptography.SHA256]::Create()
$prepared = @()
foreach ($item in $templates) {
    $templatePath = Join-Path $componentRoot ('tests\fixtures\templates\' + $item.Template)
    $destinationPath = Join-Path $originalsRoot $item.Name
    if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
        throw 'A tracked synthetic template is missing.'
    }
    $bytes = [IO.File]::ReadAllBytes($templatePath)
    $expectedHash = [BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    if (Test-Path -LiteralPath $destinationPath) {
        $actualHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash) {
            throw 'An existing original differs from its synthetic template; it was preserved.'
        }
    }
    else {
        $stream = [IO.File]::Open($destinationPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length) }
        finally { $stream.Dispose() }
    }
    Set-A2AclItem -Path $destinationPath -OwnerSid $manifest.owner_sid `
        -WorkerSid $manifest.worker_sid -WorkerRights None -DaclOnly
    $prepared += [ordered]@{
        path = ('store/originals/' + $item.Name)
        sha256 = $expectedHash
    }
}
$sha256.Dispose()

$allRecords = @($manifest.fixtures | Where-Object {
    $_.path -notin @($prepared | ForEach-Object { $_.path })
}) + $prepared
$allRecords = @($allRecords | Sort-Object -Property path)
$manifest.fixtures = $allRecords
$trusted.fixture_hashes = $allRecords

function Write-A8AtomicJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $temporaryPath = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $backupPath = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.bak'
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12) + "`n")
    [IO.File]::WriteAllBytes($temporaryPath, $bytes)
    try { [IO.File]::Replace($temporaryPath, $Path, $backupPath) }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
        if (Test-Path -LiteralPath $backupPath) { Remove-Item -LiteralPath $backupPath -Force }
    }
}

# A crash between these atomic replacements can leave the hashes mismatched.
# RuntimeLayout validates both records and fails closed until this idempotent
# command is rerun to reconcile them.
Write-A8AtomicJson -Path $trustedPath -Value $trusted
Write-A8AtomicJson -Path $manifestPath -Value $manifest

[ordered]@{
    result = 'PASS'
    seeded_synthetic_originals = $prepared.Count
    manifest_fixture_count = $allRecords.Count
} | ConvertTo-Json -Compress
