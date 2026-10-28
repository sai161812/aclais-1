$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$labRoot = 'C:\ACLAIS-Lab'
$manifestPath = Join-Path $labRoot 'state\installation.json'
$sentinelPath = Join-Path $labRoot '.owner-sentinel.json'
$sourceProbe = Join-Path $repoRoot 'tests\probes\a3_worker_probe.py'
$runtimeProbe = Join-Path $labRoot 'code\private-probes\a3_worker_probe.py'
$codeRoot = Join-Path $labRoot 'code'
$pythonRuntime = Join-Path $codeRoot 'python-runtime'
$pythonExe = Join-Path $pythonRuntime 'python.exe'
$pythonEmbedUrl = 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip'
$pythonEmbedSha256 = '4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3'

function Assert-A3NoReparsePoint([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "A3 deployment refused a reparse point at $Path."
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'A3 runtime deployment must run in the ordinary owner session, not elevated.'
}
if ($identity.User.Value -notmatch '^S-1-5-21-(\d+-){3}\d+$') {
    throw 'A3 deployment requires the provisioned local owner identity.'
}
if (-not (Test-Path -LiteralPath $sourceProbe -PathType Leaf)) {
    throw 'The private A3 worker source is missing.'
}

foreach ($path in @(
    'C:\', $labRoot, $sentinelPath, (Join-Path $labRoot 'state'), $manifestPath,
    (Join-Path $labRoot 'code'), (Join-Path $labRoot 'code\private-probes')
)) { Assert-A3NoReparsePoint -Path $path }

$sentinel = Get-Content -LiteralPath $sentinelPath -Raw -Encoding UTF8 | ConvertFrom-Json
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($sentinel.schema_version -ne 1 -or $manifest.schema_version -ne 1 -or
    $manifest.checkpoint -ne 'A2' -or $sentinel.owner_sid -ne $identity.User.Value -or
    $manifest.owner_sid -ne $identity.User.Value -or $sentinel.root_id -ne $manifest.root_id -or
    $sentinel.machine -ne $env:COMPUTERNAME -or $manifest.machine -ne $env:COMPUTERNAME -or
    $manifest.root_path -ne $labRoot -or $manifest.worker_name -ne 'AclaisWorker') {
    throw 'A3 deployment refused an unowned or inconsistent A2 installation.'
}

$runtimePython = Join-Path $labRoot 'code\venv\Scripts\python.exe'
$pythonProcesses = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='python.exe'" -ErrorAction Stop)
$unidentifiedPython = @($pythonProcesses | Where-Object { -not $_.ExecutablePath })
if ($unidentifiedPython.Count -gt 0) {
    throw 'A3 deployment cannot confirm all Python process paths; it will not modify runtime files.'
}
$activeRuntime = @(
    $pythonProcesses | Where-Object {
        $_.ExecutablePath -ieq $runtimePython -or $_.ExecutablePath -ieq $pythonExe
    }
)
if ($activeRuntime.Count -gt 0) {
    throw 'A3 deployment found a process using the protected runtime Python; it will not modify runtime files.'
}

$a3RuntimeUpdate = @($manifest.PSObject.Properties['checkpoint_runtime_updates'].Value |
    Where-Object { $_.checkpoint -eq 'A3' } | Select-Object -First 1)
if (Test-Path -LiteralPath $pythonRuntime) {
    if ($a3RuntimeUpdate.Count -eq 0 -or
        $a3RuntimeUpdate[0].python_embed_sha256 -ne $pythonEmbedSha256 -or
        $a3RuntimeUpdate[0].python_runtime -ne $pythonRuntime) {
        throw 'A3 deployment found an unregistered worker Python runtime and will not replace it.'
    }
    Assert-A3NoReparsePoint -Path $pythonRuntime
    Assert-A3NoReparsePoint -Path $pythonExe
    $expectedRuntimeFiles = @($manifest.protected_code | Where-Object { $_.path -like 'code/python-runtime/*' })
    if ($expectedRuntimeFiles.Count -eq 0) {
        throw 'A3 worker Python runtime has no trusted file inventory.'
    }
    foreach ($record in $expectedRuntimeFiles) {
        $filePath = Join-Path $labRoot ($record.path.Replace('/', '\'))
        Assert-A3NoReparsePoint -Path $filePath
        if ((Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $record.sha256) {
            throw 'A3 worker Python runtime failed its trusted file inventory.'
        }
    }
}
else {
    if ($a3RuntimeUpdate.Count -gt 0 -and $a3RuntimeUpdate[0].python_embed_sha256) {
        throw 'A3 worker Python runtime is missing although installation metadata says it was deployed.'
    }
    $archivePath = Join-Path $env:TEMP ("aclais-python-embed-$([guid]::NewGuid().ToString('N')).zip")
    $stagingPath = Join-Path $codeRoot (".a3-python-runtime-staging-$([guid]::NewGuid().ToString('N'))")
    try {
        Invoke-WebRequest -Uri $pythonEmbedUrl -OutFile $archivePath -TimeoutSec 90
        if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pythonEmbedSha256) {
            throw 'A3 Python runtime download did not match its pinned SHA-256.'
        }
        New-Item -ItemType Directory -Path $stagingPath -ErrorAction Stop | Out-Null
        Expand-Archive -LiteralPath $archivePath -DestinationPath $stagingPath -ErrorAction Stop
        foreach ($item in Get-ChildItem -LiteralPath $stagingPath -Force -Recurse) {
            Assert-A3NoReparsePoint -Path $item.FullName
        }
        $stagingPython = Join-Path $stagingPath 'python.exe'
        if (-not (Test-Path -LiteralPath $stagingPython -PathType Leaf)) {
            throw 'A3 Python runtime archive is missing its fixed interpreter.'
        }
        & $stagingPython -I -B -c 'import ctypes, json, sys; assert sys.version_info[:3] == (3, 12, 10)'
        if ($LASTEXITCODE -ne 0) { throw 'A3 embedded Python runtime failed its local smoke check.' }
        Move-Item -LiteralPath $stagingPath -Destination $pythonRuntime -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $stagingPath) {
            Remove-Item -LiteralPath $stagingPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $archivePath) {
            Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
        }
    }
}

Copy-Item -LiteralPath $sourceProbe -Destination $runtimeProbe -Force -ErrorAction Stop
Assert-A3NoReparsePoint -Path $runtimeProbe
$probeHash = (Get-FileHash -LiteralPath $runtimeProbe -Algorithm SHA256).Hash.ToLowerInvariant()
$sourceHash = (Get-FileHash -LiteralPath $sourceProbe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($probeHash -ne $sourceHash) { throw 'A3 deployed probe hash does not match its source.' }

$codeFiles = @(
    Get-ChildItem -LiteralPath $codeRoot -File -Recurse -Force -ErrorAction Stop | ForEach-Object {
        Assert-A3NoReparsePoint -Path $_.FullName
        [ordered]@{
            path = $_.FullName.Substring($labRoot.Length + 1).Replace('\', '/')
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            length = $_.Length
        }
    }
)
$manifest.protected_code = @($codeFiles | Sort-Object -Property path)
$runtimeUpdates = @()
if ($manifest.PSObject.Properties['checkpoint_runtime_updates']) {
    $runtimeUpdates = @($manifest.checkpoint_runtime_updates)
}
$runtimeUpdates = @($runtimeUpdates | Where-Object { $_.checkpoint -ne 'A3' })
$sourceRevision = (& git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceRevision -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to identify the source revision for the A3 protected runtime.'
}
$runtimeUpdates += [ordered]@{
    checkpoint = 'A3'
    source_path = 'tests/probes/a3_worker_probe.py'
    source_sha256 = $sourceHash
    source_revision = $sourceRevision
    deployed_utc = [DateTime]::UtcNow.ToString('o')
    python_runtime = $pythonRuntime
    python_version = '3.12.10'
    python_embed_sha256 = $pythonEmbedSha256
}
$manifest | Add-Member -NotePropertyName checkpoint_runtime_updates -NotePropertyValue $runtimeUpdates -Force

$temporaryManifest = "$manifestPath.a3-$([guid]::NewGuid().ToString('N')).tmp"
$backupManifest = "$manifestPath.a3-$([guid]::NewGuid().ToString('N')).bak"
try {
    $json = $manifest | ConvertTo-Json -Depth 24
    [IO.File]::WriteAllText($temporaryManifest, $json + "`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::Replace($temporaryManifest, $manifestPath, $backupManifest)
}
finally {
    if (Test-Path -LiteralPath $temporaryManifest) {
        Remove-Item -LiteralPath $temporaryManifest -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $backupManifest) {
        Remove-Item -LiteralPath $backupManifest -Force -ErrorAction SilentlyContinue
    }
}

Write-Output ([ordered]@{
    checkpoint = 'A3 runtime probe deployment'
    passed = $true
    owner_sid = $identity.User.Value
    worker_sid = $manifest.worker_sid
    elevated = $false
    runtime_probe_sha256 = $probeHash
    python_runtime = $pythonRuntime
    python_version = '3.12.10'
    python_embed_sha256 = $pythonEmbedSha256
    protected_runtime_code_files = $manifest.protected_code.Count
    source_revision = $manifest.checkpoint_runtime_updates[-1].source_revision
    credential_values_recorded = $false
} | ConvertTo-Json -Depth 5 -Compress)
