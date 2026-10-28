$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$componentRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $componentRoot
$labRoot = 'C:\ACLAIS-Lab'
$sentinelPath = Join-Path $labRoot '.owner-sentinel.json'
$manifestPath = Join-Path $labRoot 'state\installation.json'
$workerName = 'AclaisWorker'
$sourceProbe = Join-Path $componentRoot 'tests\probes\windows_a2_access_probe.ps1'
$relativeProbe = 'code/private-probes/windows_a2_access_probe.ps1'
$targetProbe = Join-Path $labRoot ($relativeProbe.Replace('/', '\'))

. (Join-Path $PSScriptRoot 'a2_acl.ps1')

function Get-A2ProtectedCodeInventory {
    param([Parameter(Mandatory)][string]$Root)

    $codeRoot = Join-Path $Root 'code'
    Test-A2NoReparsePoints -Path $codeRoot
    return @(
        Get-A2TreeItems -Path $codeRoot |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object {
                [ordered]@{
                    path = $_.FullName.Substring($Root.Length + 1).Replace('\', '/')
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                    length = $_.Length
                }
            } | Sort-Object -Property path
    )
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'A2 probe deployment must run from the ordinary owner session.'
}
if (-not (Test-Path -LiteralPath $sourceProbe -PathType Leaf) -or
    -not (Test-Path -LiteralPath $sentinelPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'A2 probe source or owned runtime metadata is missing.'
}

$sentinel = Get-Content -LiteralPath $sentinelPath -Raw -Encoding UTF8 | ConvertFrom-Json
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($sentinel.schema_version -ne 1 -or $manifest.schema_version -ne 1 -or
    $manifest.checkpoint -ne 'A2' -or $sentinel.owner_sid -ne $identity.User.Value -or
    $manifest.owner_sid -ne $identity.User.Value -or $sentinel.root_id -ne $manifest.root_id -or
    $sentinel.machine -ne $env:COMPUTERNAME -or $manifest.machine -ne $env:COMPUTERNAME -or
    $manifest.root_path -ne $labRoot -or $manifest.worker_name -ne $workerName) {
    throw 'A2 probe deployment refused unowned or inconsistent runtime metadata.'
}

$workerAccount = '{0}\{1}' -f $env:COMPUTERNAME, $workerName
$candidateProcesses = @(Get-CimInstance -ClassName Win32_Process `
    -Filter "Name='python.exe' OR Name='pythonw.exe' OR Name='powershell.exe' OR Name='pwsh.exe'" `
    -ErrorAction Stop)
$activeWorkerCount = 0
foreach ($process in $candidateProcesses) {
    try {
        $processOwner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
    }
    catch {
        throw 'Unable to verify the owner SID of a candidate worker executable; refusing probe deployment.'
    }
    if ($processOwner.ReturnValue -ne 0 -or -not $processOwner.Sid) {
        throw 'Unable to verify the owner SID of a candidate worker executable; refusing probe deployment.'
    }
    if ([string]$processOwner.Sid -eq $manifest.worker_sid) { $activeWorkerCount++ }
}
if ($activeWorkerCount -gt 0) {
    throw 'A2 probe deployment refused while the worker identity has an active process.'
}

Test-A2NoReparsePoints -Path $labRoot
$before = @(Get-A2ProtectedCodeInventory -Root $labRoot)
$expected = @($manifest.protected_code)
if ($before.Count -ne $expected.Count) { throw 'Protected runtime inventory count differs from the trusted manifest.' }
$expectedByPath = @{}
foreach ($record in $expected) { $expectedByPath[[string]$record.path] = $record }
foreach ($actual in $before) {
    $path = [string]$actual.path
    if (-not $expectedByPath.ContainsKey($path)) { throw 'Unexpected protected runtime file; refusing probe deployment.' }
    $record = $expectedByPath[$path]
    if ($actual.sha256 -ne $record.sha256 -or $actual.length -ne $record.length) {
        throw 'Protected runtime integrity differs from the trusted manifest; refusing probe deployment.'
    }
    $expectedByPath.Remove($path)
}
if ($expectedByPath.Count -ne 0) { throw 'A trusted protected runtime file is missing; refusing probe deployment.' }
if (-not (Test-Path -LiteralPath $targetProbe -PathType Leaf)) { throw 'The registered A2 private probe is missing from the protected runtime.' }
if (-not ($expected | Where-Object { $_.path -eq $relativeProbe })) { throw 'The trusted manifest does not register the fixed A2 probe.' }

$temporaryProbe = "$targetProbe.$([guid]::NewGuid().ToString('N')).tmp"
$backupProbe = Join-Path $labRoot ("state\a2-probe-$([guid]::NewGuid().ToString('N')).bak")
$temporaryManifest = "$manifestPath.$([guid]::NewGuid().ToString('N')).tmp"
$backupManifest = "$manifestPath.$([guid]::NewGuid().ToString('N')).bak"
$probeReplaced = $false
$manifestReplaced = $false
try {
    [IO.File]::WriteAllBytes($temporaryProbe, [IO.File]::ReadAllBytes($sourceProbe))
    Set-A2AclItem -Path $temporaryProbe -OwnerSid $manifest.owner_sid `
        -WorkerSid $manifest.worker_sid -WorkerRights RX -DaclOnly
    $sourceHash = (Get-FileHash -LiteralPath $sourceProbe -Algorithm SHA256).Hash.ToLowerInvariant()
    $temporaryHash = (Get-FileHash -LiteralPath $temporaryProbe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($temporaryHash -ne $sourceHash) { throw 'A2 private probe staging hash differs from its component source.' }

    [IO.File]::Replace($temporaryProbe, $targetProbe, $backupProbe)
    $probeReplaced = $true

    $manifest.protected_code = @(Get-A2ProtectedCodeInventory -Root $labRoot)
    $runtimeUpdates = @()
    if ($manifest.PSObject.Properties['checkpoint_runtime_updates']) {
        $runtimeUpdates = @($manifest.checkpoint_runtime_updates)
    }
    $runtimeUpdates = @($runtimeUpdates | Where-Object { $_.checkpoint -ne 'A2-probe-refresh' })
    $sourceRevision = (& git -C $repoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sourceRevision -notmatch '^[0-9a-f]{40}$') {
        throw 'Unable to identify the source revision for the A2 probe refresh.'
    }
    $runtimeUpdates += [ordered]@{
        checkpoint = 'A2-probe-refresh'
        source_path = 'aclais/tests/probes/windows_a2_access_probe.ps1'
        source_sha256 = $sourceHash
        source_revision = $sourceRevision
        deployed_utc = [DateTime]::UtcNow.ToString('o')
    }
    $manifest | Add-Member -NotePropertyName checkpoint_runtime_updates -NotePropertyValue $runtimeUpdates -Force
    [IO.File]::WriteAllText($temporaryManifest, ($manifest | ConvertTo-Json -Depth 24) + "`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::Replace($temporaryManifest, $manifestPath, $backupManifest)
    $manifestReplaced = $true

    $probeReplaced = $false
    $manifestReplaced = $false
    Remove-Item -LiteralPath $backupProbe,$backupManifest -Force -ErrorAction SilentlyContinue
    $result = [ordered]@{
        schema_version = 1
        checkpoint = 'A2-probe-refresh'
        passed = $true
        source_revision = $sourceRevision
        source_sha256 = $sourceHash
        protected_code_file_count = $manifest.protected_code.Count
        worker_identity = $workerAccount
        worker_process_active = $false
        secret_value_recorded = $false
    }
    $result | ConvertTo-Json -Compress
}
catch {
    if ($probeReplaced -and (Test-Path -LiteralPath $backupProbe)) {
        try { [IO.File]::Replace($backupProbe, $targetProbe, $null) } catch { }
    }
    if ($manifestReplaced -and (Test-Path -LiteralPath $backupManifest)) {
        try { [IO.File]::Replace($backupManifest, $manifestPath, $null) } catch { }
    }
    throw
}
finally {
    foreach ($temporary in @($temporaryProbe, $backupProbe, $temporaryManifest, $backupManifest)) {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}
