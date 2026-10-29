param([switch]$UseExistingControllerNamespaceGuard)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$componentRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $componentRoot
$labRoot = 'C:\ACLAIS-Lab'
$sentinelPath = Join-Path $labRoot '.owner-sentinel.json'
$manifestPath = Join-Path $labRoot 'state\installation.json'
$trustedStatePath = Join-Path $labRoot 'state\trusted-state.json'
$workerName = 'AclaisWorker'
$credentialTarget = 'ACLAIS-1/AclaisWorker'
$administratorsSid = 'S-1-5-32-544'
$usersSid = 'S-1-5-32-545'

. (Join-Path $PSScriptRoot 'a2_acl.ps1')
. (Join-Path $PSScriptRoot 'a2_credential_manager.ps1')

function Write-A2Json {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $json = $Value | ConvertTo-Json -Depth 14
    [IO.File]::WriteAllText($Path, $json + "`n", [Text.UTF8Encoding]::new($false))
}

function Write-A2KnownFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][byte[]]$Bytes)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllBytes($Path, $Bytes)
}

function Write-A2Marker {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Text)
    Write-A2KnownFile -Path $Path -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($Text))
}

function Restore-A2DisposableTargets {
    param([Parameter(Mandatory)][byte[]]$SentinelBytes)

    $privateTemplate = Join-Path $componentRoot 'tests\fixtures\templates\private-original.template.csv'
    $selectedTemplate = Join-Path $componentRoot 'tests\fixtures\templates\selected-input.template.csv'
    $privateBytes = [IO.File]::ReadAllBytes($privateTemplate)
    $selectedBytes = [IO.File]::ReadAllBytes($selectedTemplate)
    foreach ($name in @('delete-target.csv', 'rename-target.csv', 'replace-target.csv', 'overwrite-target.csv', 'dacl-target.csv')) {
        Write-A2KnownFile -Path (Join-Path $labRoot "store\originals\$name") -Bytes $privateBytes
    }
    Write-A2KnownFile -Path (Join-Path $labRoot 'store\originals\Personnel_Private.csv') -Bytes ([IO.File]::ReadAllBytes((Join-Path $labRoot 'baseline\Personnel_Private.csv')))
    foreach ($name in @('Selected_Input.csv', 'overwrite-target.csv', 'delete-target.csv', 'rename-target.csv', 'replace-target.csv')) {
        Write-A2KnownFile -Path (Join-Path $labRoot "store\selected\$name") -Bytes $selectedBytes
    }

    Write-A2Marker -Path (Join-Path $labRoot 'state\permission-write-probe.json') -Text '{"fixture":"synthetic state write permission probe"}'
    Write-A2Marker -Path (Join-Path $labRoot 'state\permission-delete-probe.json') -Text '{"fixture":"synthetic state delete permission probe"}'
    Write-A2Marker -Path (Join-Path $labRoot 'state\permission-rename-probe.json') -Text '{"fixture":"synthetic state rename permission probe"}'
    Write-A2Marker -Path (Join-Path $labRoot 'evidence\permission-write-probe.json') -Text '{"fixture":"synthetic evidence write permission probe"}'
    Write-A2Marker -Path (Join-Path $labRoot 'evidence\permission-delete-probe.json') -Text '{"fixture":"synthetic evidence delete permission probe"}'
    Write-A2Marker -Path (Join-Path $labRoot 'evidence\permission-rename-probe.json') -Text '{"fixture":"synthetic evidence rename permission probe"}'
    Write-A2Marker -Path (Join-Path $labRoot 'root-delete-probe.json') -Text '{"fixture":"synthetic root delete permission probe"}'
    Write-A2Marker -Path (Join-Path $labRoot 'root-rename-probe.json') -Text '{"fixture":"synthetic root rename permission probe"}'
    Write-A2Marker -Path (Join-Path $labRoot 'code\aclais\a2-code-delete-probe.txt') -Text 'Synthetic protected code delete probe.'
    Write-A2Marker -Path (Join-Path $labRoot 'code\aclais\a2-code-rename-probe.txt') -Text 'Synthetic protected code rename probe.'

    foreach ($path in @(
        (Join-Path $labRoot 'store\originals\worker-created-child.txt'),
        (Join-Path $labRoot 'store\worker-create-probe.txt'),
        (Join-Path $labRoot 'work\worker-create-probe.txt'),
        (Join-Path $labRoot 'worker-create-probe.txt'),
        (Join-Path $labRoot 'state\worker-created-state.txt'),
        (Join-Path $labRoot 'evidence\worker-created-evidence.txt'),
        (Join-Path $labRoot 'store\selected\rename-target.csv.worker-renamed'),
        (Join-Path $labRoot 'state\permission-rename-probe.json.worker-renamed'),
        (Join-Path $labRoot 'evidence\permission-rename-probe.json.worker-renamed'),
        (Join-Path $labRoot 'root-rename-probe.json.worker-renamed'),
        (Join-Path $labRoot 'code\aclais\a2-code-rename-probe.txt.worker-renamed'),
        (Join-Path $labRoot 'store\originals\rename-target.csv.worker-renamed'),
        (Join-Path $labRoot 'store\work-not-used.txt')
    )) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
    }

    Write-A2KnownFile -Path $sentinelPath -Bytes $SentinelBytes
}

function Get-A2AclSnapshot {
    param([Parameter(Mandatory)][string]$Path)
    $output = & "$env:SystemRoot\System32\icacls.exe" $Path 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Unable to read the post-probe ACL snapshot for '$Path'." }
    return @($output | ForEach-Object { [string]$_ })
}

function Get-A2OwnerReadCheck {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try { $null = $stream.ReadByte() } finally { $stream.Dispose() }
        return [ordered]@{ name = $Name; passed = $true; actual = 'owner_read_succeeded' }
    }
    catch {
        return [ordered]@{ name = $Name; passed = $false; actual = 'owner_read_failed'; error_type = $_.Exception.GetType().FullName }
    }
}

function Get-A2CodeInventoryCheck {
    param([Parameter(Mandatory)][object[]]$ExpectedFiles)
    $codeRoot = Join-Path $labRoot 'code'
    $expectedByPath = @{}
    foreach ($record in $ExpectedFiles) {
        $relativePath = [string]$record.path
        $expectedByPath[$relativePath] = $record
    }

    $mismatches = [Collections.Generic.List[string]]::new()
    $actualLines = [Collections.Generic.List[string]]::new()
    $actualFiles = @(Get-A2TreeItems -Path $codeRoot | Where-Object { -not $_.PSIsContainer })
    foreach ($file in $actualFiles) {
        $relativePath = $file.FullName.Substring($labRoot.Length + 1).Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $line = '{0}|{1}|{2}' -f $relativePath, $hash, $file.Length
        $actualLines.Add($line)
        if (-not $expectedByPath.ContainsKey($relativePath)) {
            $mismatches.Add('unexpected:' + $relativePath)
        }
        else {
            $expected = $expectedByPath[$relativePath]
            if ($hash -ne $expected.sha256 -or $file.Length -ne $expected.length) {
                $mismatches.Add('changed:' + $relativePath)
            }
            $expectedByPath.Remove($relativePath)
        }
    }
    foreach ($missingPath in $expectedByPath.Keys) { $mismatches.Add('missing:' + $missingPath) }

    [string[]]$expectedLines = @($ExpectedFiles | ForEach-Object {
        '{0}|{1}|{2}' -f $_.path, $_.sha256, $_.length
    })
    [string[]]$actualLinesSorted = $actualLines.ToArray()
    [Array]::Sort($expectedLines, [StringComparer]::Ordinal)
    [Array]::Sort($actualLinesSorted, [StringComparer]::Ordinal)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $expectedHash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($expectedLines -join "`n")))).Replace('-', '').ToLowerInvariant()
        $actualHash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($actualLinesSorted -join "`n")))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }

    return [ordered]@{
        passed = ($mismatches.Count -eq 0 -and $expectedHash -eq $actualHash)
        expected_file_count = $ExpectedFiles.Count
        actual_file_count = $actualFiles.Count
        expected_inventory_sha256 = $expectedHash
        actual_inventory_sha256 = $actualHash
        mismatches = @($mismatches)
    }
}

$ownerIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$ownerPrincipal = [Security.Principal.WindowsPrincipal]::new($ownerIdentity)
$isElevated = $ownerPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$summary = [ordered]@{
    schema_version = 1
    checkpoint = 'A2'
    passed = $false
    phase = 'preflight'
    machine = $env:COMPUTERNAME
    owner_sid = $ownerIdentity.User.Value
    elevated = $isElevated
    failures = @()
}
$ownerCredential = $null
$workerCredential = $null
$workerProcess = $null
$stdoutPath = $null
$stderrPath = $null
$aclRecoveryPending = $false
$sanitizedJson = Join-Path $repoRoot 'evidence\a2-access-summary.json'
$markdownPath = Join-Path $repoRoot 'evidence\A2.md'
$sanitizedJsonCreatedByRun = $false
$markdownCreatedByRun = $false
$repositoryEvidenceProbe = Join-Path $repoRoot 'evidence\.a2-worker-access-probe.tmp'
$repositoryEvidenceProbeBytes = [Text.UTF8Encoding]::new($false).GetBytes('Synthetic A2 repository evidence access marker.' + "`n")
$repositoryEvidenceProbeCreatedByRun = $false
$repositoryEvidenceChild = Join-Path (Split-Path -Parent $repositoryEvidenceProbe) 'worker-created-evidence.txt'
$repositoryEvidenceChildBytes = [Text.UTF8Encoding]::new($false).GetBytes('checkout evidence create attempt')
$repositoryEvidenceProbeHashBefore = $null
$repositoryEvidenceProbeHashAfter = $null
$repositorySourcePath = Join-Path $componentRoot 'backend\src\aclais\app.py'
$repositorySourceHashBefore = $null
$repositorySourceHashAfter = $null
$repositoryFrontendIndexPath = Join-Path $componentRoot 'frontend\dist\index.html'
$repositoryFrontendIndexHashBefore = $null
$repositoryFrontendIndexHashAfter = $null
$previousPythonPath = $env:PYTHONPATH
$additionalSources = @('aclais\backend\.venv\Lib\site-packages\fastapi\__init__.py', 'aclais\scripts\manage.ps1', 'scripts\aclais.ps1', 'shared\openapi.json', 'document-tools\src\document_tools\worker.py', 'document-tools\workers\report_formatter\entrypoint.py', 'document-tools\frontend\src\main.tsx', 'document-tools\frontend\package-lock.json')
$additionalHashes = @{}

try {
    foreach ($relative in $additionalSources) {
        $additionalHashes[$relative] = (Get-FileHash -LiteralPath (Join-Path $repoRoot $relative) -Algorithm SHA256).Hash
    }
    if ($isElevated) { throw 'Run the A2 access probe from the ordinary owner session, not its elevated setup shell.' }
    if (-not (Test-Path -LiteralPath $sentinelPath) -or -not (Test-Path -LiteralPath $manifestPath)) {
        throw 'The A2 sentinel or installation manifest is missing.'
    }
    Test-A2NoReparsePoints -Path $labRoot
    $sentinel = Get-Content -LiteralPath $sentinelPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.owner_sid -ne $ownerIdentity.User.Value -or $sentinel.owner_sid -ne $ownerIdentity.User.Value) {
        throw 'The A2 installation belongs to a different owner SID.'
    }
    $probeSource = Join-Path $componentRoot 'tests\probes\windows_a2_access_probe.ps1'
    $probePath = Join-Path $labRoot 'code\private-probes\windows_a2_access_probe.ps1'
    $probeRecord = @($manifest.protected_code | Where-Object { $_.path -eq 'code/private-probes/windows_a2_access_probe.ps1' })
    if ($probeRecord.Count -ne 1 -or -not (Test-Path -LiteralPath $probeSource -PathType Leaf) -or
        -not (Test-Path -LiteralPath $probePath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $probeSource -Algorithm SHA256).Hash.ToLowerInvariant() -ne $probeRecord[0].sha256 -or
        (Get-FileHash -LiteralPath $probePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $probeRecord[0].sha256) {
        throw 'The fixed A2 probe source and protected installation do not match; run aclais/scripts/deploy_a2_probe.ps1 first.'
    }
    if ($sentinel.root_path -ne $labRoot -or $sentinel.root_id -ne $manifest.root_id -or
        $sentinel.machine -ne $env:COMPUTERNAME -or $manifest.machine -ne $env:COMPUTERNAME) {
        throw 'The A2 sentinel does not match the owned root, manifest, or demonstration machine.'
    }
    if ($manifest.worker_name -ne $workerName -or $manifest.credential_target -ne $credentialTarget) {
        throw 'The A2 worker name or Credential Manager target does not match the specification.'
    }
    if ($manifest.worker_sid -eq $ownerIdentity.User.Value) {
        throw 'The A2 worker SID must differ from the ordinary owner SID.'
    }

    $rootGuardProbePath = Join-Path $componentRoot 'tests\probes\a2_root_guard_probe.ps1'
    $rootGuardOutput = @(& (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive `
        -ExecutionPolicy Bypass -File $rootGuardProbePath)
    if ($LASTEXITCODE -ne 0 -or $rootGuardOutput.Count -ne 1) {
        throw 'The private owned-root guard probe did not complete successfully.'
    }
    $rootGuardProbe = $rootGuardOutput[0] | ConvertFrom-Json
    if ($rootGuardProbe.kind -ne 'private_a2_root_guard_probe' -or -not $rootGuardProbe.passed) {
        throw 'The private owned-root guard probe reported a failure.'
    }
    $summary.root_guard_probe = $rootGuardProbe

    $worker = Get-LocalUser -Name $workerName -ErrorAction Stop
    if (-not $worker.Enabled -or $worker.SID.Value -ne $manifest.worker_sid) {
        throw 'The local AclaisWorker account is disabled or its SID differs from the installation manifest.'
    }
    $administrators = Get-LocalGroup -SID $administratorsSid -ErrorAction Stop
    $users = Get-LocalGroup -SID $usersSid -ErrorAction Stop
    $adminMembership = @(Get-LocalGroupMember -Group $administrators -ErrorAction Stop | Where-Object {
        $_.SID.Value -eq $worker.SID.Value
    })
    $userMembership = @(Get-LocalGroupMember -Group $users -ErrorAction Stop | Where-Object {
        $_.SID.Value -eq $worker.SID.Value
    })
    if ($adminMembership.Count -gt 0 -or $userMembership.Count -eq 0) {
        throw 'AclaisWorker must be a standard local user and not an Administrators member.'
    }

    $ownerCredential = [AclaisA2CredentialNative]::ReadGeneric($credentialTarget)
    if ($ownerCredential.UserName -ne ('{0}\{1}' -f $env:COMPUTERNAME, $workerName)) {
        $ownerCredential.Password.Dispose()
        throw 'The owner Credential Manager entry targets an unexpected account.'
    }
    $summary.owner_credential_check = [ordered]@{
        passed = $true
        target = $credentialTarget
        user_name = $ownerCredential.UserName
        owner_session_elevated = $false
        secret_value_recorded = $false
    }
    $workerCredential = [Management.Automation.PSCredential]::new($ownerCredential.UserName, $ownerCredential.Password)

    $ownerChecks = @(
        (Get-A2OwnerReadCheck -Path (Join-Path $labRoot 'store\originals\Personnel_Private.csv') -Name 'owner_can_read_original'),
        (Get-A2OwnerReadCheck -Path (Join-Path $labRoot 'state\trusted-state.json') -Name 'owner_can_read_trusted_state'),
        (Get-A2OwnerReadCheck -Path (Join-Path $labRoot 'evidence\permission-write-probe.json') -Name 'owner_can_read_evidence'),
        (Get-A2OwnerReadCheck -Path (Join-Path $labRoot 'code\aclais\app.py') -Name 'owner_can_read_protected_code'),
        (Get-A2OwnerReadCheck -Path $repositorySourcePath -Name 'owner_can_read_repository_application_code'),
        (Get-A2OwnerReadCheck -Path $repositoryFrontendIndexPath -Name 'owner_can_read_repository_frontend_bundle')
    )
    $repositoryEvidenceDir = Split-Path -Parent $repositoryEvidenceProbe
    if (-not (Test-Path -LiteralPath $repositoryEvidenceDir -PathType Container)) {
        throw 'The repository evidence directory is missing.'
    }
    if (Test-Path -LiteralPath $repositoryEvidenceProbe) {
        throw 'The reserved A2 repository evidence probe marker already exists; refusing to overwrite it.'
    }
    if (Test-Path -LiteralPath $repositoryEvidenceChild) {
        throw 'The reserved A2 repository evidence child already exists; refusing to overwrite it.'
    }
    [IO.File]::WriteAllBytes($repositoryEvidenceProbe, $repositoryEvidenceProbeBytes)
    $repositoryEvidenceProbeCreatedByRun = $true
    $ownerChecks += Get-A2OwnerReadCheck -Path $repositoryEvidenceProbe -Name 'owner_can_read_repository_evidence'
    $repositoryEvidenceProbeHashBefore = (Get-FileHash -LiteralPath $repositoryEvidenceProbe -Algorithm SHA256).Hash.ToLowerInvariant()
    $repositorySourceHashBefore = (Get-FileHash -LiteralPath $repositorySourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $repositoryFrontendIndexHashBefore = (Get-FileHash -LiteralPath $repositoryFrontendIndexPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $trustedStateHashBefore = (Get-FileHash -LiteralPath $trustedStatePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestHashBefore = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sentinelHashBefore = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sentinelBytesBefore = [IO.File]::ReadAllBytes($sentinelPath)
    $codeInventoryBefore = Get-A2CodeInventoryCheck -ExpectedFiles @($manifest.protected_code)
    $fixtureIntegrityBeforeProbe = @()
    foreach ($record in $manifest.fixtures) {
        $path = Join-Path $labRoot ($record.path.Replace('/', '\'))
        $exists = Test-Path -LiteralPath $path -PathType Leaf
        $hash = if ($exists) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        $fixtureIntegrityBeforeProbe += [ordered]@{
            name = ('fixture_precondition:' + $record.path)
            passed = ($exists -and $hash -eq $record.sha256)
            exists = $exists
            expected_sha256 = $record.sha256
            observed_sha256 = $hash
        }
    }
    $summary.fixture_integrity_before_probe = $fixtureIntegrityBeforeProbe
    if (@($fixtureIntegrityBeforeProbe | Where-Object { -not $_.passed }).Count -gt 0) {
        throw 'A seeded fixture is missing or differs from its trusted installation-manifest hash; refusing worker launch.'
    }

    $stdoutPath = Join-Path $labRoot ('state\a2-probe-' + [guid]::NewGuid().ToString('N') + '.stdout.tmp')
    $stderrPath = Join-Path $labRoot ('state\a2-probe-' + [guid]::NewGuid().ToString('N') + '.stderr.tmp')
    $probeId = [guid]::NewGuid().ToString('N')
    $selectedRecord = @($manifest.fixtures | Where-Object { $_.path -eq 'store/selected/Selected_Input.csv' }) | Select-Object -First 1
    if (-not $selectedRecord) { throw 'Selected input hash is missing from the protected installation manifest.' }
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -LabRoot "{1}" -ExpectedWorkerSid "{2}" -ExpectedSelectedHash "{3}" -RepositoryRoot "{4}" -ProbeId "{5}"' -f `
        $probePath, $labRoot, $manifest.worker_sid, $selectedRecord.sha256, $repoRoot, $probeId
    if ($arguments -match '(?i)(password|secret|credentialblob)') {
        throw 'Probe command arguments contain a forbidden credential-like string.'
    }

    if (-not $UseExistingControllerNamespaceGuard) {
        $checkoutGuards = Open-A2CheckoutNamespace -Root $repoRoot
    }
    $workerProcess = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') `
        -Credential $workerCredential `
        -ArgumentList $arguments `
        -WorkingDirectory (Join-Path $labRoot 'work\temporary-output') `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -WindowStyle Hidden -PassThru -ErrorAction Stop
    $aclRecoveryPending = $true
    $workerCredential = $null
    if (-not $workerProcess.WaitForExit(90000)) {
        $workerProcess.Kill()
        $workerProcess.WaitForExit()
        throw 'The private A2 worker probe exceeded its 90-second bound.'
    }
    $workerProcess.Refresh()

    # Repair the entire owned ACL tree before inspecting worker output or files.
    # This also recovers safely if an ACL assertion unexpectedly succeeded.
    Set-A2RootAcl -Path $labRoot -OwnerSid $manifest.owner_sid -DaclOnly
    Set-A2AclTree -Path $labRoot -OwnerSid $manifest.owner_sid `
        -WorkerSid $manifest.worker_sid -WorkerRights None -DaclOnly | Out-Null
    $aclRecoveryPending = $false

    $probeText = [IO.File]::ReadAllText($stdoutPath, [Text.Encoding]::UTF8).Trim()
    $stderrLength = if (Test-Path -LiteralPath $stderrPath) { (Get-Item -LiteralPath $stderrPath).Length } else { 0 }
    Remove-Item -LiteralPath $stdoutPath,$stderrPath -Force -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($probeText)) { throw 'The actual worker probe produced no structured result.' }
    $probe = $probeText | ConvertFrom-Json
    if ($probe.schema_version -ne 1 -or $probe.kind -ne 'private_windows_access_probe') {
        throw 'The worker probe returned an unexpected schema.'
    }

    $summary.phase = 'access_probe_completed'
    $summary.worker_process_exited = [bool]$workerProcess.HasExited
    $summary.worker_sid = $probe.observed_sid
    $summary.worker_account = $probe.observed_identity
    $summary.worker_is_administrator = $probe.is_administrator
    $summary.worker_stderr_bytes = $stderrLength
    $summary.probe = $probe
    $summary.owner_checks = $ownerChecks
    $summary.fixture_integrity_before_probe = $fixtureIntegrityBeforeProbe
    $summary.code_integrity_before_repair = $codeInventoryBefore
    $repositoryEvidenceProbeHashAfter = if (Test-Path -LiteralPath $repositoryEvidenceProbe -PathType Leaf) {
        (Get-FileHash -LiteralPath $repositoryEvidenceProbe -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { $null }
    $repositorySourceHashAfter = if (Test-Path -LiteralPath $repositorySourcePath -PathType Leaf) {
        (Get-FileHash -LiteralPath $repositorySourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { $null }
    $repositoryFrontendIndexHashAfter = if (Test-Path -LiteralPath $repositoryFrontendIndexPath -PathType Leaf) {
        (Get-FileHash -LiteralPath $repositoryFrontendIndexPath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { $null }
    foreach ($relative in $additionalSources) {
        if ((Get-FileHash -LiteralPath (Join-Path $repoRoot $relative) -Algorithm SHA256).Hash -ne $additionalHashes[$relative]) { throw 'A protected controller dependency or command changed during the access probe.' }
    }
    $summary.repository_checkout_integrity = [ordered]@{
        application_source_unchanged = ($repositorySourceHashAfter -and $repositorySourceHashAfter -eq $repositorySourceHashBefore)
        frontend_bundle_unchanged = ($repositoryFrontendIndexHashAfter -and $repositoryFrontendIndexHashAfter -eq $repositoryFrontendIndexHashBefore)
        evidence_probe_unchanged = ($repositoryEvidenceProbeHashAfter -and $repositoryEvidenceProbeHashAfter -eq $repositoryEvidenceProbeHashBefore)
        evidence_child_not_created = -not (Test-Path -LiteralPath $repositoryEvidenceChild)
        application_source_sha256_before = $repositorySourceHashBefore
        application_source_sha256_after = $repositorySourceHashAfter
        frontend_bundle_sha256_before = $repositoryFrontendIndexHashBefore
        frontend_bundle_sha256_after = $repositoryFrontendIndexHashAfter
        evidence_probe_sha256_before = $repositoryEvidenceProbeHashBefore
        evidence_probe_sha256_after = $repositoryEvidenceProbeHashAfter
    }

    $privateTemplate = Join-Path $componentRoot 'tests\fixtures\templates\private-original.template.csv'
    $selectedTemplate = Join-Path $componentRoot 'tests\fixtures\templates\selected-input.template.csv'
    $integrityChecks = @()
    foreach ($record in $manifest.fixtures) {
        $path = Join-Path $labRoot ($record.path.Replace('/', '\'))
        $exists = Test-Path -LiteralPath $path -PathType Leaf
        $hash = if ($exists) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        $integrityChecks += [ordered]@{
            name = ('fixture_integrity:' + $record.path)
            passed = ($exists -and $hash -eq $record.sha256)
            exists = $exists
            expected_sha256 = $record.sha256
            observed_sha256 = $hash
        }
    }
    $summary.fixture_integrity_before_repair = $integrityChecks

    $trustedStateExistsAfterProbe = Test-Path -LiteralPath $trustedStatePath -PathType Leaf
    $trustedStateHashAfterProbe = if ($trustedStateExistsAfterProbe) { (Get-FileHash -LiteralPath $trustedStatePath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    $summary.trusted_state_integrity = [ordered]@{
        name = 'trusted_state_integrity'
        passed = ($trustedStateExistsAfterProbe -and $trustedStateHashAfterProbe -eq $trustedStateHashBefore)
        before_sha256 = $trustedStateHashBefore
        after_probe_sha256 = $trustedStateHashAfterProbe
    }
    $manifestExistsAfterProbe = Test-Path -LiteralPath $manifestPath -PathType Leaf
    $manifestHashAfterProbe = if ($manifestExistsAfterProbe) { (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    $sentinelExistsAfterProbe = Test-Path -LiteralPath $sentinelPath -PathType Leaf
    $sentinelHashAfterProbe = if ($sentinelExistsAfterProbe) { (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    $summary.installation_manifest_integrity = [ordered]@{
        passed = ($manifestExistsAfterProbe -and $manifestHashAfterProbe -eq $manifestHashBefore)
        before_sha256 = $manifestHashBefore
        after_probe_sha256 = $manifestHashAfterProbe
    }
    $summary.sentinel_integrity = [ordered]@{
        passed = ($sentinelExistsAfterProbe -and $sentinelHashAfterProbe -eq $sentinelHashBefore)
        before_sha256 = $sentinelHashBefore
        after_probe_sha256 = $sentinelHashAfterProbe
    }

    Restore-A2DisposableTargets -SentinelBytes $sentinelBytesBefore
    if ($repositoryEvidenceProbeCreatedByRun -and (Test-Path -LiteralPath $repositoryEvidenceProbe)) {
        Remove-Item -LiteralPath $repositoryEvidenceProbe -Force -ErrorAction Stop
        $repositoryEvidenceProbeCreatedByRun = $false
    }
    if (Test-Path -LiteralPath $repositoryEvidenceChild) {
        $createdBytes = [IO.File]::ReadAllBytes($repositoryEvidenceChild)
        if ([Convert]::ToBase64String($createdBytes) -ne [Convert]::ToBase64String($repositoryEvidenceChildBytes)) {
            throw 'The repository evidence child differs from the synthetic probe content; refusing to remove it.'
        }
        Remove-Item -LiteralPath $repositoryEvidenceChild -Force -ErrorAction Stop
    }
    $replacementFiles = @(Get-ChildItem -LiteralPath (Join-Path $labRoot 'work\temporary-output') -File -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like ('a2-probe-' + $probeId + '-*')
    })
    foreach ($file in $replacementFiles) { Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop }

    Set-A2AclTree -Path $labRoot -OwnerSid $manifest.owner_sid -WorkerSid $manifest.worker_sid -WorkerRights None -DaclOnly | Out-Null
    Set-A2AclItem -Path $labRoot -OwnerSid $manifest.owner_sid -WorkerSid $manifest.worker_sid -WorkerRights X -InheritWorkerRights $false -DaclOnly
    Set-A2AclItem -Path (Join-Path $labRoot 'store') -OwnerSid $manifest.owner_sid -WorkerSid $manifest.worker_sid -WorkerRights X -InheritWorkerRights $false -DaclOnly
    Set-A2AclItem -Path (Join-Path $labRoot 'work') -OwnerSid $manifest.owner_sid -WorkerSid $manifest.worker_sid -WorkerRights X -InheritWorkerRights $false -DaclOnly
    Set-A2AclTree -Path (Join-Path $labRoot 'store\selected') -OwnerSid $manifest.owner_sid -WorkerSid $manifest.worker_sid -WorkerRights RX -DaclOnly | Out-Null
    Set-A2AclTree -Path (Join-Path $labRoot 'work\temporary-output') -OwnerSid $manifest.owner_sid -WorkerSid $manifest.worker_sid -WorkerRights M -DaclOnly | Out-Null
    Set-A2AclTree -Path (Join-Path $labRoot 'code') -OwnerSid $manifest.owner_sid -WorkerSid $manifest.worker_sid -WorkerRights RX -DaclOnly | Out-Null

    $postIntegrityChecks = @()
    foreach ($record in $manifest.fixtures) {
        $path = Join-Path $labRoot ($record.path.Replace('/', '\'))
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $postIntegrityChecks += [ordered]@{
            name = ('fixture_integrity_after_repair:' + $record.path)
            passed = ($hash -eq $record.sha256)
            expected_sha256 = $record.sha256
            observed_sha256 = $hash
        }
    }
    $summary.fixture_integrity_after_repair = $postIntegrityChecks
    $summary.code_integrity_after_repair = Get-A2CodeInventoryCheck -ExpectedFiles @($manifest.protected_code)
    $trustedStateHashAfterRepair = (Get-FileHash -LiteralPath $trustedStatePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $summary.trusted_state_integrity.after_repair_sha256 = $trustedStateHashAfterRepair
    $summary.trusted_state_integrity.passed = $summary.trusted_state_integrity.passed -and
        ($trustedStateHashAfterRepair -eq $trustedStateHashBefore)
    $summary.installation_manifest_integrity.after_repair_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $summary.installation_manifest_integrity.passed = $summary.installation_manifest_integrity.passed -and
        ($summary.installation_manifest_integrity.after_repair_sha256 -eq $manifestHashBefore)
    $sentinelHashAfterRepair = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $summary.sentinel_integrity.after_repair_sha256 = $sentinelHashAfterRepair
    $summary.sentinel_integrity.passed = $summary.sentinel_integrity.passed -and
        ($sentinelHashAfterRepair -eq $sentinelHashBefore)

    $summary.acl_snapshots = [ordered]@{
        lab_root = Get-A2AclSnapshot -Path $labRoot
        lab_parent = Get-A2AclSnapshot -Path (Split-Path -Parent $labRoot)
        store = Get-A2AclSnapshot -Path (Join-Path $labRoot 'store')
        originals = Get-A2AclSnapshot -Path (Join-Path $labRoot 'store\originals')
        selected = Get-A2AclSnapshot -Path (Join-Path $labRoot 'store\selected')
        work = Get-A2AclSnapshot -Path (Join-Path $labRoot 'work')
        temporary_output = Get-A2AclSnapshot -Path (Join-Path $labRoot 'work\temporary-output')
        trusted_state = Get-A2AclSnapshot -Path (Join-Path $labRoot 'state')
        evidence = Get-A2AclSnapshot -Path (Join-Path $labRoot 'evidence')
        protected_code = Get-A2AclSnapshot -Path (Join-Path $labRoot 'code')
        repository_application_code = Get-A2AclSnapshot -Path (Split-Path -Parent $repositorySourcePath)
        repository_evidence = Get-A2AclSnapshot -Path $repositoryEvidenceDir
    }

    $allProbeChecksPassed = [bool]$probe.passed -and [bool]$workerProcess.HasExited -and $stderrLength -eq 0
    $allOwnerChecksPassed = @($ownerChecks | Where-Object { -not $_.passed }).Count -eq 0
    $allIntegrityPassed = (@($integrityChecks | Where-Object { -not $_.passed }).Count -eq 0) -and
        (@($fixtureIntegrityBeforeProbe | Where-Object { -not $_.passed }).Count -eq 0) -and
        (@($postIntegrityChecks | Where-Object { -not $_.passed }).Count -eq 0) -and
        [bool]$summary.trusted_state_integrity.passed -and
        [bool]$summary.installation_manifest_integrity.passed -and
        [bool]$summary.sentinel_integrity.passed -and
        [bool]$summary.repository_checkout_integrity.application_source_unchanged -and
        [bool]$summary.repository_checkout_integrity.frontend_bundle_unchanged -and
        [bool]$summary.repository_checkout_integrity.evidence_probe_unchanged -and
        [bool]$summary.repository_checkout_integrity.evidence_child_not_created -and
        [bool]$codeInventoryBefore.passed -and
        [bool]$summary.code_integrity_after_repair.passed
    $summary.passed = $allProbeChecksPassed -and $allOwnerChecksPassed -and $allIntegrityPassed
    $summary.failures = @()
    if (-not $allProbeChecksPassed) { $summary.failures += 'worker_probe_failed' }
    if (-not $allOwnerChecksPassed) { $summary.failures += 'owner_access_failed' }
    if (-not $allIntegrityPassed) { $summary.failures += 'fixture_integrity_failed' }
    $summary.phase = 'completed'

    $runtimeEvidence = Join-Path $labRoot 'evidence\a2-access-result.json'
    if (-not $summary.passed) {
        Write-A2Json -Path $runtimeEvidence -Value $summary
        throw "A2 worker access probe did not pass; sanitized runtime result is at $runtimeEvidence."
    }

    $runtimePython = Join-Path $labRoot 'code\venv\Scripts\python.exe'
    $env:PYTHONPATH = Join-Path $labRoot 'code'
    & $runtimePython -B -c 'import aclais; from aclais.app import create_app; print(0)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Protected runtime environment could not import the protected ACLAIS package.' }

    $summary.runtime_import = 'passed'
    $summary.passed = $true
    $evidenceDir = Join-Path $repoRoot 'evidence'
    if (-not (Test-Path -LiteralPath $evidenceDir)) { New-Item -ItemType Directory -Path $evidenceDir | Out-Null }

    $markdown = @(
        '# A2 demonstration-machine evidence',
        '',
        "- Result: PASS",
        "- Machine: $($summary.machine)",
        "- Windows: $($manifest.windows_caption), build $($manifest.windows_build)",
        "- Owner SID: $($manifest.owner_sid)",
        "- Owner Credential Manager read: PASS (ordinary session, target $credentialTarget; value not recorded)",
        "- Worker identity: $($probe.observed_identity)",
        "- Worker SID: $($probe.observed_sid)",
        "- Worker administrator membership: $($probe.is_administrator)",
        "- ACLAIS application source revision: $($manifest.source_revision)",
        "- Probe checks: $($probe.check_count)",
        "- Repository application-code/evidence access checks: $(@($probe.checks | Where-Object { $_.name -like 'repository_*' }).Count) (PASS)",
        "- Seeded fixture preconditions: $(@($fixtureIntegrityBeforeProbe | Where-Object { $_.passed }).Count)/$($fixtureIntegrityBeforeProbe.Count) present and hash-verified before launch",
        "- Protected runtime code inventory: $($summary.code_integrity_after_repair.expected_file_count) files (PASS)",
        "- Owned-root guard checks: $($summary.root_guard_probe.check_count) (PASS)",
        "- Protected runtime import: $($summary.runtime_import)",
        '',
        'The checks below ran inside the actual AclaisWorker process. Errors are the Windows HRESULT/Win32 results returned by attempted operations. Windows may report file/path-not-found (2/3) when a protected parent denies traversal; these outcomes count only when owner-side hashes confirm the protected target existed before launch and remains present and unchanged afterward. Seeded fixtures are checked against the trusted manifest; checkout application source and the temporary evidence marker use owner-side before/after hashes. The fixture contents and worker password are not included.',
        '',
        '| Check | Result | Observed operation | Windows error |',
        '|---|---:|---|---|'
    )
    foreach ($check in $probe.checks) {
        $errorText = 'none'
        $errorDetails = $check.PSObject.Properties['error']
        if ($errorDetails -and $errorDetails.Value) {
            $hresult = $errorDetails.Value.PSObject.Properties['hresult']
            $win32Error = $errorDetails.Value.PSObject.Properties['win32_error']
            $windowsMessage = $errorDetails.Value.PSObject.Properties['windows_message']
            if ($win32Error -and $windowsMessage) {
                $hresultText = if ($hresult) { $hresult.Value } else { 'not-provided' }
                $errorText = "$hresultText / $($win32Error.Value): $($windowsMessage.Value)"
            }
            else { $errorText = 'none; identity or metadata details recorded separately' }
        }
        $markdown += "| $($check.name) | $(if ($check.passed) { 'PASS' } else { 'FAIL' }) | $($check.actual) | $errorText |"
    }
    $markdown += @(
        '',
        'Owner read access to the protected original, trusted state, evidence marker, and protected code was checked from the ordinary non-elevated owner session. The owner Credential Manager entry was read without elevation and supplied only through the process credential API; the probe arguments contained no password.',
        '',
        'Fixture SHA-256 integrity was checked after the worker probe and disposable targets were restored. Controller source, dependencies, commands and evidence remained unchanged. Raw hashes, fixture paths and ACL snapshots remain in the owner-protected local evidence report; the Git summary contains status and counts only. This is a fixture boundary, not a full machine sandbox or continuous system-call monitor.'
    )
    $markdownCreatedByRun = -not (Test-Path -LiteralPath $markdownPath)
    [IO.File]::WriteAllText($markdownPath, ($markdown -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    $sanitizedJsonCreatedByRun = -not (Test-Path -LiteralPath $sanitizedJson)
    $sanitized = [ordered]@{
        schema_version=2; checkpoint='A2'; passed=$true; elevated=$false
        source_revision=(& git -C $repoRoot rev-parse HEAD).Trim()
        tested_probe_sha256=(Get-FileHash -LiteralPath $probeSource -Algorithm SHA256).Hash.ToLowerInvariant()
        tested_harness_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        worker_sid=$probe.observed_sid; worker_is_administrator=$probe.is_administrator
        check_count=$probe.check_count; fixture_count=$fixtureIntegrityBeforeProbe.Count
        code_file_count=$summary.code_integrity_after_repair.expected_file_count
        fixture_integrity_passed=$allIntegrityPassed; owner_checks_passed=$allOwnerChecksPassed
        credential_value_recorded=$false; raw_inventory_committed=$false
        checks=@($probe.checks | ForEach-Object { @{name=$_.name; passed=$_.passed; actual=$_.actual} })
    }
    Write-A2Json -Path $sanitizedJson -Value $sanitized
    Write-A2Json -Path $runtimeEvidence -Value $summary
    Write-Output ($sanitized | ConvertTo-Json -Depth 8 -Compress)
}
catch {
    $summary.passed = $false
    if ($summary.failures.Count -eq 0) { $summary.failures = @('evidence_or_runtime_check_failed') }
    $summary.error_type = $_.Exception.GetType().FullName
    $summary.error_message = 'Details are omitted from committed evidence.'
    $failureMarkdown = @(
        '# A2 demonstration-machine evidence',
        '',
        '- Result: FAIL',
        "- Machine: $($summary.machine)",
        "- Phase: $($summary.phase)",
        "- Error type: $($summary.error_type)",
        '- Secret values and exception text are omitted.'
    )
    try {
        if (Test-Path -LiteralPath (Split-Path -Parent $markdownPath) -PathType Container) {
            [IO.File]::WriteAllText($markdownPath, ($failureMarkdown -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
            Write-A2Json -Path $sanitizedJson -Value @{schema_version=2; checkpoint='A2'; passed=$false; phase=$summary.phase; failures=$summary.failures; raw_inventory_committed=$false}
        }
    }
    catch { }
    if (Test-Path -LiteralPath (Join-Path $labRoot 'evidence')) {
        try { Write-A2Json -Path (Join-Path $labRoot 'evidence\a2-access-result.json') -Value $summary }
        catch { }
    }
    Write-Output '{"checkpoint":"A2","passed":false,"raw_inventory_committed":false}'
    throw
}
finally {
    if ($workerProcess -and -not $workerProcess.HasExited) {
        try {
            if (-not $workerProcess.WaitForExit(10000)) { $workerProcess.Kill(); $workerProcess.WaitForExit() }
        }
        catch { }
    }
    if ($aclRecoveryPending -and (Test-Path -LiteralPath $sentinelPath)) {
        try {
            Set-A2RootAcl -Path $labRoot -OwnerSid $ownerIdentity.User.Value -DaclOnly
            Set-A2AclTree -Path $labRoot -OwnerSid $ownerIdentity.User.Value `
                -WorkerSid 'S-1-0-0' -WorkerRights None -DaclOnly | Out-Null
        }
        catch { }
    }
    foreach ($temporaryOutput in @($stdoutPath, $stderrPath)) {
        if ($temporaryOutput -and (Test-Path -LiteralPath $temporaryOutput)) {
            Remove-Item -LiteralPath $temporaryOutput -Force -ErrorAction SilentlyContinue
        }
    }
    if ($repositoryEvidenceProbeCreatedByRun -and (Test-Path -LiteralPath $repositoryEvidenceProbe)) {
        Remove-Item -LiteralPath $repositoryEvidenceProbe -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $repositoryEvidenceChild) {
        try {
            $createdBytes = [IO.File]::ReadAllBytes($repositoryEvidenceChild)
            if ([Convert]::ToBase64String($createdBytes) -eq [Convert]::ToBase64String($repositoryEvidenceChildBytes)) {
                Remove-Item -LiteralPath $repositoryEvidenceChild -Force -ErrorAction SilentlyContinue
            }
        }
        catch { }
    }
    if ($ownerCredential -and $ownerCredential.Password) { $ownerCredential.Password.Dispose() }
    if (Get-Variable checkoutGuards -ErrorAction SilentlyContinue) {
        foreach ($guard in $checkoutGuards) { $guard.Dispose() }
    }
    if ($null -eq $previousPythonPath) { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue }
    else { $env:PYTHONPATH = $previousPythonPath }
}
