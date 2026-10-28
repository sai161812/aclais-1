$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$labRoot = 'C:\ACLAIS-Lab'
$sentinelPath = Join-Path $labRoot '.owner-sentinel.json'
$provisionMarkerPath = Join-Path $labRoot '.provisioning.json'
$workerName = 'AclaisWorker'
$credentialTarget = 'ACLAIS-1/AclaisWorker'
$administratorsSid = 'S-1-5-32-544'
$usersSid = 'S-1-5-32-545'

. (Join-Path $PSScriptRoot 'a2_acl.ps1')
. (Join-Path $PSScriptRoot 'a2_credential_manager.ps1')
. (Join-Path $PSScriptRoot 'a2_root_guard.ps1')

function Assert-A2Elevation {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'A2 provisioning requires the explicitly elevated setup process.'
    }
    return $identity
}

function Write-A2Json {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $json = $Value | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($Path, $json + "`n", [Text.UTF8Encoding]::new($false))
}

function Write-A2SeedFile {
    param(
        [Parameter(Mandatory)][string]$TemplatePath,
        [Parameter(Mandatory)][string]$DestinationPath
    )

    $expectedBytes = [IO.File]::ReadAllBytes($TemplatePath)
    $expectedHash = Get-A2Sha256 -Path $TemplatePath
    if (Test-Path -LiteralPath $DestinationPath) {
        if ((Get-A2Sha256 -Path $DestinationPath) -ne $expectedHash) {
            throw "Existing fixture differs from the tracked synthetic template: $DestinationPath"
        }
        return $expectedHash
    }

    [IO.File]::WriteAllBytes($DestinationPath, $expectedBytes)
    return $expectedHash
}

function Write-A2TextMarker {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Text)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $expectedHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }

    if (Test-Path -LiteralPath $Path) {
        if ((Get-A2Sha256 -Path $Path) -ne $expectedHash) {
            throw "Existing A2 marker differs from its expected synthetic content: $Path"
        }
    }
    else {
        [IO.File]::WriteAllBytes($Path, $bytes)
    }
}

function New-A2WorkerPassword {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    if ($alphabet.Length -ne 64) { throw 'Password alphabet must have 64 characters.' }

    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 64
    $password = [Security.SecureString]::new()
    try {
        $random.GetBytes($bytes)
        foreach ($byte in $bytes) {
            $index = ([int]$byte) -band 63
            $password.AppendChar($alphabet[$index])
        }
        $password.MakeReadOnly()
        return $password
    }
    catch {
        $password.Dispose()
        throw
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        $random.Dispose()
    }
}

function Ensure-A2WorkerAccount {
    param([Parameter(Mandatory)][Security.SecureString]$Password)

    $worker = Get-LocalUser -Name $workerName -ErrorAction SilentlyContinue
    if (-not $worker) {
        $worker = New-LocalUser -Name $workerName `
            -FullName 'ACLAIS restricted worker' `
            -Description 'ACLAIS non-admin isolated worker' `
            -Password $Password `
            -PasswordNeverExpires `
            -UserMayNotChangePassword `
            -ErrorAction Stop
    }
    else {
        Set-LocalUser -Name $workerName -Password $Password -PasswordNeverExpires $true -UserMayChangePassword $false
        Enable-LocalUser -Name $workerName
    }

    $worker = Get-LocalUser -Name $workerName -ErrorAction Stop
    $workerSid = $worker.SID.Value
    $userGroup = Get-LocalGroup -SID $usersSid -ErrorAction Stop
    foreach ($group in Get-LocalGroup -ErrorAction Stop) {
        $groupMembers = @(Get-LocalGroupMember -Group $group -ErrorAction Stop | Where-Object {
            $_.SID.Value -eq $workerSid
        })
        if ($group.SID.Value -ne $usersSid) {
            foreach ($member in $groupMembers) {
                Remove-LocalGroupMember -Group $group -Member $member -Confirm:$false -ErrorAction Stop
            }
        }
    }
    $userMembers = @(Get-LocalGroupMember -Group $userGroup -ErrorAction Stop | Where-Object { $_.SID.Value -eq $workerSid })
    if ($userMembers.Count -eq 0) {
        Add-LocalGroupMember -Group $userGroup -Member $worker -ErrorAction Stop
    }

    return $worker
}

function Assert-A2Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    Test-A2NoReparsePoints -Path $Path
}

function Assert-A2CredentialTargetScoped {
    try {
        $stored = [AclaisA2CredentialNative]::ReadGeneric($credentialTarget)
        try {
            $expectedUser = '{0}\{1}' -f $env:COMPUTERNAME, $workerName
            if ($stored.UserName -ne $expectedUser) {
                throw 'The project Credential Manager target already belongs to a different account; refusing to replace it.'
            }
        }
        finally { $stored.Password.Dispose() }
    }
    catch [ComponentModel.Win32Exception] {
        if ($_.Exception.NativeErrorCode -ne 1168) { throw }
    }
}

$ownerIdentity = Assert-A2Elevation
$ownerSid = $ownerIdentity.User.Value
Assert-A2CredentialTargetScoped
$existingWorker = Get-LocalUser -Name $workerName -ErrorAction SilentlyContinue
if ($existingWorker) {
    $workerAccountName = '{0}\{1}' -f $env:COMPUTERNAME, $workerName
    $workerProcesses = @(Get-Process -IncludeUserName -ErrorAction Stop | Where-Object { $_.UserName -eq $workerAccountName })
    if ($workerProcesses.Count -gt 0) {
        throw 'AclaisWorker has a running process; refusing to change its account or ACLs during use.'
    }
}
$volume = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
if ($volume.FileSystem -ne 'NTFS') {
    throw "A2 requires C: to be NTFS; observed '$($volume.FileSystem)'."
}

if (Test-Path -LiteralPath $labRoot) {
    Test-A2NoReparsePoints -Path $labRoot
}

$rootId = Resolve-A2RootId -RootPath $labRoot -SentinelPath $sentinelPath `
    -ProvisionMarkerPath $provisionMarkerPath -OwnerSid $ownerSid -Machine $env:COMPUTERNAME
if (-not (Test-Path -LiteralPath $labRoot)) {
    New-Item -ItemType Directory -Path $labRoot -ErrorAction Stop | Out-Null
}
$existingSentinel = if (Test-Path -LiteralPath $sentinelPath) {
    Get-Content -LiteralPath $sentinelPath -Raw -Encoding UTF8 | ConvertFrom-Json
}
else { $null }

Set-A2RootAcl -Path $labRoot -OwnerSid $ownerSid
if (-not (Test-Path -LiteralPath $sentinelPath) -and -not (Test-Path -LiteralPath $provisionMarkerPath)) {
    Write-A2Json -Path $provisionMarkerPath -Value @{
        schema_version = 1
        root_id = $rootId
        owner_sid = $ownerSid
        machine = $env:COMPUTERNAME
        started_utc = [DateTime]::UtcNow.ToString('o')
    }
}

$directories = @(
    $labRoot,
    (Join-Path $labRoot 'store'),
    (Join-Path $labRoot 'store\originals'),
    (Join-Path $labRoot 'store\selected'),
    (Join-Path $labRoot 'store\verified-output'),
    (Join-Path $labRoot 'state'),
    (Join-Path $labRoot 'evidence'),
    (Join-Path $labRoot 'work'),
    (Join-Path $labRoot 'work\temporary-output'),
    (Join-Path $labRoot 'baseline'),
    (Join-Path $labRoot 'code'),
    (Join-Path $labRoot 'code\aclais'),
    (Join-Path $labRoot 'code\private-probes')
)
foreach ($directory in $directories) { Assert-A2Directory -Path $directory }
Set-A2AclTree -Path $labRoot -OwnerSid $ownerSid -WorkerSid 'S-1-0-0' -WorkerRights None | Out-Null

# This is the owned runtime-code directory. Recreate it from the current checkout
# after confirming the owned tree has no reparse points and no worker is running.
foreach ($child in Get-ChildItem -LiteralPath (Join-Path $labRoot 'code') -Force -ErrorAction Stop) {
    Remove-Item -LiteralPath $child.FullName -Recurse -Force -ErrorAction Stop
}
New-Item -ItemType Directory -Path (Join-Path $labRoot 'code\aclais') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $labRoot 'code\private-probes') -Force | Out-Null

$sourcePackage = Join-Path $repoRoot 'backend\aclais\src\aclais'
$protectedPackage = Join-Path $labRoot 'code\aclais'
Copy-Item -Path (Join-Path $sourcePackage '*') -Destination $protectedPackage -Recurse -Force -ErrorAction Stop
$probeSource = Join-Path $repoRoot 'tests\probes\windows_a2_access_probe.ps1'
$probeDestination = Join-Path $labRoot 'code\private-probes\windows_a2_access_probe.ps1'
Copy-Item -LiteralPath $probeSource -Destination $probeDestination -Force -ErrorAction Stop
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'a2_credential_manager.ps1') `
    -Destination (Join-Path $labRoot 'code\private-probes\a2_credential_manager.ps1') -Force -ErrorAction Stop
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'a2_acl.ps1') `
    -Destination (Join-Path $labRoot 'code\private-probes\a2_acl.ps1') -Force -ErrorAction Stop
[IO.File]::WriteAllText(
    (Join-Path $protectedPackage 'a2-code-integrity-probe.txt'),
    'ACLAIS synthetic protected-code marker; not executable.' + "`n",
    [Text.UTF8Encoding]::new($false)
)

$fixtureTemplateDir = Join-Path $repoRoot 'tests\fixtures\templates'
$privateTemplate = Join-Path $fixtureTemplateDir 'private-original.template.csv'
$selectedTemplate = Join-Path $fixtureTemplateDir 'selected-input.template.csv'
$privateHash = Write-A2SeedFile -TemplatePath $privateTemplate -DestinationPath (Join-Path $labRoot 'store\originals\Personnel_Private.csv')
$selectedHash = Write-A2SeedFile -TemplatePath $selectedTemplate -DestinationPath (Join-Path $labRoot 'store\selected\Selected_Input.csv')
$selectedOverwriteHash = Write-A2SeedFile -TemplatePath $selectedTemplate -DestinationPath (Join-Path $labRoot 'store\selected\overwrite-target.csv')
$selectedDeleteHash = Write-A2SeedFile -TemplatePath $selectedTemplate -DestinationPath (Join-Path $labRoot 'store\selected\delete-target.csv')
$selectedRenameHash = Write-A2SeedFile -TemplatePath $selectedTemplate -DestinationPath (Join-Path $labRoot 'store\selected\rename-target.csv')
$selectedReplaceHash = Write-A2SeedFile -TemplatePath $selectedTemplate -DestinationPath (Join-Path $labRoot 'store\selected\replace-target.csv')
$deleteHash = Write-A2SeedFile -TemplatePath $privateTemplate -DestinationPath (Join-Path $labRoot 'store\originals\delete-target.csv')
$renameHash = Write-A2SeedFile -TemplatePath $privateTemplate -DestinationPath (Join-Path $labRoot 'store\originals\rename-target.csv')
$replaceHash = Write-A2SeedFile -TemplatePath $privateTemplate -DestinationPath (Join-Path $labRoot 'store\originals\replace-target.csv')
$overwriteHash = Write-A2SeedFile -TemplatePath $privateTemplate -DestinationPath (Join-Path $labRoot 'store\originals\overwrite-target.csv')
$daclHash = Write-A2SeedFile -TemplatePath $privateTemplate -DestinationPath (Join-Path $labRoot 'store\originals\dacl-target.csv')
$baselinePrivate = Join-Path $labRoot 'baseline\Personnel_Private.csv'
$null = Write-A2SeedFile -TemplatePath $privateTemplate -DestinationPath $baselinePrivate
$null = Write-A2TextMarker -Path (Join-Path $labRoot 'state\permission-write-probe.json') -Text '{"fixture":"synthetic state write permission probe"}'
$null = Write-A2TextMarker -Path (Join-Path $labRoot 'state\permission-delete-probe.json') -Text '{"fixture":"synthetic state delete permission probe"}'
$null = Write-A2TextMarker -Path (Join-Path $labRoot 'state\permission-rename-probe.json') -Text '{"fixture":"synthetic state rename permission probe"}'
$null = Write-A2TextMarker -Path (Join-Path $labRoot 'evidence\permission-write-probe.json') -Text '{"fixture":"synthetic evidence write permission probe"}'
$null = Write-A2TextMarker -Path (Join-Path $labRoot 'evidence\permission-delete-probe.json') -Text '{"fixture":"synthetic evidence delete permission probe"}'
$null = Write-A2TextMarker -Path (Join-Path $labRoot 'evidence\permission-rename-probe.json') -Text '{"fixture":"synthetic evidence rename permission probe"}'
$null = Write-A2TextMarker -Path (Join-Path $labRoot 'root-delete-probe.json') -Text '{"fixture":"synthetic root delete permission probe"}'
$null = Write-A2TextMarker -Path (Join-Path $labRoot 'root-rename-probe.json') -Text '{"fixture":"synthetic root rename permission probe"}'
$null = Write-A2TextMarker -Path (Join-Path $labRoot 'code\aclais\a2-code-delete-probe.txt') -Text 'Synthetic protected code delete probe.'
$null = Write-A2TextMarker -Path (Join-Path $labRoot 'code\aclais\a2-code-rename-probe.txt') -Text 'Synthetic protected code rename probe.'

$uv = Get-Command uv -ErrorAction Stop
$runtimeEnvironment = Join-Path $labRoot 'code\venv'
$previousEnvironment = $env:UV_PROJECT_ENVIRONMENT
$env:UV_PROJECT_ENVIRONMENT = $runtimeEnvironment
try {
    Push-Location $repoRoot
    try {
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $uvOutput = @(& $uv.Source sync --locked --no-dev --no-install-project --project backend/aclais 2>&1)
            $uvExitCode = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $previousErrorActionPreference }
        if ($uvExitCode -ne 0) { throw "uv sync failed with exit code $uvExitCode." }
    }
    finally { Pop-Location }
}
finally {
    if ($null -eq $previousEnvironment) { Remove-Item Env:UV_PROJECT_ENVIRONMENT -ErrorAction SilentlyContinue }
    else { $env:UV_PROJECT_ENVIRONMENT = $previousEnvironment }
}

$sourceRevision = (& git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceRevision -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to identify the exact source revision for the protected code copy.'
}

$password = New-A2WorkerPassword
try {
    $worker = Ensure-A2WorkerAccount -Password $password
    $workerSid = $worker.SID.Value

    $checkoutEvidence = Join-Path $repoRoot 'evidence'
    if (-not (Test-Path -LiteralPath $checkoutEvidence)) {
        New-Item -ItemType Directory -Path $checkoutEvidence -Force | Out-Null
    }
    foreach ($protectedCheckoutPath in @(
        (Join-Path $repoRoot 'backend\aclais\src'),
        (Join-Path $repoRoot 'frontend\aclais\src'),
        $checkoutEvidence
    )) {
        if (Test-Path -LiteralPath $protectedCheckoutPath) {
            Set-A2WorkerDenyTree -Path $protectedCheckoutPath -WorkerSid $workerSid -Recursive
        }
    }
Set-A2AclTree -Path $labRoot -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights None | Out-Null
Set-A2AclItem -Path $labRoot -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights X -InheritWorkerRights $false
Set-A2AclItem -Path (Join-Path $labRoot 'store') -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights X -InheritWorkerRights $false
Set-A2AclItem -Path (Join-Path $labRoot 'work') -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights X -InheritWorkerRights $false
Set-A2AclTree -Path (Join-Path $labRoot 'store\selected') -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights RX | Out-Null
Set-A2AclTree -Path (Join-Path $labRoot 'work\temporary-output') -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights M | Out-Null
Set-A2AclTree -Path (Join-Path $labRoot 'code') -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights RX | Out-Null

$sentinel = @{
    schema_version = 1
    root_id = $rootId
    root_path = $labRoot
    owner_sid = $ownerSid
    machine = $env:COMPUTERNAME
    created_utc = if ($existingSentinel) { $existingSentinel.created_utc } else { [DateTime]::UtcNow.ToString('o') }
}
Write-A2Json -Path $sentinelPath -Value $sentinel
Remove-Item -LiteralPath $provisionMarkerPath -Force -ErrorAction SilentlyContinue

$codeFiles = @(Get-ChildItem -LiteralPath (Join-Path $labRoot 'code') -File -Recurse -Force | ForEach-Object {
    [ordered]@{
        path = $_.FullName.Substring($labRoot.Length + 1).Replace('\', '/')
        sha256 = Get-A2Sha256 -Path $_.FullName
        length = $_.Length
    }
})
$fixtureRecords = @(
    [ordered]@{ path = 'store/originals/Personnel_Private.csv'; sha256 = $privateHash },
    [ordered]@{ path = 'store/originals/delete-target.csv'; sha256 = $deleteHash },
    [ordered]@{ path = 'store/originals/rename-target.csv'; sha256 = $renameHash },
    [ordered]@{ path = 'store/originals/replace-target.csv'; sha256 = $replaceHash },
    [ordered]@{ path = 'store/originals/overwrite-target.csv'; sha256 = $overwriteHash },
    [ordered]@{ path = 'store/originals/dacl-target.csv'; sha256 = $daclHash },
    [ordered]@{ path = 'store/selected/Selected_Input.csv'; sha256 = $selectedHash },
    [ordered]@{ path = 'store/selected/overwrite-target.csv'; sha256 = $selectedOverwriteHash },
    [ordered]@{ path = 'store/selected/delete-target.csv'; sha256 = $selectedDeleteHash },
    [ordered]@{ path = 'store/selected/rename-target.csv'; sha256 = $selectedRenameHash },
    [ordered]@{ path = 'store/selected/replace-target.csv'; sha256 = $selectedReplaceHash }
)
$manifest = [ordered]@{
    schema_version = 1
    checkpoint = 'A2'
    machine = $env:COMPUTERNAME
    windows_caption = (Get-CimInstance Win32_OperatingSystem).Caption
    windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    volume = 'C:'
    file_system = $volume.FileSystem
    root_path = $labRoot
    root_id = $rootId
    owner_sid = $ownerSid
    worker_name = $workerName
    worker_sid = $workerSid
    sentinel_created_utc = $sentinel.created_utc
    credential_target = $credentialTarget
    credential_type = 'CRED_TYPE_GENERIC'
    code_root = Join-Path $labRoot 'code'
    runtime_environment = $runtimeEnvironment
    source_revision = $sourceRevision
    fixtures = $fixtureRecords
    protected_code = $codeFiles
    provisioned_utc = [DateTime]::UtcNow.ToString('o')
}
Write-A2Json -Path (Join-Path $labRoot 'state\installation.json') -Value $manifest
$trustedState = [ordered]@{
    schema_version = 1
    root_id = $rootId
    owner_sid = $ownerSid
    worker_sid = $workerSid
    source_revision = $sourceRevision
    fixture_hashes = $fixtureRecords
}
Write-A2Json -Path (Join-Path $labRoot 'state\trusted-state.json') -Value $trustedState

Set-A2AclTree -Path $labRoot -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights None | Out-Null
Set-A2AclItem -Path $labRoot -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights X -InheritWorkerRights $false
Set-A2AclItem -Path (Join-Path $labRoot 'store') -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights X -InheritWorkerRights $false
Set-A2AclItem -Path (Join-Path $labRoot 'work') -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights X -InheritWorkerRights $false
Set-A2AclTree -Path (Join-Path $labRoot 'store\selected') -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights RX | Out-Null
Set-A2AclTree -Path (Join-Path $labRoot 'work\temporary-output') -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights M | Out-Null
Set-A2AclTree -Path (Join-Path $labRoot 'code') -OwnerSid $ownerSid -WorkerSid $workerSid -WorkerRights RX | Out-Null

$credentialUserName = '{0}\{1}' -f $env:COMPUTERNAME, $workerName
[AclaisA2CredentialNative]::WriteGeneric($credentialTarget, $credentialUserName, $password)

$result = [ordered]@{
    checkpoint = 'A2 provisioning'
    provisioned = $true
    elevated = $true
    owner_sid = $ownerSid
    worker_sid = $workerSid
    worker_parent_rights = 'traverse_only_on_lab_root_store_and_work'
    worker_name = $workerName
    worker_enabled = [bool]$worker.Enabled
    credential_target = $credentialTarget
    root_path = $labRoot
    source_revision = $sourceRevision
    fixture_count = $fixtureRecords.Count
    code_file_count = $codeFiles.Count
    generated_password_printed = $false
    credential_stored = $true
    credential_blob_exposed = $false
}
$resultPath = Join-Path $labRoot 'state\a2-provision-result.json'
Write-A2Json -Path $resultPath -Value $result
Write-Output ($result | ConvertTo-Json -Compress)
}
finally {
    if ($password) { $password.Dispose() }
}
