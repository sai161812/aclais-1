param(
    [Parameter(Mandatory)][string]$LabRoot,
    [Parameter(Mandatory)][string]$ExpectedWorkerSid,
    [Parameter(Mandatory)][string]$ExpectedSelectedHash,
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$ProbeId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'a2_credential_manager.ps1')
. (Join-Path $PSScriptRoot 'a2_acl.ps1')

$script:checks = @()
$script:workerName = 'AclaisWorker'
$script:credentialTarget = 'ACLAIS-1/AclaisWorker'

function Add-A2ProbeCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Actual,
        [hashtable]$ErrorDetails
    )

    $check = [ordered]@{
        name = $Name
        passed = $Passed
        expected = $Expected
        actual = $Actual
    }
    if ($ErrorDetails) { $check.error = $ErrorDetails }
    $script:checks = @($script:checks) + @($check)
}

function Get-A2WindowsError {
    param([Parameter(Mandatory)][Exception]$Exception)

    while ($Exception.InnerException) { $Exception = $Exception.InnerException }
    $hresult = [long]$Exception.HResult
    $isWin32Hresult = (($hresult -band 0xFFFF0000L) -eq 0x80070000L)
    $errorCode = if ($Exception -is [ComponentModel.Win32Exception]) {
        $Exception.NativeErrorCode
    }
    elseif ($isWin32Hresult) { [int]($hresult -band 0xFFFFL) }
    else { $null }
    $message = if ($null -ne $errorCode) {
        (New-Object ComponentModel.Win32Exception($errorCode)).Message
    }
    else {
        'The operation failed without a Win32 HRESULT.'
    }
    return [ordered]@{
        error_type = $Exception.GetType().FullName
        hresult = ('0x{0:X8}' -f ($hresult -band 0xFFFFFFFFL))
        win32_error = $errorCode
        windows_message = $message
    }
}

function Test-A2ExpectedDenied {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Operation,
        [int[]]$ExpectedWin32Errors = @(5)
    )

    try {
        & $Operation | Out-Null
        $expectedText = ($ExpectedWin32Errors | ForEach-Object { 'Win32 {0}' -f $_ }) -join ' or '
        Add-A2ProbeCheck -Name $Name -Passed $false -Expected $expectedText -Actual 'operation_allowed'
        return $false
    }
    catch {
        $details = Get-A2WindowsError -Exception $_.Exception
        $denied = $ExpectedWin32Errors -contains $details.win32_error
        $expectedText = ($ExpectedWin32Errors | ForEach-Object { 'Win32 {0}' -f $_ }) -join ' or '
        $actualText = if ($details.win32_error -eq 5) { 'access_denied' } elseif ($details.win32_error -in @(2, 3)) { 'path_hidden_or_not_found' } else { 'unexpected_error' }
        Add-A2ProbeCheck -Name $Name -Passed $denied -Expected $expectedText `
            -Actual $actualText -ErrorDetails $details
        return $denied
    }
}

function Test-A2ExpectedAllowed {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Operation)

    try {
        & $Operation | Out-Null
        Add-A2ProbeCheck -Name $Name -Passed $true -Expected 'operation_succeeded' -Actual 'operation_succeeded'
        return $true
    }
    catch {
        $details = Get-A2WindowsError -Exception $_.Exception
        Add-A2ProbeCheck -Name $Name -Passed $false -Expected 'operation_succeeded' `
            -Actual 'unexpected_error' -ErrorDetails $details
        return $false
    }
}

function Test-A2CanRead {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { $null = $stream.ReadByte() }
    finally { $stream.Dispose() }
}

function Test-A2WriteOpen {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stream.Dispose()
}

function Test-A2CanChangeDacl {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$WorkerSid)
    $descriptor = [Security.AccessControl.DirectorySecurity]::new()
    $descriptor.SetAccessRuleProtection($true, $false)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($WorkerSid),
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $descriptor.AddAccessRule($rule)
    [AclaisA2AclNative]::ApplyDaclOnly($Path, $descriptor.GetSecurityDescriptorBinaryForm())
}

function Test-A2CanChangeOwner {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$WorkerSid)
    $descriptor = [Security.AccessControl.DirectorySecurity]::new()
    $descriptor.SetOwner([Security.Principal.SecurityIdentifier]::new($WorkerSid))
    [AclaisA2AclNative]::ApplyOwnerOnly($Path, $descriptor.GetSecurityDescriptorBinaryForm())
}

$labRoot = [IO.Path]::GetFullPath($LabRoot)
$selectedPath = Join-Path $labRoot 'store\selected\Selected_Input.csv'
$originals = Join-Path $labRoot 'store\originals'
$work = Join-Path $labRoot 'work\temporary-output'
$state = Join-Path $labRoot 'state'
$evidence = Join-Path $labRoot 'evidence'
$code = Join-Path $labRoot 'code'
$store = Join-Path $labRoot 'store'
$workRoot = Join-Path $labRoot 'work'
$repositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$repositorySource = Join-Path $repositoryRoot 'aclais\backend\src\aclais\app.py'
$repositoryEvidence = Join-Path $repositoryRoot 'evidence'
$repositoryEvidenceProbe = Join-Path $repositoryEvidence '.a2-worker-access-probe.tmp'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

try {
    Add-A2ProbeCheck -Name 'worker_identity' `
        -Passed ($identity.User.Value -eq $ExpectedWorkerSid -and -not $isAdministrator) `
        -Expected 'actual AclaisWorker SID and non-administrator token' `
        -Actual $(if ($isAdministrator) { 'administrator_token' } elseif ($identity.User.Value -ne $ExpectedWorkerSid) { 'unexpected_sid' } else { 'verified_worker_sid' }) `
        -ErrorDetails @{ account = $identity.Name; sid = $identity.User.Value; is_administrator = $isAdministrator }

    $commandLineHasSecret = [regex]::IsMatch([Environment]::CommandLine, '(?i)(password|secret|token)\s*[:=]')
    Add-A2ProbeCheck -Name 'probe_command_line_contains_no_credential' -Passed (-not $commandLineHasSecret) `
        -Expected 'no credential values in process command line' `
        -Actual $(if ($commandLineHasSecret) { 'credential_pattern_found' } else { 'no_credential_pattern' })
    $credentialEnvironmentNames = @([Environment]::GetEnvironmentVariables('Process').Keys | Where-Object {
        [string]$_ -match '(?i)(password|secret|token|credential)'
    })
    Add-A2ProbeCheck -Name 'worker_environment_has_no_credential_variables' -Passed ($credentialEnvironmentNames.Count -eq 0) `
        -Expected 'no password, secret, token, or credential environment variable' `
        -Actual $(if ($credentialEnvironmentNames.Count -eq 0) { 'none_found' } else { 'credential_variable_name_found' }) `
        -ErrorDetails @{ count = $credentialEnvironmentNames.Count }

    $selectedBytes = [IO.File]::ReadAllBytes($selectedPath)
    $selectedHash = (Get-FileHash -LiteralPath $selectedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-A2ProbeCheck -Name 'selected_input_read' -Passed ($selectedHash -eq $ExpectedSelectedHash) `
        -Expected 'selected copy readable with provisioned SHA-256' -Actual 'readable' `
        -ErrorDetails @{ sha256 = $selectedHash; bytes = $selectedBytes.Length }
    $null = Test-A2ExpectedDenied -Name 'selected_input_write_denied' -Operation { Test-A2WriteOpen -Path $selectedPath }
    $selectedOverwrite = Join-Path $labRoot 'store\selected\overwrite-target.csv'
    $selectedDelete = Join-Path $labRoot 'store\selected\delete-target.csv'
    $selectedRename = Join-Path $labRoot 'store\selected\rename-target.csv'
    $selectedReplace = Join-Path $labRoot 'store\selected\replace-target.csv'
    $null = Test-A2ExpectedDenied -Name 'selected_input_overwrite_denied' -Operation {
        [IO.File]::WriteAllText($selectedOverwrite, 'worker overwrite attempt')
    }
    $null = Test-A2ExpectedDenied -Name 'selected_input_delete_denied' -Operation { [IO.File]::Delete($selectedDelete) }
    $null = Test-A2ExpectedDenied -Name 'selected_input_rename_denied' -Operation { [IO.File]::Move($selectedRename, $selectedRename + '.worker-renamed') }
    $probePrefix = 'a2-probe-' + $ProbeId
    $selectedReplacement = Join-Path $work ($probePrefix + '-selected-replacement.csv')
    $selectedBackup = Join-Path $work ($probePrefix + '-selected-backup.csv')
    [IO.File]::WriteAllText($selectedReplacement, 'ACLAIS selected replacement attempt.')
    $null = Test-A2ExpectedDenied -Name 'selected_input_replace_denied' -Operation {
        [IO.File]::Replace($selectedReplacement, $selectedReplace, $selectedBackup, $true)
    }

    $outputPath = Join-Path $work ($probePrefix + '-output-' + [guid]::NewGuid().ToString('N') + '.txt')
    $outputText = 'ACLAIS A2 synthetic worker output.'
    $null = Test-A2ExpectedAllowed -Name 'temporary_output_create_write_delete' -Operation {
        $stream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($outputText)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        if ([IO.File]::ReadAllText($outputPath, [Text.Encoding]::UTF8) -ne $outputText) {
            throw 'Temporary output verification failed.'
        }
        [IO.File]::Delete($outputPath)
        if (Test-Path -LiteralPath $outputPath) { throw 'Temporary output cleanup failed.' }
    }

    $privateOriginal = Join-Path $originals 'Personnel_Private.csv'
    $null = Test-A2ExpectedDenied -Name 'confidential_original_read_denied' -Operation { Test-A2CanRead -Path $privateOriginal }
    foreach ($permittedOriginalName in @('project-report.md', 'meeting-notes.md', 'invoice.csv')) {
        $permittedOriginal = Join-Path $originals $permittedOriginalName
        $null = Test-A2ExpectedDenied -Name ('permitted_original_read_denied:' + $permittedOriginalName) -Operation {
            Test-A2CanRead -Path $permittedOriginal
        }
    }

    $overwritePath = Join-Path $originals 'overwrite-target.csv'
    $null = Test-A2ExpectedDenied -Name 'original_overwrite_denied' -Operation {
        [IO.File]::WriteAllText($overwritePath, 'worker overwrite attempt')
    }
    $deletePath = Join-Path $originals 'delete-target.csv'
    $null = Test-A2ExpectedDenied -Name 'original_delete_denied' -Operation { [IO.File]::Delete($deletePath) }
    $renamePath = Join-Path $originals 'rename-target.csv'
    $renamedPath = $renamePath + '.worker-renamed'
    $null = Test-A2ExpectedDenied -Name 'original_rename_denied' -ExpectedWin32Errors @(2, 3, 5) `
        -Operation { [IO.File]::Move($renamePath, $renamedPath) }

    $replacePath = Join-Path $originals 'replace-target.csv'
    $replacementPath = Join-Path $work ($probePrefix + '-original-replacement.csv')
    $originalBackup = Join-Path $work ($probePrefix + '-original-backup.csv')
    [IO.File]::WriteAllText($replacementPath, 'ACLAIS A2 replacement attempt.')
    $null = Test-A2ExpectedDenied -Name 'original_replace_denied' -ExpectedWin32Errors @(2, 3, 5) -Operation {
        [IO.File]::Replace($replacementPath, $replacePath, $originalBackup, $true)
    }

    $createdOriginal = Join-Path $originals 'worker-created-child.txt'
    $null = Test-A2ExpectedDenied -Name 'originals_parent_create_child_denied' -Operation {
        [IO.File]::WriteAllText($createdOriginal, 'parent child attempt')
    }
    $null = Test-A2ExpectedDenied -Name 'store_parent_create_child_denied' -Operation {
        [IO.File]::WriteAllText((Join-Path $store 'worker-create-probe.txt'), 'parent child attempt')
    }
    $null = Test-A2ExpectedDenied -Name 'work_parent_create_child_denied' -Operation {
        [IO.File]::WriteAllText((Join-Path $workRoot 'worker-create-probe.txt'), 'parent child attempt')
    }
    $null = Test-A2ExpectedDenied -Name 'lab_root_create_child_denied' -Operation {
        [IO.File]::WriteAllText((Join-Path $labRoot 'worker-create-probe.txt'), 'parent child attempt')
    }

    $null = Test-A2ExpectedDenied -Name 'trusted_state_read_denied' -Operation { Test-A2CanRead -Path (Join-Path $state 'trusted-state.json') }
    $stateWriteMarker = Join-Path $state 'permission-write-probe.json'
    $stateDeleteMarker = Join-Path $state 'permission-delete-probe.json'
    $stateRenameMarker = Join-Path $state 'permission-rename-probe.json'
    $null = Test-A2ExpectedDenied -Name 'trusted_state_write_denied' -Operation { Test-A2WriteOpen -Path $stateWriteMarker }
    $null = Test-A2ExpectedDenied -Name 'trusted_state_delete_denied' -Operation { [IO.File]::Delete($stateDeleteMarker) }
    $null = Test-A2ExpectedDenied -Name 'trusted_state_rename_denied' -ExpectedWin32Errors @(2, 3, 5) -Operation {
        [IO.File]::Move($stateRenameMarker, $stateRenameMarker + '.worker-renamed')
    }
    $null = Test-A2ExpectedDenied -Name 'trusted_state_create_child_denied' -Operation {
        [IO.File]::WriteAllText((Join-Path $state 'worker-created-state.txt'), 'state create attempt')
    }

    $evidenceWriteMarker = Join-Path $evidence 'permission-write-probe.json'
    $evidenceDeleteMarker = Join-Path $evidence 'permission-delete-probe.json'
    $evidenceRenameMarker = Join-Path $evidence 'permission-rename-probe.json'
    $null = Test-A2ExpectedDenied -Name 'owner_evidence_read_denied' -Operation { Test-A2CanRead -Path $evidenceWriteMarker }
    $null = Test-A2ExpectedDenied -Name 'owner_evidence_write_denied' -Operation { Test-A2WriteOpen -Path $evidenceWriteMarker }
    $null = Test-A2ExpectedDenied -Name 'owner_evidence_delete_denied' -Operation { [IO.File]::Delete($evidenceDeleteMarker) }
    $null = Test-A2ExpectedDenied -Name 'owner_evidence_rename_denied' -ExpectedWin32Errors @(2, 3, 5) -Operation {
        [IO.File]::Move($evidenceRenameMarker, $evidenceRenameMarker + '.worker-renamed')
    }
    $null = Test-A2ExpectedDenied -Name 'owner_evidence_create_child_denied' -Operation {
        [IO.File]::WriteAllText((Join-Path $evidence 'worker-created-evidence.txt'), 'evidence create attempt')
    }

    $codeMarker = Join-Path $code 'aclais\app.py'
    $null = Test-A2ExpectedAllowed -Name 'protected_application_code_readable' -Operation { Test-A2CanRead -Path $codeMarker }
    $null = Test-A2ExpectedDenied -Name 'protected_application_code_write_denied' -Operation { Test-A2WriteOpen -Path $codeMarker }
    $codeDeleteMarker = Join-Path $code 'aclais\a2-code-delete-probe.txt'
    $null = Test-A2ExpectedDenied -Name 'protected_application_code_delete_denied' -Operation { [IO.File]::Delete($codeDeleteMarker) }
    $codeRenameMarker = Join-Path $code 'aclais\a2-code-rename-probe.txt'
    $null = Test-A2ExpectedDenied -Name 'protected_application_code_rename_denied' -Operation {
        [IO.File]::Move($codeRenameMarker, $codeRenameMarker + '.worker-renamed')
    }

    $null = Test-A2ExpectedDenied -Name 'repository_application_code_read_denied' -Operation {
        Test-A2CanRead -Path $repositorySource
    } -ExpectedWin32Errors @(5, 2, 3)
    $null = Test-A2ExpectedDenied -Name 'repository_application_code_write_denied' -Operation {
        Test-A2WriteOpen -Path $repositorySource
    } -ExpectedWin32Errors @(5, 2, 3)
    $null = Test-A2ExpectedDenied -Name 'repository_evidence_read_denied' -Operation {
        Test-A2CanRead -Path $repositoryEvidenceProbe
    }
    $null = Test-A2ExpectedDenied -Name 'repository_evidence_write_denied' -Operation {
        Test-A2WriteOpen -Path $repositoryEvidenceProbe
    }
    $null = Test-A2ExpectedDenied -Name 'repository_evidence_create_child_denied' -Operation {
        [IO.File]::WriteAllText((Join-Path $repositoryEvidence 'worker-created-evidence.txt'), 'checkout evidence create attempt')
    }

    $sentinelPath = Join-Path $labRoot '.owner-sentinel.json'
    $null = Test-A2ExpectedDenied -Name 'owner_sentinel_read_denied' -Operation { Test-A2CanRead -Path $sentinelPath }
    $null = Test-A2ExpectedDenied -Name 'owner_sentinel_write_denied' -Operation { Test-A2WriteOpen -Path $sentinelPath }
    $rootDeleteMarker = Join-Path $labRoot 'root-delete-probe.json'
    $rootRenameMarker = Join-Path $labRoot 'root-rename-probe.json'
    $null = Test-A2ExpectedDenied -Name 'lab_root_child_delete_denied' -Operation { [IO.File]::Delete($rootDeleteMarker) }
    $null = Test-A2ExpectedDenied -Name 'lab_root_child_rename_denied' -ExpectedWin32Errors @(2, 3, 5) -Operation {
        [IO.File]::Move($rootRenameMarker, $rootRenameMarker + '.worker-renamed')
    }

    $credentialReadable = $true
    try {
        $stored = [AclaisA2CredentialNative]::ReadGeneric($script:credentialTarget)
        $stored.Password.Dispose()
    }
    catch [ComponentModel.Win32Exception] {
        $credentialReadable = $false
        $codeValue = $_.Exception.NativeErrorCode
        $denied = $codeValue -eq 5 -or $codeValue -eq 1168
        $details = [ordered]@{
            error_type = $_.Exception.GetType().FullName
            win32_error = $codeValue
            windows_message = (New-Object ComponentModel.Win32Exception($codeValue)).Message
        }
        Add-A2ProbeCheck -Name 'owner_credential_unavailable_to_worker' -Passed $denied `
            -Expected 'ERROR_ACCESS_DENIED (5) or ERROR_NOT_FOUND (1168)' `
            -Actual $(if ($codeValue -eq 1168) { 'credential_not_found_in_worker_vault' } elseif ($denied) { 'access_denied' } else { 'unexpected_error' }) `
            -ErrorDetails $details
    }
    if ($credentialReadable) {
        Add-A2ProbeCheck -Name 'owner_credential_unavailable_to_worker' -Passed $false `
            -Expected 'ERROR_ACCESS_DENIED (5) or ERROR_NOT_FOUND (1168)' -Actual 'owner_credential_visible_to_worker'
    }

    $workerSid = $ExpectedWorkerSid
    $null = Test-A2ExpectedDenied -Name 'originals_dacl_change_denied' -Operation {
        Test-A2CanChangeDacl -Path $originals -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'trusted_state_dacl_change_denied' -Operation {
        Test-A2CanChangeDacl -Path $state -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'evidence_dacl_change_denied' -Operation {
        Test-A2CanChangeDacl -Path $evidence -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'selected_input_dacl_change_denied' -Operation {
        Test-A2CanChangeDacl -Path (Join-Path $labRoot 'store\selected') -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'application_code_dacl_change_denied' -Operation {
        Test-A2CanChangeDacl -Path $code -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'lab_root_dacl_change_denied' -Operation {
        Test-A2CanChangeDacl -Path $labRoot -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'store_dacl_change_denied' -Operation {
        Test-A2CanChangeDacl -Path $store -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'work_dacl_change_denied' -Operation {
        Test-A2CanChangeDacl -Path $workRoot -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'temporary_output_dacl_change_denied' -Operation {
        Test-A2CanChangeDacl -Path $work -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'originals_owner_change_denied' -Operation {
        Test-A2CanChangeOwner -Path $originals -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'trusted_state_owner_change_denied' -Operation {
        Test-A2CanChangeOwner -Path $state -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'evidence_owner_change_denied' -Operation {
        Test-A2CanChangeOwner -Path $evidence -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'application_code_owner_change_denied' -Operation {
        Test-A2CanChangeOwner -Path $code -WorkerSid $workerSid
    }
    $null = Test-A2ExpectedDenied -Name 'lab_root_owner_change_denied' -Operation {
        Test-A2CanChangeOwner -Path $labRoot -WorkerSid $workerSid
    }
}
catch {
    $details = Get-A2WindowsError -Exception $_.Exception
    Add-A2ProbeCheck -Name 'probe_runtime' -Passed $false -Expected 'probe completed' -Actual 'probe_exception' -ErrorDetails $details
}

$windows = Get-CimInstance Win32_OperatingSystem
$passed = @($script:checks | Where-Object { -not $_.passed }).Count -eq 0
$result = [ordered]@{
    schema_version = 1
    checkpoint = 'A2'
    kind = 'private_windows_access_probe'
    machine = $env:COMPUTERNAME
    windows_caption = $windows.Caption
    windows_build = $windows.BuildNumber
    observed_identity = $identity.Name
    observed_sid = $identity.User.Value
    is_administrator = $isAdministrator
    passed = $passed
    check_count = $script:checks.Count
    checks = $script:checks
}
Write-Output ($result | ConvertTo-Json -Depth 12 -Compress)
if (-not $passed) { exit 2 }
