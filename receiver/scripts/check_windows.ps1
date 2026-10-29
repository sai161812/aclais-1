$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot
& uv --project $componentRoot sync --locked
if ($LASTEXITCODE -ne 0) { throw 'Receiver dependency synchronization failed.' }

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run receiver target checks from the ordinary owner session, not an elevated shell.'
}
$worker = Get-LocalUser -Name 'AclaisWorker' -ErrorAction Stop
$workerSid = $worker.SID.Value
$runtimeRoot = 'C:\ACLAIS-Lab\state\receiver'
foreach ($required in @('receiver.sqlite3', 'admin.token', 'payloads', 'staging', 'quarantine')) {
    if (-not (Test-Path -LiteralPath (Join-Path $runtimeRoot $required))) {
        throw "The provisioned receiver runtime is incomplete: $required is unavailable."
    }
}

Push-Location $componentRoot
try {
    & uv --project $componentRoot run --locked python -c "from receiver.security import audit_store_root; from pathlib import Path; audit_store_root(Path(r'C:\ACLAIS-Lab\state\receiver'))"
    if ($LASTEXITCODE -ne 0) { throw 'The actual receiver runtime ACL did not verify.' }
} finally {
    Pop-Location
}

$aclScript = Join-Path $PSScriptRoot 'protect_store.ps1'
& powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $aclScript -StoreRoot $runtimeRoot -AuditOnly -WorkerSid $workerSid
if ($LASTEXITCODE -ne 0) { throw 'Receiver runtime ACL grants the worker or differs from the protected allowlist.' }

Push-Location $componentRoot
try {
    $previousAuditFlag = $env:ACLAIS_G2_LIVE_AUDIT
    $previousPythonPath = $env:PYTHONPATH
    try {
        $repositoryRoot = Split-Path -Parent $componentRoot
        $env:PYTHONPATH = Join-Path $repositoryRoot 'aclais\backend\src'
        $env:ACLAIS_G2_LIVE_AUDIT = '1'
        & uv --project $componentRoot run --locked pytest -m "windows_runtime_acl or windows_receiver_live_http"
        if ($LASTEXITCODE -ne 0) { throw 'Receiver Windows storage or live HTTP checks failed.' }
    } finally {
        $env:ACLAIS_G2_LIVE_AUDIT = $previousAuditFlag
        $env:PYTHONPATH = $previousPythonPath
    }
} finally {
    Pop-Location
}
