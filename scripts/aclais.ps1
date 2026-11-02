param([Parameter(Mandatory)][ValidateSet('start','stop','doctor','reset','teardown')][string]$Action,
      [string]$ConfirmRootId)
$ErrorActionPreference = 'Stop'
$command = Join-Path (Split-Path -Parent $PSScriptRoot) 'aclais\scripts\manage.ps1'
& $command -Action $Action -ConfirmRootId $ConfirmRootId
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw 'ACLAIS operator command failed.' }
