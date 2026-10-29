param([Parameter(Mandatory)][ValidateSet('start','stop','doctor','reset','teardown')][string]$Action,
      [string]$ConfirmRootId)
$ErrorActionPreference = 'Stop'
$backend = Join-Path (Split-Path -Parent $PSScriptRoot) 'backend'
$arguments = @('--directory',$backend,'run','--locked','python','-m','aclais.operator',$Action)
if ($ConfirmRootId) { $arguments += @('--confirm-root-id',$ConfirmRootId) }
& uv @arguments
if ($LASTEXITCODE -ne 0) { throw "ACLAIS $Action failed with exit code $LASTEXITCODE." }
