function Resolve-A2RootId {
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][string]$SentinelPath,
        [Parameter(Mandatory)][string]$ProvisionMarkerPath,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][string]$Machine
    )

    if (-not (Test-Path -LiteralPath $RootPath)) {
        return [guid]::NewGuid().ToString('D')
    }
    if (Test-Path -LiteralPath $SentinelPath) {
        $sentinel = Get-Content -LiteralPath $SentinelPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($sentinel.schema_version -ne 1 -or $sentinel.owner_sid -ne $OwnerSid -or
            $sentinel.machine -ne $Machine -or $sentinel.root_path -ne $RootPath -or
            $sentinel.root_id -notmatch '^[0-9a-fA-F-]{36}$') {
            throw 'The existing ACLAIS-Lab sentinel belongs to a different owner or machine.'
        }
        return [string]$sentinel.root_id
    }
    if (Test-Path -LiteralPath $ProvisionMarkerPath) {
        $marker = Get-Content -LiteralPath $ProvisionMarkerPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($marker.owner_sid -ne $OwnerSid -or $marker.machine -ne $Machine -or
            $marker.root_id -notmatch '^[0-9a-fA-F-]{36}$') {
            throw 'The interrupted provisioning marker belongs to a different owner or machine.'
        }
        return [string]$marker.root_id
    }

    $existingItems = @(Get-ChildItem -LiteralPath $RootPath -Force -ErrorAction Stop)
    if ($existingItems.Count -gt 0) {
        throw 'C:\ACLAIS-Lab is not empty and has no ownership sentinel; refusing to adopt it.'
    }
    return [guid]::NewGuid().ToString('D')
}
