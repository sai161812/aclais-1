$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\..\scripts\a2_root_guard.ps1')
. (Join-Path $PSScriptRoot '..\..\scripts\a2_acl.ps1')

$root = Join-Path $env:TEMP ('aclais-a2-root-guard-' + [guid]::NewGuid().ToString('N'))
$expectedOwner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$machine = $env:COMPUTERNAME
$sentinelPath = Join-Path $root '.owner-sentinel.json'
$markerPath = Join-Path $root '.provisioning.json'
$checks = [Collections.Generic.List[object]]::new()

function Add-A2GuardCheck([string]$Name, [bool]$Passed) {
    $checks.Add([ordered]@{ name = $Name; passed = $Passed })
}

function Test-A2GuardRejects([string]$Name, [scriptblock]$Action) {
    try { & $Action; Add-A2GuardCheck $Name $false }
    catch { Add-A2GuardCheck $Name $true }
}

$tempFullPath = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
$rootFullPath = [IO.Path]::GetFullPath($root)
if (-not $rootFullPath.StartsWith($tempFullPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'A2 root guard probe escaped the temporary directory.'
}

try {
    $missingId = Resolve-A2RootId -RootPath $root -SentinelPath $sentinelPath `
        -ProvisionMarkerPath $markerPath -OwnerSid $expectedOwner -Machine $machine
    Add-A2GuardCheck 'missing_owned_root_gets_new_id' ([bool]([guid]$missingId))

    [IO.Directory]::CreateDirectory($root) | Out-Null
    $emptyId = Resolve-A2RootId -RootPath $root -SentinelPath $sentinelPath `
        -ProvisionMarkerPath $markerPath -OwnerSid $expectedOwner -Machine $machine
    Add-A2GuardCheck 'empty_root_without_sentinel_is_initializable' ([bool]([guid]$emptyId))

    $unownedChild = Join-Path $root 'unowned-content.txt'
    [IO.File]::WriteAllText($unownedChild, 'do not adopt')
    Test-A2GuardRejects 'nonempty_root_without_sentinel_is_refused' {
        Resolve-A2RootId -RootPath $root -SentinelPath $sentinelPath `
            -ProvisionMarkerPath $markerPath -OwnerSid $expectedOwner -Machine $machine
    }
    [IO.File]::Delete($unownedChild)

    $rootId = [guid]::NewGuid().ToString('D')
    $validSentinel = [ordered]@{
        schema_version = 1; root_id = $rootId; root_path = $root
        owner_sid = $expectedOwner; machine = $machine
    } | ConvertTo-Json
    [IO.File]::WriteAllText($sentinelPath, $validSentinel, [Text.UTF8Encoding]::new($false))
    $resolvedSentinelId = Resolve-A2RootId -RootPath $root -SentinelPath $sentinelPath `
        -ProvisionMarkerPath $markerPath -OwnerSid $expectedOwner -Machine $machine
    Add-A2GuardCheck 'matching_sentinel_is_reused' ($resolvedSentinelId -eq $rootId)

    $badSentinel = [ordered]@{
        schema_version = 1; root_id = $rootId; root_path = $root
        owner_sid = 'S-1-5-18'; machine = $machine
    } | ConvertTo-Json
    [IO.File]::WriteAllText($sentinelPath, $badSentinel, [Text.UTF8Encoding]::new($false))
    Test-A2GuardRejects 'wrong_owner_sentinel_is_refused' {
        Resolve-A2RootId -RootPath $root -SentinelPath $sentinelPath `
            -ProvisionMarkerPath $markerPath -OwnerSid $expectedOwner -Machine $machine
    }

    [IO.File]::Delete($sentinelPath)
    $validMarker = [ordered]@{
        schema_version = 1; root_id = $rootId; owner_sid = $expectedOwner; machine = $machine
    } | ConvertTo-Json
    [IO.File]::WriteAllText($markerPath, $validMarker, [Text.UTF8Encoding]::new($false))
    $resolvedMarkerId = Resolve-A2RootId -RootPath $root -SentinelPath $sentinelPath `
        -ProvisionMarkerPath $markerPath -OwnerSid $expectedOwner -Machine $machine
    Add-A2GuardCheck 'matching_interrupted_marker_is_reused' ($resolvedMarkerId -eq $rootId)

    $badMarker = [ordered]@{
        schema_version = 1; root_id = $rootId; owner_sid = 'S-1-5-18'; machine = $machine
    } | ConvertTo-Json
    [IO.File]::WriteAllText($markerPath, $badMarker, [Text.UTF8Encoding]::new($false))
    Test-A2GuardRejects 'wrong_owner_interrupted_marker_is_refused' {
        Resolve-A2RootId -RootPath $root -SentinelPath $sentinelPath `
            -ProvisionMarkerPath $markerPath -OwnerSid $expectedOwner -Machine $machine
    }

    $knownReparsePath = Join-Path $env:USERPROFILE 'Application Data'
    if (Test-Path -LiteralPath $knownReparsePath) {
        $reparseItem = Get-Item -LiteralPath $knownReparsePath -Force
        if (($reparseItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            try {
                Test-A2NoReparsePoints -Path $knownReparsePath
                Add-A2GuardCheck 'managed_reparse_point_is_rejected' $false
            }
            catch {
                Add-A2GuardCheck 'managed_reparse_point_is_rejected' ($_.Exception.Message -like 'Reparse point found in a protected tree:*')
            }
        }
        else { Add-A2GuardCheck 'managed_reparse_point_is_rejected' $false }
    }
    else { Add-A2GuardCheck 'managed_reparse_point_is_rejected' $false }
}
finally {
    foreach ($path in @($sentinelPath, $markerPath, (Join-Path $root 'unowned-content.txt'))) {
        if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
    }
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
}

$passed = @($checks | Where-Object { -not $_.passed }).Count -eq 0
$result = [ordered]@{
    schema_version = 1
    kind = 'private_a2_root_guard_probe'
    machine = $machine
    owner_sid = $expectedOwner
    passed = $passed
    check_count = $checks.Count
    checks = @($checks)
}
Write-Output ($result | ConvertTo-Json -Depth 6 -Compress)
if (-not $passed) { exit 2 }
