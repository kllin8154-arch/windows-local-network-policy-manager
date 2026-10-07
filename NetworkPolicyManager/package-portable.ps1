[CmdletBinding()]
param(
    [ValidatePattern('^[0-9A-Za-z.-]+$')]
    [string]$Version = '0.2.0-preview.1'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
$stage = Join-Path $dist ('.portable-stage-' + [Guid]::NewGuid().ToString('N'))
$archive = Join-Path $dist "LocalNetworkPolicyManager-Portable-$Version-win-x64.zip"
$stagedArchive = Join-Path $dist ('.portable-package-' + [Guid]::NewGuid().ToString('N') + '.zip')
$launcher = Join-Path $root '本地网络策略管理器.exe'
$manager = Join-Path $PSScriptRoot '本地网络策略管理器.ps1'
$rules = Join-Path $PSScriptRoot 'network-rules.json'
$readme = Join-Path $PSScriptRoot 'README-免安装.md'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'build.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Launcher build failed.' }
foreach ($required in @($launcher, $manager, $rules, $readme)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Missing package input: $required" }
}

[void](New-Item -ItemType Directory -Path (Join-Path $stage 'NetworkPolicyManager') -Force)
try {
    Copy-Item -LiteralPath $launcher -Destination $stage
    Copy-Item -LiteralPath $manager -Destination (Join-Path $stage 'NetworkPolicyManager')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Core') -Destination (Join-Path $stage 'NetworkPolicyManager\Core') -Recurse
    Copy-Item -LiteralPath $rules -Destination (Join-Path $stage 'NetworkPolicyManager\network-rules.default.json')
    Copy-Item -LiteralPath $readme -Destination $stage

    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $stagedArchive -CompressionLevel Optimal

    $verification = Join-Path $stage 'verify'
    Expand-Archive -LiteralPath $stagedArchive -DestinationPath $verification
    $installedRules = Join-Path $verification 'NetworkPolicyManager\network-rules.json'
    if (Test-Path -LiteralPath $installedRules) {
        throw 'Portable archive must not overwrite user rules.'
    }
    $installedManager = Join-Path $verification 'NetworkPolicyManager\本地网络策略管理器.ps1'
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $result = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installedManager -SelfTest 2>&1
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($LASTEXITCODE -ne 0 -or ($result -join [Environment]::NewLine) -notmatch 'SELF_TEST_OK') {
        throw "Portable first-run self-test failed: $($result -join [Environment]::NewLine)"
    }
    if (-not (Test-Path -LiteralPath $installedRules)) {
        throw 'Portable first run did not create user rules.'
    }

    Move-Item -LiteralPath $stagedArchive -Destination $archive -Force
    $checksum = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    Write-Host "PORTABLE_OK $archive"
    Write-Host "SHA256 $checksum"
} finally {
    $distPrefix = [IO.Path]::GetFullPath($dist).TrimEnd('\') + '\'
    $stagePath = [IO.Path]::GetFullPath($stage)
    if (-not $stagePath.StartsWith($distPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe staging path: $stagePath"
    }
    $stagedArchivePath = [IO.Path]::GetFullPath($stagedArchive)
    if (-not $stagedArchivePath.StartsWith($distPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe archive path: $stagedArchivePath"
    }
    if (Test-Path -LiteralPath $stagedArchive) {
        Remove-Item -LiteralPath $stagedArchivePath -Force
    }
    Remove-Item -LiteralPath $stagePath -Recurse -Force
}
