[CmdletBinding()]
param([switch]$CheckOnly)

$ErrorActionPreference = 'Stop'
$adapterGuid = '{5A950CA9-30B4-465D-9D9D-3CEA92928C1A}'
$destination = '172.16.11.0/24'
$routeAddress = '172.16.11.0'
$routeMask = '255.255.255.0'
$knownGateways = @('172.16.21.254', '172.16.23.254')
$logDirectory = Join-Path $env:ProgramData 'LocalNetworkPolicyManager'
$logPath = Join-Path $logDirectory 'auto-route.log'

function Write-RepairLog {
    param([string]$Message)
    if (-not (Test-Path -LiteralPath $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    }
    Add-Content -LiteralPath $logPath -Encoding UTF8 -Value ('{0} {1}' -f (Get-Date -Format o), $Message)
}

function Test-SameSubnet {
    param([string]$Address, [string]$Gateway, [int]$PrefixLength)
    $addressBytes = ([Net.IPAddress]::Parse($Address)).GetAddressBytes()
    $gatewayBytes = ([Net.IPAddress]::Parse($Gateway)).GetAddressBytes()
    for ($i = 0; $i -lt 4; $i++) {
        $bits = [Math]::Max(0, [Math]::Min(8, $PrefixLength - 8 * $i))
        $mask = if ($bits -eq 0) { 0 } else { 256 - [Math]::Pow(2, 8 - $bits) }
        if (($addressBytes[$i] -band [int]$mask) -ne ($gatewayBytes[$i] -band [int]$mask)) { return $false }
    }
    return $true
}

try {
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceGuid -eq $adapterGuid })
    if ($adapters.Count -ne 1 -or $adapters[0].Status -ne 'Up') { return }
    $index = [int]$adapters[0].ifIndex
    $addresses = @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.AddressState -eq 'Preferred' })
    if ($addresses.Count -eq 0) { return }

    $onLinkGateways = @($knownGateways | Where-Object {
        $gateway = $_
        @($addresses | Where-Object {
            Test-SameSubnet -Address $_.IPAddress -Gateway $gateway -PrefixLength $_.PrefixLength
        }).Count -gt 0
    })
    if ($onLinkGateways.Count -ne 1) { return }
    $expected = [string]$onLinkGateways[0]
    $defaultRoutes = @(Get-NetRoute -InterfaceIndex $index -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
    if ($defaultRoutes.Count -gt 0 -and @($defaultRoutes | Where-Object NextHop -eq $expected).Count -eq 0) {
        Write-RepairLog "跳过：网卡默认网关与已确认网段不一致。"
        return
    }

    $active = @(Get-NetRoute -PolicyStore ActiveStore -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object DestinationPrefix -eq $destination)
    $persistent = @(Get-NetRoute -PolicyStore PersistentStore -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object DestinationPrefix -eq $destination)
    $all = @($active) + @($persistent)
    $foreign = @($all | Where-Object {
        $_.InterfaceIndex -ne $index -or $_.NextHop -notin $knownGateways
    })
    if ($foreign.Count -gt 0) {
        Write-RepairLog "跳过：$destination 存在非本任务管理的路由。"
        return
    }
    if (@($active | Where-Object NextHop -eq $expected).Count -eq 1 -and
        @($persistent | Where-Object NextHop -eq $expected).Count -eq 1 -and
        $all.Count -eq 2) { return }

    $oldGateways = @($all | ForEach-Object NextHop | Select-Object -Unique)
    if ($CheckOnly) {
        "需要修复：$destination | $($oldGateways -join ',') -> $expected | 接口 $index"
        return
    }

    foreach ($oldGateway in $oldGateways) {
        $output = & route.exe delete $routeAddress mask $routeMask $oldGateway if $index 2>&1
        if ($LASTEXITCODE -ne 0) { throw "删除旧路由失败：$($output -join ' ')" }
    }
    try {
        $output = & route.exe -p add $routeAddress mask $routeMask $expected metric 5 if $index 2>&1
        if ($LASTEXITCODE -ne 0) { throw "新增持久路由失败：$($output -join ' ')" }
        $newActive = @(Get-NetRoute -PolicyStore ActiveStore -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.DestinationPrefix -eq $destination -and $_.InterfaceIndex -eq $index -and $_.NextHop -eq $expected })
        $newPersistent = @(Get-NetRoute -PolicyStore PersistentStore -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.DestinationPrefix -eq $destination -and $_.InterfaceIndex -eq $index -and $_.NextHop -eq $expected })
        if ($newActive.Count -ne 1 -or $newPersistent.Count -ne 1) { throw '新增路由后验证失败。' }
        Write-RepairLog "已修复：$destination -> $expected | 接口 $index"
    } catch {
        foreach ($oldGateway in $oldGateways) {
            & route.exe -p add $routeAddress mask $routeMask $oldGateway metric 5 if $index | Out-Null
        }
        throw
    }
} catch {
    Write-RepairLog "失败：$($_.Exception.Message)"
    exit 1
}
