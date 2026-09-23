[CmdletBinding()]
param(
    [ValidateSet('Status', 'Apply', 'Test', 'Rollback')]
    [string]$Action = 'Status',

    [string]$InternetAdapterDescription = 'Remote NDIS based Internet Sharing Device',
    [string]$OfflineAdapterDescription = 'Realtek PCIe GbE Family Controller',
    [string]$OfflineIPAddress = '172.16.21.114',
    [ValidateRange(1, 32)]
    [int]$OfflinePrefixLength = 24,
    [string]$OfflineGateway = '172.16.21.254',
    [string[]]$OfflinePrefixes = @('172.16.11.0/24'),
    [string]$OfflineTestAddress = '172.16.11.208'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$InternetMetric = 10
$OfflineMetric = 500
$OfflineRouteMetric = 5
$StatePath = Join-Path $PSScriptRoot '.network-policy-state.json'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '此操作需要在“以管理员身份运行”的 PowerShell 中执行。'
    }
}

function Resolve-Adapter {
    param([Parameter(Mandatory)][string]$Description)

    $candidates = @(
        Get-NetAdapter -IncludeHidden |
            Where-Object {
                $_.InterfaceDescription -eq $Description -and $_.Status -ne 'Not Present'
            }
    )
    $connected = @($candidates | Where-Object Status -eq 'Up')
    if ($connected.Count -eq 1) {
        return $connected[0]
    }
    if ($candidates.Count -eq 1) {
        return $candidates[0]
    }
    if ($candidates.Count -eq 0) {
        throw "找不到网卡设备：$Description"
    }
    throw "网卡设备不唯一：$Description。请只保留当前使用的设备实例。"
}

function Get-IPv4Interface {
    param([Parameter(Mandatory)][string]$Alias)

    Get-NetAdapter -Name $Alias -ErrorAction Stop | Out-Null
    return Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction Stop
}

function Get-PersistentPolicyRoute {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][int]$InterfaceIndex,
        [Parameter(Mandatory)][string]$Gateway
    )

    return @(
        Get-NetRoute -PolicyStore PersistentStore -AddressFamily IPv4 `
            -DestinationPrefix $Prefix -ErrorAction SilentlyContinue |
            Where-Object {
                $_.InterfaceIndex -eq $InterfaceIndex -and $_.NextHop -eq $Gateway
            }
    )
}

function ConvertTo-RouteParts {
    param([Parameter(Mandatory)][string]$Prefix)

    $parts = $Prefix.Split('/')
    if ($parts.Count -ne 2) {
        throw "无效的 CIDR 网段：$Prefix"
    }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$address)) {
        throw "无效的 IPv4 地址：$Prefix"
    }
    $prefixLength = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefixLength) -or $prefixLength -lt 0 -or $prefixLength -gt 32) {
        throw "无效的 IPv4 前缀长度：$Prefix"
    }

    $addressBytes = $address.GetAddressBytes()
    if ($addressBytes.Count -ne 4) {
        throw "仅支持 IPv4 网段：$Prefix"
    }
    $maskBytes = [byte[]]::new(4)
    $networkBytes = [byte[]]::new(4)
    for ($i = 0; $i -lt 4; $i++) {
        $remaining = $prefixLength - ($i * 8)
        $maskBytes[$i] = if ($remaining -ge 8) {
            255
        } elseif ($remaining -le 0) {
            0
        } else {
            [byte](256 - [Math]::Pow(2, 8 - $remaining))
        }
        $networkBytes[$i] = $addressBytes[$i] -band $maskBytes[$i]
    }

    return [pscustomobject]@{
        Destination = ([Net.IPAddress]::new($networkBytes)).ToString()
        Mask = ([Net.IPAddress]::new($maskBytes)).ToString()
    }
}

function Add-PersistentPolicyRoute {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][int]$InterfaceIndex,
        [Parameter(Mandatory)][string]$Gateway
    )

    $routeParts = ConvertTo-RouteParts -Prefix $Prefix
    $output = & route.exe -p add $routeParts.Destination mask $routeParts.Mask `
        $Gateway metric $OfflineRouteMetric if $InterfaceIndex 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "创建持久路由失败：$Prefix -> $Gateway`n$($output -join "`n")"
    }
}

function Remove-PersistentPolicyRoute {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][int]$InterfaceIndex,
        [Parameter(Mandatory)][string]$Gateway
    )

    $routeParts = ConvertTo-RouteParts -Prefix $Prefix
    $output = & route.exe delete $routeParts.Destination mask $routeParts.Mask `
        $Gateway if $InterfaceIndex 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "删除持久路由失败：$Prefix -> $Gateway`n$($output -join "`n")"
    }
}

function Get-SelectedIPv4Route {
    param([Parameter(Mandatory)][string]$RemoteAddress)

    return Find-NetRoute -RemoteIPAddress $RemoteAddress -ErrorAction Stop |
        Where-Object {
            $_.PSObject.Properties.Name -contains 'DestinationPrefix' -and $_.DestinationPrefix
        } |
        Select-Object -First 1
}

function Show-Status {
    $adapters = @($script:InternetAdapter, $script:OfflineAdapter)
    $rows = foreach ($adapter in $adapters) {
        $alias = $adapter.Name
        $ipInterface = Get-IPv4Interface -Alias $alias
        $addresses = @(
            Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike '169.254.*' } |
            ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }
        )
        $defaults = @(
            Get-NetRoute -InterfaceAlias $alias -AddressFamily IPv4 `
                -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
        )

        [pscustomobject]@{
            网卡       = $alias
            设备       = $adapter.InterfaceDescription
            状态       = $adapter.Status
            IPv4       = $addresses -join ', '
            自动跃点   = $ipInterface.AutomaticMetric
            接口跃点   = $ipInterface.InterfaceMetric
            默认网关   = (($defaults | ForEach-Object NextHop | Sort-Object -Unique) -join ', ')
            默认有效跃点 = if ($defaults) {
                (($defaults | ForEach-Object { $_.RouteMetric + $ipInterface.InterfaceMetric }) |
                    Sort-Object) -join ', '
            } else { '' }
        }
    }

    $rows | Format-Table -AutoSize

    Write-Host "`n离线网段持久路由："
    foreach ($prefix in $OfflinePrefixes) {
        $routes = @(Get-PersistentPolicyRoute -Prefix $prefix `
            -InterfaceIndex $script:OfflineAdapter.ifIndex -Gateway $OfflineGateway)
        if ($routes.Count -eq 0) {
            Write-Host "  [缺失] $prefix -> $OfflineGateway ($($script:OfflineAdapter.Name))" -ForegroundColor Yellow
        } else {
            Write-Host "  [已配置] $prefix -> $OfflineGateway ($($script:OfflineAdapter.Name))" -ForegroundColor Green
        }
    }
}

function Save-OriginalState {
    if (Test-Path -LiteralPath $StatePath) {
        $savedState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        $savedPrefixes = @($savedState.Routes.DestinationPrefix | Sort-Object)
        $requestedPrefixes = @($OfflinePrefixes | Sort-Object)
        $sameConfig = (
            $savedState.OfflineGateway -eq $OfflineGateway -and
            (Compare-Object $savedPrefixes $requestedPrefixes).Count -eq 0
        )
        if (-not $sameConfig) {
            throw '已存在不同参数的回滚状态。请先执行 Rollback，再用完整的新参数重新 Apply。'
        }
        if ([int]$savedState.Version -lt 2) {
            $savedState.Version = 2
            $savedState | Add-Member -NotePropertyName AdapterIdentities -NotePropertyValue ([pscustomobject]@{
                InternetDescription = $script:InternetAdapter.InterfaceDescription
                OfflineDescription = $script:OfflineAdapter.InterfaceDescription
            })
            $savedState | Add-Member -NotePropertyName OfflineIPv4 -NotePropertyValue ([pscustomobject]@{
                DhcpEnabled = $true
                StaticAddressExistedBeforeApply = $false
            })
            $savedState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $StatePath -Encoding UTF8
        }
        return
    }

    $internet = Get-IPv4Interface -Alias $script:InternetAdapter.Name
    $offline = Get-IPv4Interface -Alias $script:OfflineAdapter.Name
    $staticAddress = @(Get-NetIPAddress -InterfaceIndex $script:OfflineAdapter.ifIndex `
        -AddressFamily IPv4 -IPAddress $OfflineIPAddress -ErrorAction SilentlyContinue)
    $routes = foreach ($prefix in $OfflinePrefixes) {
        $existing = @(Get-PersistentPolicyRoute -Prefix $prefix `
            -InterfaceIndex $script:OfflineAdapter.ifIndex -Gateway $OfflineGateway)
        [ordered]@{
            DestinationPrefix = $prefix
            ExistedBeforeApply = ($existing.Count -gt 0)
        }
    }

    $state = [ordered]@{
        Version = 2
        SavedAt = (Get-Date).ToString('o')
        InternetInterface = $script:InternetAdapter.Name
        OfflineInterface = $script:OfflineAdapter.Name
        OfflineGateway = $OfflineGateway
        AdapterIdentities = [ordered]@{
            InternetDescription = $script:InternetAdapter.InterfaceDescription
            OfflineDescription = $script:OfflineAdapter.InterfaceDescription
        }
        Interfaces = [ordered]@{
            Internet = [ordered]@{
                AutomaticMetric = [bool]$internet.AutomaticMetric
                InterfaceMetric = [int]$internet.InterfaceMetric
            }
            Offline = [ordered]@{
                AutomaticMetric = [bool]$offline.AutomaticMetric
                InterfaceMetric = [int]$offline.InterfaceMetric
            }
        }
        OfflineIPv4 = [ordered]@{
            DhcpEnabled = ($offline.Dhcp -eq 'Enabled')
            StaticAddressExistedBeforeApply = ($staticAddress.Count -gt 0)
        }
        Routes = @($routes)
    }

    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

function Apply-Policy {
    Assert-Administrator
    Get-IPv4Interface -Alias $script:InternetAdapter.Name | Out-Null
    Get-IPv4Interface -Alias $script:OfflineAdapter.Name | Out-Null
    Save-OriginalState

    Set-NetIPInterface -InterfaceIndex $script:InternetAdapter.ifIndex -AddressFamily IPv4 `
        -AutomaticMetric Disabled -InterfaceMetric $InternetMetric
    Set-NetIPInterface -InterfaceIndex $script:OfflineAdapter.ifIndex -AddressFamily IPv4 `
        -Dhcp Disabled -AutomaticMetric Disabled -InterfaceMetric $OfflineMetric

    $offlineAddress = @(Get-NetIPAddress -InterfaceIndex $script:OfflineAdapter.ifIndex `
        -AddressFamily IPv4 -IPAddress $OfflineIPAddress -ErrorAction SilentlyContinue)
    if ($offlineAddress.Count -eq 0) {
        New-NetIPAddress -InterfaceIndex $script:OfflineAdapter.ifIndex `
            -AddressFamily IPv4 -IPAddress $OfflineIPAddress `
            -PrefixLength $OfflinePrefixLength | Out-Null
    }

    $offlineAddress = Get-NetIPAddress -InterfaceIndex $script:OfflineAdapter.ifIndex `
        -AddressFamily IPv4 -IPAddress $OfflineIPAddress -ErrorAction Stop
    if ($offlineAddress.AddressState -eq 'Duplicate') {
        throw "静态地址 $OfflineIPAddress 在离线网络中发生冲突，已停止建立路由。"
    }

    foreach ($prefix in $OfflinePrefixes) {
        $existing = @(Get-PersistentPolicyRoute -Prefix $prefix `
            -InterfaceIndex $script:OfflineAdapter.ifIndex -Gateway $OfflineGateway)
        if ($existing.Count -eq 0) {
            Add-PersistentPolicyRoute -Prefix $prefix `
                -InterfaceIndex $script:OfflineAdapter.ifIndex -Gateway $OfflineGateway
        }
    }

    Write-Host '网络策略已应用。离线网卡使用无默认网关的静态地址，Hiddify 出口不再受它影响。' -ForegroundColor Green
    Show-Status
}

function Restore-InterfaceMetric {
    param(
        [Parameter(Mandatory)][string]$Alias,
        [Parameter(Mandatory)]$SavedInterface
    )

    if ([bool]$SavedInterface.AutomaticMetric) {
        Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -AutomaticMetric Enabled
    } else {
        Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 `
            -AutomaticMetric Disabled -InterfaceMetric ([int]$SavedInterface.InterfaceMetric)
    }
}

function Rollback-Policy {
    Assert-Administrator
    if (-not (Test-Path -LiteralPath $StatePath)) {
        throw "找不到回滚状态文件：$StatePath"
    }

    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    Restore-InterfaceMetric -Alias $script:InternetAdapter.Name -SavedInterface $state.Interfaces.Internet
    Restore-InterfaceMetric -Alias $script:OfflineAdapter.Name -SavedInterface $state.Interfaces.Offline

    foreach ($routeState in $state.Routes) {
        if (-not [bool]$routeState.ExistedBeforeApply) {
            $route = @(Get-PersistentPolicyRoute -Prefix $routeState.DestinationPrefix `
                -InterfaceIndex $script:OfflineAdapter.ifIndex -Gateway $state.OfflineGateway)
            if ($route.Count -gt 0) {
                Remove-PersistentPolicyRoute -Prefix $routeState.DestinationPrefix `
                    -InterfaceIndex $script:OfflineAdapter.ifIndex -Gateway $state.OfflineGateway
            }
        }
    }

    if ($state.PSObject.Properties.Name -contains 'OfflineIPv4') {
        if (-not [bool]$state.OfflineIPv4.StaticAddressExistedBeforeApply) {
            Get-NetIPAddress -InterfaceIndex $script:OfflineAdapter.ifIndex `
                -AddressFamily IPv4 -IPAddress $OfflineIPAddress -ErrorAction SilentlyContinue |
                Remove-NetIPAddress -Confirm:$false
        }
        if ([bool]$state.OfflineIPv4.DhcpEnabled) {
            Set-NetIPInterface -InterfaceIndex $script:OfflineAdapter.ifIndex `
                -AddressFamily IPv4 -Dhcp Enabled
        }
    }

    Remove-Item -LiteralPath $StatePath -Force
    Write-Host '已恢复应用前的接口跃点，并删除本脚本新建的持久路由。' -ForegroundColor Green
    Show-Status
}

function Test-Policy {
    $tests = @(
        [pscustomobject]@{
            Name = '普通互联网'; Address = '1.1.1.1'
            ExpectedInterface = $script:InternetAdapter.Name
        }
    )
    foreach ($prefix in $OfflinePrefixes) {
        $tests += [pscustomobject]@{
            Name = "离线网段 $prefix"
            Address = $OfflineTestAddress
            ExpectedInterface = $script:OfflineAdapter.Name
        }
    }

    $results = foreach ($test in $tests) {
        try {
            $route = Get-SelectedIPv4Route -RemoteAddress $test.Address
            [pscustomobject]@{
                测试       = $test.Name
                目标       = $test.Address
                实际网卡   = $route.InterfaceAlias
                期望网卡   = $test.ExpectedInterface
                结果       = if ($route.InterfaceAlias -eq $test.ExpectedInterface) { '通过' } else { '未通过' }
                匹配路由   = $route.DestinationPrefix
                下一跳     = $route.NextHop
            }
        } catch {
            [pscustomobject]@{
                测试 = $test.Name; 目标 = $test.Address; 实际网卡 = ''; 期望网卡 = $test.ExpectedInterface
                结果 = '无可用路由'; 匹配路由 = ''; 下一跳 = ''
            }
        }
    }

    $results | Format-Table -AutoSize
    if ($script:OfflineAdapter.Status -ne 'Up') {
        Write-Warning '外接主网线当前未连接，离线路由只能在插线后做最终验证。'
    }
}

$script:InternetAdapter = Resolve-Adapter -Description $InternetAdapterDescription
$script:OfflineAdapter = Resolve-Adapter -Description $OfflineAdapterDescription

switch ($Action) {
    'Status'   { Show-Status }
    'Apply'    { Apply-Policy }
    'Test'     { Test-Policy }
    'Rollback' { Rollback-Policy }
}
