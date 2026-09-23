[CmdletBinding()]
param([ValidateSet('Status', 'Apply', 'Rollback')][string]$Action = 'Status')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$targets = @('59.232.4.33', '192.168.2.227', '59.232.12.34')
$backupFile = Join-Path $PSScriptRoot '特殊地址分流-变更前备份-20260903.json'
$stateFile = Join-Path $PSScriptRoot '特殊地址直连-状态.json'
$proxyScript = Join-Path $PSScriptRoot '特殊地址代理例外.ps1'
$logFile = Join-Path $PSScriptRoot '特殊地址直连-执行日志.txt'

function Get-ExactRoutes {
    param([string]$Address, [string]$Store = 'ActiveStore')
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$Address/32" `
        -PolicyStore $Store -ErrorAction SilentlyContinue
}

function Get-CurrentGateway {
    param($Adapter)

    $routes = @(Get-NetRoute -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '0.0.0.0' } |
        Sort-Object RouteMetric)
    if ($routes.Count -eq 0) {
        throw '“外接主网线”当前没有 IPv4 默认网关，请先插好对应网线。'
    }
    [string]$routes[0].NextHop
}

function Get-ManagedState {
    if (-not (Test-Path -LiteralPath $stateFile)) { return $null }
    Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Show-Status {
    $rows = foreach ($address in @($targets + '1.1.1.1')) {
        $route = Find-NetRoute -RemoteIPAddress $address |
            Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } |
            Select-Object -First 1
        [pscustomobject]@{
            目标 = $address
            网卡 = $route.InterfaceAlias
            匹配路由 = $route.DestinationPrefix
            网关 = $route.NextHop
        }
    }
    $rows | Format-Table -AutoSize
    & $proxyScript -Action Check
}

if ($Action -eq 'Status') {
    Show-Status
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '请在管理员 PowerShell 中运行此脚本；普通权限不能修改系统路由。'
}

Start-Transcript -LiteralPath $logFile -Append | Out-Null
try {
    $backup = Get-Content -LiteralPath $backupFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $adapters = @(Get-NetAdapter | Where-Object {
        $_.InterfaceDescription -eq $backup.InterfaceDescription
    })
    if ($adapters.Count -ne 1) { throw '外接主网卡未找到或不唯一，停止修改。' }
    $adapter = $adapters[0]
    $managed = Get-ManagedState

    if ($Action -eq 'Apply') {
        if ($adapter.Status -ne 'Up') { throw '请先连接外接主网线。' }
        $gateway = Get-CurrentGateway -Adapter $adapter
        $previousGateway = if ($null -ne $managed) {
            [string]$managed.Gateway
        } else {
            [string]$backup.Gateway
        }
        $previousInterfaceIndex = if ($null -ne $managed) {
            [int]$managed.InterfaceIndex
        } else {
            [int]$backup.InterfaceIndex
        }

        # 先检查所有目标均无冲突，再写入；不删除或替换任何已有不同路由。
        foreach ($address in $targets) {
            $routes = @(Get-ExactRoutes $address) + @(Get-ExactRoutes $address 'PersistentStore')
            if (@($routes | Where-Object {
                $isCurrent = $_.NextHop -eq $gateway -and $_.InterfaceIndex -eq $adapter.ifIndex
                $isPreviouslyManaged = $_.NextHop -eq $previousGateway -and
                    $_.InterfaceIndex -eq $previousInterfaceIndex
                -not ($isCurrent -or $isPreviouslyManaged)
            }).Count -gt 0) { throw "目标 $address 存在其他配置的主机路由，停止修改。" }
        }

        # 网关或接口编号变化时，只迁移本策略此前管理的旧路由。
        if ($previousGateway -ne $gateway -or $previousInterfaceIndex -ne $adapter.ifIndex) {
            foreach ($address in $targets) {
                $old = @(Get-ExactRoutes $address) + @(Get-ExactRoutes $address 'PersistentStore') |
                    Where-Object {
                        $_.NextHop -eq $previousGateway -and
                        $_.InterfaceIndex -eq $previousInterfaceIndex
                    }
                if (@($old).Count -gt 0) {
                    & route.exe delete $address mask 255.255.255.255 $previousGateway
                    if ($LASTEXITCODE -ne 0) { throw "旧路由删除失败：$address" }
                }
            }
        }

        foreach ($address in $targets) {
            $persistent = @(Get-ExactRoutes $address 'PersistentStore')
            if ($persistent.Count -eq 0) {
                & route.exe -p add $address mask 255.255.255.255 $gateway metric 5 if $adapter.ifIndex
                if ($LASTEXITCODE -ne 0) { throw "持久路由添加失败：$address" }
            }
        }
        & $proxyScript -Action Apply

        [pscustomobject]@{
            AppliedAt = (Get-Date).ToString('o')
            InterfaceGuid = [string]$adapter.InterfaceGuid
            InterfaceDescription = [string]$adapter.InterfaceDescription
            InterfaceAlias = [string]$adapter.Name
            InterfaceIndex = [int]$adapter.ifIndex
            Gateway = $gateway
            Targets = $targets
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $stateFile -Encoding UTF8

        foreach ($address in $targets) {
            $selected = Find-NetRoute -RemoteIPAddress $address |
                Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } |
                Select-Object -First 1
            if ($selected.InterfaceIndex -ne $adapter.ifIndex -or $selected.NextHop -ne $gateway) {
                throw "路由选择验证失败：$address"
            }
        }
        Write-Host '指定主机路由及代理例外已应用。未修改 IP、DHCP、默认路由或网卡跃点。' -ForegroundColor Green
    } else {
        if ($null -eq $managed) {
            Write-Host '没有本脚本已应用状态，无需撤销。' -ForegroundColor Yellow
            return
        }
        $gateway = [string]$managed.Gateway

        # 只撤销备份确认原先不存在、且下一跳仍属于本次配置的目标路由。
        foreach ($address in $targets) {
            if (@($backup.PriorTargetRoutes | Where-Object DestinationPrefix -eq "$address/32").Count -gt 0) {
                throw "备份显示 $address 原有路由，拒绝删除。"
            }
            $routes = @(Get-ExactRoutes $address) + @(Get-ExactRoutes $address 'PersistentStore')
            if (@($routes | Where-Object NextHop -ne $gateway).Count -gt 0) {
                throw "目标 $address 已被其他配置修改，拒绝删除。"
            }
            if ($routes.Count -gt 0) {
                & route.exe delete $address mask 255.255.255.255 $gateway if $adapter.ifIndex
                if ($LASTEXITCODE -ne 0) { throw "路由撤销失败：$address" }
            }
        }
        & $proxyScript -Action Rollback
        Remove-Item -LiteralPath $stateFile -Force
        Write-Host '已撤销指定特殊地址的路由及新增代理例外，备份与日志继续保留。' -ForegroundColor Green
    }
    Show-Status
} catch {
    Write-Host ("操作未完成：" + $_.Exception.Message) -ForegroundColor Red
    Write-Host '请保留此窗口；日志已保存在脚本目录。不要运行旧版“本地网络策略.ps1”的 Apply。'
    throw
} finally {
    Stop-Transcript | Out-Null
}
