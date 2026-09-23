[CmdletBinding()]
param([ValidateSet('Status', 'Apply', 'Rollback')][string]$Action = 'Status')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$targets = @(
    '192.168.2.122',
    '192.168.2.223',
    '192.168.2.224',
    '192.168.2.225',
    '172.16.23.120'
)
$backupFile = Join-Path $PSScriptRoot 'MSTSC外接主网线-变更前备份-20260908.json'
$stateFile = Join-Path $PSScriptRoot 'MSTSC外接主网线-状态.json'
$logFile = Join-Path $PSScriptRoot 'MSTSC外接主网线-执行日志.txt'

function Get-ExternalAdapter {
    param($Backup)

    $matches = @(Get-NetAdapter | Where-Object {
        $_.InterfaceGuid -eq $Backup.InterfaceGuid -and
        $_.InterfaceDescription -eq $Backup.InterfaceDescription
    })
    if ($matches.Count -ne 1) {
        throw '未能按硬件标识唯一找到“外接主网线”，停止修改。'
    }
    $matches[0]
}

function Get-ExactRoutes {
    param([string]$Address)

    @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$Address/32" `
        -ErrorAction SilentlyContinue)
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
        $route = Find-NetRoute -RemoteIPAddress $address -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } |
            Select-Object -First 1
        [pscustomobject]@{
            目标 = $address
            实际网卡 = if ($null -eq $route) { '无可用路由' } else { $route.InterfaceAlias }
            匹配路由 = if ($null -eq $route) { '' } else { $route.DestinationPrefix }
            下一跳 = if ($null -eq $route) { '' } else { $route.NextHop }
        }
    }
    $rows | Format-Table -AutoSize
}

if ($Action -eq 'Status') {
    Show-Status
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '请在管理员 PowerShell 中运行；普通权限不能修改系统路由。'
}

Start-Transcript -LiteralPath $logFile -Append | Out-Null
try {
    $backup = Get-Content -LiteralPath $backupFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $adapter = Get-ExternalAdapter -Backup $backup
    $managed = Get-ManagedState

    if ($Action -eq 'Apply') {
        if ($adapter.Status -ne 'Up') { throw '请先连接外接主网线。' }
        $gateway = Get-CurrentGateway -Adapter $adapter

        # 所有目标先做冲突检查，确保失败时不会只改一半。
        foreach ($address in $targets) {
            $routes = @(Get-ExactRoutes -Address $address)
            $conflicts = @($routes | Where-Object {
                $isCurrent = $_.InterfaceIndex -eq $adapter.ifIndex -and $_.NextHop -eq $gateway
                $isPreviouslyManaged = $null -ne $managed -and
                    $_.NextHop -eq [string]$managed.Gateway -and
                    $_.InterfaceIndex -eq [int]$managed.InterfaceIndex
                -not ($isCurrent -or $isPreviouslyManaged)
            })
            if ($conflicts.Count -gt 0) {
                throw "目标 $address 已有其他配置的主机路由，未修改任何路由。"
            }
        }

        # 外接网络换了网关或接口编号时，只更新本脚本上次创建的路由。
        if ($null -ne $managed -and
            ([string]$managed.Gateway -ne $gateway -or [int]$managed.InterfaceIndex -ne $adapter.ifIndex)) {
            foreach ($address in $targets) {
                $old = @(Get-ExactRoutes -Address $address | Where-Object {
                    $_.NextHop -eq [string]$managed.Gateway -and
                    $_.InterfaceIndex -eq [int]$managed.InterfaceIndex
                })
                if ($old.Count -gt 0) {
                    & route.exe delete $address mask 255.255.255.255 ([string]$managed.Gateway)
                    if ($LASTEXITCODE -ne 0) { throw "旧路由删除失败：$address" }
                }
            }
        }

        foreach ($address in $targets) {
            $current = @(Get-ExactRoutes -Address $address | Where-Object {
                $_.NextHop -eq $gateway -and $_.InterfaceIndex -eq $adapter.ifIndex
            })
            if ($current.Count -eq 0) {
                & route.exe -p add $address mask 255.255.255.255 $gateway metric 5 if $adapter.ifIndex
                if ($LASTEXITCODE -ne 0) { throw "持久路由添加失败：$address" }
            }
        }

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
        Write-Host 'MSTSC 服务器已固定走外接主网线；未修改默认路由、代理、IP、DHCP 或跃点。' -ForegroundColor Green
    } else {
        if ($null -eq $managed) {
            Write-Host '没有本脚本已应用状态，无需撤销。' -ForegroundColor Yellow
            return
        }
        if (@($backup.PriorTargetRoutes).Count -gt 0) {
            throw '备份显示目标原有主机路由，为避免误删，拒绝自动撤销。'
        }
        foreach ($address in $targets) {
            $managedRoutes = @(Get-ExactRoutes -Address $address | Where-Object {
                $_.NextHop -eq [string]$managed.Gateway -and
                $_.InterfaceIndex -eq [int]$managed.InterfaceIndex
            })
            if ($managedRoutes.Count -gt 0) {
                & route.exe delete $address mask 255.255.255.255 ([string]$managed.Gateway)
                if ($LASTEXITCODE -ne 0) { throw "路由撤销失败：$address" }
            }
        }
        Remove-Item -LiteralPath $stateFile -Force
        Write-Host '已撤销本脚本创建的 MSTSC 主机路由；备份与日志仍保留。' -ForegroundColor Green
    }
    Show-Status
} catch {
    Write-Host ("操作未完成：" + $_.Exception.Message) -ForegroundColor Red
    Write-Host '请保留此窗口，执行日志在脚本目录中。'
    throw
} finally {
    Stop-Transcript | Out-Null
}
