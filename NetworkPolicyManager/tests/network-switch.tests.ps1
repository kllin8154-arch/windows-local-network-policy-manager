[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# 只提取函数定义，禁止执行管理器的启动、配置读写及 UI 代码。
$managerPath = Join-Path (Split-Path -Parent $PSScriptRoot) '本地网络策略管理器.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($managerPath, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -gt 0) { throw '管理器语法检查失败。' }
$functionNames = @('Get-NormalizedGuid', 'ConvertTo-NormalizedPrefix', 'Test-IPv4Address',
    'Test-IPv4InPrefix', 'Resolve-Adapter', 'Get-RuleGateway', 'Get-ExactRoutes',
    'Get-StateEntry', 'Set-StateEntry', 'Get-ProxyTokenForRule', 'Apply-RulePolicy')
foreach ($name in $functionNames) {
    $definition = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $true) | Where-Object Name -eq $name)
    if ($definition.Count -ne 1) { throw "无法唯一提取函数：$name" }
    . ([scriptblock]::Create($definition[0].Extent.Text))
}

$script:Adapter = [pscustomobject]@{
    Index = 10; Name = '外接主网线'; Status = 'Up'
    Guid = '{5A950CA9-30B4-465D-9D9D-3CEA92928C1A}'
    Description = 'Realtek PCIe GbE Family Controller'
}

# 以下所有网络变更、管理员、日志及状态保存均为内存桩。
function Test-IsAdministrator { $true }
function Get-Adapters { $script:Adapter }
function Get-NetIPAddress {
    [CmdletBinding()] param($InterfaceIndex, $AddressFamily)
    [pscustomobject]@{ InterfaceIndex = 10; IPAddress = $script:CurrentAddress; PrefixLength = 24; AddressState = 'Preferred' }
}
function Get-NetRoute {
    [CmdletBinding()] param($AddressFamily, $PolicyStore = 'ActiveStore', $DestinationPrefix, $InterfaceIndex)
    $rows = @($script:Routes | Where-Object PolicyStore -eq $PolicyStore)
    if ($PSBoundParameters.ContainsKey('DestinationPrefix')) { $rows = @($rows | Where-Object DestinationPrefix -eq $DestinationPrefix) }
    if ($PSBoundParameters.ContainsKey('InterfaceIndex')) { $rows = @($rows | Where-Object InterfaceIndex -eq $InterfaceIndex) }
    $rows
}
function Save-State { $script:SaveCount++ }
function Write-AppLog { param($Message, $Level) }
function Get-ProxyTokens { @() }
function Set-ProxyTokens { param($Tokens) throw '本组用例不应修改代理。' }
function Add-ExactRoute {
    param([string]$Prefix, [string]$Gateway, [int]$InterfaceIndex, [switch]$ActiveOnly, [int]$Metric = 5)
    $script:Operations += "ADD $Prefix $Gateway $InterfaceIndex"
    if ($script:FailAddGateway -eq $Gateway) { throw '注入新增路由失败。' }
    Add-MemoryRoute -Prefix $Prefix -Gateway $Gateway -Index $InterfaceIndex -Store 'ActiveStore' -Metric $Metric
    if (-not $ActiveOnly) { Add-MemoryRoute -Prefix $Prefix -Gateway $Gateway -Index $InterfaceIndex -Store 'PersistentStore' -Metric $Metric }
}
function Remove-ExactRoute {
    param([string]$Prefix, [string]$Gateway, [int]$InterfaceIndex = 0)
    $script:Operations += "REMOVE $Prefix $Gateway $InterfaceIndex"
    $script:Routes = @($script:Routes | Where-Object {
        -not ($_.DestinationPrefix -eq $Prefix -and $_.NextHop -eq $Gateway -and
            ($InterfaceIndex -eq 0 -or $_.InterfaceIndex -eq $InterfaceIndex))
    })
}
function Add-MemoryRoute {
    param([string]$Prefix, [string]$Gateway, [int]$Index = 10, [string]$Store = 'ActiveStore', [int]$Metric = 5)
    $script:Routes += [pscustomobject]@{
        DestinationPrefix = $Prefix; NextHop = $Gateway; InterfaceIndex = $Index
        InterfaceAlias = if ($Index -eq 10) { '外接主网线' } else { '其他网卡' }
        PolicyStore = $Store; RouteMetric = $Metric
    }
}
function Reset-MemoryNetwork {
    param([string]$Address = '172.16.23.248', [string]$Gateway = '172.16.23.254')
    $script:CurrentAddress = $Address
    $script:Routes = @()
    $script:State = @()
    $script:Operations = @()
    $script:SaveCount = 0
    $script:FailAddGateway = ''
    Add-MemoryRoute -Prefix '0.0.0.0/0' -Gateway $Gateway -Metric 500
    Add-MemoryRoute -Prefix (ConvertTo-NormalizedPrefix -Value "$Address/24") -Gateway '0.0.0.0' -Metric 256
}
function New-TestRule {
    param([string]$Destination = '59.232.4.33/32', [bool]$OwnExistingRoute = $true)
    [pscustomobject]@{
        Id = 'test-rule'; Name = '测试服务器'; Destination = $Destination
        AdapterGuid = $script:Adapter.Guid; AdapterDescription = $script:Adapter.Description
        GatewayMode = 'Auto'; Gateway = '172.16.21.254'; Enabled = $true
        OwnExistingRoute = $OwnExistingRoute; BypassProxy = $false; OwnExistingProxy = $false
    }
}
function Add-PreviousState {
    param([string]$Destination, [string]$Gateway)
    $script:State = @([pscustomobject]@{
        Id = 'test-rule'; Destination = $Destination; AdapterGuid = $script:Adapter.Guid
        AdapterDescription = $script:Adapter.Description; InterfaceIndex = 10
        Gateway = $Gateway; RouteOwned = $true; ProxyToken = ''; ProxyOwned = $false; AppliedAt = 'before'
    })
}
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Get-MemoryJson { param($Value) ConvertTo-Json -InputObject @($Value) -Depth 8 -Compress }
function Add-PreviousRoute {
    param([string]$Destination, [string]$Gateway, [int]$Index = 10, [int]$Metric = 5)
    Add-MemoryRoute -Prefix $Destination -Gateway $Gateway -Index $Index -Store 'ActiveStore' -Metric $Metric
    Add-MemoryRoute -Prefix $Destination -Gateway $Gateway -Index $Index -Store 'PersistentStore' -Metric $Metric
}

Reset-MemoryNetwork
$rule = New-TestRule
Add-PreviousRoute -Destination $rule.Destination -Gateway '192.168.18.254'
Apply-RulePolicy -Rule $rule -AdaptOwnedRoute
$migrated = @($script:Routes | Where-Object DestinationPrefix -eq $rule.Destination)
Assert-True ($migrated.Count -eq 2 -and @($migrated | Where-Object NextHop -ne '172.16.23.254').Count -eq 0) '旧网关迁移后未同时更新活动和持久路由。'
Assert-True ($script:State.Count -eq 1 -and $script:State[0].RouteOwned -and $script:State[0].Gateway -eq '172.16.23.254') '迁移后状态不正确。'
Write-Host 'PASS 1/5 已接管旧网关 192.168.18.254 迁移到当前网关。'

Reset-MemoryNetwork
$rule = New-TestRule
Add-PreviousRoute -Destination $rule.Destination -Gateway '192.168.18.254' -Index 99
$beforeRoutes = Get-MemoryJson $script:Routes
$rejected = $false
try { Apply-RulePolicy -Rule $rule -AdaptOwnedRoute } catch { $rejected = $true }
Assert-True ($rejected -and $script:Operations.Count -eq 0 -and $script:SaveCount -eq 0) '其他网卡冲突未拒绝，或拒绝前已产生写入。'
Assert-True ((Get-MemoryJson $script:Routes) -eq $beforeRoutes) '其他网卡冲突改变了内存路由。'
Write-Host 'PASS 2/5 其他网卡同目标冲突被拒绝，未产生写入。'

Reset-MemoryNetwork
$rule = New-TestRule -OwnExistingRoute $false
Add-PreviousRoute -Destination $rule.Destination -Gateway '172.16.21.254' -Metric 7
Add-PreviousState -Destination $rule.Destination -Gateway '172.16.21.254'
$beforeState = Get-MemoryJson $script:State
$script:FailAddGateway = '172.16.23.254'
$failed = $false
try { Apply-RulePolicy -Rule $rule -AdaptOwnedRoute } catch { $failed = $true }
$restored = @($script:Routes | Where-Object DestinationPrefix -eq $rule.Destination)
Assert-True ($failed -and $restored.Count -eq 2) '新增失败后未恢复活动和持久旧路由。'
Assert-True (@($restored | Where-Object { $_.NextHop -ne '172.16.21.254' -or $_.RouteMetric -ne 7 }).Count -eq 0) '新增失败后旧网关或跃点未恢复。'
Assert-True ((Get-MemoryJson $script:State) -eq $beforeState) '新增失败后旧管理状态未恢复。'
Write-Host 'PASS 3/5 新增失败后恢复旧路由、跃点及旧状态。'

Reset-MemoryNetwork
$rule = New-TestRule -Destination '172.16.23.120/32' -OwnExistingRoute $false
Add-PreviousRoute -Destination $rule.Destination -Gateway '172.16.21.254'
Add-PreviousState -Destination $rule.Destination -Gateway '172.16.21.254'
Apply-RulePolicy -Rule $rule -AdaptOwnedRoute
Assert-True (@($script:Routes | Where-Object DestinationPrefix -eq $rule.Destination).Count -eq 0) '同网段目标仍保留旧主机路由。'
Assert-True (@($script:Routes | Where-Object { $_.DestinationPrefix -eq '172.16.23.0/24' -and $_.NextHop -eq '0.0.0.0' }).Count -eq 1) '同网段适配删除或修改了系统直连路由。'
Assert-True (@($script:Operations | Where-Object { $_ -like 'ADD *' -or $_ -like 'REMOVE 172.16.23.0/24 *' }).Count -eq 0) '同网段适配创建了多余路由或删除系统直连路由。'
Assert-True ($script:State[0].Gateway -eq '0.0.0.0' -and -not $script:State[0].RouteOwned) '系统直连路由被错误认领。'
Write-Host 'PASS 4/5 同网段目标使用系统直连路由，且未取得系统路由所有权。'
Reset-MemoryNetwork -Address '172.16.21.252' -Gateway '172.16.21.254'
$rule = New-TestRule -Destination '172.16.11.0/24'
Add-PreviousRoute -Destination $rule.Destination -Gateway '172.16.23.254'
Add-PreviousState -Destination $rule.Destination -Gateway '172.16.23.254'
Apply-RulePolicy -Rule $rule -AdaptOwnedRoute
$returned = @($script:Routes | Where-Object DestinationPrefix -eq $rule.Destination)
Assert-True ($returned.Count -eq 2 -and @($returned | Where-Object NextHop -ne '172.16.21.254').Count -eq 0) '换回原网段后未恢复使用 172.16.21.254 网关。'
Write-Host 'PASS 5/5 换回原 172.16.21.x 网段后再次适配成功。'
Write-Host 'NETWORK_SWITCH_MEMORY_TESTS_OK cases=5 network_writes=0 file_writes=0'
