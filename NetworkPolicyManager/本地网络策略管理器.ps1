[CmdletBinding()]
param(
    [switch]$SelfTest,
    [switch]$DumpStatus,
    [switch]$UiSmokeTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AppRoot = $PSScriptRoot
$script:RulesPath = Join-Path $script:AppRoot 'network-rules.json'
$script:StatePath = Join-Path $script:AppRoot 'manager-state.json'
$script:LogPath = Join-Path $script:AppRoot 'network-policy-manager.log'
$script:Rules = @()
$script:State = @()
$script:LogControl = $null

function Write-AppLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
    if ($null -ne $script:LogControl -and -not $script:LogControl.IsDisposed) {
        $script:LogControl.AppendText($line + [Environment]::NewLine)
        $script:LogControl.SelectionStart = $script:LogControl.TextLength
        $script:LogControl.ScrollToCaret()
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-JsonArray {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }
    $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($text)) {
        return @()
    }
    @($text | ConvertFrom-Json)
}

function Save-Rules {
    @($script:Rules) | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:RulesPath -Encoding UTF8
}

function Save-State {
    @($script:State) | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:StatePath -Encoding UTF8
}

function Get-NormalizedGuid {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    try { ([Guid]$Value).ToString('B').ToUpperInvariant() } catch { $Value.ToUpperInvariant() }
}

function ConvertTo-NormalizedPrefix {
    param([Parameter(Mandatory)][string]$Value)

    $trimmed = $Value.Trim()
    if ($trimmed -notmatch '/') {
        $trimmed += '/32'
    }
    $parts = $trimmed.Split('/')
    if ($parts.Count -ne 2) {
        throw "无效的 IPv4/CIDR：$Value"
    }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$address) -or $address.AddressFamily -ne 'InterNetwork') {
        throw "无效的 IPv4 地址：$Value"
    }
    $prefixLength = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefixLength) -or $prefixLength -lt 0 -or $prefixLength -gt 32) {
        throw "无效的 IPv4 前缀长度：$Value"
    }

    $bytes = $address.GetAddressBytes()
    $network = [byte[]]::new(4)
    for ($i = 0; $i -lt 4; $i++) {
        $remaining = $prefixLength - ($i * 8)
        $mask = if ($remaining -ge 8) { 255 } elseif ($remaining -le 0) { 0 } else {
            [int](256 - [Math]::Pow(2, 8 - $remaining))
        }
        $network[$i] = [byte]($bytes[$i] -band $mask)
    }
    '{0}/{1}' -f ([Net.IPAddress]::new($network)).ToString(), $prefixLength
}

function ConvertTo-RouteParts {
    param([Parameter(Mandatory)][string]$Prefix)

    $normalized = ConvertTo-NormalizedPrefix -Value $Prefix
    $parts = $normalized.Split('/')
    $prefixLength = [int]$parts[1]
    $maskBytes = [byte[]]::new(4)
    for ($i = 0; $i -lt 4; $i++) {
        $remaining = $prefixLength - ($i * 8)
        $maskBytes[$i] = if ($remaining -ge 8) { 255 } elseif ($remaining -le 0) { 0 } else {
            [byte](256 - [Math]::Pow(2, 8 - $remaining))
        }
    }
    [pscustomobject]@{
        Destination = $parts[0]
        Mask = ([Net.IPAddress]::new($maskBytes)).ToString()
        PrefixLength = $prefixLength
    }
}

function Test-IPv4Address {
    param([Parameter(Mandatory)][string]$Value)

    $address = $null
    [Net.IPAddress]::TryParse($Value, [ref]$address) -and $address.AddressFamily -eq 'InterNetwork'
}

function Get-Adapters {
    @(
        Get-NetAdapter -IncludeHidden -ErrorAction Stop |
            Where-Object { $_.Status -ne 'Not Present' -and $_.InterfaceDescription -notmatch '^WAN Miniport' } |
            Sort-Object @{ Expression = { if ($_.HardwareInterface) { 0 } else { 1 } } }, Name |
            ForEach-Object {
                [pscustomobject]@{
                    Name = [string]$_.Name
                    Description = [string]$_.InterfaceDescription
                    Guid = Get-NormalizedGuid -Value ([string]$_.InterfaceGuid)
                    Index = [int]$_.ifIndex
                    Status = [string]$_.Status
                    Hardware = [bool]$_.HardwareInterface
                    Display = '{0}  |  {1}  |  {2}' -f $_.Name, $_.InterfaceDescription, $_.Status
                }
            }
    )
}

function Resolve-Adapter {
    param(
        [Parameter(Mandatory)]$Rule,
        [object[]]$Adapters = $(Get-Adapters)
    )

    $guid = Get-NormalizedGuid -Value ([string]$Rule.AdapterGuid)
    $matches = @($Adapters | Where-Object Guid -eq $guid)
    if ($matches.Count -eq 1) { return $matches[0] }

    $matches = @($Adapters | Where-Object Description -eq ([string]$Rule.AdapterDescription))
    if ($matches.Count -eq 1) { return $matches[0] }
    if ($matches.Count -eq 0) { throw "找不到网卡：$($Rule.AdapterDescription)" }
    throw "网卡设备不唯一：$($Rule.AdapterDescription)"
}

function Get-RuleGateway {
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)]$Adapter,
        [object[]]$Routes = $null
    )

    if ([string]$Rule.GatewayMode -eq 'Manual') {
        if (-not (Test-IPv4Address -Value ([string]$Rule.Gateway))) {
            throw "规则「$($Rule.Name)」的手动网关无效。"
        }
        return [string]$Rule.Gateway
    }

    if ($null -eq $Routes) {
        $Routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
    }
    $route = $Routes |
        Where-Object {
            $_.DestinationPrefix -eq '0.0.0.0/0' -and
            $_.InterfaceIndex -eq $Adapter.Index -and $_.NextHop -ne '0.0.0.0'
        } |
        Sort-Object RouteMetric |
        Select-Object -First 1
    if ($null -eq $route) {
        throw "网卡「$($Adapter.Name)」当前没有 IPv4 默认网关。"
    }
    [string]$route.NextHop
}

function Get-StateEntry {
    param([Parameter(Mandatory)][string]$Id)
    @($script:State | Where-Object Id -eq $Id) | Select-Object -First 1
}

function Set-StateEntry {
    param([Parameter(Mandatory)]$Entry)

    $script:State = @($script:State | Where-Object Id -ne $Entry.Id)
    $script:State += $Entry
    Save-State
}

function Remove-StateEntry {
    param([Parameter(Mandatory)][string]$Id)

    $script:State = @($script:State | Where-Object Id -ne $Id)
    Save-State
}

function Get-ProxyTokens {
    $settings = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    @(([string]$settings.ProxyOverride -split ';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Set-ProxyTokens {
    param([Parameter(Mandatory)][string[]]$Tokens)

    $registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $value = (@($Tokens | Select-Object -Unique) -join ';')
    Set-ItemProperty -LiteralPath $registryPath -Name ProxyOverride -Value $value

    if (-not ('NetworkPolicyManagerWinInet' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NetworkPolicyManagerWinInet {
    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int option, IntPtr buffer, int length);
    public static void Refresh() {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }
}
'@
    }
    [NetworkPolicyManagerWinInet]::Refresh()
}

function Get-ProxyTokenForRule {
    param([Parameter(Mandatory)]$Rule)

    if (-not [bool]$Rule.BypassProxy) { return '' }
    $parts = (ConvertTo-NormalizedPrefix -Value ([string]$Rule.Destination)).Split('/')
    if ([int]$parts[1] -ne 32) {
        throw '系统代理绕过仅支持单个 IPv4（/32），不支持 CIDR 网段。'
    }
    [string]$parts[0]
}

function Get-ExactRoutes {
    param([Parameter(Mandatory)][string]$Prefix)
    @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $Prefix -ErrorAction SilentlyContinue)
}

function Add-ExactRoute {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Gateway,
        [Parameter(Mandatory)][int]$InterfaceIndex
    )

    $parts = ConvertTo-RouteParts -Prefix $Prefix
    $output = & route.exe -p add $parts.Destination mask $parts.Mask $Gateway metric 5 if $InterfaceIndex 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "添加持久路由失败：$Prefix -> $Gateway`n$($output -join "`n")"
    }
}

function Remove-ExactRoute {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Gateway,
        [int]$InterfaceIndex = 0
    )

    $parts = ConvertTo-RouteParts -Prefix $Prefix
    $arguments = @('delete', $parts.Destination, 'mask', $parts.Mask, $Gateway)
    if ($InterfaceIndex -gt 0) { $arguments += @('if', [string]$InterfaceIndex) }
    $output = & route.exe @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $stillExists = @(Get-ExactRoutes -Prefix $Prefix | Where-Object NextHop -eq $Gateway).Count -gt 0
        if ($stillExists) {
            throw "删除路由失败：$Prefix -> $Gateway`n$($output -join "`n")"
        }
    }
}

function Get-SystemSnapshot {
    $adapters = Get-Adapters
    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue)
    [pscustomobject]@{
        Adapters = $adapters
        Routes = $routes
        ProxyTokens = @(Get-ProxyTokens)
    }
}

function Get-RuleStatus {
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)]$Snapshot
    )

    if (-not [bool]$Rule.Enabled) {
        return [pscustomobject]@{ State = 'Disabled'; Text = '已禁用'; Actual = ''; Color = 'Gray' }
    }
    try {
        $adapter = Resolve-Adapter -Rule $Rule -Adapters $Snapshot.Adapters
        $prefix = ConvertTo-NormalizedPrefix -Value ([string]$Rule.Destination)
        $gateway = Get-RuleGateway -Rule $Rule -Adapter $adapter -Routes $Snapshot.Routes
        $exact = @($Snapshot.Routes | Where-Object DestinationPrefix -eq $prefix)
        $matching = @($exact | Where-Object {
            $_.InterfaceIndex -eq $adapter.Index -and $_.NextHop -eq $gateway
        })
        if ($exact.Count -gt 0 -and $matching.Count -eq 0) {
            $actual = ($exact | ForEach-Object { "$($_.InterfaceAlias) / $($_.NextHop)" }) -join ', '
            return [pscustomobject]@{
                State = 'Conflict'; Text = "存在冲突路由（期望 $($adapter.Name) / $gateway）"
                Actual = $actual; Color = 'Red'
            }
        }
        if ($matching.Count -eq 0) {
            return [pscustomobject]@{ State = 'Missing'; Text = '未应用'; Actual = ''; Color = 'Orange' }
        }
        if ([bool]$Rule.BypassProxy) {
            $token = Get-ProxyTokenForRule -Rule $Rule
            if ($token -notin $Snapshot.ProxyTokens) {
                return [pscustomobject]@{
                    State = 'ProxyMissing'; Text = '路由已应用，代理绕过缺失'
                    Actual = "$($adapter.Name) / $gateway"; Color = 'Orange'
                }
            }
        }
        $text = if ($adapter.Status -eq 'Up') { '已应用' } else { '已配置（网卡未连接）' }
        [pscustomobject]@{
            State = 'Applied'; Text = $text; Actual = "$($adapter.Name) / $gateway"
            Color = if ($adapter.Status -eq 'Up') { 'Green' } else { 'Gray' }
        }
    } catch {
        [pscustomobject]@{ State = 'Unavailable'; Text = $_.Exception.Message; Actual = ''; Color = 'Red' }
    }
}

function Apply-RulePolicy {
    param([Parameter(Mandatory)]$Rule)

    if (-not (Test-IsAdministrator)) {
        throw '应用规则需要管理员权限。请通过桌面快捷方式启动。'
    }
    if (-not [bool]$Rule.Enabled) {
        throw "规则「$($Rule.Name)」已禁用。"
    }

    $adapters = Get-Adapters
    $adapter = Resolve-Adapter -Rule $Rule -Adapters $adapters
    if ($adapter.Status -ne 'Up') {
        throw "网卡「$($adapter.Name)」当前未连接，请插好网线后再应用。"
    }
    $prefix = ConvertTo-NormalizedPrefix -Value ([string]$Rule.Destination)
    $gateway = Get-RuleGateway -Rule $Rule -Adapter $adapter
    $previous = Get-StateEntry -Id ([string]$Rule.Id)
    $exact = Get-ExactRoutes -Prefix $prefix
    $matching = @($exact | Where-Object {
        $_.InterfaceIndex -eq $adapter.Index -and $_.NextHop -eq $gateway
    })
    $conflicts = @($exact | Where-Object {
        $_.InterfaceIndex -ne $adapter.Index -or $_.NextHop -ne $gateway
    })

    $removedPrevious = $false
    if ($conflicts.Count -gt 0) {
        $canReplacePrevious = $null -ne $previous -and [bool]$previous.RouteOwned -and
            @($conflicts | Where-Object NextHop -ne ([string]$previous.Gateway)).Count -eq 0
        if (-not $canReplacePrevious) {
            $details = ($conflicts | ForEach-Object { "$($_.InterfaceAlias) / $($_.NextHop)" }) -join ', '
            throw "目标 $prefix 已有其他路由：$details。为避免覆盖，未做修改。"
        }
        $previousAdapter = @($adapters | Where-Object Guid -eq (Get-NormalizedGuid -Value ([string]$previous.AdapterGuid))) |
            Select-Object -First 1
        $previousIndex = if ($null -ne $previousAdapter) { $previousAdapter.Index } else { [int]$previous.InterfaceIndex }
        Remove-ExactRoute -Prefix ([string]$previous.Destination) -Gateway ([string]$previous.Gateway) `
            -InterfaceIndex $previousIndex
        $removedPrevious = $true
        $matching = @()
    }

    $routeCreated = $false
    $proxyAdded = $false
    try {
        if ($matching.Count -eq 0) {
            Add-ExactRoute -Prefix $prefix -Gateway $gateway -InterfaceIndex $adapter.Index
            $routeCreated = $true
        }

        $routeOwned = $routeCreated -or [bool]$Rule.OwnExistingRoute -or
            ($null -ne $previous -and [bool]$previous.RouteOwned)
        $proxyToken = Get-ProxyTokenForRule -Rule $Rule
        $proxyOwned = $false
        if (-not [string]::IsNullOrWhiteSpace($proxyToken)) {
            $tokens = @(Get-ProxyTokens)
            if ($proxyToken -notin $tokens) {
                Set-ProxyTokens -Tokens @($tokens + $proxyToken)
                $proxyAdded = $true
                $proxyOwned = $true
            } else {
                $proxyOwned = [bool]$Rule.OwnExistingProxy -or
                    ($null -ne $previous -and [bool]$previous.ProxyOwned)
            }
        }

        $entry = [pscustomobject]@{
            Id = [string]$Rule.Id
            Destination = $prefix
            AdapterGuid = [string]$adapter.Guid
            AdapterDescription = [string]$adapter.Description
            InterfaceIndex = [int]$adapter.Index
            Gateway = $gateway
            RouteOwned = [bool]$routeOwned
            ProxyToken = $proxyToken
            ProxyOwned = [bool]$proxyOwned
            AppliedAt = (Get-Date).ToString('o')
        }
        Set-StateEntry -Entry $entry

        $verified = @(Get-ExactRoutes -Prefix $prefix | Where-Object {
            $_.InterfaceIndex -eq $adapter.Index -and $_.NextHop -eq $gateway
        })
        if ($verified.Count -eq 0) {
            throw "应用后验证失败：$prefix"
        }
        Write-AppLog -Message "已应用：$($Rule.Name) | $prefix -> $($adapter.Name) / $gateway"
    } catch {
        if ($routeCreated) {
            try { Remove-ExactRoute -Prefix $prefix -Gateway $gateway -InterfaceIndex $adapter.Index } catch { }
        }
        if ($proxyAdded) {
            try { Set-ProxyTokens -Tokens @((Get-ProxyTokens) | Where-Object { $_ -ne $proxyToken }) } catch { }
        }
        if ($removedPrevious -and $null -ne $previous) {
            try {
                Add-ExactRoute -Prefix ([string]$previous.Destination) -Gateway ([string]$previous.Gateway) `
                    -InterfaceIndex ([int]$previous.InterfaceIndex)
            } catch { }
        }
        throw
    }
}

function Remove-RulePolicy {
    param([Parameter(Mandatory)]$Rule)

    if (-not (Test-IsAdministrator)) {
        throw '撤销规则需要管理员权限。请通过桌面快捷方式启动。'
    }

    $prefix = ConvertTo-NormalizedPrefix -Value ([string]$Rule.Destination)
    $state = Get-StateEntry -Id ([string]$Rule.Id)
    $adapters = Get-Adapters
    $adapter = $null
    try { $adapter = Resolve-Adapter -Rule $Rule -Adapters $adapters } catch { }

    $routeOwned = ($null -ne $state -and [bool]$state.RouteOwned) -or [bool]$Rule.OwnExistingRoute
    if ($routeOwned) {
        $routePrefix = if ($null -ne $state) { [string]$state.Destination } else { $prefix }
        $routes = Get-ExactRoutes -Prefix $routePrefix
        $gateway = if ($null -ne $state) { [string]$state.Gateway } else {
            if ($null -ne $adapter) {
                try { Get-RuleGateway -Rule $Rule -Adapter $adapter } catch { '' }
            } else { '' }
        }
        if ([string]::IsNullOrWhiteSpace($gateway) -and $null -ne $adapter) {
            $gateway = [string](@($routes | Where-Object InterfaceIndex -eq $adapter.Index) | Select-Object -First 1).NextHop
        }
        if (-not [string]::IsNullOrWhiteSpace($gateway)) {
            $index = if ($null -ne $adapter) { [int]$adapter.Index } elseif ($null -ne $state) {
                [int]$state.InterfaceIndex
            } else { 0 }
            $managedRoutes = @($routes | Where-Object {
                $_.NextHop -eq $gateway -and ($index -eq 0 -or $_.InterfaceIndex -eq $index)
            })
            if ($managedRoutes.Count -gt 0) {
                Remove-ExactRoute -Prefix $routePrefix -Gateway $gateway -InterfaceIndex $index
            }
        }
    }

    $proxyToken = if ($null -ne $state) { [string]$state.ProxyToken } else {
        try { Get-ProxyTokenForRule -Rule $Rule } catch { '' }
    }
    $proxyOwned = ($null -ne $state -and [bool]$state.ProxyOwned) -or [bool]$Rule.OwnExistingProxy
    if ($proxyOwned -and -not [string]::IsNullOrWhiteSpace($proxyToken)) {
        $otherRuleUsesToken = @($script:Rules | Where-Object {
            $_.Id -ne $Rule.Id -and [bool]$_.BypassProxy -and
            (Get-ProxyTokenForRule -Rule $_) -eq $proxyToken
        }).Count -gt 0
        if (-not $otherRuleUsesToken) {
            Set-ProxyTokens -Tokens @((Get-ProxyTokens) | Where-Object { $_ -ne $proxyToken })
        }
    }

    Remove-StateEntry -Id ([string]$Rule.Id)
    Write-AppLog -Message "已撤销：$($Rule.Name) | $prefix"
}

function Test-RulePolicy {
    param([Parameter(Mandatory)]$Rule)

    $snapshot = Get-SystemSnapshot
    $status = Get-RuleStatus -Rule $Rule -Snapshot $snapshot
    $parts = (ConvertTo-NormalizedPrefix -Value ([string]$Rule.Destination)).Split('/')
    $testAddress = [string]$parts[0]
    $selected = Find-NetRoute -RemoteIPAddress $testAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } |
        Select-Object -First 1
    [pscustomobject]@{
        Name = [string]$Rule.Name
        Destination = [string]$Rule.Destination
        Status = [string]$status.Text
        SelectedAdapter = if ($null -eq $selected) { '无可用路由' } else { [string]$selected.InterfaceAlias }
        MatchedRoute = if ($null -eq $selected) { '' } else { [string]$selected.DestinationPrefix }
        NextHop = if ($null -eq $selected) { '' } else { [string]$selected.NextHop }
    }
}

function Assert-Configuration {
    $ids = @{}
    $destinations = @{}
    foreach ($rule in $script:Rules) {
        if ([string]::IsNullOrWhiteSpace([string]$rule.Id)) { throw '存在缺少 Id 的规则。' }
        if ($ids.ContainsKey([string]$rule.Id)) { throw "规则 Id 重复：$($rule.Id)" }
        $ids[[string]$rule.Id] = $true
        if ([string]::IsNullOrWhiteSpace([string]$rule.Name)) { throw "规则 $($rule.Id) 缺少名称。" }
        $prefix = ConvertTo-NormalizedPrefix -Value ([string]$rule.Destination)
        if ($destinations.ContainsKey($prefix)) { throw "目标重复：$prefix" }
        $destinations[$prefix] = $true
        if ([string]$rule.GatewayMode -notin @('Auto', 'Manual')) {
            throw "规则「$($rule.Name)」的网关模式无效。"
        }
        if ([string]$rule.GatewayMode -eq 'Manual' -and -not (Test-IPv4Address -Value ([string]$rule.Gateway))) {
            throw "规则「$($rule.Name)」的手动网关无效。"
        }
        if ([string]::IsNullOrWhiteSpace([string]$rule.AdapterGuid) -and
            [string]::IsNullOrWhiteSpace([string]$rule.AdapterDescription)) {
            throw "规则「$($rule.Name)」没有指定网卡。"
        }
        if ([bool]$rule.BypassProxy -and -not $prefix.EndsWith('/32')) {
            throw "规则「$($rule.Name)」启用了代理绕过，但目标不是单个 IPv4。"
        }
    }

    $stateIds = @{}
    foreach ($entry in $script:State) {
        if ($stateIds.ContainsKey([string]$entry.Id)) { throw "状态 Id 重复：$($entry.Id)" }
        $stateIds[[string]$entry.Id] = $true
        ConvertTo-NormalizedPrefix -Value ([string]$entry.Destination) | Out-Null
        if (-not (Test-IPv4Address -Value ([string]$entry.Gateway))) {
            throw "状态 $($entry.Id) 的网关无效。"
        }
    }
}

$script:Rules = Read-JsonArray -Path $script:RulesPath
$script:State = Read-JsonArray -Path $script:StatePath
Assert-Configuration

if ($SelfTest) {
    "SELF_TEST_OK rules=$($script:Rules.Count) state=$($script:State.Count)"
    exit 0
}

if ($DumpStatus) {
    $snapshot = Get-SystemSnapshot
    $rows = foreach ($rule in $script:Rules) {
        $status = Get-RuleStatus -Rule $rule -Snapshot $snapshot
        [pscustomobject]@{
            Id = $rule.Id
            Name = $rule.Name
            Destination = $rule.Destination
            Status = $status.Text
            Actual = $status.Actual
        }
    }
    $rows | ConvertTo-Json -Depth 5
    exit 0
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[Windows.Forms.Application]::EnableVisualStyles()

function New-UiButton {
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$Width = 100
    )

    $button = [Windows.Forms.Button]::new()
    $button.Text = $Text
    $button.Width = $Width
    $button.Height = 32
    $button.Margin = [Windows.Forms.Padding]::new(4, 8, 4, 8)
    $button.FlatStyle = 'System'
    $button
}

function Show-RuleEditor {
    param([object]$Rule = $null)

    $isEdit = $null -ne $Rule
    $dialog = [Windows.Forms.Form]::new()
    $dialog.Text = if ($isEdit) { '修改通信规则' } else { '新增通信规则' }
    $dialog.ClientSize = [Drawing.Size]::new(620, 430)
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.StartPosition = 'CenterParent'
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.ShowInTaskbar = $false
    $dialog.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)

    $labels = @('规则名称', '目标 IPv4 / CIDR', '指定网卡', '网关模式', '手动网关')
    for ($i = 0; $i -lt $labels.Count; $i++) {
        $label = [Windows.Forms.Label]::new()
        $label.Text = $labels[$i]
        $label.AutoSize = $true
        $label.Location = [Drawing.Point]::new(28, 32 + ($i * 58))
        $dialog.Controls.Add($label)
    }

    $nameBox = [Windows.Forms.TextBox]::new()
    $nameBox.Location = [Drawing.Point]::new(170, 28)
    $nameBox.Size = [Drawing.Size]::new(410, 26)
    $dialog.Controls.Add($nameBox)

    $destinationBox = [Windows.Forms.TextBox]::new()
    $destinationBox.Location = [Drawing.Point]::new(170, 86)
    $destinationBox.Size = [Drawing.Size]::new(410, 26)
    $dialog.Controls.Add($destinationBox)

    $adapterBox = [Windows.Forms.ComboBox]::new()
    $adapterBox.Location = [Drawing.Point]::new(170, 144)
    $adapterBox.Size = [Drawing.Size]::new(410, 28)
    $adapterBox.DropDownStyle = 'DropDownList'
    $adapterBox.DisplayMember = 'Display'
    $adapters = Get-Adapters
    foreach ($adapter in $adapters) { [void]$adapterBox.Items.Add($adapter) }
    $dialog.Controls.Add($adapterBox)

    $gatewayModeBox = [Windows.Forms.ComboBox]::new()
    $gatewayModeBox.Location = [Drawing.Point]::new(170, 202)
    $gatewayModeBox.Size = [Drawing.Size]::new(410, 28)
    $gatewayModeBox.DropDownStyle = 'DropDownList'
    [void]$gatewayModeBox.Items.Add('自动使用该网卡当前默认网关')
    [void]$gatewayModeBox.Items.Add('手动指定网关')
    $dialog.Controls.Add($gatewayModeBox)

    $gatewayBox = [Windows.Forms.TextBox]::new()
    $gatewayBox.Location = [Drawing.Point]::new(170, 260)
    $gatewayBox.Size = [Drawing.Size]::new(410, 26)
    $dialog.Controls.Add($gatewayBox)

    $bypassCheck = [Windows.Forms.CheckBox]::new()
    $bypassCheck.Text = '同时绕过 Windows 系统代理（仅单个 IPv4）'
    $bypassCheck.AutoSize = $true
    $bypassCheck.Location = [Drawing.Point]::new(170, 312)
    $dialog.Controls.Add($bypassCheck)

    $enabledCheck = [Windows.Forms.CheckBox]::new()
    $enabledCheck.Text = '启用此规则'
    $enabledCheck.AutoSize = $true
    $enabledCheck.Location = [Drawing.Point]::new(170, 344)
    $enabledCheck.Checked = $true
    $dialog.Controls.Add($enabledCheck)

    $saveButton = New-UiButton -Text '保存' -Width 92
    $saveButton.Location = [Drawing.Point]::new(386, 382)
    $dialog.Controls.Add($saveButton)

    $cancelButton = New-UiButton -Text '取消' -Width 92
    $cancelButton.Location = [Drawing.Point]::new(488, 382)
    $cancelButton.DialogResult = 'Cancel'
    $dialog.CancelButton = $cancelButton
    $dialog.Controls.Add($cancelButton)

    $gatewayModeBox.Add_SelectedIndexChanged({
        $gatewayBox.Enabled = $gatewayModeBox.SelectedIndex -eq 1
    })

    if ($isEdit) {
        $nameBox.Text = [string]$Rule.Name
        $destinationBox.Text = [string]$Rule.Destination
        $ruleGuid = Get-NormalizedGuid -Value ([string]$Rule.AdapterGuid)
        for ($i = 0; $i -lt $adapterBox.Items.Count; $i++) {
            if ($adapterBox.Items[$i].Guid -eq $ruleGuid) { $adapterBox.SelectedIndex = $i; break }
        }
        $gatewayModeBox.SelectedIndex = if ([string]$Rule.GatewayMode -eq 'Manual') { 1 } else { 0 }
        $gatewayBox.Text = [string]$Rule.Gateway
        $bypassCheck.Checked = [bool]$Rule.BypassProxy
        $enabledCheck.Checked = [bool]$Rule.Enabled
    } else {
        $realtekIndex = -1
        for ($i = 0; $i -lt $adapterBox.Items.Count; $i++) {
            if ($adapterBox.Items[$i].Description -eq 'Realtek PCIe GbE Family Controller') {
                $realtekIndex = $i
                break
            }
        }
        if ($realtekIndex -ge 0) { $adapterBox.SelectedIndex = $realtekIndex }
        elseif ($adapterBox.Items.Count -gt 0) { $adapterBox.SelectedIndex = 0 }
        $gatewayModeBox.SelectedIndex = 0
    }

    $saveButton.Add_Click({
        try {
            if ([string]::IsNullOrWhiteSpace($nameBox.Text)) { throw '请输入规则名称。' }
            $prefix = ConvertTo-NormalizedPrefix -Value $destinationBox.Text
            if ($null -eq $adapterBox.SelectedItem) { throw '请选择网卡。' }
            $adapter = $adapterBox.SelectedItem
            $mode = if ($gatewayModeBox.SelectedIndex -eq 1) { 'Manual' } else { 'Auto' }
            $gateway = $gatewayBox.Text.Trim()
            if ($mode -eq 'Manual' -and -not (Test-IPv4Address -Value $gateway)) {
                throw '请输入有效的手动 IPv4 网关。'
            }
            if ($bypassCheck.Checked -and -not $prefix.EndsWith('/32')) {
                throw '系统代理绕过仅支持单个 IPv4（/32）。'
            }
            $sameManagedIdentity = $isEdit -and
                (ConvertTo-NormalizedPrefix -Value ([string]$Rule.Destination)) -eq $prefix -and
                (Get-NormalizedGuid -Value ([string]$Rule.AdapterGuid)) -eq $adapter.Guid -and
                [string]$Rule.GatewayMode -eq $mode -and [string]$Rule.Gateway -eq $gateway
            $dialog.Tag = [pscustomobject]@{
                Id = if ($isEdit) { [string]$Rule.Id } else { [Guid]::NewGuid().ToString('N') }
                Name = $nameBox.Text.Trim()
                Destination = $prefix
                AdapterGuid = [string]$adapter.Guid
                AdapterDescription = [string]$adapter.Description
                GatewayMode = $mode
                Gateway = if ($mode -eq 'Manual') { $gateway } else { '' }
                BypassProxy = [bool]$bypassCheck.Checked
                Enabled = [bool]$enabledCheck.Checked
                OwnExistingRoute = if ($sameManagedIdentity) { [bool]$Rule.OwnExistingRoute } else { $false }
                OwnExistingProxy = if ($sameManagedIdentity) { [bool]$Rule.OwnExistingProxy } else { $false }
            }
            $dialog.DialogResult = 'OK'
            $dialog.Close()
        } catch {
            [Windows.Forms.MessageBox]::Show($_.Exception.Message, '无法保存', 'OK', 'Warning') | Out-Null
        }
    })

    if ($dialog.ShowDialog() -eq 'OK') { return $dialog.Tag }
    $null
}

$form = [Windows.Forms.Form]::new()
$form.Text = '本地网络策略管理器'
$form.StartPosition = 'CenterScreen'
$form.Size = [Drawing.Size]::new(1240, 780)
$form.MinimumSize = [Drawing.Size]::new(1020, 650)
$form.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
$form.AutoScaleMode = 'Dpi'

$header = [Windows.Forms.Panel]::new()
$header.Dock = 'Top'
$header.Height = 86
$header.BackColor = [Drawing.Color]::FromArgb(245, 248, 252)
$form.Controls.Add($header)

$titleLabel = [Windows.Forms.Label]::new()
$titleLabel.Text = '本地网络策略管理器'
$titleLabel.Font = [Drawing.Font]::new('Microsoft YaHei UI', 18, [Drawing.FontStyle]::Bold)
$titleLabel.AutoSize = $true
$titleLabel.Location = [Drawing.Point]::new(18, 12)
$header.Controls.Add($titleLabel)

$descriptionLabel = [Windows.Forms.Label]::new()
$descriptionLabel.Text = '按目标 IPv4/CIDR 指定出口网卡；不修改默认路由、IP、DHCP 或网卡跃点。'
$descriptionLabel.ForeColor = [Drawing.Color]::FromArgb(75, 85, 99)
$descriptionLabel.AutoSize = $true
$descriptionLabel.Location = [Drawing.Point]::new(21, 50)
$header.Controls.Add($descriptionLabel)

$summaryLabel = [Windows.Forms.Label]::new()
$summaryLabel.Anchor = 'Top,Right'
$summaryLabel.TextAlign = 'MiddleRight'
$summaryLabel.Location = [Drawing.Point]::new(715, 13)
$summaryLabel.Size = [Drawing.Size]::new(490, 52)
$header.Controls.Add($summaryLabel)

$toolbar = [Windows.Forms.FlowLayoutPanel]::new()
$toolbar.Dock = 'Top'
$toolbar.Height = 52
$toolbar.Padding = [Windows.Forms.Padding]::new(10, 2, 8, 2)
$toolbar.WrapContents = $false
$form.Controls.Add($toolbar)

$addButton = New-UiButton -Text '新增规则' -Width 96
$editButton = New-UiButton -Text '修改规则' -Width 96
$deleteButton = New-UiButton -Text '删除规则' -Width 96
$applyButton = New-UiButton -Text '应用所选' -Width 96
$applyAllButton = New-UiButton -Text '应用全部' -Width 96
$removeButton = New-UiButton -Text '撤销所选' -Width 96
$testButton = New-UiButton -Text '测试所选' -Width 96
$refreshButton = New-UiButton -Text '刷新状态' -Width 96
@($addButton, $editButton, $deleteButton, $applyButton, $applyAllButton,
    $removeButton, $testButton, $refreshButton) | ForEach-Object { $toolbar.Controls.Add($_) }

$logBox = [Windows.Forms.RichTextBox]::new()
$logBox.Dock = 'Bottom'
$logBox.Height = 130
$logBox.ReadOnly = $true
$logBox.BackColor = [Drawing.Color]::FromArgb(250, 250, 250)
$logBox.BorderStyle = 'FixedSingle'
$logBox.Font = [Drawing.Font]::new('Consolas', 9)
$form.Controls.Add($logBox)
$script:LogControl = $logBox

$grid = [Windows.Forms.DataGridView]::new()
$grid.Dock = 'Fill'
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.MultiSelect = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.RowHeadersVisible = $false
$grid.AutoGenerateColumns = $false
$grid.BackgroundColor = [Drawing.Color]::White
$grid.BorderStyle = 'None'
$grid.AutoSizeRowsMode = 'AllCells'
$grid.DefaultCellStyle.WrapMode = 'False'
$form.Controls.Add($grid)

function Add-GridColumn {
    param([string]$Name, [string]$Header, [int]$Width, [string]$AutoSizeMode = 'None')
    $column = [Windows.Forms.DataGridViewTextBoxColumn]::new()
    $column.Name = $Name
    $column.HeaderText = $Header
    $column.Width = $Width
    $column.AutoSizeMode = $AutoSizeMode
    [void]$grid.Columns.Add($column)
}

Add-GridColumn -Name 'Enabled' -Header '启用' -Width 55
Add-GridColumn -Name 'Name' -Header '名称' -Width 245
Add-GridColumn -Name 'Destination' -Header '目标 IPv4 / CIDR' -Width 150
Add-GridColumn -Name 'Adapter' -Header '指定网卡' -Width 150
Add-GridColumn -Name 'Gateway' -Header '网关' -Width 145
Add-GridColumn -Name 'Proxy' -Header '绕过代理' -Width 82
Add-GridColumn -Name 'Status' -Header '当前状态' -Width 210
Add-GridColumn -Name 'Actual' -Header '实际路由' -Width 160 -AutoSizeMode 'Fill'

$layout = [Windows.Forms.TableLayoutPanel]::new()
$layout.Dock = 'Fill'
$layout.ColumnCount = 1
$layout.RowCount = 4
[void]$layout.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent', 100))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 86))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 52))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 130))
$form.Controls.Clear()
$header.Dock = 'Fill'
$toolbar.Dock = 'Fill'
$grid.Dock = 'Fill'
$logBox.Dock = 'Fill'
$layout.Controls.Add($header, 0, 0)
$layout.Controls.Add($toolbar, 0, 1)
$layout.Controls.Add($grid, 0, 2)
$layout.Controls.Add($logBox, 0, 3)
$form.Controls.Add($layout)

function Get-SelectedRule {
    if ($grid.SelectedRows.Count -eq 0) { return $null }
    $grid.SelectedRows[0].Tag
}

function Refresh-Grid {
    $selectedId = if ($grid.SelectedRows.Count -gt 0 -and $null -ne $grid.SelectedRows[0].Tag) {
        [string]$grid.SelectedRows[0].Tag.Id
    } else { '' }
    $form.Cursor = [Windows.Forms.Cursors]::WaitCursor
    try {
        $snapshot = Get-SystemSnapshot
        $grid.Rows.Clear()
        $applied = 0
        foreach ($rule in $script:Rules) {
            $status = Get-RuleStatus -Rule $rule -Snapshot $snapshot
            if ($status.State -eq 'Applied') { $applied++ }
            $adapter = $null
            try { $adapter = Resolve-Adapter -Rule $rule -Adapters $snapshot.Adapters } catch { }
            $adapterName = if ($null -eq $adapter) { [string]$rule.AdapterDescription } else { [string]$adapter.Name }
            $gatewayText = if ([string]$rule.GatewayMode -eq 'Manual') {
                [string]$rule.Gateway
            } else { '自动（当前默认网关）' }
            $rowIndex = $grid.Rows.Add(
                $(if ([bool]$rule.Enabled) { '是' } else { '否' }),
                [string]$rule.Name,
                [string]$rule.Destination,
                $adapterName,
                $gatewayText,
                $(if ([bool]$rule.BypassProxy) { '是' } else { '否' }),
                [string]$status.Text,
                [string]$status.Actual
            )
            $row = $grid.Rows[$rowIndex]
            $row.Tag = $rule
            switch ($status.Color) {
                'Green' { $row.DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(236, 253, 245) }
                'Orange' { $row.DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(255, 251, 235) }
                'Red' { $row.DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(254, 242, 242) }
                default { $row.DefaultCellStyle.ForeColor = [Drawing.Color]::FromArgb(107, 114, 128) }
            }
            if ([string]$rule.Id -eq $selectedId) { $row.Selected = $true }
        }
        $upAdapters = @($snapshot.Adapters | Where-Object { $_.Hardware -and $_.Status -eq 'Up' } |
            ForEach-Object Name)
        $summaryLabel.Text = "已应用 $applied / $($script:Rules.Count) 条规则`n已连接实体网卡：$($upAdapters -join '、')"
    } catch {
        Write-AppLog -Message ("刷新失败：" + $_.Exception.Message) -Level 'ERROR'
        $summaryLabel.Text = '状态刷新失败'
    } finally {
        $form.Cursor = [Windows.Forms.Cursors]::Default
    }
}

function Save-NewRule {
    $newRule = Show-RuleEditor
    if ($null -eq $newRule) { return }
    $oldRules = @($script:Rules)
    try {
        $script:Rules += $newRule
        Assert-Configuration
        Save-Rules
        Write-AppLog -Message "已新增规则：$($newRule.Name)"
        Refresh-Grid
    } catch {
        $script:Rules = $oldRules
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '新增失败', 'OK', 'Error') | Out-Null
    }
}

function Edit-SelectedRule {
    $oldRule = Get-SelectedRule
    if ($null -eq $oldRule) {
        [Windows.Forms.MessageBox]::Show('请先选择一条规则。', '提示', 'OK', 'Information') | Out-Null
        return
    }
    $newRule = Show-RuleEditor -Rule $oldRule
    if ($null -eq $newRule) { return }

    $policyChanged =
        (ConvertTo-NormalizedPrefix -Value ([string]$oldRule.Destination)) -ne [string]$newRule.Destination -or
        (Get-NormalizedGuid -Value ([string]$oldRule.AdapterGuid)) -ne [string]$newRule.AdapterGuid -or
        [string]$oldRule.GatewayMode -ne [string]$newRule.GatewayMode -or
        [string]$oldRule.Gateway -ne [string]$newRule.Gateway -or
        [bool]$oldRule.BypassProxy -ne [bool]$newRule.BypassProxy -or
        ([bool]$oldRule.Enabled -and -not [bool]$newRule.Enabled)

    if ($policyChanged) {
        $answer = [Windows.Forms.MessageBox]::Show(
            '这次修改会改变通信策略。程序将先撤销旧规则；保存后请点击「应用所选」应用新规则。是否继续？',
            '确认修改', 'YesNo', 'Question')
        if ($answer -ne 'Yes') { return }
        try { Remove-RulePolicy -Rule $oldRule } catch {
            [Windows.Forms.MessageBox]::Show($_.Exception.Message, '无法撤销旧规则', 'OK', 'Error') | Out-Null
            return
        }
    }

    $oldRules = @($script:Rules)
    try {
        $script:Rules = @($script:Rules | ForEach-Object {
            if ($_.Id -eq $oldRule.Id) { $newRule } else { $_ }
        })
        Assert-Configuration
        Save-Rules
        Write-AppLog -Message "已修改规则：$($newRule.Name)"
        Refresh-Grid
    } catch {
        $script:Rules = $oldRules
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '修改失败', 'OK', 'Error') | Out-Null
    }
}

$addButton.Add_Click({ Save-NewRule })
$editButton.Add_Click({ Edit-SelectedRule })
$grid.Add_CellDoubleClick({ param($sender, $eventArgs); if ($eventArgs.RowIndex -ge 0) { Edit-SelectedRule } })

$deleteButton.Add_Click({
    $rule = Get-SelectedRule
    if ($null -eq $rule) {
        [Windows.Forms.MessageBox]::Show('请先选择一条规则。', '提示', 'OK', 'Information') | Out-Null
        return
    }
    $answer = [Windows.Forms.MessageBox]::Show(
        "将删除规则「$($rule.Name)」，并撤销它管理的精确路由和代理绕过。是否继续？",
        '确认删除', 'YesNo', 'Warning')
    if ($answer -ne 'Yes') { return }
    try {
        Remove-RulePolicy -Rule $rule
        $script:Rules = @($script:Rules | Where-Object Id -ne $rule.Id)
        Save-Rules
        Write-AppLog -Message "已删除规则：$($rule.Name)"
        Refresh-Grid
    } catch {
        Write-AppLog -Message ("删除失败：" + $_.Exception.Message) -Level 'ERROR'
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '删除失败', 'OK', 'Error') | Out-Null
    }
})

$applyButton.Add_Click({
    $rule = Get-SelectedRule
    if ($null -eq $rule) {
        [Windows.Forms.MessageBox]::Show('请先选择一条规则。', '提示', 'OK', 'Information') | Out-Null
        return
    }
    $form.Cursor = [Windows.Forms.Cursors]::WaitCursor
    try {
        Apply-RulePolicy -Rule $rule
        Refresh-Grid
    } catch {
        Write-AppLog -Message ("应用失败：" + $_.Exception.Message) -Level 'ERROR'
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '应用失败', 'OK', 'Error') | Out-Null
    } finally {
        $form.Cursor = [Windows.Forms.Cursors]::Default
    }
})

$applyAllButton.Add_Click({
    $enabledRules = @($script:Rules | Where-Object Enabled)
    if ($enabledRules.Count -eq 0) { return }
    $answer = [Windows.Forms.MessageBox]::Show(
        "将应用 $($enabledRules.Count) 条启用规则。未连接或网关不匹配的规则会保留并报告错误。是否继续？",
        '应用全部', 'YesNo', 'Question')
    if ($answer -ne 'Yes') { return }
    $form.Cursor = [Windows.Forms.Cursors]::WaitCursor
    $errors = [Collections.Generic.List[string]]::new()
    foreach ($rule in $enabledRules) {
        try { Apply-RulePolicy -Rule $rule } catch {
            $message = "$($rule.Name)：$($_.Exception.Message)"
            $errors.Add($message)
            Write-AppLog -Message $message -Level 'ERROR'
        }
    }
    Refresh-Grid
    $form.Cursor = [Windows.Forms.Cursors]::Default
    if ($errors.Count -gt 0) {
        [Windows.Forms.MessageBox]::Show(
            "部分规则未应用：`n`n$($errors -join "`n`n")", '应用完成（有错误）', 'OK', 'Warning') | Out-Null
    }
})

$removeButton.Add_Click({
    $rule = Get-SelectedRule
    if ($null -eq $rule) {
        [Windows.Forms.MessageBox]::Show('请先选择一条规则。', '提示', 'OK', 'Information') | Out-Null
        return
    }
    $answer = [Windows.Forms.MessageBox]::Show(
        "只撤销规则「$($rule.Name)」当前管理的路由和代理绕过，保留规则记录。是否继续？",
        '确认撤销', 'YesNo', 'Question')
    if ($answer -ne 'Yes') { return }
    try {
        Remove-RulePolicy -Rule $rule
        Refresh-Grid
    } catch {
        Write-AppLog -Message ("撤销失败：" + $_.Exception.Message) -Level 'ERROR'
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '撤销失败', 'OK', 'Error') | Out-Null
    }
})

$testButton.Add_Click({
    $rule = Get-SelectedRule
    if ($null -eq $rule) {
        [Windows.Forms.MessageBox]::Show('请先选择一条规则。', '提示', 'OK', 'Information') | Out-Null
        return
    }
    try {
        $result = Test-RulePolicy -Rule $rule
        $message = @(
            "规则：$($result.Name)",
            "目标：$($result.Destination)",
            "状态：$($result.Status)",
            "Windows 实际选择网卡：$($result.SelectedAdapter)",
            "匹配路由：$($result.MatchedRoute)",
            "下一跳：$($result.NextHop)"
        ) -join "`n"
        [Windows.Forms.MessageBox]::Show($message, '规则测试结果', 'OK', 'Information') | Out-Null
    } catch {
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '测试失败', 'OK', 'Error') | Out-Null
    }
})

$refreshButton.Add_Click({ Refresh-Grid })

$isAdministrator = Test-IsAdministrator
if (-not $isAdministrator) {
    @($addButton, $editButton, $deleteButton, $applyButton, $applyAllButton, $removeButton) |
        ForEach-Object { $_.Enabled = $false }
    $descriptionLabel.Text += ' 当前为只读模式。'
}

if (Test-Path -LiteralPath $script:LogPath) {
    $previousLog = Get-Content -LiteralPath $script:LogPath -Tail 18 -Encoding UTF8
    if ($previousLog) { $logBox.Text = ($previousLog -join [Environment]::NewLine) + [Environment]::NewLine }
}

$form.Add_Shown({
    Write-AppLog -Message "程序启动；管理员=$isAdministrator"
    Refresh-Grid
    if ($UiSmokeTest) {
        $script:SmokeTimer = [Windows.Forms.Timer]::new()
        $script:SmokeTimer.Interval = 1200
        $script:SmokeTimer.Add_Tick({
            $script:SmokeTimer.Stop()
            $bitmap = [Drawing.Bitmap]::new($form.Width, $form.Height)
            try {
                $form.DrawToBitmap($bitmap, [Drawing.Rectangle]::new(0, 0, $bitmap.Width, $bitmap.Height))
                $bitmap.Save((Join-Path $script:AppRoot 'ui-smoke-test.png'), [Drawing.Imaging.ImageFormat]::Png)
            } finally {
                $bitmap.Dispose()
            }
            $form.Close()
        })
        $script:SmokeTimer.Start()
    }
})

[Windows.Forms.Application]::Run($form)
if ($UiSmokeTest) { 'UI_SMOKE_TEST_OK' }
