[CmdletBinding()]
param(
    [switch]$SelfTest,
    [switch]$DumpStatus,
    [switch]$UiSmokeTest,
    [ValidateSet('ListRules', 'Discover', 'SaveRule', 'ApplyRule', 'RemoveRule', 'TestRule')]
    [string]$Command,
    [string]$RuleId,
    [string]$RuleJson,
    [switch]$Approved
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

function Get-NetworkPolicyDiscovery {
    $snapshot = Get-SystemSnapshot
    $ipRows = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)

    $adapterRows = foreach ($adapter in $snapshot.Adapters) {
        $addresses = @($ipRows | Where-Object InterfaceIndex -eq $adapter.Index |
            ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
        [pscustomobject]@{
            Name = $adapter.Name
            Description = $adapter.Description
            Guid = $adapter.Guid
            Index = $adapter.Index
            Status = $adapter.Status
            Hardware = $adapter.Hardware
            IPv4 = @($addresses)
        }
    }

    $defaultRoutes = @($snapshot.Routes | Where-Object {
        $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -ne '0.0.0.0'
    } | Sort-Object RouteMetric | ForEach-Object {
        [pscustomobject]@{
            Destination = [string]$_.DestinationPrefix
            InterfaceIndex = [int]$_.InterfaceIndex
            InterfaceAlias = [string]$_.InterfaceAlias
            Gateway = [string]$_.NextHop
            Metric = [int]$_.RouteMetric
        }
    })

    $specificRoutes = @($snapshot.Routes | Where-Object {
        $_.DestinationPrefix -ne '0.0.0.0/0' -and
        $_.NextHop -ne '0.0.0.0' -and
        $_.DestinationPrefix -notlike '224.*' -and
        $_.DestinationPrefix -notlike '255.*'
    } | Sort-Object DestinationPrefix, InterfaceIndex, RouteMetric | ForEach-Object {
        $route = $_
        $prefix = ConvertTo-NormalizedPrefix -Value ([string]$route.DestinationPrefix)
        $matchedRule = $null
        foreach ($rule in $script:Rules) {
            try {
                if ((ConvertTo-NormalizedPrefix -Value ([string]$rule.Destination)) -ne $prefix) { continue }
                $adapter = Resolve-Adapter -Rule $rule -Adapters $snapshot.Adapters
                if ($adapter.Index -ne [int]$route.InterfaceIndex) { continue }
                $expectedGateway = Get-RuleGateway -Rule $rule -Adapter $adapter -Routes $snapshot.Routes
                if ($expectedGateway -ne [string]$route.NextHop) { continue }
                $matchedRule = $rule
                break
            } catch { }
        }
        $stateEntry = if ($null -eq $matchedRule) { $null } else { Get-StateEntry -Id ([string]$matchedRule.Id) }
        [pscustomobject]@{
            Destination = $prefix
            InterfaceIndex = [int]$route.InterfaceIndex
            InterfaceAlias = [string]$route.InterfaceAlias
            Gateway = [string]$route.NextHop
            Metric = [int]$route.RouteMetric
            Managed = $null -ne $matchedRule
            RuleId = if ($null -eq $matchedRule) { '' } else { [string]$matchedRule.Id }
            RuleName = if ($null -eq $matchedRule) { '' } else { [string]$matchedRule.Name }
            Owned = $null -ne $stateEntry -and [bool]$stateEntry.RouteOwned
        }
    })

    $proxyRows = foreach ($token in $snapshot.ProxyTokens) {
        $matchingRule = @($script:Rules | Where-Object {
            if (-not [bool]$_.BypassProxy) { return $false }
            try { (Get-ProxyTokenForRule -Rule $_) -eq $token } catch { $false }
        } | Select-Object -First 1)
        $actionable = Test-IPv4Address -Value ([string]$token)
        [pscustomobject]@{
            Token = [string]$token
            Actionable = [bool]$actionable
            Managed = $matchingRule.Count -gt 0
            RuleId = if ($matchingRule.Count -gt 0) { [string]$matchingRule[0].Id } else { '' }
        }
    }

    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o')
        Adapters = @($adapterRows)
        DefaultRoutes = @($defaultRoutes)
        SpecificRoutes = @($specificRoutes)
        ProxyBypass = @($proxyRows)
        UnmanagedSpecificRouteCount = @($specificRoutes | Where-Object { -not $_.Managed }).Count
        UnmanagedProxyBypassCount = @($proxyRows | Where-Object { $_.Actionable -and -not $_.Managed }).Count
    }
}

function Get-RuleById {
    param([Parameter(Mandatory)][string]$Id)
    $rule = @($script:Rules | Where-Object Id -eq $Id | Select-Object -First 1)
    if ($rule.Count -eq 0) { throw "找不到规则：$Id" }
    $rule[0]
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

if (-not [string]::IsNullOrWhiteSpace($Command)) {
    switch ($Command) {
        'ListRules' {
            @($script:Rules) | ConvertTo-Json -Depth 8
            exit 0
        }
        'Discover' {
            Get-NetworkPolicyDiscovery | ConvertTo-Json -Depth 8
            exit 0
        }
        'SaveRule' {
            if ([string]::IsNullOrWhiteSpace($RuleJson)) { throw 'SaveRule 需要 -RuleJson。' }
            $incoming = $RuleJson | ConvertFrom-Json
            $id = if ([string]::IsNullOrWhiteSpace([string]$incoming.Id)) { [Guid]::NewGuid().ToString('N') } else { [string]$incoming.Id }
            $rule = [pscustomobject]@{
                Id = $id
                Name = [string]$incoming.Name
                Destination = ConvertTo-NormalizedPrefix -Value ([string]$incoming.Destination)
                AdapterGuid = Get-NormalizedGuid -Value ([string]$incoming.AdapterGuid)
                AdapterDescription = [string]$incoming.AdapterDescription
                GatewayMode = if ([string]$incoming.GatewayMode -eq 'Auto') { 'Auto' } else { 'Manual' }
                Gateway = if ([string]$incoming.GatewayMode -eq 'Auto') { '' } else { [string]$incoming.Gateway }
                BypassProxy = [bool]$incoming.BypassProxy
                Enabled = if ($null -eq $incoming.Enabled) { $true } else { [bool]$incoming.Enabled }
                OwnExistingRoute = [bool]$incoming.OwnExistingRoute
                OwnExistingProxy = [bool]$incoming.OwnExistingProxy
            }
            $oldRules = @($script:Rules)
            try {
                $script:Rules = @($script:Rules | Where-Object Id -ne $id)
                $script:Rules += $rule
                Assert-Configuration
                Save-Rules
                Write-AppLog -Message "CLI 保存规则：$($rule.Name) | $($rule.Destination)"
                $rule | ConvertTo-Json -Depth 8
                exit 0
            } catch {
                $script:Rules = $oldRules
                throw
            }
        }
        'TestRule' {
            if ([string]::IsNullOrWhiteSpace($RuleId)) { throw 'TestRule 需要 -RuleId。' }
            Test-RulePolicy -Rule (Get-RuleById -Id $RuleId) | ConvertTo-Json -Depth 8
            exit 0
        }
        'ApplyRule' {
            if ([string]::IsNullOrWhiteSpace($RuleId)) { throw 'ApplyRule 需要 -RuleId。' }
            if (-not $Approved) { throw 'ApplyRule 会修改 Windows 路由/代理；需要显式传入 -Approved。' }
            $rule = Get-RuleById -Id $RuleId
            Apply-RulePolicy -Rule $rule
            Test-RulePolicy -Rule $rule | ConvertTo-Json -Depth 8
            exit 0
        }
        'RemoveRule' {
            if ([string]::IsNullOrWhiteSpace($RuleId)) { throw 'RemoveRule 需要 -RuleId。' }
            if (-not $Approved) { throw 'RemoveRule 会修改 Windows 路由/代理；需要显式传入 -Approved。' }
            $rule = Get-RuleById -Id $RuleId
            Remove-RulePolicy -Rule $rule
            [pscustomobject]@{ Removed = $true; RuleId = $RuleId } | ConvertTo-Json
            exit 0
        }
    }
}

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

# 美式复古主题：取自用户提供的配色参考图。
# 主色严格控制在 #1A1A1A / #CDA47B / #9F4125 / #382020，
# 仅补充少量同色系的暖白、暗面和边框色用于可读性。
$script:Theme = @{
    Background = [Drawing.Color]::FromArgb(26, 26, 26)      # #1A1A1A
    Surface = [Drawing.Color]::FromArgb(43, 31, 29)
    SurfaceAlt = [Drawing.Color]::FromArgb(56, 32, 32)      # #382020
    Accent = [Drawing.Color]::FromArgb(205, 164, 123)       # #CDA47B
    AccentStrong = [Drawing.Color]::FromArgb(159, 65, 37)   # #9F4125
    WarmText = [Drawing.Color]::FromArgb(244, 228, 209)
    MutedText = [Drawing.Color]::FromArgb(190, 158, 128)
    Border = [Drawing.Color]::FromArgb(92, 61, 50)
    DarkText = [Drawing.Color]::FromArgb(26, 26, 26)
}

function Set-UiInputTheme {
    param([Parameter(Mandatory)]$Control)

    $Control.BackColor = $script:Theme.Surface
    $Control.ForeColor = $script:Theme.WarmText
    if ($Control.PSObject.Properties.Name -contains 'BorderStyle') {
        try { $Control.BorderStyle = 'FixedSingle' } catch { }
    }
}

function Initialize-GridTheme {
    param([Parameter(Mandatory)][Windows.Forms.DataGridView]$Grid)

    $Grid.EnableHeadersVisualStyles = $false
    $Grid.BackgroundColor = $script:Theme.Background
    $Grid.BorderStyle = 'None'
    $Grid.GridColor = $script:Theme.Border
    $Grid.CellBorderStyle = 'SingleHorizontal'
    $Grid.ColumnHeadersBorderStyle = 'None'
    $Grid.ColumnHeadersHeight = 38
    $Grid.ColumnHeadersDefaultCellStyle.BackColor = $script:Theme.Accent
    $Grid.ColumnHeadersDefaultCellStyle.ForeColor = $script:Theme.DarkText
    $Grid.ColumnHeadersDefaultCellStyle.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9, [Drawing.FontStyle]::Bold)
    $Grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $script:Theme.Accent
    $Grid.ColumnHeadersDefaultCellStyle.SelectionForeColor = $script:Theme.DarkText
    $Grid.DefaultCellStyle.BackColor = $script:Theme.Surface
    $Grid.DefaultCellStyle.ForeColor = $script:Theme.WarmText
    $Grid.DefaultCellStyle.SelectionBackColor = $script:Theme.AccentStrong
    $Grid.DefaultCellStyle.SelectionForeColor = $script:Theme.WarmText
    $Grid.DefaultCellStyle.Padding = [Windows.Forms.Padding]::new(5, 3, 5, 3)
    $Grid.AlternatingRowsDefaultCellStyle.BackColor = $script:Theme.SurfaceAlt
    $Grid.RowTemplate.Height = 32
}

function New-UiButton {
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$Width = 100,
        [ValidateSet('Secondary', 'Primary', 'Accent', 'Danger')][string]$Variant = 'Secondary'
    )

    $button = [Windows.Forms.Button]::new()
    $button.Text = $Text
    $button.Width = $Width
    $button.Height = 34
    $button.Margin = [Windows.Forms.Padding]::new(4, 8, 4, 8)
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderSize = 1
    $button.UseVisualStyleBackColor = $false
    $button.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9, [Drawing.FontStyle]::Bold)

    switch ($Variant) {
        'Primary' {
            $button.BackColor = $script:Theme.AccentStrong
            $button.ForeColor = $script:Theme.WarmText
            $button.FlatAppearance.BorderColor = $script:Theme.AccentStrong
        }
        'Accent' {
            $button.BackColor = $script:Theme.Accent
            $button.ForeColor = $script:Theme.DarkText
            $button.FlatAppearance.BorderColor = $script:Theme.Accent
        }
        'Danger' {
            $button.BackColor = $script:Theme.SurfaceAlt
            $button.ForeColor = $script:Theme.Accent
            $button.FlatAppearance.BorderColor = $script:Theme.AccentStrong
        }
        default {
            $button.BackColor = $script:Theme.Background
            $button.ForeColor = $script:Theme.Accent
            $button.FlatAppearance.BorderColor = $script:Theme.Border
        }
    }
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
    $dialog.BackColor = $script:Theme.Background
    $dialog.ForeColor = $script:Theme.WarmText

    $labels = @('规则名称', '目标 IPv4 / CIDR', '指定网卡', '网关模式', '手动网关')
    for ($i = 0; $i -lt $labels.Count; $i++) {
        $label = [Windows.Forms.Label]::new()
        $label.Text = $labels[$i]
        $label.AutoSize = $true
        $label.ForeColor = $script:Theme.Accent
        $label.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9, [Drawing.FontStyle]::Bold)
        $label.Location = [Drawing.Point]::new(28, 32 + ($i * 58))
        $dialog.Controls.Add($label)
    }

    $nameBox = [Windows.Forms.TextBox]::new()
    $nameBox.Location = [Drawing.Point]::new(170, 28)
    $nameBox.Size = [Drawing.Size]::new(410, 26)
    Set-UiInputTheme -Control $nameBox
    $dialog.Controls.Add($nameBox)

    $destinationBox = [Windows.Forms.TextBox]::new()
    $destinationBox.Location = [Drawing.Point]::new(170, 86)
    $destinationBox.Size = [Drawing.Size]::new(410, 26)
    Set-UiInputTheme -Control $destinationBox
    $dialog.Controls.Add($destinationBox)

    $adapterBox = [Windows.Forms.ComboBox]::new()
    $adapterBox.Location = [Drawing.Point]::new(170, 144)
    $adapterBox.Size = [Drawing.Size]::new(410, 28)
    $adapterBox.DropDownStyle = 'DropDownList'
    $adapterBox.DisplayMember = 'Display'
    Set-UiInputTheme -Control $adapterBox
    $adapters = Get-Adapters
    foreach ($adapter in $adapters) { [void]$adapterBox.Items.Add($adapter) }
    $dialog.Controls.Add($adapterBox)

    $gatewayModeBox = [Windows.Forms.ComboBox]::new()
    $gatewayModeBox.Location = [Drawing.Point]::new(170, 202)
    $gatewayModeBox.Size = [Drawing.Size]::new(410, 28)
    $gatewayModeBox.DropDownStyle = 'DropDownList'
    Set-UiInputTheme -Control $gatewayModeBox
    [void]$gatewayModeBox.Items.Add('自动使用该网卡当前默认网关')
    [void]$gatewayModeBox.Items.Add('手动指定网关')
    $dialog.Controls.Add($gatewayModeBox)

    $gatewayBox = [Windows.Forms.TextBox]::new()
    $gatewayBox.Location = [Drawing.Point]::new(170, 260)
    $gatewayBox.Size = [Drawing.Size]::new(410, 26)
    Set-UiInputTheme -Control $gatewayBox
    $dialog.Controls.Add($gatewayBox)

    $bypassCheck = [Windows.Forms.CheckBox]::new()
    $bypassCheck.Text = '同时绕过 Windows 系统代理（仅单个 IPv4）'
    $bypassCheck.AutoSize = $true
    $bypassCheck.ForeColor = $script:Theme.MutedText
    $bypassCheck.Location = [Drawing.Point]::new(170, 312)
    $dialog.Controls.Add($bypassCheck)

    $enabledCheck = [Windows.Forms.CheckBox]::new()
    $enabledCheck.Text = '启用此规则'
    $enabledCheck.AutoSize = $true
    $enabledCheck.ForeColor = $script:Theme.MutedText
    $enabledCheck.Location = [Drawing.Point]::new(170, 344)
    $enabledCheck.Checked = $true
    $dialog.Controls.Add($enabledCheck)

    $saveButton = New-UiButton -Text '保存' -Width 92 -Variant 'Primary'
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

function Show-DiscoveryDialog {
    $discovery = Get-NetworkPolicyDiscovery
    $dialog = [Windows.Forms.Form]::new()
    $dialog.Text = '自动识别当前网络策略'
    $dialog.ClientSize = [Drawing.Size]::new(1120, 700)
    $dialog.MinimumSize = [Drawing.Size]::new(940, 600)
    $dialog.StartPosition = 'CenterParent'
    $dialog.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
    $dialog.BackColor = $script:Theme.Background
    $dialog.ForeColor = $script:Theme.WarmText

    $hero = [Windows.Forms.Panel]::new()
    $hero.Dock = 'Top'
    $hero.Height = 88
    $hero.BackColor = $script:Theme.Background
    $dialog.Controls.Add($hero)

    $heroBar = [Windows.Forms.Panel]::new()
    $heroBar.BackColor = $script:Theme.AccentStrong
    $heroBar.Location = [Drawing.Point]::new(16, 15)
    $heroBar.Size = [Drawing.Size]::new(6, 56)
    $hero.Controls.Add($heroBar)

    $heroTitle = [Windows.Forms.Label]::new()
    $heroTitle.Text = '当前网络策略识别'
    $heroTitle.Font = [Drawing.Font]::new('Microsoft YaHei UI', 15, [Drawing.FontStyle]::Bold)
    $heroTitle.ForeColor = $script:Theme.Accent
    $heroTitle.AutoSize = $true
    $heroTitle.Location = [Drawing.Point]::new(34, 11)
    $hero.Controls.Add($heroTitle)

    $heroText = [Windows.Forms.Label]::new()
    $heroText.Text = "识别到 $($discovery.Adapters.Count) 张网卡 · $($discovery.DefaultRoutes.Count) 条默认路由 · $($discovery.SpecificRoutes.Count) 条特定路由；未管理 $($discovery.UnmanagedSpecificRouteCount) 条。自动识别仅查看，接管已有策略必须由你确认。"
    $heroText.ForeColor = $script:Theme.MutedText
    $heroText.AutoSize = $true
    $heroText.MaximumSize = [Drawing.Size]::new(1020, 0)
    $heroText.Location = [Drawing.Point]::new(35, 48)
    $hero.Controls.Add($heroText)

    $buttons = [Windows.Forms.FlowLayoutPanel]::new()
    $buttons.Dock = 'Bottom'
    $buttons.Height = 58
    $buttons.Padding = [Windows.Forms.Padding]::new(8, 4, 12, 4)
    $buttons.FlowDirection = 'RightToLeft'
    $buttons.BackColor = $script:Theme.Background
    $dialog.Controls.Add($buttons)

    $tabs = [Windows.Forms.TabControl]::new()
    $tabs.Dock = 'Fill'
    $tabs.DrawMode = 'OwnerDrawFixed'
    $tabs.SizeMode = 'Fixed'
    $tabs.ItemSize = [Drawing.Size]::new(150, 34)
    $tabs.Padding = [Drawing.Point]::new(16, 5)
    $dialog.Controls.Add($tabs)

    $tabs.Add_DrawItem({
        param($sender, $eventArgs)
        $tab = $sender.TabPages[$eventArgs.Index]
        $selected = $eventArgs.Index -eq $sender.SelectedIndex
        $back = if ($selected) { $script:Theme.Accent } else { $script:Theme.SurfaceAlt }
        $fore = if ($selected) { $script:Theme.DarkText } else { $script:Theme.Accent }
        $eventArgs.Graphics.FillRectangle([Drawing.SolidBrush]::new($back), $eventArgs.Bounds)
        $font = [Drawing.Font]::new('Microsoft YaHei UI', 9, [Drawing.FontStyle]::Bold)
        $flags = [Drawing.StringFormat]::new()
        $flags.Alignment = 'Center'
        $flags.LineAlignment = 'Center'
        $eventArgs.Graphics.DrawString($tab.Text, $font, [Drawing.SolidBrush]::new($fore), $eventArgs.Bounds, $flags)
        $font.Dispose()
        $flags.Dispose()
    })

    $routeTab = [Windows.Forms.TabPage]::new()
    $routeTab.Text = "特定路由  $($discovery.SpecificRoutes.Count)"
    $routeTab.BackColor = $script:Theme.Background
    $tabs.TabPages.Add($routeTab)

    $adapterTab = [Windows.Forms.TabPage]::new()
    $adapterTab.Text = "网卡概览  $($discovery.Adapters.Count)"
    $adapterTab.BackColor = $script:Theme.Background
    $tabs.TabPages.Add($adapterTab)

    $proxyTab = [Windows.Forms.TabPage]::new()
    $proxyTab.Text = "代理绕过  $($discovery.ProxyBypass.Count)"
    $proxyTab.BackColor = $script:Theme.Background
    $tabs.TabPages.Add($proxyTab)

    $grid = [Windows.Forms.DataGridView]::new()
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.RowHeadersVisible = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $false
    $grid.AutoGenerateColumns = $false
    Initialize-GridTheme -Grid $grid
    $routeTab.Controls.Add($grid)

    foreach ($spec in @(
        @('Managed','管理状态',95),
        @('Destination','目标 IPv4 / CIDR',175),
        @('Adapter','实际网卡',210),
        @('Gateway','下一跳',150),
        @('Metric','Metric',72),
        @('RuleName','匹配规则',260)
    )) {
        $column = [Windows.Forms.DataGridViewTextBoxColumn]::new()
        $column.Name = $spec[0]
        $column.HeaderText = $spec[1]
        $column.Width = [int]$spec[2]
        if ($spec[0] -eq 'RuleName') { $column.AutoSizeMode = 'Fill' }
        [void]$grid.Columns.Add($column)
    }

    foreach ($route in $discovery.SpecificRoutes) {
        $stateText = if ($route.Managed) {
            if ($route.Owned) { '已接管' } else { '已匹配' }
        } else { '未管理' }
        $index = $grid.Rows.Add(
            $stateText,
            [string]$route.Destination,
            [string]$route.InterfaceAlias,
            [string]$route.Gateway,
            [string]$route.Metric,
            [string]$route.RuleName
        )
        $row = $grid.Rows[$index]
        $row.Tag = $route
        if ($route.Owned) {
            $row.DefaultCellStyle.BackColor = $script:Theme.SurfaceAlt
            $row.DefaultCellStyle.ForeColor = $script:Theme.Accent
        } elseif ($route.Managed) {
            $row.DefaultCellStyle.BackColor = $script:Theme.Surface
            $row.DefaultCellStyle.ForeColor = $script:Theme.WarmText
        } else {
            $row.DefaultCellStyle.BackColor = $script:Theme.Accent
            $row.DefaultCellStyle.ForeColor = $script:Theme.DarkText
        }
    }

    $adapterGrid = [Windows.Forms.DataGridView]::new()
    $adapterGrid.Dock = 'Fill'
    $adapterGrid.ReadOnly = $true
    $adapterGrid.AllowUserToAddRows = $false
    $adapterGrid.AllowUserToDeleteRows = $false
    $adapterGrid.AllowUserToResizeRows = $false
    $adapterGrid.RowHeadersVisible = $false
    $adapterGrid.SelectionMode = 'FullRowSelect'
    $adapterGrid.MultiSelect = $false
    $adapterGrid.AutoGenerateColumns = $false
    Initialize-GridTheme -Grid $adapterGrid
    $adapterTab.Controls.Add($adapterGrid)

    foreach ($spec in @(
        @('Status','状态',82),
        @('Name','网卡名称',150),
        @('Description','硬件 / 驱动描述',300),
        @('IPv4','IPv4',210),
        @('Gateway','默认网关',150),
        @('Guid','硬件 GUID',260)
    )) {
        $column = [Windows.Forms.DataGridViewTextBoxColumn]::new()
        $column.Name = $spec[0]
        $column.HeaderText = $spec[1]
        $column.Width = [int]$spec[2]
        if ($spec[0] -eq 'Guid') { $column.AutoSizeMode = 'Fill' }
        [void]$adapterGrid.Columns.Add($column)
    }

    foreach ($adapter in $discovery.Adapters) {
        $defaultForAdapter = @($discovery.DefaultRoutes | Where-Object InterfaceIndex -eq ([int]$adapter.Index))
        $gatewayText = if ($defaultForAdapter.Count -gt 0) {
            ($defaultForAdapter | ForEach-Object Gateway) -join ' / '
        } else { '—' }
        $rowIndex = $adapterGrid.Rows.Add(
            [string]$adapter.Status,
            [string]$adapter.Name,
            [string]$adapter.Description,
            (@($adapter.IPv4) -join ' / '),
            $gatewayText,
            [string]$adapter.Guid
        )
        if ([string]$adapter.Status -eq 'Up') {
            $adapterGrid.Rows[$rowIndex].DefaultCellStyle.ForeColor = $script:Theme.Accent
        }
    }

    $proxyGrid = [Windows.Forms.DataGridView]::new()
    $proxyGrid.Dock = 'Fill'
    $proxyGrid.ReadOnly = $true
    $proxyGrid.AllowUserToAddRows = $false
    $proxyGrid.AllowUserToDeleteRows = $false
    $proxyGrid.AllowUserToResizeRows = $false
    $proxyGrid.RowHeadersVisible = $false
    $proxyGrid.SelectionMode = 'FullRowSelect'
    $proxyGrid.MultiSelect = $false
    $proxyGrid.AutoGenerateColumns = $false
    Initialize-GridTheme -Grid $proxyGrid
    $proxyTab.Controls.Add($proxyGrid)

    foreach ($spec in @(
        @('Token','代理绕过项',360),
        @('Type','可作为 IPv4 规则',150),
        @('Managed','管理状态',130),
        @('RuleId','匹配规则 ID',320)
    )) {
        $column = [Windows.Forms.DataGridViewTextBoxColumn]::new()
        $column.Name = $spec[0]
        $column.HeaderText = $spec[1]
        $column.Width = [int]$spec[2]
        if ($spec[0] -eq 'RuleId') { $column.AutoSizeMode = 'Fill' }
        [void]$proxyGrid.Columns.Add($column)
    }

    foreach ($proxy in $discovery.ProxyBypass) {
        $rowIndex = $proxyGrid.Rows.Add(
            [string]$proxy.Token,
            $(if ($proxy.Actionable) { '是' } else { '否' }),
            $(if ($proxy.Managed) { '已匹配' } else { '未管理' }),
            [string]$proxy.RuleId
        )
        if ($proxy.Actionable -and -not $proxy.Managed) {
            $proxyGrid.Rows[$rowIndex].DefaultCellStyle.BackColor = $script:Theme.Accent
            $proxyGrid.Rows[$rowIndex].DefaultCellStyle.ForeColor = $script:Theme.DarkText
        }
    }

    $closeButton = New-UiButton -Text '关闭' -Width 88
    $importButton = New-UiButton -Text '仅导入规则' -Width 108 -Variant 'Accent'
    $adoptButton = New-UiButton -Text '导入并接管' -Width 112 -Variant 'Primary'
    $buttons.Controls.Add($closeButton)
    $buttons.Controls.Add($adoptButton)
    $buttons.Controls.Add($importButton)

    $closeButton.Add_Click({ $dialog.Close() })

    $importRoute = {
        param([bool]$TakeOwnership)
        if ($grid.SelectedRows.Count -eq 0) {
            [Windows.Forms.MessageBox]::Show('请先在“特定路由”页选择一条路由。', '提示', 'OK', 'Information') | Out-Null
            return
        }
        $route = $grid.SelectedRows[0].Tag
        if ($route.Managed) {
            [Windows.Forms.MessageBox]::Show('该路由已经匹配现有规则，无需重复导入。', '提示', 'OK', 'Information') | Out-Null
            return
        }
        $adapter = @(Get-Adapters | Where-Object Index -eq ([int]$route.InterfaceIndex) | Select-Object -First 1)
        if ($adapter.Count -eq 0) {
            [Windows.Forms.MessageBox]::Show('无法识别该路由对应的网卡。', '导入失败', 'OK', 'Error') | Out-Null
            return
        }
        $proxyToken = ([string]$route.Destination).Split('/')[0]
        $bypass = ([string]$route.Destination).EndsWith('/32') -and $proxyToken -in @(Get-ProxyTokens)
        $newRule = [pscustomobject]@{
            Id = [Guid]::NewGuid().ToString('N')
            Name = "识别导入 - $($route.Destination)"
            Destination = [string]$route.Destination
            AdapterGuid = [string]$adapter[0].Guid
            AdapterDescription = [string]$adapter[0].Description
            GatewayMode = 'Manual'
            Gateway = [string]$route.Gateway
            BypassProxy = [bool]$bypass
            Enabled = $true
            OwnExistingRoute = [bool]$TakeOwnership
            OwnExistingProxy = [bool]($TakeOwnership -and $bypass)
        }
        $oldRules = @($script:Rules)
        try {
            $script:Rules += $newRule
            Assert-Configuration
            Save-Rules
            Write-AppLog -Message "从当前系统导入规则：$($newRule.Name)；接管=$TakeOwnership"
            [Windows.Forms.MessageBox]::Show(
                $(if ($TakeOwnership) {
                    '已导入并接管。以后撤销此规则时，本程序可以删除对应路由。'
                } else {
                    '已导入为规则，但保留为外部已有策略；撤销规则不会主动删除原有路由。'
                }),
                '导入完成', 'OK', 'Information') | Out-Null
            $dialog.Close()
            Refresh-Grid
        } catch {
            $script:Rules = $oldRules
            [Windows.Forms.MessageBox]::Show($_.Exception.Message, '导入失败', 'OK', 'Error') | Out-Null
        }
    }

    $importButton.Add_Click({ & $importRoute $false })
    $adoptButton.Add_Click({
        $answer = [Windows.Forms.MessageBox]::Show(
            '接管意味着本程序取得该已有路由的管理权；以后撤销规则时可以删除它。确定继续吗？',
            '确认接管现有策略', 'YesNo', 'Warning')
        if ($answer -eq 'Yes') { & $importRoute $true }
    })

    [void]$dialog.ShowDialog($form)
}

$form = [Windows.Forms.Form]::new()
$form.Text = '本地网络策略管理器'
$form.StartPosition = 'CenterScreen'
$form.Size = [Drawing.Size]::new(1320, 820)
$form.MinimumSize = [Drawing.Size]::new(1080, 680)
$form.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
$form.AutoScaleMode = 'Dpi'
$form.BackColor = $script:Theme.Background
$form.ForeColor = $script:Theme.WarmText

$header = [Windows.Forms.Panel]::new()
$header.Dock = 'Top'
$header.Height = 100
$header.BackColor = $script:Theme.Background
$form.Controls.Add($header)

$accentStrip = [Windows.Forms.Panel]::new()
$accentStrip.BackColor = $script:Theme.AccentStrong
$accentStrip.Location = [Drawing.Point]::new(18, 17)
$accentStrip.Size = [Drawing.Size]::new(6, 66)
$header.Controls.Add($accentStrip)

$eyebrowLabel = [Windows.Forms.Label]::new()
$eyebrowLabel.Text = 'LOCAL NETWORK POLICY'
$eyebrowLabel.Font = [Drawing.Font]::new('Segoe UI', 8, [Drawing.FontStyle]::Bold)
$eyebrowLabel.ForeColor = $script:Theme.AccentStrong
$eyebrowLabel.AutoSize = $true
$eyebrowLabel.Location = [Drawing.Point]::new(36, 13)
$header.Controls.Add($eyebrowLabel)

$titleLabel = [Windows.Forms.Label]::new()
$titleLabel.Text = '本地网络策略管理器'
$titleLabel.Font = [Drawing.Font]::new('Microsoft YaHei UI', 19, [Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = $script:Theme.Accent
$titleLabel.AutoSize = $true
$titleLabel.Location = [Drawing.Point]::new(34, 31)
$header.Controls.Add($titleLabel)

$descriptionLabel = [Windows.Forms.Label]::new()
$descriptionLabel.Text = '启动自动识别当前策略 · 精确 IPv4/CIDR 分流 · 不修改默认路由、IP、DHCP 或网卡跃点'
$descriptionLabel.ForeColor = $script:Theme.MutedText
$descriptionLabel.AutoSize = $true
$descriptionLabel.Location = [Drawing.Point]::new(37, 70)
$header.Controls.Add($descriptionLabel)

$summaryLabel = [Windows.Forms.Label]::new()
$summaryLabel.Anchor = 'Top,Right'
$summaryLabel.TextAlign = 'MiddleRight'
$summaryLabel.ForeColor = $script:Theme.Accent
$summaryLabel.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9, [Drawing.FontStyle]::Bold)
$summaryLabel.Location = [Drawing.Point]::new(815, 20)
$summaryLabel.Size = [Drawing.Size]::new(470, 58)
$header.Controls.Add($summaryLabel)

$toolbar = [Windows.Forms.FlowLayoutPanel]::new()
$toolbar.Dock = 'Top'
$toolbar.Height = 58
$toolbar.Padding = [Windows.Forms.Padding]::new(12, 3, 8, 3)
$toolbar.WrapContents = $false
$toolbar.BackColor = $script:Theme.SurfaceAlt
$form.Controls.Add($toolbar)

$discoverButton = New-UiButton -Text '识别当前策略' -Width 118 -Variant 'Accent'
$addButton = New-UiButton -Text '新增规则' -Width 96
$editButton = New-UiButton -Text '修改规则' -Width 96
$applyButton = New-UiButton -Text '应用所选' -Width 96 -Variant 'Primary'
$applyAllButton = New-UiButton -Text '应用全部' -Width 96 -Variant 'Primary'
$testButton = New-UiButton -Text '测试所选' -Width 96
$refreshButton = New-UiButton -Text '刷新状态' -Width 96
$removeButton = New-UiButton -Text '撤销所选' -Width 96 -Variant 'Danger'
$deleteButton = New-UiButton -Text '删除规则' -Width 96 -Variant 'Danger'
@($discoverButton, $addButton, $editButton, $applyButton, $applyAllButton,
    $testButton, $refreshButton, $removeButton, $deleteButton) | ForEach-Object { $toolbar.Controls.Add($_) }

$logBox = [Windows.Forms.RichTextBox]::new()
$logBox.Dock = 'Bottom'
$logBox.Height = 128
$logBox.ReadOnly = $true
$logBox.BackColor = $script:Theme.SurfaceAlt
$logBox.ForeColor = $script:Theme.Accent
$logBox.BorderStyle = 'None'
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
$grid.AutoSizeRowsMode = 'AllCells'
$grid.DefaultCellStyle.WrapMode = 'False'
Initialize-GridTheme -Grid $grid
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
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 100))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 58))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 128))
$layout.BackColor = $script:Theme.Background
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
                'Green' {
                    $row.DefaultCellStyle.BackColor = $script:Theme.SurfaceAlt
                    $row.DefaultCellStyle.ForeColor = $script:Theme.Accent
                }
                'Orange' {
                    $row.DefaultCellStyle.BackColor = $script:Theme.Accent
                    $row.DefaultCellStyle.ForeColor = $script:Theme.DarkText
                }
                'Red' {
                    $row.DefaultCellStyle.BackColor = $script:Theme.AccentStrong
                    $row.DefaultCellStyle.ForeColor = $script:Theme.WarmText
                }
                default {
                    $row.DefaultCellStyle.BackColor = $script:Theme.Surface
                    $row.DefaultCellStyle.ForeColor = $script:Theme.MutedText
                }
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
$discoverButton.Add_Click({ Show-DiscoveryDialog })

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
    try {
        $discovery = Get-NetworkPolicyDiscovery
        Write-AppLog -Message "自动识别完成：特定目标路由=$($discovery.SpecificRoutes.Count)，未管理=$($discovery.UnmanagedSpecificRouteCount)，代理绕过未管理=$($discovery.UnmanagedProxyBypassCount)"
        if (-not $UiSmokeTest -and ($discovery.UnmanagedSpecificRouteCount -gt 0 -or $discovery.UnmanagedProxyBypassCount -gt 0)) {
            $form.BeginInvoke([Action]{ Show-DiscoveryDialog }) | Out-Null
        }
    } catch {
        Write-AppLog -Message ("自动识别失败：" + $_.Exception.Message) -Level 'WARN'
    }
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
