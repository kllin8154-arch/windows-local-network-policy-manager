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
    param([object]$Snapshot = $null)

    $snapshot = if ($null -eq $Snapshot) { Get-SystemSnapshot } else { $Snapshot }
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
    $prefix = ConvertTo-NormalizedPrefix -Value ([string]$Rule.Destination)
    $parts = $prefix.Split('/')
    $testAddress = [string]$parts[0]
    $selected = Find-NetRoute -RemoteIPAddress $testAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } |
        Select-Object -First 1

    $adapter = $null
    $expectedGateway = ''
    try {
        $adapter = Resolve-Adapter -Rule $Rule -Adapters $snapshot.Adapters
        $expectedGateway = Get-RuleGateway -Rule $Rule -Adapter $adapter -Routes $snapshot.Routes
    } catch { }

    $proxyToken = ''
    $proxyPresent = $false
    if ([bool]$Rule.BypassProxy) {
        try {
            $proxyToken = Get-ProxyTokenForRule -Rule $Rule
            $proxyPresent = $proxyToken -in $snapshot.ProxyTokens
        } catch { }
    }

    $state = Get-StateEntry -Id ([string]$Rule.Id)
    $routeMatches = $null -ne $selected -and $null -ne $adapter -and
        [int]$selected.InterfaceIndex -eq [int]$adapter.Index -and
        [string]$selected.NextHop -eq [string]$expectedGateway
    $healthy = $status.State -eq 'Applied' -and $routeMatches -and
        (-not [bool]$Rule.BypassProxy -or $proxyPresent)

    [pscustomobject]@{
        Id = [string]$Rule.Id
        Name = [string]$Rule.Name
        Destination = $prefix
        Healthy = [bool]$healthy
        StatusCode = [string]$status.State
        Status = [string]$status.Text
        ExpectedAdapter = if ($null -eq $adapter) { [string]$Rule.AdapterDescription } else { [string]$adapter.Name }
        AdapterStatus = if ($null -eq $adapter) { 'Unavailable' } else { [string]$adapter.Status }
        ExpectedGateway = [string]$expectedGateway
        SelectedAdapter = if ($null -eq $selected) { '无可用路由' } else { [string]$selected.InterfaceAlias }
        MatchedRoute = if ($null -eq $selected) { '' } else { [string]$selected.DestinationPrefix }
        NextHop = if ($null -eq $selected) { '' } else { [string]$selected.NextHop }
        RouteMatches = [bool]$routeMatches
        ProxyBypassExpected = [bool]$Rule.BypassProxy
        ProxyBypassToken = [string]$proxyToken
        ProxyBypassPresent = [bool]$proxyPresent
        ManagedStatePresent = $null -ne $state
        RouteOwned = $null -ne $state -and [bool]$state.RouteOwned
        ProxyOwned = $null -ne $state -and [bool]$state.ProxyOwned
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
    $grid.MultiSelect = $true
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

    foreach ($route in @($discovery.SpecificRoutes | Sort-Object @{ Expression = { if ($_.Managed) { 1 } else { 0 } } }, Destination)) {
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
    $exportButton = New-UiButton -Text '导出诊断快照' -Width 118
    $importButton = New-UiButton -Text '导入所选' -Width 100 -Variant 'Accent'
    $adoptButton = New-UiButton -Text '导入并接管' -Width 112 -Variant 'Primary'
    $buttons.Controls.Add($closeButton)
    $buttons.Controls.Add($exportButton)
    $buttons.Controls.Add($adoptButton)
    $buttons.Controls.Add($importButton)

    $closeButton.Add_Click({ $dialog.Close() })

    $exportButton.Add_Click({
        try {
            $save = [Windows.Forms.SaveFileDialog]::new()
            $save.Title = '导出当前网络诊断快照'
            $save.Filter = 'JSON 文件 (*.json)|*.json'
            $save.FileName = 'network-policy-snapshot-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'
            if ($save.ShowDialog($dialog) -eq 'OK') {
                $discovery | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $save.FileName -Encoding UTF8
                Write-AppLog -Message "已导出网络诊断快照：$($save.FileName)"
            }
        } catch {
            [Windows.Forms.MessageBox]::Show($_.Exception.Message, '导出失败', 'OK', 'Error') | Out-Null
        }
    })

    $importRoutes = {
        param([bool]$TakeOwnership)

        $selectedRoutes = @(
            $grid.SelectedRows |
                ForEach-Object { $_.Tag } |
                Where-Object { $null -ne $_ -and -not $_.Managed }
        )
        if ($selectedRoutes.Count -eq 0) {
            [Windows.Forms.MessageBox]::Show(
                '请在“特定路由”页选择至少一条“未管理”的路由。可按 Ctrl / Shift 多选。',
                '提示', 'OK', 'Information') | Out-Null
            return
        }

        $oldRules = @($script:Rules)
        $added = [Collections.Generic.List[string]]::new()
        $skipped = [Collections.Generic.List[string]]::new()
        try {
            $adapters = Get-Adapters
            $proxyTokens = @(Get-ProxyTokens)

            foreach ($route in $selectedRoutes) {
                $prefix = ConvertTo-NormalizedPrefix -Value ([string]$route.Destination)
                $alreadyDefined = @($script:Rules | Where-Object {
                    (ConvertTo-NormalizedPrefix -Value ([string]$_.Destination)) -eq $prefix
                }).Count -gt 0
                if ($alreadyDefined) {
                    $skipped.Add("$prefix：已有规则定义")
                    continue
                }

                $adapter = @($adapters | Where-Object Index -eq ([int]$route.InterfaceIndex) | Select-Object -First 1)
                if ($adapter.Count -eq 0) {
                    $skipped.Add("$prefix：无法识别对应网卡")
                    continue
                }

                $proxyToken = $prefix.Split('/')[0]
                $bypass = $prefix.EndsWith('/32') -and $proxyToken -in $proxyTokens
                $newRule = [pscustomobject]@{
                    Id = [Guid]::NewGuid().ToString('N')
                    Name = "识别导入 - $prefix"
                    Destination = $prefix
                    AdapterGuid = [string]$adapter[0].Guid
                    AdapterDescription = [string]$adapter[0].Description
                    GatewayMode = 'Manual'
                    Gateway = [string]$route.Gateway
                    BypassProxy = [bool]$bypass
                    Enabled = $true
                    OwnExistingRoute = [bool]$TakeOwnership
                    OwnExistingProxy = [bool]($TakeOwnership -and $bypass)
                }
                $script:Rules += $newRule
                $added.Add($prefix)
            }

            if ($added.Count -eq 0) {
                $script:Rules = $oldRules
                [Windows.Forms.MessageBox]::Show(
                    "没有可导入的规则。" + [Environment]::NewLine + ($skipped -join [Environment]::NewLine),
                    '未导入', 'OK', 'Information') | Out-Null
                return
            }

            Assert-Configuration
            Save-Rules
            Write-AppLog -Message "从当前系统批量导入 $($added.Count) 条规则；接管=$TakeOwnership"

            $message = "已导入 $($added.Count) 条规则。"
            if ($TakeOwnership) {
                $message += [Environment]::NewLine + '这些已有路由现在由本程序接管，后续撤销时可以删除。'
            } else {
                $message += [Environment]::NewLine + '仅保存规则定义，不取得已有路由所有权。'
            }
            if ($skipped.Count -gt 0) {
                $message += [Environment]::NewLine + [Environment]::NewLine +
                    "跳过 $($skipped.Count) 条：" + [Environment]::NewLine + ($skipped -join [Environment]::NewLine)
            }
            [Windows.Forms.MessageBox]::Show($message, '导入完成', 'OK', 'Information') | Out-Null
            $dialog.Close()
            Refresh-Grid
        } catch {
            $script:Rules = $oldRules
            [Windows.Forms.MessageBox]::Show($_.Exception.Message, '导入失败', 'OK', 'Error') | Out-Null
        }
    }

    $importButton.Add_Click({ & $importRoutes $false })
    $adoptButton.Add_Click({
        $count = @($grid.SelectedRows | ForEach-Object { $_.Tag } | Where-Object { $null -ne $_ -and -not $_.Managed }).Count
        if ($count -eq 0) {
            [Windows.Forms.MessageBox]::Show('请先选择未管理路由。', '提示', 'OK', 'Information') | Out-Null
            return
        }
        $answer = [Windows.Forms.MessageBox]::Show(
            "将接管所选 $count 条已有路由。以后撤销对应规则时，本程序可以删除这些路由。确定继续吗？",
            '确认接管现有策略', 'YesNo', 'Warning')
        if ($answer -eq 'Yes') { & $importRoutes $true }
    })

    [void]$dialog.ShowDialog($form)
}

$form = [Windows.Forms.Form]::new()
$form.Text = '本地网络策略管理器'
$form.StartPosition = 'CenterScreen'
$form.Size = [Drawing.Size]::new(1380, 860)
$form.MinimumSize = [Drawing.Size]::new(1120, 700)
$form.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
$form.AutoScaleMode = 'Dpi'
$form.BackColor = $script:Theme.Background
$form.ForeColor = $script:Theme.WarmText
$form.KeyPreview = $true

$header = [Windows.Forms.Panel]::new()
$header.Dock = 'Fill'
$header.BackColor = $script:Theme.Background

$accentStrip = [Windows.Forms.Panel]::new()
$accentStrip.BackColor = $script:Theme.AccentStrong
$accentStrip.Location = [Drawing.Point]::new(18, 17)
$accentStrip.Size = [Drawing.Size]::new(6, 68)
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
$descriptionLabel.Text = '自动识别当前网络 · 精确 IPv4/CIDR 分流 · 先看清现状，再决定是否接管'
$descriptionLabel.ForeColor = $script:Theme.MutedText
$descriptionLabel.AutoSize = $true
$descriptionLabel.Location = [Drawing.Point]::new(37, 72)
$header.Controls.Add($descriptionLabel)

$summaryLabel = [Windows.Forms.Label]::new()
$summaryLabel.Anchor = 'Top,Right'
$summaryLabel.TextAlign = 'MiddleRight'
$summaryLabel.ForeColor = $script:Theme.Accent
$summaryLabel.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9, [Drawing.FontStyle]::Bold)
$summaryLabel.Location = [Drawing.Point]::new(855, 21)
$summaryLabel.Size = [Drawing.Size]::new(490, 58)
$header.Controls.Add($summaryLabel)

function New-MetricCard {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Value,
        [int]$Width = 305
    )
    $panel = [Windows.Forms.Panel]::new()
    $panel.Width = $Width
    $panel.Height = 68
    $panel.Margin = [Windows.Forms.Padding]::new(7, 7, 7, 5)
    $panel.BackColor = $script:Theme.SurfaceAlt

    $titleLabel = [Windows.Forms.Label]::new()
    $titleLabel.Text = $Title
    $titleLabel.ForeColor = $script:Theme.MutedText
    $titleLabel.Font = [Drawing.Font]::new('Microsoft YaHei UI', 8, [Drawing.FontStyle]::Bold)
    $titleLabel.AutoSize = $true
    $titleLabel.Location = [Drawing.Point]::new(14, 10)
    $panel.Controls.Add($titleLabel)

    $valueLabel = [Windows.Forms.Label]::new()
    $valueLabel.Text = $Value
    $valueLabel.ForeColor = $script:Theme.Accent
    $valueLabel.Font = [Drawing.Font]::new('Microsoft YaHei UI', 11, [Drawing.FontStyle]::Bold)
    $valueLabel.AutoEllipsis = $true
    $valueLabel.Location = [Drawing.Point]::new(13, 31)
    $valueLabel.Size = [Drawing.Size]::new($Width - 26, 25)
    $panel.Controls.Add($valueLabel)

    [pscustomobject]@{ Panel = $panel; Value = $valueLabel; Title = $titleLabel }
}

$metrics = [Windows.Forms.FlowLayoutPanel]::new()
$metrics.Dock = 'Fill'
$metrics.WrapContents = $false
$metrics.Padding = [Windows.Forms.Padding]::new(7, 0, 7, 0)
$metrics.BackColor = $script:Theme.Background

$ruleMetric = New-MetricCard -Title '规则状态' -Value '正在读取…'
$adapterMetric = New-MetricCard -Title '已连接实体网卡' -Value '正在识别…'
$routeMetric = New-MetricCard -Title '当前默认出口' -Value '正在识别…'
$pendingMetric = New-MetricCard -Title '待处理现有策略' -Value '正在识别…'
@($ruleMetric, $adapterMetric, $routeMetric, $pendingMetric) | ForEach-Object {
    [void]$metrics.Controls.Add($_.Panel)
}

$toolbar = [Windows.Forms.FlowLayoutPanel]::new()
$toolbar.Dock = 'Fill'
$toolbar.Height = 60
$toolbar.Padding = [Windows.Forms.Padding]::new(12, 4, 8, 4)
$toolbar.WrapContents = $false
$toolbar.BackColor = $script:Theme.SurfaceAlt

$discoverButton = New-UiButton -Text '识别当前策略' -Width 118 -Variant 'Accent'
$addButton = New-UiButton -Text '新增规则' -Width 92
$applyAllButton = New-UiButton -Text '应用全部' -Width 92 -Variant 'Primary'
$refreshButton = New-UiButton -Text '刷新' -Width 78
$backupButton = New-UiButton -Text '备份规则' -Width 92
$restoreButton = New-UiButton -Text '导入备份' -Width 92

@($discoverButton, $addButton, $applyAllButton, $refreshButton, $backupButton, $restoreButton) |
    ForEach-Object { [void]$toolbar.Controls.Add($_) }

$searchLabel = [Windows.Forms.Label]::new()
$searchLabel.Text = '搜索'
$searchLabel.AutoSize = $true
$searchLabel.ForeColor = $script:Theme.MutedText
$searchLabel.Margin = [Windows.Forms.Padding]::new(16, 14, 4, 0)
$toolbar.Controls.Add($searchLabel)

$searchBox = [Windows.Forms.TextBox]::new()
$searchBox.Width = 200
$searchBox.Height = 26
$searchBox.Margin = [Windows.Forms.Padding]::new(4, 10, 4, 0)
Set-UiInputTheme -Control $searchBox
$toolbar.Controls.Add($searchBox)

$filterBox = [Windows.Forms.ComboBox]::new()
$filterBox.Width = 135
$filterBox.DropDownStyle = 'DropDownList'
$filterBox.Margin = [Windows.Forms.Padding]::new(8, 10, 4, 0)
Set-UiInputTheme -Control $filterBox
@('全部状态', '已应用', '未应用', '异常 / 冲突', '已禁用') | ForEach-Object {
    [void]$filterBox.Items.Add($_)
}
$filterBox.SelectedIndex = 0
$toolbar.Controls.Add($filterBox)

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

function Add-GridColumn {
    param([string]$Name, [string]$Header, [int]$Width, [string]$AutoSizeMode = 'None')
    $column = [Windows.Forms.DataGridViewTextBoxColumn]::new()
    $column.Name = $Name
    $column.HeaderText = $Header
    $column.Width = $Width
    $column.AutoSizeMode = $AutoSizeMode
    [void]$grid.Columns.Add($column)
}

Add-GridColumn -Name 'Enabled' -Header '启用' -Width 52
Add-GridColumn -Name 'Name' -Header '规则' -Width 220
Add-GridColumn -Name 'Destination' -Header '目标 IPv4 / CIDR' -Width 145
Add-GridColumn -Name 'Adapter' -Header '指定网卡' -Width 145
Add-GridColumn -Name 'Gateway' -Header '网关' -Width 135
Add-GridColumn -Name 'Proxy' -Header '代理' -Width 58
Add-GridColumn -Name 'Status' -Header '当前状态' -Width 190
Add-GridColumn -Name 'Actual' -Header '实际路由' -Width 150 -AutoSizeMode 'Fill'

$detailPanel = [Windows.Forms.Panel]::new()
$detailPanel.Dock = 'Fill'
$detailPanel.BackColor = $script:Theme.SurfaceAlt
$detailPanel.Padding = [Windows.Forms.Padding]::new(16)

$detailTitle = [Windows.Forms.Label]::new()
$detailTitle.Text = 'RULE DETAIL'
$detailTitle.Font = [Drawing.Font]::new('Segoe UI', 8, [Drawing.FontStyle]::Bold)
$detailTitle.ForeColor = $script:Theme.AccentStrong
$detailTitle.AutoSize = $true
$detailTitle.Location = [Drawing.Point]::new(16, 14)
$detailPanel.Controls.Add($detailTitle)

$detailNameLabel = [Windows.Forms.Label]::new()
$detailNameLabel.Text = '选择一条规则'
$detailNameLabel.Font = [Drawing.Font]::new('Microsoft YaHei UI', 14, [Drawing.FontStyle]::Bold)
$detailNameLabel.ForeColor = $script:Theme.Accent
$detailNameLabel.AutoEllipsis = $true
$detailNameLabel.Location = [Drawing.Point]::new(15, 36)
$detailNameLabel.Size = [Drawing.Size]::new(315, 30)
$detailPanel.Controls.Add($detailNameLabel)

$detailStateLabel = [Windows.Forms.Label]::new()
$detailStateLabel.Text = '—'
$detailStateLabel.TextAlign = 'MiddleCenter'
$detailStateLabel.BackColor = $script:Theme.Background
$detailStateLabel.ForeColor = $script:Theme.MutedText
$detailStateLabel.Location = [Drawing.Point]::new(16, 73)
$detailStateLabel.Size = [Drawing.Size]::new(150, 26)
$detailPanel.Controls.Add($detailStateLabel)

$detailBox = [Windows.Forms.RichTextBox]::new()
$detailBox.ReadOnly = $true
$detailBox.BorderStyle = 'None'
$detailBox.BackColor = $script:Theme.SurfaceAlt
$detailBox.ForeColor = $script:Theme.WarmText
$detailBox.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
$detailBox.Location = [Drawing.Point]::new(16, 112)
$detailBox.Anchor = 'Top,Bottom,Left,Right'
$detailBox.Size = [Drawing.Size]::new(320, 260)
$detailBox.Text = "选择左侧规则后，这里会显示期望出口、当前状态和所有权信息。"
$detailPanel.Controls.Add($detailBox)

$detailActions = [Windows.Forms.FlowLayoutPanel]::new()
$detailActions.Dock = 'Bottom'
$detailActions.Height = 116
$detailActions.Padding = [Windows.Forms.Padding]::new(0, 6, 0, 0)
$detailActions.WrapContents = $true
$detailActions.BackColor = $script:Theme.SurfaceAlt
$detailPanel.Controls.Add($detailActions)

$applyButton = New-UiButton -Text '应用' -Width 150 -Variant 'Primary'
$testButton = New-UiButton -Text '诊断' -Width 150 -Variant 'Accent'
$editButton = New-UiButton -Text '修改' -Width 150
$copyDetailButton = New-UiButton -Text '复制详情' -Width 150
$removeButton = New-UiButton -Text '撤销' -Width 150 -Variant 'Danger'
$deleteButton = New-UiButton -Text '删除' -Width 150 -Variant 'Danger'
@($applyButton, $testButton, $editButton, $copyDetailButton, $removeButton, $deleteButton) |
    ForEach-Object { [void]$detailActions.Controls.Add($_) }

$split = [Windows.Forms.SplitContainer]::new()
$split.Dock = 'Fill'
$split.Orientation = 'Vertical'
$split.SplitterWidth = 5
$split.SplitterDistance = 985
$split.BackColor = $script:Theme.Border
$split.Panel1.BackColor = $script:Theme.Background
$split.Panel2.BackColor = $script:Theme.SurfaceAlt
$split.Panel1.Controls.Add($grid)
$split.Panel2.Controls.Add($detailPanel)

$logPanel = [Windows.Forms.Panel]::new()
$logPanel.Dock = 'Fill'
$logPanel.BackColor = $script:Theme.SurfaceAlt

$logTitle = [Windows.Forms.Label]::new()
$logTitle.Text = '操作日志'
$logTitle.Dock = 'Top'
$logTitle.Height = 24
$logTitle.Padding = [Windows.Forms.Padding]::new(12, 4, 0, 0)
$logTitle.ForeColor = $script:Theme.MutedText
$logTitle.Font = [Drawing.Font]::new('Microsoft YaHei UI', 8, [Drawing.FontStyle]::Bold)
$logPanel.Controls.Add($logTitle)

$logBox = [Windows.Forms.RichTextBox]::new()
$logBox.Dock = 'Fill'
$logBox.ReadOnly = $true
$logBox.BackColor = $script:Theme.SurfaceAlt
$logBox.ForeColor = $script:Theme.Accent
$logBox.BorderStyle = 'None'
$logBox.Font = [Drawing.Font]::new('Consolas', 9)
$logPanel.Controls.Add($logBox)
$logBox.BringToFront()
$script:LogControl = $logBox

$footer = [Windows.Forms.FlowLayoutPanel]::new()
$footer.Dock = 'Fill'
$footer.FlowDirection = 'LeftToRight'
$footer.WrapContents = $false
$footer.Padding = [Windows.Forms.Padding]::new(10, 3, 8, 0)
$footer.BackColor = $script:Theme.Background

$modeLabel = [Windows.Forms.Label]::new()
$modeLabel.AutoSize = $true
$modeLabel.ForeColor = $script:Theme.MutedText
$modeLabel.Margin = [Windows.Forms.Padding]::new(0, 5, 18, 0)
$footer.Controls.Add($modeLabel)

$lastRefreshLabel = [Windows.Forms.Label]::new()
$lastRefreshLabel.Text = '尚未刷新'
$lastRefreshLabel.AutoSize = $true
$lastRefreshLabel.ForeColor = $script:Theme.MutedText
$lastRefreshLabel.Margin = [Windows.Forms.Padding]::new(0, 5, 18, 0)
$footer.Controls.Add($lastRefreshLabel)

$visibleCountLabel = [Windows.Forms.Label]::new()
$visibleCountLabel.AutoSize = $true
$visibleCountLabel.ForeColor = $script:Theme.MutedText
$visibleCountLabel.Margin = [Windows.Forms.Padding]::new(0, 5, 18, 0)
$footer.Controls.Add($visibleCountLabel)

$autoRefreshCheck = [Windows.Forms.CheckBox]::new()
$autoRefreshCheck.Text = '15 秒自动刷新'
$autoRefreshCheck.Checked = $true
$autoRefreshCheck.AutoSize = $true
$autoRefreshCheck.ForeColor = $script:Theme.Accent
$autoRefreshCheck.Margin = [Windows.Forms.Padding]::new(0, 3, 16, 0)
$footer.Controls.Add($autoRefreshCheck)

$toggleLogButton = [Windows.Forms.Button]::new()
$toggleLogButton.Text = '隐藏日志'
$toggleLogButton.AutoSize = $true
$toggleLogButton.FlatStyle = 'Flat'
$toggleLogButton.FlatAppearance.BorderSize = 0
$toggleLogButton.BackColor = $script:Theme.Background
$toggleLogButton.ForeColor = $script:Theme.Accent
$toggleLogButton.Margin = [Windows.Forms.Padding]::new(0, 0, 0, 0)
$footer.Controls.Add($toggleLogButton)

$layout = [Windows.Forms.TableLayoutPanel]::new()
$layout.Dock = 'Fill'
$layout.ColumnCount = 1
$layout.RowCount = 6
[void]$layout.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent', 100))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 104))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 82))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 60))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 118))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 30))
$layout.BackColor = $script:Theme.Background
$layout.Controls.Add($header, 0, 0)
$layout.Controls.Add($metrics, 0, 1)
$layout.Controls.Add($toolbar, 0, 2)
$layout.Controls.Add($split, 0, 3)
$layout.Controls.Add($logPanel, 0, 4)
$layout.Controls.Add($footer, 0, 5)
$form.Controls.Add($layout)

$script:RuleViewCache = @()
$script:LogVisible = $true

function Get-SelectedRule {
    if ($grid.SelectedRows.Count -eq 0) { return $null }
    $grid.SelectedRows[0].Tag
}

function Set-SelectedActionState {
    param([bool]$HasSelection)
    $adminReady = $HasSelection -and (Test-IsAdministrator)
    $editButton.Enabled = $adminReady
    $applyButton.Enabled = $adminReady
    $removeButton.Enabled = $adminReady
    $deleteButton.Enabled = $adminReady
    $testButton.Enabled = $HasSelection
    $copyDetailButton.Enabled = $HasSelection
}

function Update-RuleDetail {
    $rule = Get-SelectedRule
    if ($null -eq $rule) {
        $detailNameLabel.Text = '选择一条规则'
        $detailStateLabel.Text = '—'
        $detailStateLabel.BackColor = $script:Theme.Background
        $detailStateLabel.ForeColor = $script:Theme.MutedText
        $detailBox.Text = "选择左侧规则后，这里会显示期望出口、当前状态和所有权信息。"
        Set-SelectedActionState -HasSelection $false
        return
    }

    $item = @($script:RuleViewCache | Where-Object { $_.Rule.Id -eq $rule.Id } | Select-Object -First 1)
    $status = if ($item.Count -gt 0) { $item[0].Status } else { $null }
    $state = Get-StateEntry -Id ([string]$rule.Id)
    $detailNameLabel.Text = [string]$rule.Name
    $detailStateLabel.Text = if ($null -eq $status) { '未知' } else { [string]$status.Text }

    if ($null -ne $status) {
        switch ([string]$status.Color) {
            'Green' {
                $detailStateLabel.BackColor = $script:Theme.SurfaceAlt
                $detailStateLabel.ForeColor = $script:Theme.Accent
            }
            'Orange' {
                $detailStateLabel.BackColor = $script:Theme.Accent
                $detailStateLabel.ForeColor = $script:Theme.DarkText
            }
            'Red' {
                $detailStateLabel.BackColor = $script:Theme.AccentStrong
                $detailStateLabel.ForeColor = $script:Theme.WarmText
            }
            default {
                $detailStateLabel.BackColor = $script:Theme.Background
                $detailStateLabel.ForeColor = $script:Theme.MutedText
            }
        }
    }

    $adapterText = if ($item.Count -gt 0) { [string]$item[0].AdapterName } else { [string]$rule.AdapterDescription }
    $gatewayText = if ([string]$rule.GatewayMode -eq 'Manual') { [string]$rule.Gateway } else { '自动读取当前默认网关' }
    $ownership = if ($null -ne $state -and [bool]$state.RouteOwned) {
        '由本程序接管'
    } elseif ([bool]$rule.OwnExistingRoute) {
        '配置为接管已有路由'
    } else {
        '仅管理规则定义'
    }
    $actualText = if ($null -ne $status -and -not [string]::IsNullOrWhiteSpace([string]$status.Actual)) {
        [string]$status.Actual
    } else { '—' }

    $detailBox.Text = @(
        "目标        $($rule.Destination)",
        "指定网卡    $adapterText",
        "网关模式    $($rule.GatewayMode)",
        "期望网关    $gatewayText",
        "代理绕过    $(if ([bool]$rule.BypassProxy) { '是' } else { '否' })",
        "当前实际    $actualText",
        "",
        "所有权      $ownership",
        "规则 ID     $($rule.Id)",
        "",
        "双击规则可修改；“诊断”会检查 Windows 最终选路、代理绕过和管理状态。"
    ) -join [Environment]::NewLine

    Set-SelectedActionState -HasSelection $true
}

function Test-ItemMatchesFilter {
    param([Parameter(Mandatory)]$Item)

    $query = $searchBox.Text.Trim()
    if (-not [string]::IsNullOrWhiteSpace($query)) {
        $haystack = @(
            [string]$Item.Rule.Name,
            [string]$Item.Rule.Destination,
            [string]$Item.AdapterName,
            [string]$Item.GatewayText,
            [string]$Item.Status.Text,
            [string]$Item.Status.Actual
        ) -join ' '
        if ($haystack.IndexOf($query, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            return $false
        }
    }

    switch ([string]$filterBox.SelectedItem) {
        '已应用' { return $Item.Status.State -eq 'Applied' }
        '未应用' { return $Item.Status.State -in @('Missing', 'ProxyMissing') }
        '异常 / 冲突' { return $Item.Status.State -in @('Conflict', 'Unavailable') }
        '已禁用' { return $Item.Status.State -eq 'Disabled' }
        default { return $true }
    }
}

function Render-RuleGrid {
    $selectedId = if ($grid.SelectedRows.Count -gt 0 -and $null -ne $grid.SelectedRows[0].Tag) {
        [string]$grid.SelectedRows[0].Tag.Id
    } else { '' }

    $grid.SuspendLayout()
    try {
        $grid.Rows.Clear()
        foreach ($item in $script:RuleViewCache) {
            if (-not (Test-ItemMatchesFilter -Item $item)) { continue }
            $rule = $item.Rule
            $status = $item.Status
            $rowIndex = $grid.Rows.Add(
                $(if ([bool]$rule.Enabled) { '是' } else { '否' }),
                [string]$rule.Name,
                [string]$rule.Destination,
                [string]$item.AdapterName,
                [string]$item.GatewayText,
                $(if ([bool]$rule.BypassProxy) { '是' } else { '否' }),
                [string]$status.Text,
                [string]$status.Actual
            )
            $row = $grid.Rows[$rowIndex]
            $row.Tag = $rule
            switch ([string]$status.Color) {
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
            if ([string]$rule.Id -eq $selectedId) {
                $row.Selected = $true
            }
        }

        if ($grid.SelectedRows.Count -eq 0 -and $grid.Rows.Count -gt 0) {
            $grid.Rows[0].Selected = $true
        }
        $visibleCountLabel.Text = "显示 $($grid.Rows.Count) / $($script:Rules.Count) 条"
    } finally {
        $grid.ResumeLayout()
    }
    Update-RuleDetail
}

function Refresh-Grid {
    $form.Cursor = [Windows.Forms.Cursors]::WaitCursor
    try {
        $snapshot = Get-SystemSnapshot
        $cache = foreach ($rule in $script:Rules) {
            $status = Get-RuleStatus -Rule $rule -Snapshot $snapshot
            $adapter = $null
            try { $adapter = Resolve-Adapter -Rule $rule -Adapters $snapshot.Adapters } catch { }
            [pscustomobject]@{
                Rule = $rule
                Status = $status
                AdapterName = if ($null -eq $adapter) { [string]$rule.AdapterDescription } else { [string]$adapter.Name }
                GatewayText = if ([string]$rule.GatewayMode -eq 'Manual') {
                    [string]$rule.Gateway
                } else { '自动（当前默认网关）' }
            }
        }
        $script:RuleViewCache = @($cache)

        $applied = @($script:RuleViewCache | Where-Object { $_.Status.State -eq 'Applied' }).Count
        $upAdapters = @($snapshot.Adapters | Where-Object { $_.Hardware -and $_.Status -eq 'Up' })
        $defaults = @($snapshot.Routes | Where-Object {
            $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -ne '0.0.0.0'
        } | Sort-Object RouteMetric)

        $discovery = Get-NetworkPolicyDiscovery -Snapshot $snapshot
        $script:LastDiscovery = $discovery
        $pending = [int]$discovery.UnmanagedSpecificRouteCount + [int]$discovery.UnmanagedProxyBypassCount

        $ruleMetric.Value.Text = "$applied / $($script:Rules.Count) 已应用"
        $adapterMetric.Value.Text = if ($upAdapters.Count -eq 0) { '未检测到已连接实体网卡' } else {
            ($upAdapters | ForEach-Object Name) -join ' · '
        }
        $routeMetric.Value.Text = if ($defaults.Count -eq 0) { '无 IPv4 默认出口' } else {
            "$($defaults[0].InterfaceAlias) → $($defaults[0].NextHop)"
        }
        $pendingMetric.Value.Text = if ($pending -eq 0) { '0 · 当前已归档' } else { "$pending 条 · 点击“识别当前策略”处理" }
        $pendingMetric.Panel.BackColor = if ($pending -gt 0) { $script:Theme.Accent } else { $script:Theme.SurfaceAlt }
        $pendingMetric.Value.ForeColor = if ($pending -gt 0) { $script:Theme.DarkText } else { $script:Theme.Accent }
        $pendingMetric.Title.ForeColor = if ($pending -gt 0) { $script:Theme.DarkText } else { $script:Theme.MutedText }

        $summaryLabel.Text = if ($pending -gt 0) {
            '已自动识别当前网络' + [Environment]::NewLine + "发现 $pending 条未纳入管理的现有策略"
        } else {
            '已自动识别当前网络' + [Environment]::NewLine + '当前没有待处理的现有策略'
        }
        $lastRefreshLabel.Text = "最后刷新 $(Get-Date -Format 'HH:mm:ss')"
        Render-RuleGrid
    } catch {
        Write-AppLog -Message ("刷新失败：" + $_.Exception.Message) -Level 'ERROR'
        $summaryLabel.Text = '状态刷新失败'
    } finally {
        $form.Cursor = [Windows.Forms.Cursors]::Default
    }
}

function Backup-RulesToFile {
    $dialog = [Windows.Forms.SaveFileDialog]::new()
    $dialog.Title = '备份网络策略规则'
    $dialog.Filter = 'JSON 文件 (*.json)|*.json'
    $dialog.FileName = 'network-rules-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'
    if ($dialog.ShowDialog($form) -ne 'OK') { return }

    $bundle = [pscustomobject]@{
        Format = 'windows-local-network-policy-manager/rules-backup'
        Version = 1
        ExportedAt = (Get-Date).ToString('o')
        ComputerName = $env:COMPUTERNAME
        Rules = @($script:Rules)
    }
    $bundle | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $dialog.FileName -Encoding UTF8
    Write-AppLog -Message "规则备份完成：$($dialog.FileName)"
}

function Restore-RulesFromFile {
    $dialog = [Windows.Forms.OpenFileDialog]::new()
    $dialog.Title = '导入网络策略规则备份'
    $dialog.Filter = 'JSON 文件 (*.json)|*.json'
    if ($dialog.ShowDialog($form) -ne 'OK') { return }

    $raw = Get-Content -LiteralPath $dialog.FileName -Raw -Encoding UTF8 | ConvertFrom-Json
    $incoming = if ($null -ne $raw.Rules) { @($raw.Rules) } else { @($raw) }
    if ($incoming.Count -eq 0) {
        [Windows.Forms.MessageBox]::Show('备份中没有规则。', '无法导入', 'OK', 'Warning') | Out-Null
        return
    }

    $answer = [Windows.Forms.MessageBox]::Show(
        "将导入 $($incoming.Count) 条规则定义。为避免跨机器误删已有路由，导入后会清除“接管已有路由/代理”的所有权标记；不会立即修改 Windows 网络。是否继续？",
        '确认导入规则备份', 'YesNo', 'Question')
    if ($answer -ne 'Yes') { return }

    $normalized = foreach ($rule in $incoming) {
        [pscustomobject]@{
            Id = if ([string]::IsNullOrWhiteSpace([string]$rule.Id)) { [Guid]::NewGuid().ToString('N') } else { [string]$rule.Id }
            Name = [string]$rule.Name
            Destination = ConvertTo-NormalizedPrefix -Value ([string]$rule.Destination)
            AdapterGuid = Get-NormalizedGuid -Value ([string]$rule.AdapterGuid)
            AdapterDescription = [string]$rule.AdapterDescription
            GatewayMode = if ([string]$rule.GatewayMode -eq 'Auto') { 'Auto' } else { 'Manual' }
            Gateway = if ([string]$rule.GatewayMode -eq 'Auto') { '' } else { [string]$rule.Gateway }
            BypassProxy = [bool]$rule.BypassProxy
            Enabled = [bool]$rule.Enabled
            OwnExistingRoute = $false
            OwnExistingProxy = $false
        }
    }

    $oldRules = @($script:Rules)
    try {
        $script:Rules = @($normalized)
        Assert-Configuration
        Save-Rules
        Write-AppLog -Message "已从备份导入 $($script:Rules.Count) 条规则定义：$($dialog.FileName)"
        Refresh-Grid
    } catch {
        $script:Rules = $oldRules
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '导入失败', 'OK', 'Error') | Out-Null
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
$grid.Add_CellDoubleClick({
    param($sender, $eventArgs)
    if ($eventArgs.RowIndex -ge 0) { Edit-SelectedRule }
})
$grid.Add_SelectionChanged({ Update-RuleDetail })

$searchBox.Add_TextChanged({ Render-RuleGrid })
$filterBox.Add_SelectedIndexChanged({ Render-RuleGrid })

$backupButton.Add_Click({
    try { Backup-RulesToFile } catch {
        Write-AppLog -Message ("备份失败：" + $_.Exception.Message) -Level 'ERROR'
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '备份失败', 'OK', 'Error') | Out-Null
    }
})

$restoreButton.Add_Click({
    try { Restore-RulesFromFile } catch {
        Write-AppLog -Message ("导入备份失败：" + $_.Exception.Message) -Level 'ERROR'
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '导入失败', 'OK', 'Error') | Out-Null
    }
})

$copyDetailButton.Add_Click({
    if (-not [string]::IsNullOrWhiteSpace($detailBox.Text)) {
        [Windows.Forms.Clipboard]::SetText(
            $detailNameLabel.Text + [Environment]::NewLine +
            $detailStateLabel.Text + [Environment]::NewLine +
            $detailBox.Text
        )
        Write-AppLog -Message "已复制规则详情：$($detailNameLabel.Text)"
    }
})

$toggleLogButton.Add_Click({
    $script:LogVisible = -not $script:LogVisible
    if ($script:LogVisible) {
        $layout.RowStyles[4].Height = 118
        $toggleLogButton.Text = '隐藏日志'
    } else {
        $layout.RowStyles[4].Height = 0
        $toggleLogButton.Text = '显示日志'
    }
})

$pendingMetric.Panel.Cursor = [Windows.Forms.Cursors]::Hand
$pendingMetric.Value.Cursor = [Windows.Forms.Cursors]::Hand
$pendingMetric.Title.Cursor = [Windows.Forms.Cursors]::Hand
$pendingMetric.Panel.Add_Click({ Show-DiscoveryDialog })
$pendingMetric.Value.Add_Click({ Show-DiscoveryDialog })
$pendingMetric.Title.Add_Click({ Show-DiscoveryDialog })

$deleteButton.Add_Click({
    $rule = Get-SelectedRule
    if ($null -eq $rule) { return }
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
    if ($null -eq $rule) { return }
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
        "将应用 $($enabledRules.Count) 条启用规则。未连接、网关异常或存在冲突的规则会单独报告。是否继续？",
        '应用全部', 'YesNo', 'Question')
    if ($answer -ne 'Yes') { return }

    $form.Cursor = [Windows.Forms.Cursors]::WaitCursor
    $errors = [Collections.Generic.List[string]]::new()
    $success = 0
    try {
        foreach ($rule in $enabledRules) {
            try {
                Apply-RulePolicy -Rule $rule
                $success++
            } catch {
                $message = "$($rule.Name)：$($_.Exception.Message)"
                $errors.Add($message)
                Write-AppLog -Message $message -Level 'ERROR'
            }
        }
        Refresh-Grid
    } finally {
        $form.Cursor = [Windows.Forms.Cursors]::Default
    }

    if ($errors.Count -gt 0) {
        [Windows.Forms.MessageBox]::Show(
            "成功 $success 条，失败 $($errors.Count) 条。" + [Environment]::NewLine + [Environment]::NewLine +
            ($errors -join ([Environment]::NewLine + [Environment]::NewLine)),
            '应用完成（部分失败）', 'OK', 'Warning') | Out-Null
    } else {
        [Windows.Forms.MessageBox]::Show(
            "已成功应用 $success 条规则。",
            '应用完成', 'OK', 'Information') | Out-Null
    }
})

$removeButton.Add_Click({
    $rule = Get-SelectedRule
    if ($null -eq $rule) { return }
    $answer = [Windows.Forms.MessageBox]::Show(
        "只撤销规则「$($rule.Name)」当前由本程序管理的路由和代理绕过，保留规则定义。是否继续？",
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
    if ($null -eq $rule) { return }
    try {
        $result = Test-RulePolicy -Rule $rule
        $message = @(
            "规则：$($result.Name)",
            "目标：$($result.Destination)",
            "健康状态：$(if ($result.Healthy) { '正常' } else { '需要检查' })",
            "规则状态：$($result.Status)",
            "",
            "期望网卡：$($result.ExpectedAdapter)  [$($result.AdapterStatus)]",
            "期望网关：$($result.ExpectedGateway)",
            "实际网卡：$($result.SelectedAdapter)",
            "匹配路由：$($result.MatchedRoute)",
            "实际下一跳：$($result.NextHop)",
            "选路符合预期：$(if ($result.RouteMatches) { '是' } else { '否' })",
            "",
            "代理绕过要求：$(if ($result.ProxyBypassExpected) { '是' } else { '否' })",
            "代理绕过存在：$(if (-not $result.ProxyBypassExpected) { '不适用' } elseif ($result.ProxyBypassPresent) { '是' } else { '否' })",
            "管理状态记录：$(if ($result.ManagedStatePresent) { '存在' } else { '不存在' })",
            "路由所有权：$(if ($result.RouteOwned) { '本程序拥有' } else { '未接管' })"
        ) -join [Environment]::NewLine
        [Windows.Forms.MessageBox]::Show($message, '规则诊断', 'OK', 'Information') | Out-Null
    } catch {
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '诊断失败', 'OK', 'Error') | Out-Null
    }
})

$refreshButton.Add_Click({ Refresh-Grid })
$discoverButton.Add_Click({ Show-DiscoveryDialog })

$form.Add_KeyDown({
    param($sender, $eventArgs)
    if ($eventArgs.KeyCode -eq 'F5') {
        Refresh-Grid
        $eventArgs.Handled = $true
    } elseif ($eventArgs.Control -and $eventArgs.KeyCode -eq 'F') {
        $searchBox.Focus()
        $searchBox.SelectAll()
        $eventArgs.Handled = $true
    } elseif ($eventArgs.Control -and $eventArgs.KeyCode -eq 'N') {
        Save-NewRule
        $eventArgs.Handled = $true
    } elseif ($eventArgs.Control -and $eventArgs.KeyCode -eq 'D') {
        Show-DiscoveryDialog
        $eventArgs.Handled = $true
    }
})

$script:RefreshTimer = [Windows.Forms.Timer]::new()
$script:RefreshTimer.Interval = 15000
$script:RefreshTimer.Add_Tick({
    if ($autoRefreshCheck.Checked -and $form.Visible -and -not $form.IsDisposed) {
        Refresh-Grid
    }
})
$script:RefreshTimer.Start()

$toolTip = [Windows.Forms.ToolTip]::new()
$toolTip.SetToolTip($discoverButton, '重新扫描当前 Windows 网卡、路由和代理绕过（Ctrl+D）')
$toolTip.SetToolTip($refreshButton, '刷新规则实际状态（F5）')
$toolTip.SetToolTip($searchBox, '按规则名称、目标地址、网卡、网关或状态搜索（Ctrl+F）')
$toolTip.SetToolTip($backupButton, '导出规则定义备份，不包含系统路由状态')
$toolTip.SetToolTip($restoreButton, '导入规则备份；不会立即修改 Windows 网络')
$toolTip.SetToolTip($applyButton, '应用当前规则到 Windows')
$toolTip.SetToolTip($testButton, '只读诊断 Windows 实际选路和代理状态')

$isAdministrator = Test-IsAdministrator
$modeLabel.Text = if ($isAdministrator) {
    '管理员模式 · 可应用和撤销网络策略'
} else {
    '只读模式 · 可识别、搜索、诊断和备份'
}
$modeLabel.ForeColor = if ($isAdministrator) { $script:Theme.Accent } else { $script:Theme.AccentStrong }

if (-not $isAdministrator) {
    @($addButton, $editButton, $deleteButton, $applyButton, $applyAllButton, $removeButton) |
        ForEach-Object { $_.Enabled = $false }
    $descriptionLabel.Text += ' · 当前为只读模式'
} else {
    Set-SelectedActionState -HasSelection $false
}

if (Test-Path -LiteralPath $script:LogPath) {
    $previousLog = Get-Content -LiteralPath $script:LogPath -Tail 18 -Encoding UTF8
    if ($previousLog) { $logBox.Text = ($previousLog -join [Environment]::NewLine) + [Environment]::NewLine }
}

$form.Add_Shown({
    Write-AppLog -Message "程序启动；管理员=$isAdministrator"
    Refresh-Grid

    if ($null -ne $script:LastDiscovery) {
        $pending = [int]$script:LastDiscovery.UnmanagedSpecificRouteCount +
            [int]$script:LastDiscovery.UnmanagedProxyBypassCount
        Write-AppLog -Message "自动识别完成：特定目标路由=$($script:LastDiscovery.SpecificRoutes.Count)，待处理=$pending"
        if (-not $UiSmokeTest -and $pending -gt 0) {
            $summaryLabel.Text = '已自动识别当前网络' + [Environment]::NewLine +
                "发现 $pending 条现有策略待你决定是否纳入管理"
        }
    }

    if ($UiSmokeTest) {
        $script:SmokeTimer = [Windows.Forms.Timer]::new()
        $script:SmokeTimer.Interval = 1400
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
