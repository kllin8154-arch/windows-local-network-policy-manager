[CmdletBinding()]
param(
    [switch]$SelfTest,
    [switch]$DumpStatus,
    [switch]$UiSmokeTest,
    [ValidateSet('ListRules', 'ListGroups', 'PlanGroup', 'Discover', 'Audit', 'Drift', 'PlanRepair', 'ExplainAddress', 'PlanRule', 'CreateBackup', 'ListBackups', 'RestoreRules', 'SaveRule', 'ApplyRule', 'RemoveRule', 'TestRule')]
    [string]$Command,
    [string]$RuleId,
    [string]$Address,
    [string]$Group,
    [string]$RuleJson,
    [ValidateSet('Apply', 'Remove')]
    [string]$Action = 'Apply',
    [string]$BackupId,
    [string]$ExpectedFingerprint,
    [switch]$Approved
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AppRoot = $PSScriptRoot
$script:RulesPath = Join-Path $script:AppRoot 'network-rules.json'
$script:DefaultRulesPath = Join-Path $script:AppRoot 'network-rules.default.json'
$script:StatePath = Join-Path $script:AppRoot 'manager-state.json'
$script:LogPath = Join-Path $script:AppRoot 'network-policy-manager.log'
$script:BackupRoot = Join-Path $script:AppRoot 'backups'
$script:MutationMutexName = 'Local\WindowsLocalNetworkPolicyManager.Mutation'
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
    $parsed = ConvertFrom-Json -InputObject $text
    if ($parsed -isnot [array]) { throw "JSON 根节点必须是数组：$Path" }
    foreach ($item in $parsed) { $item }
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [int]$Depth = 10
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }

    $tempPath = Join-Path $directory ('.' + [IO.Path]::GetFileName($Path) + '.tmp.' + $PID + '.' + [Guid]::NewGuid().ToString('N'))
    $json = $Value | ConvertTo-Json -Depth $Depth
    $encoding = [Text.UTF8Encoding]::new($true)
    [IO.File]::WriteAllText($tempPath, $json, $encoding)

    try {
        if (Test-Path -LiteralPath $Path) {
            try {
                [IO.File]::Replace($tempPath, $Path, $null, $true)
            } catch {
                Move-Item -LiteralPath $tempPath -Destination $Path -Force
            }
        } else {
            Move-Item -LiteralPath $tempPath -Destination $Path
        }
    } finally {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
}

function Save-Rules {
    $lock = Enter-MutationLock
    try {
        Write-JsonAtomic -Path $script:RulesPath -Value @($script:Rules) -Depth 8
    } finally {
        Exit-MutationLock -Mutex $lock
    }
}

function Save-State {
    $lock = Enter-MutationLock
    try {
        Write-JsonAtomic -Path $script:StatePath -Value @($script:State) -Depth 8
    } finally {
        Exit-MutationLock -Mutex $lock
    }
}

function Enter-MutationLock {
    $mutex = [Threading.Mutex]::new($false, $script:MutationMutexName)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds(15))
        } catch [Threading.AbandonedMutexException] {
            $acquired = $true
        }
        if (-not $acquired) {
            $mutex.Dispose()
            throw '另一个管理器或 MCP 正在修改网络策略。请等待当前操作完成后重试。'
        }
        return $mutex
    } catch {
        if (-not $acquired) { $mutex.Dispose() }
        throw
    }
}

function Exit-MutationLock {
    param([Threading.Mutex]$Mutex)
    if ($null -eq $Mutex) { return }
    try { $Mutex.ReleaseMutex() } catch { }
    $Mutex.Dispose()
}

function Get-TextSha256 {
    param([Parameter(Mandatory)][string]$Text)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        (($sha256.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha256.Dispose()
    }
}

function Remove-ExpiredSafetyBackups {
    param([int]$Keep = 50)

    if (-not (Test-Path -LiteralPath $script:BackupRoot)) { return }
    $files = @(Get-ChildItem -LiteralPath $script:BackupRoot -Filter 'snapshot-*.json' -File |
        Sort-Object LastWriteTimeUtc -Descending)
    if ($files.Count -le $Keep) { return }

    foreach ($file in @($files | Select-Object -Skip $Keep)) {
        Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($file.FullName + '.sha256') -Force -ErrorAction SilentlyContinue
    }
}

function New-SafetySnapshot {
    param(
        [Parameter(Mandatory)][string]$Reason,
        [string]$RuleId = ''
    )

    if (-not (Test-Path -LiteralPath $script:BackupRoot)) {
        [void](New-Item -ItemType Directory -Path $script:BackupRoot -Force)
    }

    $snapshot = Get-SystemSnapshot
    $managedPrefixes = @($script:Rules | ForEach-Object {
        try { ConvertTo-NormalizedPrefix -Value ([string]$_.Destination) } catch { }
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

    $managedRoutes = @($snapshot.Routes | Where-Object {
        [string]$_.DestinationPrefix -in $managedPrefixes
    } | Sort-Object DestinationPrefix, InterfaceIndex, NextHop | ForEach-Object {
        [pscustomobject]@{
            Destination = [string]$_.DestinationPrefix
            InterfaceIndex = [int]$_.InterfaceIndex
            InterfaceAlias = [string]$_.InterfaceAlias
            Gateway = [string]$_.NextHop
            Metric = [int]$_.RouteMetric
            PolicyStore = if ($_.PSObject.Properties.Name -contains 'PolicyStore') { [string]$_.PolicyStore } else { '' }
        }
    })

    $id = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $path = Join-Path $script:BackupRoot ("snapshot-$id.json")
    $payload = [ordered]@{
        Format = 'windows-local-network-policy-manager/safety-snapshot'
        Version = 1
        Id = $id
        CreatedAt = (Get-Date).ToString('o')
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        Reason = $Reason
        RuleId = $RuleId
        Rules = @($script:Rules)
        State = @($script:State)
        ProxyTokens = @($snapshot.ProxyTokens)
        ManagedRoutes = $managedRoutes
        DefaultRoutes = @($snapshot.Routes | Where-Object {
            $_.DestinationPrefix -eq '0.0.0.0/0'
        } | Sort-Object RouteMetric | ForEach-Object {
            [pscustomobject]@{
                InterfaceIndex = [int]$_.InterfaceIndex
                InterfaceAlias = [string]$_.InterfaceAlias
                Gateway = [string]$_.NextHop
                Metric = [int]$_.RouteMetric
            }
        })
    }

    Write-JsonAtomic -Path $path -Value $payload -Depth 12
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath ($path + '.sha256') -Value $hash -Encoding ASCII
    Remove-ExpiredSafetyBackups

    Write-AppLog -Message "安全快照：$id | $Reason | $RuleId"
    [pscustomobject]@{
        Id = $id
        Path = $path
        Sha256 = $hash
        Reason = $Reason
        CreatedAt = [string]$payload.CreatedAt
    }
}

function Get-SafetyBackupList {
    if (-not (Test-Path -LiteralPath $script:BackupRoot)) { return @() }

    @(
        Get-ChildItem -LiteralPath $script:BackupRoot -Filter 'snapshot-*.json' -File |
        Sort-Object LastWriteTimeUtc -Descending |
        ForEach-Object {
            $path = $_.FullName
            $sidecar = $path + '.sha256'
            $expected = if (Test-Path -LiteralPath $sidecar) {
                (Get-Content -LiteralPath $sidecar -Raw -Encoding ASCII).Trim().ToLowerInvariant()
            } else { '' }
            $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            $parsed = $null
            try { $parsed = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
            [pscustomobject]@{
                Id = if ($null -eq $parsed) { $_.BaseName.Replace('snapshot-', '') } else { [string]$parsed.Id }
                CreatedAt = if ($null -eq $parsed) { $_.LastWriteTime.ToString('o') } else { [string]$parsed.CreatedAt }
                Reason = if ($null -eq $parsed) { 'unreadable' } else { [string]$parsed.Reason }
                RuleId = if ($null -eq $parsed) { '' } else { [string]$parsed.RuleId }
                ComputerName = if ($null -eq $parsed) { '' } else { [string]$parsed.ComputerName }
                IntegrityOk = -not [string]::IsNullOrWhiteSpace($expected) -and $expected -eq $actual
                Path = $path
            }
        }
    )
}

function Get-SafetyBackupById {
    param([Parameter(Mandatory)][string]$Id)

    if ($Id.Length -ne 24 -or $Id -notmatch '^[0-9]{8}-[0-9]{6}-[0-9a-fA-F]{8}') {
        throw '备份 Id 格式无效。'
    }
    $path = Join-Path $script:BackupRoot ("snapshot-$Id.json")
    if (-not (Test-Path -LiteralPath $path)) {
        throw "找不到安全快照：$Id"
    }
    $sidecar = $path + '.sha256'
    if (-not (Test-Path -LiteralPath $sidecar)) {
        throw "安全快照缺少校验文件：$Id"
    }
    $expected = (Get-Content -LiteralPath $sidecar -Raw -Encoding ASCII).Trim().ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "安全快照完整性校验失败：$Id"
    }
    $parsed = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$parsed.ComputerName -ne $env:COMPUTERNAME) {
        throw "安全快照来自其他计算机：$($parsed.ComputerName)。禁止直接还原。"
    }
    $parsed
}

function Restore-RulesFromSafetyBackup {
    param([Parameter(Mandatory)][string]$Id)

    $backup = Get-SafetyBackupById -Id $Id
    $before = New-SafetySnapshot -Reason 'before-restore-rules' -RuleId $Id

    $restored = foreach ($rule in @($backup.Rules)) {
        [pscustomobject]@{
            Id = [string]$rule.Id
            Name = [string]$rule.Name
            Group = Get-RuleGroup -Rule $rule
            Tags = @(Get-RuleTags -Rule $rule)
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
        $script:Rules = @($restored)
        Assert-Configuration
        Save-Rules
        Write-AppLog -Message "已从安全快照恢复规则定义：$Id；所有权标记已清除。"
        [pscustomobject]@{
            Restored = $true
            BackupId = $Id
            RuleCount = $script:Rules.Count
            PreRestoreBackupId = $before.Id
            SystemNetworkChanged = $false
            OwnershipReset = $true
        }
    } catch {
        $script:Rules = $oldRules
        throw
    }
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
    $registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $settings = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
    if ($null -eq $settings -or $settings.PSObject.Properties.Name -notcontains 'ProxyOverride') {
        return @()
    }
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

function Get-RuleGroup {
    param([Parameter(Mandatory)]$Rule)

    if ($Rule.PSObject.Properties.Name -contains 'Group') {
        return ([string]$Rule.Group).Trim()
    }
    ''
}

function ConvertTo-NormalizedTags {
    param($Value)

    $items = [Collections.Generic.List[string]]::new()
    foreach ($raw in @($Value)) {
        if ($null -eq $raw) { continue }
        foreach ($part in ([string]$raw -split '[,，;；]')) {
            $tag = $part.Trim()
            if ([string]::IsNullOrWhiteSpace($tag)) { continue }
            if ($tag.Length -gt 40) { throw "标签过长：$tag" }
            if ($tag -notin @($items)) { $items.Add($tag) }
        }
    }
    @($items)
}

function Get-RuleTags {
    param([Parameter(Mandatory)]$Rule)

    if ($Rule.PSObject.Properties.Name -contains 'Tags') {
        return @(ConvertTo-NormalizedTags -Value $Rule.Tags)
    }
    @()
}

function Get-RuleGroupDisplay {
    param([Parameter(Mandatory)]$Rule)
    $group = Get-RuleGroup -Rule $Rule
    if ([string]::IsNullOrWhiteSpace($group)) { return '未分组' }
    $group
}

function Get-GroupSummaries {
    $groups = @($script:Rules | ForEach-Object { Get-RuleGroup -Rule $_ } | Sort-Object -Unique)
    foreach ($groupName in $groups) {
        $rules = @($script:Rules | Where-Object { (Get-RuleGroup -Rule $_) -eq $groupName })
        [pscustomobject]@{
            Group = $groupName
            DisplayName = if ([string]::IsNullOrWhiteSpace($groupName)) { '未分组' } else { $groupName }
            RuleCount = $rules.Count
            EnabledCount = @($rules | Where-Object { [bool]$_.Enabled }).Count
            Tags = @($rules | ForEach-Object { Get-RuleTags -Rule $_ } | Sort-Object -Unique)
        }
    }
}

function Get-GroupPlan {
    param(
        [AllowEmptyString()][string]$GroupName,
        [ValidateSet('Apply', 'Remove')][string]$Action = 'Apply'
    )

    $rules = @($script:Rules | Where-Object {
        (Get-RuleGroup -Rule $_) -eq $GroupName -and
        ($Action -ne 'Apply' -or [bool]$_.Enabled)
    })

    $plans = [Collections.Generic.List[object]]::new()
    foreach ($rule in $rules) {
        $plans.Add((Get-RulePlan -Rule $rule -Action $Action))
    }

    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o')
        Group = $GroupName
        DisplayName = if ([string]::IsNullOrWhiteSpace($GroupName)) { '未分组' } else { $GroupName }
        Action = $Action
        RuleCount = $rules.Count
        Allowed = @($plans | Where-Object { -not [bool]$_.Allowed }).Count -eq 0
        SystemChangeCount = if ($plans.Count -eq 0) { 0 } else { [int](($plans | Measure-Object -Property SystemChangeCount -Sum).Sum) }
        WarningCount = @($plans | ForEach-Object { @($_.Warnings) }).Count
        Plans = @($plans)
    }
}

function Get-StateDriftReport {
    param([object]$Snapshot = $null)

    $snapshot = if ($null -eq $Snapshot) { Get-SystemSnapshot } else { $Snapshot }
    $items = [Collections.Generic.List[object]]::new()

    foreach ($state in @($script:State)) {
        $ruleMatches = @($script:Rules | Where-Object Id -eq ([string]$state.Id) | Select-Object -First 1)
        if ($ruleMatches.Count -eq 0) {
            $items.Add([pscustomobject]@{
                Severity = 'Warning'
                Code = 'OrphanState'
                RuleId = [string]$state.Id
                RuleName = '[规则已不存在]'
                Resource = 'ManagerState'
                Repairable = $false
                ManualOnly = $true
                Message = 'manager-state 中仍有记录，但规则定义已经不存在。为避免误删外部资源，不自动清理。'
            })
            continue
        }

        $rule = $ruleMatches[0]
        if (-not [bool]$rule.Enabled -and ([bool]$state.RouteOwned -or [bool]$state.ProxyOwned)) {
            $items.Add([pscustomobject]@{
                Severity = 'Warning'
                Code = 'DisabledRuleStillManaged'
                RuleId = [string]$rule.Id
                RuleName = [string]$rule.Name
                Resource = 'ManagerState'
                Repairable = $true
                ManualOnly = $false
                Message = '规则已经禁用，但 manager-state 仍声明拥有系统资源。建议生成 Remove 修复计划，只撤销明确拥有的资源。'
            })
        }

        $statePrefix = ''
        try { $statePrefix = ConvertTo-NormalizedPrefix -Value ([string]$state.Destination) } catch {
            $statePrefix = [string]$state.Destination
        }
        $stateGateway = [string]$state.Gateway
        $stateGuid = Get-NormalizedGuid -Value ([string]$state.AdapterGuid)
        $adapterMatches = @($snapshot.Adapters | Where-Object Guid -eq $stateGuid | Select-Object -First 1)
        $acceptableIndexes = @([int]$state.InterfaceIndex)
        if ($adapterMatches.Count -gt 0) {
            $acceptableIndexes += [int]$adapterMatches[0].Index
        }
        $acceptableIndexes = @($acceptableIndexes | Where-Object { $_ -gt 0 } | Select-Object -Unique)

        $ownedTupleRoutes = @($snapshot.Routes | Where-Object {
            [string]$_.DestinationPrefix -eq $statePrefix -and
            [string]$_.NextHop -eq $stateGateway -and
            ($acceptableIndexes.Count -eq 0 -or [int]$_.InterfaceIndex -in $acceptableIndexes)
        })
        $samePrefixRoutes = @($snapshot.Routes | Where-Object {
            [string]$_.DestinationPrefix -eq $statePrefix
        })

        if ([bool]$state.RouteOwned) {
            if ($ownedTupleRoutes.Count -eq 0) {
                $replacement = $samePrefixRoutes.Count -gt 0
                $items.Add([pscustomobject]@{
                    Severity = if ($replacement) { 'Error' } else { 'Warning' }
                    Code = if ($replacement) { 'OwnedRouteReplacedExternally' } else { 'OwnedRouteMissing' }
                    RuleId = [string]$rule.Id
                    RuleName = [string]$rule.Name
                    Resource = 'Route'
                    Repairable = [bool]$rule.Enabled
                    ManualOnly = -not [bool]$rule.Enabled
                    Message = if ($replacement) {
                        "本程序拥有的路由 $statePrefix -> $stateGateway 已不存在，但同前缀出现了其他路由；必须重新 Plan，不能直接覆盖。"
                    } else {
                        "本程序拥有的路由 $statePrefix -> $stateGateway 已从 Windows 中消失。"
                    }
                })
            }
        } elseif (-not [string]::IsNullOrWhiteSpace($statePrefix) -and $ownedTupleRoutes.Count -eq 0) {
            $items.Add([pscustomobject]@{
                Severity = 'Warning'
                Code = 'ExternalRouteMissing'
                RuleId = [string]$rule.Id
                RuleName = [string]$rule.Name
                Resource = 'Route'
                Repairable = [bool]$rule.Enabled
                ManualOnly = -not [bool]$rule.Enabled
                Message = '该规则之前依赖一条不属于本程序的外部路由，但这条路由现在已经不存在。修复会重新 Plan，并可能创建新的受管路由。'
            })
        }

        $desiredPrefix = ''
        $desiredGateway = ''
        $desiredGuid = Get-NormalizedGuid -Value ([string]$rule.AdapterGuid)
        $desiredResolved = $false
        try {
            $desiredPrefix = ConvertTo-NormalizedPrefix -Value ([string]$rule.Destination)
            $desiredAdapter = Resolve-Adapter -Rule $rule -Adapters $snapshot.Adapters
            $desiredGateway = Get-RuleGateway -Rule $rule -Adapter $desiredAdapter -Routes $snapshot.Routes
            $desiredGuid = [string]$desiredAdapter.Guid
            $desiredResolved = $true
        } catch { }

        if ($desiredResolved -and (
            $desiredPrefix -ne $statePrefix -or
            $desiredGateway -ne $stateGateway -or
            $desiredGuid -ne $stateGuid
        )) {
            $items.Add([pscustomobject]@{
                Severity = 'Warning'
                Code = 'DesiredRouteChanged'
                RuleId = [string]$rule.Id
                RuleName = [string]$rule.Name
                Resource = 'Route'
                Repairable = [bool]$rule.Enabled
                ManualOnly = -not [bool]$rule.Enabled
                Message = "规则定义当前期望 $desiredPrefix -> $desiredGateway，但 manager-state 仍记录 $statePrefix -> $stateGateway。"
            })
        }

        $stateProxy = [string]$state.ProxyToken
        $stateProxyPresent = -not [string]::IsNullOrWhiteSpace($stateProxy) -and $stateProxy -in @($snapshot.ProxyTokens)
        if ([bool]$state.ProxyOwned -and -not [string]::IsNullOrWhiteSpace($stateProxy) -and -not $stateProxyPresent) {
            $items.Add([pscustomobject]@{
                Severity = 'Warning'
                Code = 'OwnedProxyMissing'
                RuleId = [string]$rule.Id
                RuleName = [string]$rule.Name
                Resource = 'ProxyBypass'
                Repairable = [bool]$rule.Enabled
                ManualOnly = -not [bool]$rule.Enabled
                Message = "本程序拥有的代理绕过 token「$stateProxy」已从 ProxyOverride 中消失。"
            })
        } elseif (-not [bool]$state.ProxyOwned -and -not [string]::IsNullOrWhiteSpace($stateProxy) -and -not $stateProxyPresent) {
            $items.Add([pscustomobject]@{
                Severity = 'Warning'
                Code = 'ExternalProxyMissing'
                RuleId = [string]$rule.Id
                RuleName = [string]$rule.Name
                Resource = 'ProxyBypass'
                Repairable = [bool]$rule.Enabled
                ManualOnly = -not [bool]$rule.Enabled
                Message = "规则之前依赖外部代理绕过 token「$stateProxy」，但它现在已经不存在。"
            })
        }

        $desiredProxy = ''
        try { $desiredProxy = Get-ProxyTokenForRule -Rule $rule } catch { }
        if ($desiredProxy -ne $stateProxy) {
            $items.Add([pscustomobject]@{
                Severity = 'Warning'
                Code = 'DesiredProxyChanged'
                RuleId = [string]$rule.Id
                RuleName = [string]$rule.Name
                Resource = 'ProxyBypass'
                Repairable = [bool]$rule.Enabled
                ManualOnly = -not [bool]$rule.Enabled
                Message = "规则定义的代理绕过目标已变化：当前期望「$desiredProxy」，manager-state 记录「$stateProxy」。"
            })
        }
    }

    foreach ($rule in @($script:Rules)) {
        $state = Get-StateEntry -Id ([string]$rule.Id)
        if ($null -ne $state -or -not [bool]$rule.Enabled) { continue }
        $status = Get-RuleStatus -Rule $rule -Snapshot $snapshot
        if ([string]$status.State -eq 'Applied') {
            $items.Add([pscustomobject]@{
                Severity = 'Info'
                Code = 'ExternalMatchWithoutState'
                RuleId = [string]$rule.Id
                RuleName = [string]$rule.Name
                Resource = 'Route'
                Repairable = $false
                ManualOnly = $true
                Message = '当前 Windows 路由与规则吻合，但没有 manager-state 所有权记录；视为外部匹配，不自动接管。'
            })
        }
    }

    $errors = @($items | Where-Object Severity -eq 'Error').Count
    $warnings = @($items | Where-Object Severity -eq 'Warning').Count
    $infos = @($items | Where-Object Severity -eq 'Info').Count

    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o')
        Healthy = ($errors + $warnings) -eq 0
        StateCount = @($script:State).Count
        DriftCount = $errors + $warnings
        Summary = [pscustomobject]@{
            Error = $errors
            Warning = $warnings
            Info = $infos
            ManualOnly = @($items | Where-Object ManualOnly).Count
            Repairable = @($items | Where-Object Repairable).Count
        }
        Items = @($items)
    }
}

function Get-RepairPlan {
    param([Parameter(Mandatory)][string]$RuleId)

    $rule = Get-RuleById -Id $RuleId
    $drift = Get-StateDriftReport
    $items = @($drift.Items | Where-Object RuleId -eq $RuleId)
    $action = if ([bool]$rule.Enabled) { 'Apply' } else { 'Remove' }
    $plan = Get-RulePlan -Rule $rule -Action $action

    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o')
        RuleId = $RuleId
        RuleName = [string]$rule.Name
        Group = Get-RuleGroup -Rule $rule
        HasDrift = @($items | Where-Object { $_.Severity -in @('Error','Warning') }).Count -gt 0
        RecommendedAction = $action
        Repairable = [bool]$plan.Allowed -and @($items | Where-Object Repairable).Count -gt 0
        DriftItems = @($items)
        Fingerprint = [string]$plan.Fingerprint
        Plan = $plan
    }
}

function ConvertTo-IPv4UInt64 {
    param([Parameter(Mandatory)][string]$Address)
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork') {
        throw "无效的 IPv4 地址：$Address"
    }
    $b = $ip.GetAddressBytes()
    ([uint64]$b[0] -shl 24) -bor ([uint64]$b[1] -shl 16) -bor ([uint64]$b[2] -shl 8) -bor [uint64]$b[3]
}

function Get-PrefixRange {
    param([Parameter(Mandatory)][string]$Prefix)
    $normalized = ConvertTo-NormalizedPrefix -Value $Prefix
    $parts = $normalized.Split('/')
    $start = ConvertTo-IPv4UInt64 -Address $parts[0]
    $length = [int]$parts[1]
    $size = if ($length -eq 0) { [uint64]4294967296 } else { [uint64]1 -shl (32 - $length) }
    [pscustomobject]@{
        Prefix = $normalized
        PrefixLength = $length
        Start = $start
        End = $start + $size - 1
    }
}

function Test-PrefixOverlap {
    param(
        [Parameter(Mandatory)][string]$Left,
        [Parameter(Mandatory)][string]$Right
    )
    $a = Get-PrefixRange -Prefix $Left
    $b = Get-PrefixRange -Prefix $Right
    $a.Start -le $b.End -and $b.Start -le $a.End
}
function Test-IPv4InPrefix {
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$Prefix
    )

    if (-not (Test-IPv4Address -Value $Address)) {
        throw "无效的 IPv4 地址：$Address"
    }
    $value = ConvertTo-IPv4UInt64 -Address $Address
    $range = Get-PrefixRange -Prefix $Prefix
    $value -ge $range.Start -and $value -le $range.End
}

function Get-RoutePropertyInt {
    param(
        [Parameter(Mandatory)]$Route,
        [Parameter(Mandatory)][string]$Name,
        [int]$Default = 0
    )
    if ($Route.PSObject.Properties.Name -contains $Name -and $null -ne $Route.$Name) {
        try { return [int]$Route.$Name } catch { }
    }
    $Default
}

function Get-AddressExplanation {
    param([Parameter(Mandatory)][string]$Address)

    if (-not (Test-IPv4Address -Value $Address)) {
        throw "ExplainAddress 只支持单个 IPv4 地址：$Address"
    }

    $snapshot = Get-SystemSnapshot
    $candidateRoutes = [Collections.Generic.List[object]]::new()

    foreach ($route in @($snapshot.Routes)) {
        $rawPrefix = [string]$route.DestinationPrefix
        if ([string]::IsNullOrWhiteSpace($rawPrefix)) { continue }

        $prefix = $null
        try { $prefix = ConvertTo-NormalizedPrefix -Value $rawPrefix } catch { continue }
        if (-not (Test-IPv4InPrefix -Address $Address -Prefix $prefix)) { continue }

        $range = Get-PrefixRange -Prefix $prefix
        $routeMetric = Get-RoutePropertyInt -Route $route -Name 'RouteMetric'
        $interfaceMetric = Get-RoutePropertyInt -Route $route -Name 'InterfaceMetric'
        $candidateRoutes.Add([pscustomobject]@{
            Destination = $prefix
            PrefixLength = [int]$range.PrefixLength
            InterfaceIndex = [int]$route.InterfaceIndex
            InterfaceAlias = [string]$route.InterfaceAlias
            Gateway = [string]$route.NextHop
            RouteMetric = $routeMetric
            InterfaceMetric = $interfaceMetric
            EffectiveMetric = $routeMetric + $interfaceMetric
            PolicyStore = if ($route.PSObject.Properties.Name -contains 'PolicyStore') { [string]$route.PolicyStore } else { '' }
            IsDefault = $prefix -eq '0.0.0.0/0'
        })
    }

    $sortedRoutes = @($candidateRoutes |
        Sort-Object @{ Expression = 'PrefixLength'; Descending = $true },
                    @{ Expression = 'EffectiveMetric'; Descending = $false },
                    @{ Expression = 'RouteMetric'; Descending = $false },
                    @{ Expression = 'InterfaceIndex'; Descending = $false })

    $selectedRaw = @(Find-NetRoute -RemoteIPAddress $Address -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } |
        Select-Object -First 1)

    $selected = $null
    if ($selectedRaw.Count -gt 0) {
        $r = $selectedRaw[0]
        $selectedPrefix = ''
        try { $selectedPrefix = ConvertTo-NormalizedPrefix -Value ([string]$r.DestinationPrefix) } catch {
            $selectedPrefix = [string]$r.DestinationPrefix
        }
        $selectedPrefixLength = -1
        if ($selectedPrefix -like '*/*') {
            try { $selectedPrefixLength = [int]$selectedPrefix.Split('/')[1] } catch { }
        }
        $selected = [pscustomobject]@{
            Destination = $selectedPrefix
            PrefixLength = $selectedPrefixLength
            InterfaceIndex = [int]$r.InterfaceIndex
            InterfaceAlias = [string]$r.InterfaceAlias
            Gateway = [string]$r.NextHop
            RouteMetric = Get-RoutePropertyInt -Route $r -Name 'RouteMetric'
            InterfaceMetric = Get-RoutePropertyInt -Route $r -Name 'InterfaceMetric'
        }
        $selected | Add-Member -NotePropertyName EffectiveMetric -NotePropertyValue (
            [int]$selected.RouteMetric + [int]$selected.InterfaceMetric
        )
    } elseif ($sortedRoutes.Count -gt 0) {
        $selected = $sortedRoutes[0]
    }

    $matchingRules = [Collections.Generic.List[object]]::new()
    foreach ($rule in @($script:Rules)) {
        $prefix = $null
        try { $prefix = ConvertTo-NormalizedPrefix -Value ([string]$rule.Destination) } catch { continue }
        if (-not (Test-IPv4InPrefix -Address $Address -Prefix $prefix)) { continue }

        $range = Get-PrefixRange -Prefix $prefix
        $adapter = $null
        $gateway = ''
        $resolutionError = ''
        try {
            $adapter = Resolve-Adapter -Rule $rule -Adapters $snapshot.Adapters
            $gateway = Get-RuleGateway -Rule $rule -Adapter $adapter -Routes $snapshot.Routes
        } catch {
            $resolutionError = $_.Exception.Message
        }

        $state = Get-StateEntry -Id ([string]$rule.Id
        )
        $status = $null
        try { $status = Get-RuleStatus -Rule $rule -Snapshot $snapshot } catch { }

        $controlsSelected = $false
        if ($null -ne $selected -and $null -ne $adapter -and -not [string]::IsNullOrWhiteSpace($gateway)) {
            $controlsSelected =
                [string]$selected.Destination -eq $prefix -and
                [int]$selected.InterfaceIndex -eq [int]$adapter.Index -and
                [string]$selected.Gateway -eq $gateway
        }

        $matchingRules.Add([pscustomobject]@{
            Id = [string]$rule.Id
            Name = [string]$rule.Name
            Destination = $prefix
            PrefixLength = [int]$range.PrefixLength
            Enabled = [bool]$rule.Enabled
            ExpectedAdapter = if ($null -eq $adapter) { [string]$rule.AdapterDescription } else { [string]$adapter.Name }
            AdapterStatus = if ($null -eq $adapter) { 'Unavailable' } else { [string]$adapter.Status }
            ExpectedGateway = $gateway
            BypassProxy = [bool]$rule.BypassProxy
            StatusCode = if ($null -eq $status) { '' } else { [string]$status.State }
            Status = if ($null -eq $status) { '' } else { [string]$status.Text }
            RouteOwned = $null -ne $state -and [bool]$state.RouteOwned
            ProxyOwned = $null -ne $state -and [bool]$state.ProxyOwned
            ControlsSelectedRoute = [bool]$controlsSelected
            ResolutionError = $resolutionError
        })
    }

    $sortedRules = @($matchingRules |
        Sort-Object @{ Expression = 'PrefixLength'; Descending = $true },
                    @{ Expression = 'Enabled'; Descending = $true },
                    @{ Expression = 'Name'; Descending = $false })

    $proxyExact = $Address -in @($snapshot.ProxyTokens)
    $selectedRule = @($sortedRules | Where-Object ControlsSelectedRoute | Select-Object -First 1)
    $mostSpecificRule = @($sortedRules | Where-Object Enabled | Select-Object -First 1)

    $summary = if ($null -eq $selected) {
        "Windows 当前没有为 $Address 选出可用 IPv4 路由。"
    } else {
        $routeSummary = "$Address → $($selected.Destination) → $($selected.InterfaceAlias)"
        if (-not [string]::IsNullOrWhiteSpace([string]$selected.Gateway) -and [string]$selected.Gateway -ne '0.0.0.0') {
            $routeSummary += " → $($selected.Gateway)"
        }
        if ($selectedRule.Count -gt 0) {
            $routeSummary += "；由规则「$($selectedRule[0].Name)」与当前实际路由一致。"
        } elseif ($mostSpecificRule.Count -gt 0) {
            $routeSummary += "；存在匹配规则「$($mostSpecificRule[0].Name)」，但它没有控制当前最终路由。"
        } else {
            $routeSummary += '；没有管理器规则匹配该地址，当前由 Windows/其他软件路由决定。'
        }
        $routeSummary
    }

    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o')
        Address = $Address
        Summary = $summary
        SelectionRule = 'Windows 先比较最长前缀；前缀长度相同时再比较路由/接口 Metric。'
        SelectedRoute = $selected
        MatchingRules = @($sortedRules)
        CandidateRoutes = @($sortedRoutes)
        ProxyBypassExactPresent = [bool]$proxyExact
        ProxyBypassExactToken = if ($proxyExact) { $Address } else { '' }
        ManagedRuleControlsSelectedRoute = $selectedRule.Count -gt 0
        SelectedManagedRuleId = if ($selectedRule.Count -gt 0) { [string]$selectedRule[0].Id } else { '' }
        SelectedManagedRuleName = if ($selectedRule.Count -gt 0) { [string]$selectedRule[0].Name } else { '' }
    }
}

function Get-PolicyAudit {
    $issues = [Collections.Generic.List[object]]::new()
    $snapshot = Get-SystemSnapshot

    foreach ($rule in $script:Rules) {
        $prefix = ConvertTo-NormalizedPrefix -Value ([string]$rule.Destination)
        if ($prefix -eq '0.0.0.0/0') {
            $issues.Add([pscustomobject]@{
                Severity = 'Critical'
                Code = 'DefaultRouteProtected'
                RuleId = [string]$rule.Id
                RuleName = [string]$rule.Name
                Message = '禁止由本程序管理 0.0.0.0/0 默认路由。'
            })
        }

        try {
            $adapter = Resolve-Adapter -Rule $rule -Adapters $snapshot.Adapters
            if ($adapter.Status -ne 'Up' -and [bool]$rule.Enabled) {
                $issues.Add([pscustomobject]@{
                    Severity = 'Warning'
                    Code = 'AdapterDown'
                    RuleId = [string]$rule.Id
                    RuleName = [string]$rule.Name
                    Message = "指定网卡当前未连接：$($adapter.Name)"
                })
            }
            if ([string]$rule.GatewayMode -eq 'Auto') {
                try { [void](Get-RuleGateway -Rule $rule -Adapter $adapter -Routes $snapshot.Routes) } catch {
                    $issues.Add([pscustomobject]@{
                        Severity = 'Error'
                        Code = 'AutoGatewayUnavailable'
                        RuleId = [string]$rule.Id
                        RuleName = [string]$rule.Name
                        Message = $_.Exception.Message
                    })
                }
            }
        } catch {
            $issues.Add([pscustomobject]@{
                Severity = 'Error'
                Code = 'AdapterUnavailable'
                RuleId = [string]$rule.Id
                RuleName = [string]$rule.Name
                Message = $_.Exception.Message
            })
        }

        $state = Get-StateEntry -Id ([string]$rule.Id)
        if ([bool]$rule.OwnExistingRoute -and ($null -eq $state -or -not [bool]$state.RouteOwned)) {
            $issues.Add([pscustomobject]@{
                Severity = 'Warning'
                Code = 'OwnershipClaimWithoutState'
                RuleId = [string]$rule.Id
                RuleName = [string]$rule.Name
                Message = '规则声明接管已有路由，但当前管理状态中没有对应所有权记录。'
            })
        }
    }

    for ($i = 0; $i -lt $script:Rules.Count; $i++) {
        $left = $script:Rules[$i]
        if (-not [bool]$left.Enabled) { continue }
        for ($j = $i + 1; $j -lt $script:Rules.Count; $j++) {
            $right = $script:Rules[$j]
            if (-not [bool]$right.Enabled) { continue }
            if (-not (Test-PrefixOverlap -Left ([string]$left.Destination) -Right ([string]$right.Destination))) { continue }

            $sameAdapter = (Get-NormalizedGuid -Value ([string]$left.AdapterGuid)) -eq
                (Get-NormalizedGuid -Value ([string]$right.AdapterGuid))
            $sameGateway = [string]$left.GatewayMode -eq [string]$right.GatewayMode -and
                [string]$left.Gateway -eq [string]$right.Gateway
            $severity = if ($sameAdapter -and $sameGateway) { 'Info' } else { 'Warning' }
            $issues.Add([pscustomobject]@{
                Severity = $severity
                Code = 'OverlappingRules'
                RuleId = [string]$left.Id
                RuleName = [string]$left.Name
                OtherRuleId = [string]$right.Id
                OtherRuleName = [string]$right.Name
                Message = "规则网段重叠：$($left.Destination) 与 $($right.Destination)。Windows 将优先使用更长前缀。"
            })
        }
    }

    $critical = @($issues | Where-Object Severity -eq 'Critical').Count
    $errors = @($issues | Where-Object Severity -eq 'Error').Count
    $warnings = @($issues | Where-Object Severity -eq 'Warning').Count
    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o')
        RuleCount = $script:Rules.Count
        StateCount = $script:State.Count
        Healthy = ($critical + $errors) -eq 0
        Summary = [pscustomobject]@{
            Critical = $critical
            Error = $errors
            Warning = $warnings
            Info = @($issues | Where-Object Severity -eq 'Info').Count
        }
        Issues = @($issues)
    }
}

function Get-RulePlan {
    param(
        [Parameter(Mandatory)]$Rule,
        [ValidateSet('Apply', 'Remove')][string]$Action = 'Apply'
    )

    $snapshot = Get-SystemSnapshot
    $prefix = ConvertTo-NormalizedPrefix -Value ([string]$Rule.Destination)
    $adapter = $null
    $gateway = ''
    $errors = [Collections.Generic.List[string]]::new()
    $warnings = [Collections.Generic.List[string]]::new()
    $diff = [Collections.Generic.List[object]]::new()

    if ($Action -eq 'Apply' -and -not [bool]$Rule.Enabled) {
        $errors.Add("规则「$($Rule.Name)」已禁用。")
    }

    try {
        $adapter = Resolve-Adapter -Rule $Rule -Adapters $snapshot.Adapters
        if ($adapter.Status -ne 'Up') {
            if ($Action -eq 'Apply') {
                $errors.Add("指定网卡当前未连接：$($adapter.Name)")
            } else {
                $warnings.Add("指定网卡当前未连接：$($adapter.Name)")
            }
        }
        $gateway = Get-RuleGateway -Rule $Rule -Adapter $adapter -Routes $snapshot.Routes
    } catch {
        if ($Action -eq 'Apply') {
            $errors.Add($_.Exception.Message)
        } else {
            $warnings.Add("撤销时不依赖当前规则出口解析：$($_.Exception.Message)")
        }
    }

    $exactRoutes = @($snapshot.Routes | Where-Object DestinationPrefix -eq $prefix |
        Sort-Object InterfaceIndex, NextHop, RouteMetric | ForEach-Object {
            [pscustomobject]@{
                Destination = $prefix
                InterfaceIndex = [int]$_.InterfaceIndex
                InterfaceAlias = [string]$_.InterfaceAlias
                Gateway = [string]$_.NextHop
                Metric = [int]$_.RouteMetric
            }
        })

    $state = Get-StateEntry -Id ([string]$Rule.Id)
    $previousDestination = ''
    $previousGateway = ''
    $previousIndex = 0
    $previousAdapterGuid = ''
    $previousRoutePresent = $false
    $previousStateRoutes = @()
    $previousRouteOwned = $null -ne $state -and [bool]$state.RouteOwned

    if ($null -ne $state) {
        try { $previousDestination = ConvertTo-NormalizedPrefix -Value ([string]$state.Destination) } catch {
            $previousDestination = [string]$state.Destination
        }
        $previousGateway = [string]$state.Gateway
        $previousIndex = [int]$state.InterfaceIndex
        $previousAdapterGuid = Get-NormalizedGuid -Value ([string]$state.AdapterGuid)
        $previousAdapter = @($snapshot.Adapters | Where-Object {
            $_.Guid -eq $previousAdapterGuid
        } | Select-Object -First 1)
        $acceptablePreviousIndexes = @($previousIndex)
        if ($previousAdapter.Count -gt 0) {
            $acceptablePreviousIndexes += [int]$previousAdapter[0].Index
        }
        $acceptablePreviousIndexes = @($acceptablePreviousIndexes | Where-Object { $_ -gt 0 } | Select-Object -Unique)

        $previousStateRoutes = @($snapshot.Routes | Where-Object {
            [string]$_.DestinationPrefix -eq $previousDestination -and
            [string]$_.NextHop -eq $previousGateway -and
            ($acceptablePreviousIndexes.Count -eq 0 -or [int]$_.InterfaceIndex -in $acceptablePreviousIndexes)
        } | Sort-Object InterfaceIndex, NextHop, RouteMetric | ForEach-Object {
            [pscustomobject]@{
                Destination = [string]$_.DestinationPrefix
                InterfaceIndex = [int]$_.InterfaceIndex
                InterfaceAlias = [string]$_.InterfaceAlias
                Gateway = [string]$_.NextHop
                Metric = [int]$_.RouteMetric
            }
        })
        $previousRoutePresent = $previousStateRoutes.Count -gt 0
    }

    $desired = if ($null -eq $adapter -or [string]::IsNullOrWhiteSpace($gateway)) {
        $null
    } else {
        [pscustomobject]@{
            Destination = $prefix
            InterfaceIndex = [int]$adapter.Index
            InterfaceAlias = [string]$adapter.Name
            AdapterGuid = [string]$adapter.Guid
            Gateway = $gateway
        }
    }

    $matchingRoutes = @(if ($null -ne $desired) {
        $exactRoutes | Where-Object {
            $_.InterfaceIndex -eq $desired.InterfaceIndex -and $_.Gateway -eq $desired.Gateway
        }
    })
    $conflicts = @(if ($null -ne $desired) {
        $exactRoutes | Where-Object {
            $_.InterfaceIndex -ne $desired.InterfaceIndex -or $_.Gateway -ne $desired.Gateway
        }
    })

    $canReplaceConflicts = $false
    if ($conflicts.Count -gt 0 -and $previousRouteOwned -and
        -not [string]::IsNullOrWhiteSpace($previousDestination) -and
        $previousDestination -eq $prefix) {

        $previousIndexes = @([int]$state.InterfaceIndex)
        $resolvedPreviousAdapter = @($snapshot.Adapters | Where-Object {
            $_.Guid -eq (Get-NormalizedGuid -Value ([string]$state.AdapterGuid))
        } | Select-Object -First 1)
        if ($resolvedPreviousAdapter.Count -gt 0) {
            $previousIndexes += [int]$resolvedPreviousAdapter[0].Index
        }
        $previousIndexes = @($previousIndexes | Where-Object { $_ -gt 0 } | Select-Object -Unique)

        $foreign = @($conflicts | Where-Object {
            $_.Gateway -ne $previousGateway -or
            ($previousIndexes.Count -gt 0 -and $_.InterfaceIndex -notin $previousIndexes)
        })
        $canReplaceConflicts = $foreign.Count -eq 0
    }

    $proxyToken = ''
    if ([bool]$Rule.BypassProxy) {
        try { $proxyToken = Get-ProxyTokenForRule -Rule $Rule } catch { $errors.Add($_.Exception.Message) }
    }
    $proxyPresent = -not [string]::IsNullOrWhiteSpace($proxyToken) -and $proxyToken -in @($snapshot.ProxyTokens)

    $previousProxyToken = if ($null -eq $state) { '' } else { [string]$state.ProxyToken }
    $previousProxyOwned = $null -ne $state -and [bool]$state.ProxyOwned
    $previousProxyPresent = -not [string]::IsNullOrWhiteSpace($previousProxyToken) -and
        $previousProxyToken -in @($snapshot.ProxyTokens)
    $otherRuleUsesPreviousProxy = $false
    if (-not [string]::IsNullOrWhiteSpace($previousProxyToken)) {
        $otherRuleUsesPreviousProxy = @($script:Rules | Where-Object {
            $_.Id -ne $Rule.Id -and [bool]$_.BypassProxy -and
            $(try { (Get-ProxyTokenForRule -Rule $_) -eq $previousProxyToken } catch { $false })
        }).Count -gt 0
    }

    if ($Action -eq 'Apply') {
        if ($null -eq $desired) {
            $diff.Add([pscustomobject]@{
                Resource = 'Route'
                Operation = 'Blocked'
                WillChange = $false
                Owned = $false
                Current = @($exactRoutes)
                Desired = $null
                Reason = '无法解析期望网卡或网关。'
            })
        } else {
            $previousDesiredDiffers = $previousRouteOwned -and (
                $previousDestination -ne $prefix -or
                $previousGateway -ne $gateway -or
                (-not [string]::IsNullOrWhiteSpace($previousAdapterGuid) -and
                 $previousAdapterGuid -ne [string]$adapter.Guid)
            )

            if ($previousDesiredDiffers) {
                $diff.Add([pscustomobject]@{
                    Resource = 'Route'
                    Operation = if ($previousRoutePresent) { 'Remove' } else { 'Drift' }
                    WillChange = [bool]$previousRoutePresent
                    Owned = $true
                    Current = [pscustomobject]@{
                        Destination = $previousDestination
                        InterfaceIndex = $previousIndex
                        Gateway = $previousGateway
                    }
                    Desired = $null
                    Reason = if ($previousRoutePresent) {
                        '规则期望已变化，先移除本程序之前拥有的旧路由。'
                    } else {
                        '管理状态声明拥有旧路由，但真实 Windows 中已找不到该路由。'
                    }
                })
            }

            if ($conflicts.Count -gt 0 -and -not $canReplaceConflicts) {
                $errors.Add('目标前缀已存在由其他网卡或网关负责的路由；程序不会覆盖。')
                $diff.Add([pscustomobject]@{
                    Resource = 'Route'
                    Operation = 'Conflict'
                    WillChange = $false
                    Owned = $false
                    Current = @($conflicts)
                    Desired = $desired
                    Reason = '存在不属于当前规则所有权范围的同目标路由。'
                })
            } elseif ($matchingRoutes.Count -gt 0) {
                $diff.Add([pscustomobject]@{
                    Resource = 'Route'
                    Operation = 'Keep'
                    WillChange = $false
                    Owned = $previousRouteOwned
                    Current = @($matchingRoutes)
                    Desired = $desired
                    Reason = '期望路由已经存在。'
                })
            } else {
                if ($conflicts.Count -gt 0 -and $canReplaceConflicts) {
                    $diff.Add([pscustomobject]@{
                        Resource = 'Route'
                        Operation = 'Remove'
                        WillChange = $true
                        Owned = $true
                        Current = @($conflicts)
                        Desired = $null
                        Reason = '同目标冲突路由与本程序之前拥有的路由一致，可安全替换。'
                    })
                }
                $diff.Add([pscustomobject]@{
                    Resource = 'Route'
                    Operation = 'Add'
                    WillChange = $true
                    Owned = $true
                    Current = @()
                    Desired = $desired
                    Reason = '期望路由当前不存在。'
                })
            }
        }

        if ($previousProxyOwned -and $previousProxyToken -ne $proxyToken) {
            if ($previousProxyPresent -and -not $otherRuleUsesPreviousProxy) {
                $diff.Add([pscustomobject]@{
                    Resource = 'ProxyBypass'
                    Operation = 'Remove'
                    WillChange = $true
                    Owned = $true
                    Current = $previousProxyToken
                    Desired = ''
                    Reason = '规则的代理绕过目标已变化，移除旧的已拥有 token。'
                })
            } elseif ($previousProxyPresent -and $otherRuleUsesPreviousProxy) {
                $diff.Add([pscustomobject]@{
                    Resource = 'ProxyBypass'
                    Operation = 'KeepShared'
                    WillChange = $false
                    Owned = $true
                    Current = $previousProxyToken
                    Desired = $previousProxyToken
                    Reason = '旧 token 仍被其他规则使用，不能移除。'
                })
            } elseif (-not $previousProxyPresent) {
                $diff.Add([pscustomobject]@{
                    Resource = 'ProxyBypass'
                    Operation = 'Drift'
                    WillChange = $false
                    Owned = $true
                    Current = ''
                    Desired = ''
                    Reason = '管理状态声明拥有旧代理绕过，但真实 ProxyOverride 中已不存在。'
                })
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($proxyToken)) {
            $diff.Add([pscustomobject]@{
                Resource = 'ProxyBypass'
                Operation = if ($proxyPresent) { 'Keep' } else { 'Add' }
                WillChange = -not $proxyPresent
                Owned = if ($proxyPresent) { $previousProxyOwned } else { $true }
                Current = if ($proxyPresent) { $proxyToken } else { '' }
                Desired = $proxyToken
                Reason = if ($proxyPresent) { '代理绕过已经存在。' } else { '规则要求精确 IPv4 代理绕过。' }
            })
        }

        $diff.Add([pscustomobject]@{
            Resource = 'ManagerState'
            Operation = if ($null -eq $state) { 'Add' } else { 'Update' }
            WillChange = $true
            Owned = $true
            Current = $state
            Desired = [pscustomobject]@{
                Destination = $prefix
                AdapterGuid = if ($null -eq $adapter) { '' } else { [string]$adapter.Guid }
                InterfaceIndex = if ($null -eq $adapter) { 0 } else { [int]$adapter.Index }
                Gateway = $gateway
                ProxyToken = $proxyToken
            }
            Reason = '记录本程序实际应用后的资源所有权和期望状态。'
        })
    } else {
        if ($previousRouteOwned) {
            $diff.Add([pscustomobject]@{
                Resource = 'Route'
                Operation = if ($previousRoutePresent) { 'Remove' } else { 'Drift' }
                WillChange = [bool]$previousRoutePresent
                Owned = $true
                Current = if ($previousRoutePresent) {
                    [pscustomobject]@{
                        Destination = $previousDestination
                        InterfaceIndex = $previousIndex
                        Gateway = $previousGateway
                    }
                } else { $null }
                Desired = $null
                Reason = if ($previousRoutePresent) {
                    '仅撤销 manager-state 记录为本程序拥有的路由。'
                } else {
                    'manager-state 声明拥有路由，但真实 Windows 中已不存在。'
                }
            })
        } else {
            $diff.Add([pscustomobject]@{
                Resource = 'Route'
                Operation = 'KeepExternal'
                WillChange = $false
                Owned = $false
                Current = @($exactRoutes)
                Desired = @($exactRoutes)
                Reason = '规则没有该路由的所有权，撤销时不会删除外部路由。'
            })
        }

        if ($previousProxyOwned -and -not [string]::IsNullOrWhiteSpace($previousProxyToken)) {
            $operation = if (-not $previousProxyPresent) {
                'Drift'
            } elseif ($otherRuleUsesPreviousProxy) {
                'KeepShared'
            } else {
                'Remove'
            }
            $diff.Add([pscustomobject]@{
                Resource = 'ProxyBypass'
                Operation = $operation
                WillChange = $operation -eq 'Remove'
                Owned = $true
                Current = if ($previousProxyPresent) { $previousProxyToken } else { '' }
                Desired = if ($operation -eq 'KeepShared') { $previousProxyToken } else { '' }
                Reason = switch ($operation) {
                    'Remove' { '该代理绕过由本程序拥有且没有其他规则共享。' }
                    'KeepShared' { '其他规则仍使用同一代理绕过，保留。' }
                    default { 'manager-state 声明拥有代理绕过，但真实 ProxyOverride 中已不存在。' }
                }
            })
        }

        $diff.Add([pscustomobject]@{
            Resource = 'ManagerState'
            Operation = if ($null -eq $state) { 'NoOp' } else { 'Remove' }
            WillChange = $null -ne $state
            Owned = $true
            Current = $state
            Desired = $null
            Reason = '撤销完成后清除该规则的 manager-state。'
        })
    }

    $fingerprintData = [ordered]@{
        Action = $Action
        Rule = [ordered]@{
            Id = [string]$Rule.Id
            Destination = $prefix
            AdapterGuid = Get-NormalizedGuid -Value ([string]$Rule.AdapterGuid)
            GatewayMode = [string]$Rule.GatewayMode
            Gateway = [string]$Rule.Gateway
            BypassProxy = [bool]$Rule.BypassProxy
            Enabled = [bool]$Rule.Enabled
        }
        Adapter = if ($null -eq $adapter) { $null } else {
            [ordered]@{
                Guid = [string]$adapter.Guid
                Index = [int]$adapter.Index
                Status = [string]$adapter.Status
            }
        }
        ResolvedGateway = $gateway
        ExactRoutes = @($exactRoutes)
        PreviousStateRoutes = @($previousStateRoutes)
        ProxyState = [ordered]@{
            DesiredToken = $proxyToken
            DesiredPresent = [bool]$proxyPresent
            PreviousToken = $previousProxyToken
            PreviousPresent = [bool]$previousProxyPresent
            OtherRuleUsesPrevious = [bool]$otherRuleUsesPreviousProxy
        }
        State = if ($null -eq $state) { $null } else {
            [ordered]@{
                Destination = [string]$state.Destination
                AdapterGuid = [string]$state.AdapterGuid
                InterfaceIndex = [int]$state.InterfaceIndex
                Gateway = [string]$state.Gateway
                RouteOwned = [bool]$state.RouteOwned
                ProxyToken = [string]$state.ProxyToken
                ProxyOwned = [bool]$state.ProxyOwned
            }
        }
    }
    $fingerprint = Get-TextSha256 -Text ($fingerprintData | ConvertTo-Json -Depth 10 -Compress)

    $changes = [Collections.Generic.List[string]]::new()
    foreach ($entry in @($diff | Where-Object WillChange)) {
        switch ([string]$entry.Resource) {
            'Route' {
                if ($entry.Operation -eq 'Add') {
                    $changes.Add("新增持久路由：$prefix -> $gateway")
                } elseif ($entry.Operation -eq 'Remove') {
                    $changes.Add('移除本程序拥有的旧/当前路由')
                }
            }
            'ProxyBypass' {
                if ($entry.Operation -eq 'Add') {
                    $changes.Add("新增系统代理绕过：$($entry.Desired)")
                } elseif ($entry.Operation -eq 'Remove') {
                    $changes.Add("移除本程序拥有的代理绕过：$($entry.Current)")
                }
            }
            'ManagerState' {
                if ($entry.Operation -eq 'Remove') {
                    $changes.Add('清除该规则的管理状态记录')
                }
            }
        }
    }
    if ($changes.Count -eq 0) {
        $changes.Add('当前真实状态已经符合计划，不需要修改系统路由或代理。')
    }

    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o')
        Action = $Action
        RuleId = [string]$Rule.Id
        RuleName = [string]$Rule.Name
        Group = Get-RuleGroup -Rule $Rule
        Destination = $prefix
        Allowed = $errors.Count -eq 0
        Fingerprint = $fingerprint
        ExpectedAdapter = if ($null -eq $adapter) { '' } else { [string]$adapter.Name }
        ExpectedGateway = $gateway
        ExistingRoutes = @($exactRoutes)
        ProxyToken = $proxyToken
        Diff = @($diff)
        ChangeCount = @($diff | Where-Object WillChange).Count
        SystemChangeCount = @($diff | Where-Object { $_.WillChange -and $_.Resource -ne 'ManagerState' }).Count
        Changes = @($changes)
        Warnings = @($warnings)
        Errors = @($errors)
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

function Invoke-ApplyRulePolicyCore {
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

    $previousPrefix = ''
    $previousGateway = ''
    $previousAdapterGuid = ''
    $samePreviousDesired = $false
    if ($null -ne $previous) {
        try { $previousPrefix = ConvertTo-NormalizedPrefix -Value ([string]$previous.Destination) } catch {
            $previousPrefix = [string]$previous.Destination
        }
        $previousGateway = [string]$previous.Gateway
        $previousAdapterGuid = Get-NormalizedGuid -Value ([string]$previous.AdapterGuid)
        $samePreviousDesired =
            [bool]$previous.RouteOwned -and
            $previousPrefix -eq $prefix -and
            $previousGateway -eq $gateway -and
            $previousAdapterGuid -eq [string]$adapter.Guid
    }

    $removedRoutes = [Collections.Generic.List[object]]::new()
    $routeCreated = $false
    $proxyAdded = $false
    $oldProxyRemoved = $false
    $oldProxyToken = ''

    try {
        if ($null -ne $previous -and [bool]$previous.RouteOwned -and -not $samePreviousDesired) {
            $previousRoutes = @(Get-ExactRoutes -Prefix $previousPrefix | Where-Object {
                [string]$_.NextHop -eq $previousGateway
            })
            $storedIndex = [int]$previous.InterfaceIndex
            $preferred = @($previousRoutes | Where-Object InterfaceIndex -eq $storedIndex | Select-Object -First 1)
            $ownedRoute = if ($preferred.Count -gt 0) { $preferred[0] } else { $null }

            if ($null -ne $ownedRoute) {
                Remove-ExactRoute -Prefix $previousPrefix -Gateway $previousGateway -InterfaceIndex ([int]$ownedRoute.InterfaceIndex)
                $removedRoutes.Add([pscustomobject]@{
                    Destination = $previousPrefix
                    Gateway = $previousGateway
                    InterfaceIndex = [int]$ownedRoute.InterfaceIndex
                })
            }
        }

        $exact = Get-ExactRoutes -Prefix $prefix
        $matching = @($exact | Where-Object {
            $_.InterfaceIndex -eq $adapter.Index -and $_.NextHop -eq $gateway
        })
        $conflicts = @($exact | Where-Object {
            $_.InterfaceIndex -ne $adapter.Index -or $_.NextHop -ne $gateway
        })

        if ($conflicts.Count -gt 0) {
            $ownedConflictIndexes = @()
            if ($null -ne $previous -and [bool]$previous.RouteOwned -and $previousPrefix -eq $prefix) {
                $ownedConflictIndexes += [int]$previous.InterfaceIndex
            }
            $ownedConflictIndexes = @($ownedConflictIndexes | Where-Object { $_ -gt 0 } | Select-Object -Unique)

            $foreignConflicts = @($conflicts | Where-Object {
                $previousGateway -ne [string]$_.NextHop -or
                $ownedConflictIndexes.Count -eq 0 -or
                [int]$_.InterfaceIndex -notin $ownedConflictIndexes
            })
            if ($foreignConflicts.Count -gt 0) {
                $details = ($foreignConflicts | ForEach-Object { "$($_.InterfaceAlias) / $($_.NextHop)" }) -join ', '
                throw "目标 $prefix 已有其他路由：$details。为避免覆盖，未做修改。"
            }

            foreach ($conflict in $conflicts) {
                Remove-ExactRoute -Prefix $prefix -Gateway ([string]$conflict.NextHop) -InterfaceIndex ([int]$conflict.InterfaceIndex)
                $removedRoutes.Add([pscustomobject]@{
                    Destination = $prefix
                    Gateway = [string]$conflict.NextHop
                    InterfaceIndex = [int]$conflict.InterfaceIndex
                })
            }
            $matching = @()
        }

        if ($matching.Count -eq 0) {
            Add-ExactRoute -Prefix $prefix -Gateway $gateway -InterfaceIndex $adapter.Index
            $routeCreated = $true
        }

        $routeOwned = $routeCreated -or [bool]$Rule.OwnExistingRoute -or $samePreviousDesired

        $proxyToken = Get-ProxyTokenForRule -Rule $Rule
        $samePreviousProxy = $null -ne $previous -and [bool]$previous.ProxyOwned -and
            [string]$previous.ProxyToken -eq $proxyToken -and
            -not [string]::IsNullOrWhiteSpace($proxyToken)

        if ($null -ne $previous -and [bool]$previous.ProxyOwned) {
            $oldProxyToken = [string]$previous.ProxyToken
            if (-not [string]::IsNullOrWhiteSpace($oldProxyToken) -and $oldProxyToken -ne $proxyToken) {
                $otherRuleUsesOldProxy = @($script:Rules | Where-Object {
                    $_.Id -ne $Rule.Id -and [bool]$_.BypassProxy -and
                    $(try { (Get-ProxyTokenForRule -Rule $_) -eq $oldProxyToken } catch { $false })
                }).Count -gt 0
                $tokensBefore = @(Get-ProxyTokens)
                if (-not $otherRuleUsesOldProxy -and $oldProxyToken -in $tokensBefore) {
                    Set-ProxyTokens -Tokens @($tokensBefore | Where-Object { $_ -ne $oldProxyToken })
                    $oldProxyRemoved = $true
                }
            }
        }

        $proxyOwned = $false
        if (-not [string]::IsNullOrWhiteSpace($proxyToken)) {
            $tokens = @(Get-ProxyTokens)
            if ($proxyToken -notin $tokens) {
                Set-ProxyTokens -Tokens @($tokens + $proxyToken)
                $proxyAdded = $true
                $proxyOwned = $true
            } else {
                $proxyOwned = [bool]$Rule.OwnExistingProxy -or $samePreviousProxy
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
        if ($oldProxyRemoved -and -not [string]::IsNullOrWhiteSpace($oldProxyToken)) {
            try {
                $tokens = @(Get-ProxyTokens)
                if ($oldProxyToken -notin $tokens) {
                    Set-ProxyTokens -Tokens @($tokens + $oldProxyToken)
                }
            } catch { }
        }
        foreach ($removed in @($removedRoutes)) {
            try {
                $exists = @(Get-ExactRoutes -Prefix ([string]$removed.Destination) | Where-Object {
                    $_.NextHop -eq [string]$removed.Gateway -and
                    $_.InterfaceIndex -eq [int]$removed.InterfaceIndex
                }).Count -gt 0
                if (-not $exists) {
                    Add-ExactRoute -Prefix ([string]$removed.Destination) -Gateway ([string]$removed.Gateway) -InterfaceIndex ([int]$removed.InterfaceIndex)
                }
            } catch { }
        }
        throw
    }
}

function Invoke-RemoveRulePolicyCore {
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

function Apply-RulePolicy {
    param(
        [Parameter(Mandatory)]$Rule,
        [string]$ExpectedFingerprint = ''
    )

    $lock = Enter-MutationLock
    try {
        $plan = Get-RulePlan -Rule $Rule -Action 'Apply'
        if (-not [bool]$plan.Allowed) {
            throw ("应用前检查未通过：" + (@($plan.Errors) -join '；'))
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedFingerprint) -and
            [string]$plan.Fingerprint -ne $ExpectedFingerprint) {
            throw '网络状态自计划生成后已经变化。为避免基于过期状态修改网络，请重新生成计划后再确认。'
        }

        [void](New-SafetySnapshot -Reason 'before-apply-rule' -RuleId ([string]$Rule.Id))
        Invoke-ApplyRulePolicyCore -Rule $Rule
    } finally {
        Exit-MutationLock -Mutex $lock
    }
}

function Remove-RulePolicy {
    param(
        [Parameter(Mandatory)]$Rule,
        [string]$ExpectedFingerprint = ''
    )

    $lock = Enter-MutationLock
    try {
        $plan = Get-RulePlan -Rule $Rule -Action 'Remove'
        if (-not [bool]$plan.Allowed) {
            throw ("撤销前检查未通过：" + (@($plan.Errors) -join '；'))
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedFingerprint) -and
            [string]$plan.Fingerprint -ne $ExpectedFingerprint) {
            throw '网络状态自计划生成后已经变化。为避免基于过期状态撤销网络策略，请重新生成计划后再确认。'
        }

        [void](New-SafetySnapshot -Reason 'before-remove-rule' -RuleId ([string]$Rule.Id))
        Invoke-RemoveRulePolicyCore -Rule $Rule
    } finally {
        Exit-MutationLock -Mutex $lock
    }
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
        $groupName = Get-RuleGroup -Rule $rule
        if ($groupName.Length -gt 60) { throw "规则「$($rule.Name)」的分组名称超过 60 个字符。" }
        [void](Get-RuleTags -Rule $rule)
        $prefix = ConvertTo-NormalizedPrefix -Value ([string]$rule.Destination)
        if ($prefix -eq '0.0.0.0/0') {
            throw "规则「$($rule.Name)」试图管理默认路由 0.0.0.0/0；该目标受保护。"
        }
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

if (-not (Test-Path -LiteralPath $script:RulesPath)) {
    if (-not (Test-Path -LiteralPath $script:DefaultRulesPath)) {
        throw "缺少规则文件：$($script:RulesPath)。请从备份恢复，或重新解压完整免安装包。"
    }
    Copy-Item -LiteralPath $script:DefaultRulesPath -Destination $script:RulesPath
}
$script:Rules = @(Read-JsonArray -Path $script:RulesPath)
$script:State = @(Read-JsonArray -Path $script:StatePath)
Assert-Configuration

if (-not [string]::IsNullOrWhiteSpace($Command)) {
    switch ($Command) {
        'ListRules' {
            ConvertTo-Json -InputObject @($script:Rules) -Depth 8
            exit 0
        }
        'ListGroups' {
            ConvertTo-Json -InputObject @(Get-GroupSummaries) -Depth 8
            exit 0
        }
        'PlanGroup' {
            Get-GroupPlan -GroupName $Group -Action $Action | ConvertTo-Json -Depth 12
            exit 0
        }
        'Discover' {
            Get-NetworkPolicyDiscovery | ConvertTo-Json -Depth 8
            exit 0
        }
        'Audit' {
            Get-PolicyAudit | ConvertTo-Json -Depth 10
            exit 0
        }
        'Drift' {
            Get-StateDriftReport | ConvertTo-Json -Depth 12
            exit 0
        }
        'PlanRepair' {
            if ([string]::IsNullOrWhiteSpace($RuleId)) { throw 'PlanRepair 需要 -RuleId。' }
            Get-RepairPlan -RuleId $RuleId | ConvertTo-Json -Depth 14
            exit 0
        }
        'ExplainAddress' {
            if ([string]::IsNullOrWhiteSpace($Address)) { throw 'ExplainAddress 需要 -Address。' }
            Get-AddressExplanation -Address $Address | ConvertTo-Json -Depth 12
            exit 0
        }
        'PlanRule' {
            if ([string]::IsNullOrWhiteSpace($RuleId)) { throw 'PlanRule 需要 -RuleId。' }
            Get-RulePlan -Rule (Get-RuleById -Id $RuleId) -Action $Action | ConvertTo-Json -Depth 10
            exit 0
        }
        'CreateBackup' {
            New-SafetySnapshot -Reason 'manual-cli-backup' -RuleId $RuleId | ConvertTo-Json -Depth 6
            exit 0
        }
        'ListBackups' {
            ConvertTo-Json -InputObject @(Get-SafetyBackupList) -Depth 6
            exit 0
        }
        'RestoreRules' {
            if ([string]::IsNullOrWhiteSpace($BackupId)) { throw 'RestoreRules 需要 -BackupId。' }
            if (-not $Approved) { throw 'RestoreRules 会替换规则定义；需要显式传入 -Approved。' }
            $lock = Enter-MutationLock
            try {
                Restore-RulesFromSafetyBackup -Id $BackupId | ConvertTo-Json -Depth 8
            } finally {
                Exit-MutationLock -Mutex $lock
            }
            exit 0
        }
        'SaveRule' {
            if ([string]::IsNullOrWhiteSpace($RuleJson)) { throw 'SaveRule 需要 -RuleJson。' }
            $incoming = $RuleJson | ConvertFrom-Json
            $id = if ([string]::IsNullOrWhiteSpace([string]$incoming.Id)) { [Guid]::NewGuid().ToString('N') } else { [string]$incoming.Id }
            $rule = [pscustomobject]@{
                Id = $id
                Name = [string]$incoming.Name
                Group = if ($incoming.PSObject.Properties.Name -contains 'Group') { ([string]$incoming.Group).Trim() } else { '' }
                Tags = if ($incoming.PSObject.Properties.Name -contains 'Tags') { @(ConvertTo-NormalizedTags -Value $incoming.Tags) } else { @() }
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
            $lock = Enter-MutationLock
            $oldRules = @($script:Rules)
            try {
                [void](New-SafetySnapshot -Reason 'before-save-rule' -RuleId $id)
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
            } finally {
                Exit-MutationLock -Mutex $lock
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
            Apply-RulePolicy -Rule $rule -ExpectedFingerprint $ExpectedFingerprint
            Test-RulePolicy -Rule $rule | ConvertTo-Json -Depth 8
            exit 0
        }
        'RemoveRule' {
            if ([string]::IsNullOrWhiteSpace($RuleId)) { throw 'RemoveRule 需要 -RuleId。' }
            if (-not $Approved) { throw 'RemoveRule 会修改 Windows 路由/代理；需要显式传入 -Approved。' }
            $rule = Get-RuleById -Id $RuleId
            Remove-RulePolicy -Rule $rule -ExpectedFingerprint $ExpectedFingerprint
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
    $dialog.ClientSize = [Drawing.Size]::new(660, 535)
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.StartPosition = 'CenterParent'
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.ShowInTaskbar = $false
    $dialog.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
    $dialog.BackColor = $script:Theme.Background
    $dialog.ForeColor = $script:Theme.WarmText

    $labels = @(
        @('规则名称', 28),
        @('分组', 82),
        @('标签', 136),
        @('目标 IPv4 / CIDR', 190),
        @('指定网卡', 244),
        @('网关模式', 298),
        @('手动网关', 352)
    )
    foreach ($spec in $labels) {
        $label = [Windows.Forms.Label]::new()
        $label.Text = [string]$spec[0]
        $label.AutoSize = $true
        $label.ForeColor = $script:Theme.Accent
        $label.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9, [Drawing.FontStyle]::Bold)
        $label.Location = [Drawing.Point]::new(28, [int]$spec[1])
        $dialog.Controls.Add($label)
    }

    $nameBox = [Windows.Forms.TextBox]::new()
    $nameBox.Location = [Drawing.Point]::new(170, 24)
    $nameBox.Size = [Drawing.Size]::new(450, 26)
    Set-UiInputTheme -Control $nameBox
    $dialog.Controls.Add($nameBox)

    $groupBox = [Windows.Forms.TextBox]::new()
    $groupBox.Location = [Drawing.Point]::new(170, 78)
    $groupBox.Size = [Drawing.Size]::new(450, 26)
    Set-UiInputTheme -Control $groupBox
    $dialog.Controls.Add($groupBox)

    $tagsBox = [Windows.Forms.TextBox]::new()
    $tagsBox.Location = [Drawing.Point]::new(170, 132)
    $tagsBox.Size = [Drawing.Size]::new(450, 26)
    Set-UiInputTheme -Control $tagsBox
    $dialog.Controls.Add($tagsBox)

    $destinationBox = [Windows.Forms.TextBox]::new()
    $destinationBox.Location = [Drawing.Point]::new(170, 186)
    $destinationBox.Size = [Drawing.Size]::new(450, 26)
    Set-UiInputTheme -Control $destinationBox
    $dialog.Controls.Add($destinationBox)

    $adapterBox = [Windows.Forms.ComboBox]::new()
    $adapterBox.Location = [Drawing.Point]::new(170, 240)
    $adapterBox.Size = [Drawing.Size]::new(450, 28)
    $adapterBox.DropDownStyle = 'DropDownList'
    $adapterBox.DisplayMember = 'Display'
    Set-UiInputTheme -Control $adapterBox
    $adapters = Get-Adapters
    foreach ($adapter in $adapters) { [void]$adapterBox.Items.Add($adapter) }
    $dialog.Controls.Add($adapterBox)

    $gatewayModeBox = [Windows.Forms.ComboBox]::new()
    $gatewayModeBox.Location = [Drawing.Point]::new(170, 294)
    $gatewayModeBox.Size = [Drawing.Size]::new(450, 28)
    $gatewayModeBox.DropDownStyle = 'DropDownList'
    Set-UiInputTheme -Control $gatewayModeBox
    [void]$gatewayModeBox.Items.Add('自动使用该网卡当前默认网关')
    [void]$gatewayModeBox.Items.Add('手动指定网关')
    $dialog.Controls.Add($gatewayModeBox)

    $gatewayBox = [Windows.Forms.TextBox]::new()
    $gatewayBox.Location = [Drawing.Point]::new(170, 348)
    $gatewayBox.Size = [Drawing.Size]::new(450, 26)
    Set-UiInputTheme -Control $gatewayBox
    $dialog.Controls.Add($gatewayBox)

    $bypassCheck = [Windows.Forms.CheckBox]::new()
    $bypassCheck.Text = '同时绕过 Windows 系统代理（仅单个 IPv4）'
    $bypassCheck.AutoSize = $true
    $bypassCheck.ForeColor = $script:Theme.MutedText
    $bypassCheck.Location = [Drawing.Point]::new(170, 398)
    $dialog.Controls.Add($bypassCheck)

    $enabledCheck = [Windows.Forms.CheckBox]::new()
    $enabledCheck.Text = '启用此规则'
    $enabledCheck.AutoSize = $true
    $enabledCheck.ForeColor = $script:Theme.MutedText
    $enabledCheck.Location = [Drawing.Point]::new(170, 430)
    $enabledCheck.Checked = $true
    $dialog.Controls.Add($enabledCheck)

    $hint = [Windows.Forms.Label]::new()
    $hint.Text = '分组用于组织和批量计划；标签用于搜索。它们不会改变路由所有权。'
    $hint.AutoSize = $true
    $hint.ForeColor = $script:Theme.MutedText
    $hint.Location = [Drawing.Point]::new(170, 461)
    $dialog.Controls.Add($hint)

    $saveButton = New-UiButton -Text '保存' -Width 92 -Variant 'Primary'
    $saveButton.Location = [Drawing.Point]::new(426, 492)
    $dialog.Controls.Add($saveButton)

    $cancelButton = New-UiButton -Text '取消' -Width 92
    $cancelButton.Location = [Drawing.Point]::new(528, 492)
    $cancelButton.DialogResult = 'Cancel'
    $dialog.CancelButton = $cancelButton
    $dialog.Controls.Add($cancelButton)

    $gatewayModeBox.Add_SelectedIndexChanged({
        $gatewayBox.Enabled = $gatewayModeBox.SelectedIndex -eq 1
    })

    if ($isEdit) {
        $nameBox.Text = [string]$Rule.Name
        $groupBox.Text = Get-RuleGroup -Rule $Rule
        $tagsBox.Text = (@(Get-RuleTags -Rule $Rule) -join ', ')
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
            $group = $groupBox.Text.Trim()
            if ($group.Length -gt 60) { throw '分组名称不能超过 60 个字符。' }
            $tags = @(ConvertTo-NormalizedTags -Value $tagsBox.Text)
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
                Group = $group
                Tags = @($tags)
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
                    Group = '系统识别'
                    Tags = @('自动识别')
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

function Format-PlanForConfirmation {
    param([Parameter(Mandatory)]$Plan)

    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("规则：$($Plan.RuleName)")
    $lines.Add("动作：$($Plan.Action)")
    $lines.Add("目标：$($Plan.Destination)")
    $lines.Add("系统变更：$($Plan.SystemChangeCount) 项")
    $lines.Add('')

    if (@($Plan.Diff).Count -gt 0) {
        $lines.Add('变更 Diff')
        foreach ($entry in @($Plan.Diff)) {
            $mark = switch ([string]$entry.Operation) {
                'Add' { '+' }
                'Remove' { '-' }
                'Conflict' { '!' }
                'Blocked' { '!' }
                'Drift' { '~' }
                'KeepShared' { '=' }
                'KeepExternal' { '=' }
                'Keep' { '=' }
                default { '·' }
            }
            $lines.Add("$mark $($entry.Resource) / $($entry.Operation)")
            $lines.Add("    $($entry.Reason)")
        }
    }

    if (@($Plan.Warnings).Count -gt 0) {
        $lines.Add('')
        $lines.Add('警告')
        foreach ($warning in @($Plan.Warnings)) {
            $lines.Add("  - $warning")
        }
    }

    if (@($Plan.Errors).Count -gt 0) {
        $lines.Add('')
        $lines.Add('阻止执行的问题')
        foreach ($errorText in @($Plan.Errors)) {
            $lines.Add("  - $errorText")
        }
    }

    $lines.Add('')
    $shortFingerprint = if ([string]$Plan.Fingerprint.Length -gt 12) {
        [string]$Plan.Fingerprint.Substring(0, 12)
    } else {
        [string]$Plan.Fingerprint
    }
    $lines.Add("计划指纹：$shortFingerprint…")
    $lines -join [Environment]::NewLine
}

function Show-AddressExplainDialog {
    param([string]$InitialAddress = '')

    $dialog = [Windows.Forms.Form]::new()
    $dialog.Text = '选路解释器'
    $dialog.ClientSize = [Drawing.Size]::new(1080, 700)
    $dialog.MinimumSize = [Drawing.Size]::new(900, 600)
    $dialog.StartPosition = 'CenterParent'
    $dialog.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
    $dialog.BackColor = $script:Theme.Background
    $dialog.ForeColor = $script:Theme.WarmText
    $dialog.KeyPreview = $true

    $header = [Windows.Forms.Panel]::new()
    $header.Dock = 'Top'
    $header.Height = 104
    $header.Padding = [Windows.Forms.Padding]::new(18, 12, 18, 10)
    $header.BackColor = $script:Theme.Background
    $dialog.Controls.Add($header)

    $title = [Windows.Forms.Label]::new()
    $title.Text = '这个 IP 最终会怎么走？'
    $title.Font = [Drawing.Font]::new('Microsoft YaHei UI', 15, [Drawing.FontStyle]::Bold)
    $title.ForeColor = $script:Theme.Accent
    $title.AutoSize = $true
    $title.Location = [Drawing.Point]::new(18, 10)
    $header.Controls.Add($title)

    $sub = [Windows.Forms.Label]::new()
    $sub.Text = '只读查询。按 Windows 最长前缀优先规则解释最终路由，并同时展示匹配的管理器规则和代理绕过。'
    $sub.ForeColor = $script:Theme.MutedText
    $sub.AutoSize = $true
    $sub.Location = [Drawing.Point]::new(20, 43)
    $header.Controls.Add($sub)

    $addressBox = [Windows.Forms.TextBox]::new()
    $addressBox.Text = $InitialAddress
    $addressBox.Location = [Drawing.Point]::new(20, 69)
    $addressBox.Size = [Drawing.Size]::new(260, 26)
    Set-UiInputTheme -Control $addressBox
    $header.Controls.Add($addressBox)

    $queryButton = New-UiButton -Text '解释选路' -Width 96 -Variant 'Primary'
    $queryButton.Location = [Drawing.Point]::new(292, 64)
    $header.Controls.Add($queryButton)

    $copyButton = New-UiButton -Text '复制结论' -Width 96
    $copyButton.Location = [Drawing.Point]::new(396, 64)
    $header.Controls.Add($copyButton)

    $tabs = [Windows.Forms.TabControl]::new()
    $tabs.Dock = 'Fill'
    $dialog.Controls.Add($tabs)

    $overviewTab = [Windows.Forms.TabPage]::new()
    $overviewTab.Text = '结论'
    $overviewTab.BackColor = $script:Theme.Background
    $tabs.TabPages.Add($overviewTab)

    $routeTab = [Windows.Forms.TabPage]::new()
    $routeTab.Text = '候选路由'
    $routeTab.BackColor = $script:Theme.Background
    $tabs.TabPages.Add($routeTab)

    $ruleTab = [Windows.Forms.TabPage]::new()
    $ruleTab.Text = '匹配规则'
    $ruleTab.BackColor = $script:Theme.Background
    $tabs.TabPages.Add($ruleTab)

    $overviewBox = [Windows.Forms.RichTextBox]::new()
    $overviewBox.Dock = 'Fill'
    $overviewBox.ReadOnly = $true
    $overviewBox.BorderStyle = 'None'
    $overviewBox.BackColor = $script:Theme.Surface
    $overviewBox.ForeColor = $script:Theme.WarmText
    $overviewBox.Font = [Drawing.Font]::new('Microsoft YaHei UI', 10)
    $overviewBox.Text = '输入单个 IPv4 地址后点击“解释选路”。'
    $overviewTab.Controls.Add($overviewBox)

    $routeGrid = [Windows.Forms.DataGridView]::new()
    $routeGrid.Dock = 'Fill'
    $routeGrid.ReadOnly = $true
    $routeGrid.AllowUserToAddRows = $false
    $routeGrid.AllowUserToDeleteRows = $false
    $routeGrid.RowHeadersVisible = $false
    $routeGrid.SelectionMode = 'FullRowSelect'
    $routeGrid.MultiSelect = $false
    $routeGrid.AutoGenerateColumns = $false
    Initialize-GridTheme -Grid $routeGrid
    $routeTab.Controls.Add($routeGrid)

    foreach ($spec in @(
        @('Prefix','目标前缀',170),
        @('Length','前缀长度',80),
        @('Adapter','网卡',220),
        @('Gateway','下一跳',150),
        @('Metric','Metric',90),
        @('Selected','最终',75)
    )) {
        $column = [Windows.Forms.DataGridViewTextBoxColumn]::new()
        $column.Name = $spec[0]
        $column.HeaderText = $spec[1]
        $column.Width = [int]$spec[2]
        if ($spec[0] -eq 'Adapter') { $column.AutoSizeMode = 'Fill' }
        [void]$routeGrid.Columns.Add($column)
    }

    $ruleGrid = [Windows.Forms.DataGridView]::new()
    $ruleGrid.Dock = 'Fill'
    $ruleGrid.ReadOnly = $true
    $ruleGrid.AllowUserToAddRows = $false
    $ruleGrid.AllowUserToDeleteRows = $false
    $ruleGrid.RowHeadersVisible = $false
    $ruleGrid.SelectionMode = 'FullRowSelect'
    $ruleGrid.MultiSelect = $false
    $ruleGrid.AutoGenerateColumns = $false
    Initialize-GridTheme -Grid $ruleGrid
    $ruleTab.Controls.Add($ruleGrid)

    foreach ($spec in @(
        @('Rule','规则',220),
        @('Prefix','目标前缀',160),
        @('Adapter','期望网卡',220),
        @('Gateway','期望网关',135),
        @('Status','状态',150),
        @('Controls','控制最终路由',105)
    )) {
        $column = [Windows.Forms.DataGridViewTextBoxColumn]::new()
        $column.Name = $spec[0]
        $column.HeaderText = $spec[1]
        $column.Width = [int]$spec[2]
        if ($spec[0] -eq 'Rule') { $column.AutoSizeMode = 'Fill' }
        [void]$ruleGrid.Columns.Add($column)
    }

    $script:lastAddressExplanationText = ''

    $runQuery = {
        $address = $addressBox.Text.Trim()
        try {
            $result = Get-AddressExplanation -Address $address
            $routeGrid.Rows.Clear()
            $ruleGrid.Rows.Clear()

            foreach ($route in @($result.CandidateRoutes)) {
                $isSelected = $false
                if ($null -ne $result.SelectedRoute) {
                    $isSelected =
                        [string]$route.Destination -eq [string]$result.SelectedRoute.Destination -and
                        [int]$route.InterfaceIndex -eq [int]$result.SelectedRoute.InterfaceIndex -and
                        [string]$route.Gateway -eq [string]$result.SelectedRoute.Gateway
                }
                [void]$routeGrid.Rows.Add(
                    [string]$route.Destination,
                    [string]$route.PrefixLength,
                    [string]$route.InterfaceAlias,
                    [string]$route.Gateway,
                    [string]$route.EffectiveMetric,
                    $(if ($isSelected) { '是' } else { '' })
                )
            }

            foreach ($rule in @($result.MatchingRules)) {
                [void]$ruleGrid.Rows.Add(
                    [string]$rule.Name,
                    [string]$rule.Destination,
                    [string]$rule.ExpectedAdapter,
                    [string]$rule.ExpectedGateway,
                    $(if ([string]::IsNullOrWhiteSpace([string]$rule.ResolutionError)) { [string]$rule.Status } else { [string]$rule.ResolutionError }),
                    $(if ($rule.ControlsSelectedRoute) { '是' } else { '' })
                )
            }

            $lines = [Collections.Generic.List[string]]::new()
            $lines.Add($result.Summary)
            $lines.Add('')
            $lines.Add('选路原则')
            $lines.Add('  ' + [string]$result.SelectionRule)
            $lines.Add('')

            if ($null -eq $result.SelectedRoute) {
                $lines.Add('最终路由：无')
            } else {
                $lines.Add('最终路由')
                $lines.Add("  前缀：$($result.SelectedRoute.Destination)")
                $lines.Add("  网卡：$($result.SelectedRoute.InterfaceAlias)  [Index $($result.SelectedRoute.InterfaceIndex)]")
                $lines.Add("  下一跳：$($result.SelectedRoute.Gateway)")
                $lines.Add("  Effective Metric：$($result.SelectedRoute.EffectiveMetric)")
            }
            $lines.Add('')
            $lines.Add("匹配的管理器规则：$(@($result.MatchingRules).Count) 条")
            $lines.Add("匹配的 Windows 路由：$(@($result.CandidateRoutes).Count) 条")
            $lines.Add("精确代理绕过：$(if ($result.ProxyBypassExactPresent) { '存在' } else { '不存在' })")
            $lines.Add("当前最终路由由管理器规则控制：$(if ($result.ManagedRuleControlsSelectedRoute) { '是' } else { '否' })")
            if ($result.ManagedRuleControlsSelectedRoute) {
                $lines.Add("控制规则：$($result.SelectedManagedRuleName)")
            }

            $script:lastAddressExplanationText = $lines -join [Environment]::NewLine
            $overviewBox.Text = $script:lastAddressExplanationText
            Write-AppLog -Message "选路解释：$address | $($result.Summary)"
        } catch {
            $script:lastAddressExplanationText = ''
            $overviewBox.Text = $_.Exception.Message
            [Windows.Forms.MessageBox]::Show($_.Exception.Message, '选路查询失败', 'OK', 'Error') | Out-Null
        }
    }

    $queryButton.Add_Click({ & $runQuery })
    $copyButton.Add_Click({
        if (-not [string]::IsNullOrWhiteSpace($script:lastAddressExplanationText)) {
            [Windows.Forms.Clipboard]::SetText($script:lastAddressExplanationText)
        }
    })
    $addressBox.Add_KeyDown({
        param($sender, $eventArgs)
        if ($eventArgs.KeyCode -eq 'Enter') {
            & $runQuery
            $eventArgs.SuppressKeyPress = $true
        }
    })
    $dialog.Add_Shown({
        $addressBox.Focus()
        $addressBox.SelectAll()
        if (-not [string]::IsNullOrWhiteSpace($addressBox.Text)) { & $runQuery }
    })

    [void]$dialog.ShowDialog($form)
}

function Show-SafetyCenter {
    $dialog = [Windows.Forms.Form]::new()
    $dialog.Text = '安全中心'
    $dialog.ClientSize = [Drawing.Size]::new(1060, 680)
    $dialog.MinimumSize = [Drawing.Size]::new(900, 580)
    $dialog.StartPosition = 'CenterParent'
    $dialog.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
    $dialog.BackColor = $script:Theme.Background
    $dialog.ForeColor = $script:Theme.WarmText

    $header = [Windows.Forms.Panel]::new()
    $header.Dock = 'Top'
    $header.Height = 82
    $header.BackColor = $script:Theme.Background
    $dialog.Controls.Add($header)

    $title = [Windows.Forms.Label]::new()
    $title.Text = '策略安全与恢复'
    $title.Font = [Drawing.Font]::new('Microsoft YaHei UI', 15, [Drawing.FontStyle]::Bold)
    $title.ForeColor = $script:Theme.Accent
    $title.AutoSize = $true
    $title.Location = [Drawing.Point]::new(18, 12)
    $header.Controls.Add($title)

    $sub = [Windows.Forms.Label]::new()
    $sub.Text = '审计当前规则风险，管理本机安全快照。规则恢复不会直接回放旧 Windows 路由。'
    $sub.ForeColor = $script:Theme.MutedText
    $sub.AutoSize = $true
    $sub.Location = [Drawing.Point]::new(20, 49)
    $header.Controls.Add($sub)

    $tabs = [Windows.Forms.TabControl]::new()
    $tabs.Dock = 'Fill'
    $dialog.Controls.Add($tabs)

    $auditTab = [Windows.Forms.TabPage]::new('策略审计')
    $auditTab.BackColor = $script:Theme.Background
    $tabs.TabPages.Add($auditTab)

    $backupTab = [Windows.Forms.TabPage]::new('安全快照')
    $backupTab.BackColor = $script:Theme.Background
    $tabs.TabPages.Add($backupTab)

    $auditBox = [Windows.Forms.RichTextBox]::new()
    $auditBox.Dock = 'Fill'
    $auditBox.ReadOnly = $true
    $auditBox.BorderStyle = 'None'
    $auditBox.BackColor = $script:Theme.Surface
    $auditBox.ForeColor = $script:Theme.WarmText
    $auditBox.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
    $auditTab.Controls.Add($auditBox)

    $backupGrid = [Windows.Forms.DataGridView]::new()
    $backupGrid.Dock = 'Fill'
    $backupGrid.ReadOnly = $true
    $backupGrid.AllowUserToAddRows = $false
    $backupGrid.AllowUserToDeleteRows = $false
    $backupGrid.RowHeadersVisible = $false
    $backupGrid.SelectionMode = 'FullRowSelect'
    $backupGrid.MultiSelect = $false
    $backupGrid.AutoGenerateColumns = $false
    Initialize-GridTheme -Grid $backupGrid
    $backupTab.Controls.Add($backupGrid)

    foreach ($spec in @(
        @('CreatedAt','时间',180),
        @('Reason','原因',220),
        @('RuleId','关联规则',180),
        @('Integrity','完整性',90),
        @('Id','Backup ID',210)
    )) {
        $column = [Windows.Forms.DataGridViewTextBoxColumn]::new()
        $column.Name = $spec[0]
        $column.HeaderText = $spec[1]
        $column.Width = [int]$spec[2]
        if ($spec[0] -eq 'Id') { $column.AutoSizeMode = 'Fill' }
        [void]$backupGrid.Columns.Add($column)
    }

    $buttons = [Windows.Forms.FlowLayoutPanel]::new()
    $buttons.Dock = 'Bottom'
    $buttons.Height = 58
    $buttons.Padding = [Windows.Forms.Padding]::new(8, 4, 12, 4)
    $buttons.FlowDirection = 'RightToLeft'
    $buttons.BackColor = $script:Theme.Background
    $dialog.Controls.Add($buttons)

    $closeButton = New-UiButton -Text '关闭' -Width 88
    $refreshSafetyButton = New-UiButton -Text '重新审计' -Width 96
    $createSnapshotButton = New-UiButton -Text '创建快照' -Width 96 -Variant 'Accent'
    $restoreSnapshotButton = New-UiButton -Text '恢复所选规则' -Width 112 -Variant 'Danger'
    $buttons.Controls.Add($closeButton)
    $buttons.Controls.Add($restoreSnapshotButton)
    $buttons.Controls.Add($createSnapshotButton)
    $buttons.Controls.Add($refreshSafetyButton)

    $refreshSafety = {
        $audit = Get-PolicyAudit
        $lines = [Collections.Generic.List[string]]::new()
        $lines.Add("健康状态：$(if ($audit.Healthy) { '通过' } else { '需要处理' })")
        $lines.Add("Critical=$($audit.Summary.Critical)  Error=$($audit.Summary.Error)  Warning=$($audit.Summary.Warning)  Info=$($audit.Summary.Info)")
        $lines.Add('')
        if (@($audit.Issues).Count -eq 0) {
            $lines.Add('没有发现规则审计问题。')
        } else {
            foreach ($issue in @($audit.Issues)) {
                $other = if ($issue.PSObject.Properties.Name -contains 'OtherRuleName' -and
                    -not [string]::IsNullOrWhiteSpace([string]$issue.OtherRuleName)) {
                    " / $($issue.OtherRuleName)"
                } else { '' }
                $lines.Add("[$($issue.Severity)] $($issue.RuleName)$other")
                $lines.Add("  $($issue.Message)")
                $lines.Add('')
            }
        }
        $auditBox.Text = $lines -join [Environment]::NewLine

        $backupGrid.Rows.Clear()
        foreach ($backup in @(Get-SafetyBackupList)) {
            $rowIndex = $backupGrid.Rows.Add(
                [string]$backup.CreatedAt,
                [string]$backup.Reason,
                [string]$backup.RuleId,
                $(if ($backup.IntegrityOk) { '正常' } else { '失败' }),
                [string]$backup.Id
            )
            $backupGrid.Rows[$rowIndex].Tag = $backup
            if (-not [bool]$backup.IntegrityOk) {
                $backupGrid.Rows[$rowIndex].DefaultCellStyle.BackColor = $script:Theme.AccentStrong
                $backupGrid.Rows[$rowIndex].DefaultCellStyle.ForeColor = $script:Theme.WarmText
            }
        }
    }

    $closeButton.Add_Click({ $dialog.Close() })
    $refreshSafetyButton.Add_Click({ & $refreshSafety })
    $createSnapshotButton.Add_Click({
        try {
            $backup = New-SafetySnapshot -Reason 'manual-gui-backup'
            [Windows.Forms.MessageBox]::Show(
                "安全快照已创建：$($backup.Id)",
                '快照完成', 'OK', 'Information') | Out-Null
            & $refreshSafety
        } catch {
            [Windows.Forms.MessageBox]::Show($_.Exception.Message, '创建快照失败', 'OK', 'Error') | Out-Null
        }
    })
    $restoreSnapshotButton.Add_Click({
        if ($backupGrid.SelectedRows.Count -eq 0) {
            [Windows.Forms.MessageBox]::Show('请先选择一个安全快照。', '提示', 'OK', 'Information') | Out-Null
            return
        }
        $backup = $backupGrid.SelectedRows[0].Tag
        if (-not [bool]$backup.IntegrityOk) {
            [Windows.Forms.MessageBox]::Show('该快照完整性校验失败，禁止恢复。', '禁止恢复', 'OK', 'Error') | Out-Null
            return
        }
        $answer = [Windows.Forms.MessageBox]::Show(
            "将从快照 $($backup.Id) 恢复规则定义。" +
            [Environment]::NewLine +
            '不会直接修改 Windows 路由；恢复后的已有路由/代理所有权标记会被清除。是否继续？',
            '确认恢复规则', 'YesNo', 'Warning')
        if ($answer -ne 'Yes') { return }

        $lock = $null
        try {
            $lock = Enter-MutationLock
            $result = Restore-RulesFromSafetyBackup -Id ([string]$backup.Id)
            [Windows.Forms.MessageBox]::Show(
                "已恢复 $($result.RuleCount) 条规则。" +
                [Environment]::NewLine +
                "恢复前快照：$($result.PreRestoreBackupId)" +
                [Environment]::NewLine +
                '请重新审计并按需应用规则。',
                '恢复完成', 'OK', 'Information') | Out-Null
            Refresh-Grid
            & $refreshSafety
        } catch {
            [Windows.Forms.MessageBox]::Show($_.Exception.Message, '恢复失败', 'OK', 'Error') | Out-Null
        } finally {
            Exit-MutationLock -Mutex $lock
        }
    })

    & $refreshSafety
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

$metrics = [Windows.Forms.TableLayoutPanel]::new()
$metrics.Dock = 'Fill'
$metrics.ColumnCount = 4
$metrics.RowCount = 1
$metrics.Padding = [Windows.Forms.Padding]::new(7, 0, 7, 0)
$metrics.BackColor = $script:Theme.Background
1..4 | ForEach-Object {
    [void]$metrics.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent', 25))
}
[void]$metrics.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100))

$ruleMetric = New-MetricCard -Title '规则状态' -Value '正在读取…'
$adapterMetric = New-MetricCard -Title '已连接实体网卡' -Value '正在识别…'
$routeMetric = New-MetricCard -Title '当前默认出口' -Value '正在识别…'
$pendingMetric = New-MetricCard -Title '待处理现有策略' -Value '正在识别…'
$metricCards = @($ruleMetric, $adapterMetric, $routeMetric, $pendingMetric)
for ($i = 0; $i -lt $metricCards.Count; $i++) {
    $metricCards[$i].Panel.Dock = 'Fill'
    $metricCards[$i].Panel.Margin = [Windows.Forms.Padding]::new(7, 7, 7, 5)
    $metricCards[$i].Value.Anchor = 'Top,Left,Right'
    $metricCards[$i].Value.Width = 260
    [void]$metrics.Controls.Add($metricCards[$i].Panel, $i, 0)
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
$explainButton = New-UiButton -Text '选路查询' -Width 92 -Variant 'Accent'
$backupButton = New-UiButton -Text '备份规则' -Width 92
$restoreButton = New-UiButton -Text '导入备份' -Width 92
$safetyButton = New-UiButton -Text '安全中心' -Width 92 -Variant 'Accent'

@($discoverButton, $addButton, $applyAllButton, $refreshButton, $explainButton, $safetyButton, $backupButton, $restoreButton) |
    ForEach-Object { [void]$toolbar.Controls.Add($_) }

$searchLabel = [Windows.Forms.Label]::new()
$searchLabel.Text = '搜索'
$searchLabel.AutoSize = $true
$searchLabel.ForeColor = $script:Theme.MutedText
$searchLabel.Margin = [Windows.Forms.Padding]::new(16, 14, 4, 0)
$toolbar.Controls.Add($searchLabel)

$searchBox = [Windows.Forms.TextBox]::new()
$searchBox.Width = 160
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

$groupFilterBox = [Windows.Forms.ComboBox]::new()
$groupFilterBox.Width = 128
$groupFilterBox.DropDownStyle = 'DropDownList'
$groupFilterBox.DisplayMember = 'Display'
$groupFilterBox.Margin = [Windows.Forms.Padding]::new(8, 10, 4, 0)
Set-UiInputTheme -Control $groupFilterBox
$toolbar.Controls.Add($groupFilterBox)

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
Add-GridColumn -Name 'Name' -Header '规则' -Width 190
Add-GridColumn -Name 'Group' -Header '分组' -Width 105
Add-GridColumn -Name 'Destination' -Header '目标 IPv4 / CIDR' -Width 145
Add-GridColumn -Name 'Adapter' -Header '指定网卡' -Width 145
Add-GridColumn -Name 'Gateway' -Header '网关' -Width 135
Add-GridColumn -Name 'Proxy' -Header '代理' -Width 58
Add-GridColumn -Name 'Status' -Header '当前状态' -Width 190
Add-GridColumn -Name 'Actual' -Header '实际路由' -Width 150 -AutoSizeMode 'Fill'

$detailPanel = [Windows.Forms.TableLayoutPanel]::new()
$detailPanel.Dock = 'Fill'
$detailPanel.BackColor = $script:Theme.SurfaceAlt
$detailPanel.ColumnCount = 1
$detailPanel.RowCount = 3
[void]$detailPanel.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent', 100))
[void]$detailPanel.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 108))
[void]$detailPanel.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100))
[void]$detailPanel.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 162))

$detailHeader = [Windows.Forms.Panel]::new()
$detailHeader.Dock = 'Top'
$detailHeader.Height = 108
$detailHeader.Padding = [Windows.Forms.Padding]::new(16, 12, 16, 4)
$detailHeader.BackColor = $script:Theme.SurfaceAlt
$detailPanel.Controls.Add($detailHeader, 0, 0)

$detailTitle = [Windows.Forms.Label]::new()
$detailTitle.Text = 'RULE DETAIL'
$detailTitle.Font = [Drawing.Font]::new('Segoe UI', 8, [Drawing.FontStyle]::Bold)
$detailTitle.ForeColor = $script:Theme.AccentStrong
$detailTitle.AutoSize = $true
$detailTitle.Location = [Drawing.Point]::new(16, 12)
$detailHeader.Controls.Add($detailTitle)

$detailNameLabel = [Windows.Forms.Label]::new()
$detailNameLabel.Text = '选择一条规则'
$detailNameLabel.Font = [Drawing.Font]::new('Microsoft YaHei UI', 14, [Drawing.FontStyle]::Bold)
$detailNameLabel.ForeColor = $script:Theme.Accent
$detailNameLabel.AutoEllipsis = $true
$detailNameLabel.Location = [Drawing.Point]::new(15, 34)
$detailNameLabel.Anchor = 'Top,Left,Right'
$detailNameLabel.Size = [Drawing.Size]::new(315, 30)
$detailHeader.Controls.Add($detailNameLabel)

$detailStateLabel = [Windows.Forms.Label]::new()
$detailStateLabel.Text = '—'
$detailStateLabel.TextAlign = 'MiddleCenter'
$detailStateLabel.BackColor = $script:Theme.Background
$detailStateLabel.ForeColor = $script:Theme.MutedText
$detailStateLabel.Location = [Drawing.Point]::new(16, 72)
$detailStateLabel.Size = [Drawing.Size]::new(150, 26)
$detailHeader.Controls.Add($detailStateLabel)

$detailActions = [Windows.Forms.FlowLayoutPanel]::new()
$detailActions.Dock = 'Bottom'
$detailActions.Height = 162
$detailActions.Padding = [Windows.Forms.Padding]::new(10, 6, 10, 4)
$detailActions.WrapContents = $true
$detailActions.BackColor = $script:Theme.SurfaceAlt
$detailPanel.Controls.Add($detailActions, 0, 2)

$applyButton = New-UiButton -Text '应用' -Width 145 -Variant 'Primary'
$testButton = New-UiButton -Text '诊断' -Width 145 -Variant 'Accent'
$editButton = New-UiButton -Text '修改' -Width 145
$copyDetailButton = New-UiButton -Text '复制详情' -Width 145
$removeButton = New-UiButton -Text '撤销' -Width 145 -Variant 'Danger'
$deleteButton = New-UiButton -Text '删除' -Width 145 -Variant 'Danger'
@($applyButton, $testButton, $editButton, $copyDetailButton, $removeButton, $deleteButton) |
    ForEach-Object { [void]$detailActions.Controls.Add($_) }

$detailBody = [Windows.Forms.Panel]::new()
$detailBody.Dock = 'Fill'
$detailBody.Padding = [Windows.Forms.Padding]::new(16, 8, 16, 8)
$detailBody.BackColor = $script:Theme.SurfaceAlt
$detailPanel.Controls.Add($detailBody, 0, 1)

$detailBox = [Windows.Forms.RichTextBox]::new()
$detailBox.Dock = 'Fill'
$detailBox.ReadOnly = $true
$detailBox.BorderStyle = 'None'
$detailBox.BackColor = $script:Theme.SurfaceAlt
$detailBox.ForeColor = $script:Theme.WarmText
$detailBox.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
$detailBox.Text = "选择左侧规则后，这里会显示期望出口、当前状态和所有权信息。"
$detailBody.Controls.Add($detailBox)

$split = [Windows.Forms.SplitContainer]::new()
$split.Size = [Drawing.Size]::new(1340, 400)
$split.Dock = 'Fill'
$split.Orientation = 'Vertical'
$split.SplitterWidth = 5
$split.Panel1MinSize = 650
$split.Panel2MinSize = 330
$split.SplitterDistance = 985
$split.BackColor = $script:Theme.Border
$split.Panel1.BackColor = $script:Theme.Background
$split.Panel2.BackColor = $script:Theme.SurfaceAlt
$split.Panel1.Controls.Add($grid)
$split.Panel2.Controls.Add($detailPanel)

$logPanel = [Windows.Forms.Panel]::new()
$logPanel.Dock = 'Fill'
$logPanel.BackColor = $script:Theme.SurfaceAlt

$logLayout = [Windows.Forms.TableLayoutPanel]::new()
$logLayout.Dock = 'Fill'
$logLayout.ColumnCount = 1
$logLayout.RowCount = 2
[void]$logLayout.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent', 100))
[void]$logLayout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 24))
[void]$logLayout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100))
$logPanel.Controls.Add($logLayout)

$logTitle = [Windows.Forms.Label]::new()
$logTitle.Text = '操作日志'
$logTitle.Dock = 'Fill'
$logTitle.Padding = [Windows.Forms.Padding]::new(12, 4, 0, 0)
$logTitle.ForeColor = $script:Theme.MutedText
$logTitle.Font = [Drawing.Font]::new('Microsoft YaHei UI', 8, [Drawing.FontStyle]::Bold)
$logLayout.Controls.Add($logTitle, 0, 0)

$logBox = [Windows.Forms.RichTextBox]::new()
$logBox.Dock = 'Fill'
$logBox.ReadOnly = $true
$logBox.BackColor = $script:Theme.SurfaceAlt
$logBox.ForeColor = $script:Theme.Accent
$logBox.BorderStyle = 'None'
$logBox.Font = [Drawing.Font]::new('Consolas', 9)
$logLayout.Controls.Add($logBox, 0, 1)
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

    $groupText = Get-RuleGroupDisplay -Rule $rule
    $tagsText = @(Get-RuleTags -Rule $rule) -join ', '
    if ([string]::IsNullOrWhiteSpace($tagsText)) { $tagsText = '—' }

    $detailBox.Text = @(
        "分组        $groupText",
        "标签        $tagsText",
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
        '双击规则可修改；诊断会检查 Windows 最终选路、代理绕过和管理状态。'
    ) -join [Environment]::NewLine

    Set-SelectedActionState -HasSelection $true
}

function Get-SelectedGroupFilterKey {
    if ($null -eq $groupFilterBox.SelectedItem) { return '*' }
    if ($groupFilterBox.SelectedItem.PSObject.Properties.Name -contains 'Key') {
        return [string]$groupFilterBox.SelectedItem.Key
    }
    '*'
}

function Refresh-GroupFilterOptions {
    $selectedKey = Get-SelectedGroupFilterKey
    $groupFilterBox.BeginUpdate()
    try {
        $groupFilterBox.Items.Clear()
        [void]$groupFilterBox.Items.Add([pscustomobject]@{ Key = '*'; Display = '全部分组' })
        [void]$groupFilterBox.Items.Add([pscustomobject]@{ Key = ''; Display = '未分组' })
        foreach ($summary in @(Get-GroupSummaries | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Group) })) {
            [void]$groupFilterBox.Items.Add([pscustomobject]@{
                Key = [string]$summary.Group
                Display = "$($summary.DisplayName) ($($summary.RuleCount))"
            })
        }

        $target = 0
        for ($i = 0; $i -lt $groupFilterBox.Items.Count; $i++) {
            if ([string]$groupFilterBox.Items[$i].Key -eq $selectedKey) {
                $target = $i
                break
            }
        }
        $groupFilterBox.SelectedIndex = $target
    } finally {
        $groupFilterBox.EndUpdate()
    }
}

function Test-ItemMatchesFilter {
    param([Parameter(Mandatory)]$Item)

    $query = $searchBox.Text.Trim()
    if (-not [string]::IsNullOrWhiteSpace($query)) {
        $haystack = @(
            [string]$Item.Rule.Name,
            (Get-RuleGroup -Rule $Item.Rule),
            (@(Get-RuleTags -Rule $Item.Rule) -join ' '),
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

    $selectedGroup = Get-SelectedGroupFilterKey
    if ($selectedGroup -ne '*' -and (Get-RuleGroup -Rule $Item.Rule) -ne $selectedGroup) {
        return $false
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
                (Get-RuleGroupDisplay -Rule $rule),
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
        $pendingMetric.Value.Text = if ($pending -eq 0) { '0 · 当前已归档' } else { "$pending 条 · 点击识别当前策略处理" }
        $pendingMetric.Panel.BackColor = if ($pending -gt 0) { $script:Theme.Accent } else { $script:Theme.SurfaceAlt }
        $pendingMetric.Value.ForeColor = if ($pending -gt 0) { $script:Theme.DarkText } else { $script:Theme.Accent }
        $pendingMetric.Title.ForeColor = if ($pending -gt 0) { $script:Theme.DarkText } else { $script:Theme.MutedText }

        $summaryLabel.Text = if ($pending -gt 0) {
            '已自动识别当前网络' + [Environment]::NewLine + "发现 $pending 条未纳入管理的现有策略"
        } else {
            '已自动识别当前网络' + [Environment]::NewLine + '当前没有待处理的现有策略'
        }
        $lastRefreshLabel.Text = "最后刷新 $(Get-Date -Format 'HH:mm:ss')"
        Refresh-GroupFilterOptions
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
    $hasRulesProperty = $null -ne $raw -and $raw.PSObject.Properties.Name -contains 'Rules'
    $incoming = if ($hasRulesProperty) { @($raw.Rules) } else { @($raw) }
    if ($incoming.Count -eq 0) {
        [Windows.Forms.MessageBox]::Show('备份中没有规则。', '无法导入', 'OK', 'Warning') | Out-Null
        return
    }

    $answer = [Windows.Forms.MessageBox]::Show(
        "备份包含 $($incoming.Count) 条规则，将替换当前 $($script:Rules.Count) 条规则定义。" +
        [Environment]::NewLine +
        '程序会先自动保存当前规则的安全备份；导入后会清除“接管已有路由/代理”的所有权标记，也不会立即修改 Windows 网络。是否继续？',
        '确认替换当前规则', 'YesNo', 'Warning')
    if ($answer -ne 'Yes') { return }

    $safetySnapshot = New-SafetySnapshot -Reason 'before-import-rule-backup'

    $normalized = foreach ($rule in $incoming) {
        [pscustomobject]@{
            Id = if ([string]::IsNullOrWhiteSpace([string]$rule.Id)) { [Guid]::NewGuid().ToString('N') } else { [string]$rule.Id }
            Name = [string]$rule.Name
            Group = Get-RuleGroup -Rule $rule
            Tags = @(Get-RuleTags -Rule $rule)
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
        Write-AppLog -Message "已从备份替换为 $($script:Rules.Count) 条规则定义：$($dialog.FileName)"
        Write-AppLog -Message "导入前安全快照：$($safetySnapshot.Id)"
        [Windows.Forms.MessageBox]::Show(
            "规则导入完成。" + [Environment]::NewLine +
            "导入前安全快照：" + $safetySnapshot.Id,
            '导入完成', 'OK', 'Information') | Out-Null
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
        [void](New-SafetySnapshot -Reason 'before-gui-add-rule')
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

    [void](New-SafetySnapshot -Reason 'before-gui-edit-rule' -RuleId ([string]$oldRule.Id))

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
$groupFilterBox.Add_SelectedIndexChanged({
    $key = Get-SelectedGroupFilterKey
    $applyAllButton.Text = if ($key -eq '*') { '应用全部' } else { '应用分组' }
    Render-RuleGrid
})

$explainButton.Add_Click({
    $initial = ''
    $rule = Get-SelectedRule
    if ($null -ne $rule) {
        try {
            $prefix = ConvertTo-NormalizedPrefix -Value ([string]$rule.Destination)
            $initial = [string]$prefix.Split('/')[0]
        } catch { }
    }
    Show-AddressExplainDialog -InitialAddress $initial
})
$safetyButton.Add_Click({ Show-SafetyCenter })

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

    try {
        $plan = Get-RulePlan -Rule $rule -Action 'Apply'
        $message = Format-PlanForConfirmation -Plan $plan
        if (-not [bool]$plan.Allowed) {
            [Windows.Forms.MessageBox]::Show($message, '应用计划被阻止', 'OK', 'Error') | Out-Null
            return
        }

        $icon = if (@($plan.Warnings).Count -gt 0) { 'Warning' } else { 'Question' }
        $answer = [Windows.Forms.MessageBox]::Show(
            $message + [Environment]::NewLine + [Environment]::NewLine + '确认按此计划应用？',
            '确认应用计划', 'YesNo', $icon)
        if ($answer -ne 'Yes') { return }

        $form.Cursor = [Windows.Forms.Cursors]::WaitCursor
        Apply-RulePolicy -Rule $rule -ExpectedFingerprint ([string]$plan.Fingerprint)
        $result = Test-RulePolicy -Rule $rule
        Write-AppLog -Message "应用后验证：$($rule.Name) | Healthy=$($result.Healthy)"
        Refresh-Grid
    } catch {
        Write-AppLog -Message ("应用失败：" + $_.Exception.Message) -Level 'ERROR'
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, '应用失败', 'OK', 'Error') | Out-Null
    } finally {
        $form.Cursor = [Windows.Forms.Cursors]::Default
    }
})

$applyAllButton.Add_Click({
    $selectedGroup = Get-SelectedGroupFilterKey
    $planned = [Collections.Generic.List[object]]::new()
    $blocked = [Collections.Generic.List[string]]::new()
    $summary = [Collections.Generic.List[string]]::new()

    if ($selectedGroup -eq '*') {
        $enabledRules = @($script:Rules | Where-Object Enabled)
        if ($enabledRules.Count -eq 0) { return }

        $summary.Add("将检查并应用 $($enabledRules.Count) 条启用规则：")
        $summary.Add('')
        foreach ($rule in $enabledRules) {
            $plan = Get-RulePlan -Rule $rule -Action 'Apply'
            $planned.Add([pscustomobject]@{ Rule = $rule; Plan = $plan })
            if (-not [bool]$plan.Allowed) {
                $blocked.Add("$($rule.Name)：$(@($plan.Errors) -join '；')")
            }
            $summary.Add("• $($rule.Name)  系统变更=$($plan.SystemChangeCount)  警告=$(@($plan.Warnings).Count)")
        }
    } else {
        $groupPlan = Get-GroupPlan -GroupName $selectedGroup -Action 'Apply'
        if ([int]$groupPlan.RuleCount -eq 0) {
            [Windows.Forms.MessageBox]::Show(
                "分组「$($groupPlan.DisplayName)」没有启用规则。",
                '无需应用', 'OK', 'Information') | Out-Null
            return
        }

        $summary.Add("分组「$($groupPlan.DisplayName)」：$($groupPlan.RuleCount) 条启用规则，预计系统变更 $($groupPlan.SystemChangeCount) 项。")
        $summary.Add('')
        foreach ($plan in @($groupPlan.Plans)) {
            $rule = Get-RuleById -Id ([string]$plan.RuleId)
            $planned.Add([pscustomobject]@{ Rule = $rule; Plan = $plan })
            if (-not [bool]$plan.Allowed) {
                $blocked.Add("$($rule.Name)：$(@($plan.Errors) -join '；')")
            }
            $summary.Add("• $($rule.Name)  系统变更=$($plan.SystemChangeCount)  警告=$(@($plan.Warnings).Count)")
        }
    }

    if ($blocked.Count -gt 0) {
        [Windows.Forms.MessageBox]::Show(
            "批量计划存在被阻止的规则，不执行任何修改。" +
            [Environment]::NewLine + [Environment]::NewLine +
            ($blocked -join [Environment]::NewLine),
            '批量应用被阻止', 'OK', 'Error') | Out-Null
        return
    }

    $summary.Add('')
    $summary.Add('每条规则执行前都会再次校验各自的计划指纹；任一计划失效或执行失败后立即停止。')
    $answer = [Windows.Forms.MessageBox]::Show(
        $summary -join [Environment]::NewLine,
        $(if ($selectedGroup -eq '*') { '确认应用全部计划' } else { '确认应用分组计划' }),
        'YesNo', 'Warning')
    if ($answer -ne 'Yes') { return }

    $form.Cursor = [Windows.Forms.Cursors]::WaitCursor
    $errors = [Collections.Generic.List[string]]::new()
    $success = 0
    try {
        foreach ($item in @($planned)) {
            try {
                Apply-RulePolicy -Rule $item.Rule -ExpectedFingerprint ([string]$item.Plan.Fingerprint)
                $success++
            } catch {
                $message = "$($item.Rule.Name)：$($_.Exception.Message)"
                $errors.Add($message)
                Write-AppLog -Message $message -Level 'ERROR'
                break
            }
        }
        Refresh-Grid
    } finally {
        $form.Cursor = [Windows.Forms.Cursors]::Default
    }

    if ($errors.Count -gt 0) {
        [Windows.Forms.MessageBox]::Show(
            "已成功 $success 条；随后停止。" + [Environment]::NewLine + [Environment]::NewLine +
            ($errors -join [Environment]::NewLine),
            '批量应用已停止', 'OK', 'Warning') | Out-Null
    } else {
        $scopeText = if ($selectedGroup -eq '*') { '全部启用规则' } else { "分组「$(if ([string]::IsNullOrWhiteSpace($selectedGroup)) { '未分组' } else { $selectedGroup })」" }
        [Windows.Forms.MessageBox]::Show(
            "$scopeText 已成功应用 $success 条规则。",
            '应用完成', 'OK', 'Information') | Out-Null
    }
})

$removeButton.Add_Click({
    $rule = Get-SelectedRule
    if ($null -eq $rule) { return }

    try {
        $plan = Get-RulePlan -Rule $rule -Action 'Remove'
        $message = Format-PlanForConfirmation -Plan $plan
        if (-not [bool]$plan.Allowed) {
            [Windows.Forms.MessageBox]::Show($message, '撤销计划被阻止', 'OK', 'Error') | Out-Null
            return
        }

        $answer = [Windows.Forms.MessageBox]::Show(
            $message + [Environment]::NewLine + [Environment]::NewLine + '确认只撤销本程序拥有的资源？',
            '确认撤销计划', 'YesNo', 'Warning')
        if ($answer -ne 'Yes') { return }

        Remove-RulePolicy -Rule $rule -ExpectedFingerprint ([string]$plan.Fingerprint)
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
    } elseif ($eventArgs.Control -and $eventArgs.KeyCode -eq 'Q') {
        Show-AddressExplainDialog
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
$toolTip.SetToolTip($searchBox, '按名称、分组、标签、目标、网卡、网关或状态搜索（Ctrl+F）')
$toolTip.SetToolTip($groupFilterBox, '按规则分组筛选；筛选分组后“应用全部”会变为“应用分组”')
$toolTip.SetToolTip($backupButton, '导出规则定义备份，不包含系统路由状态')
$toolTip.SetToolTip($restoreButton, '导入规则备份；不会立即修改 Windows 网络')
$toolTip.SetToolTip($applyButton, '先生成变更 Diff，再确认应用到 Windows')
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
