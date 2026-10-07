[CmdletBinding()]
param(
    [switch]$Ui,
    [switch]$Mcp
)

$ErrorActionPreference = 'Stop'
$manager = Join-Path $PSScriptRoot '本地网络策略管理器.ps1'
$mcpRoots = @(
    Join-Path $PSScriptRoot 'mcp-user'
    Join-Path $PSScriptRoot 'mcp-dev'
)

function Invoke-ManagerReadOnly {
    param([string[]]$Arguments)

    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $manager @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($output -join [Environment]::NewLine)
    }
    $output
}

function ConvertFrom-JsonArrayText {
    param([Parameter(Mandatory)][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    $parsed = $Text | ConvertFrom-Json
    if ($parsed -is [Array]) {
        foreach ($item in $parsed) { $item }
    } elseif ($null -ne $parsed) {
        $parsed
    }
}

Write-Host 'Core 纯逻辑单元测试...' -ForegroundColor Cyan
$coreTest = Join-Path $PSScriptRoot 'tests\pure-core.tests.ps1'
$coreOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $coreTest 2>&1
if ($LASTEXITCODE -ne 0 -or ($coreOutput -join [Environment]::NewLine) -notmatch 'PURE_CORE_TEST_OK') {
    throw "Core 单元测试失败：$($coreOutput -join [Environment]::NewLine)"
}
Write-Host ($coreOutput -join [Environment]::NewLine) -ForegroundColor Green

Write-Host '1/10 PowerShell / 配置自检...' -ForegroundColor Cyan
$selfTest = Invoke-ManagerReadOnly -Arguments @('-SelfTest')
Write-Host ($selfTest -join [Environment]::NewLine) -ForegroundColor Green

Write-Host '2/10 自动识别接口...' -ForegroundColor Cyan
$discoverText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'Discover')) -join [Environment]::NewLine
$discover = $discoverText | ConvertFrom-Json
Write-Host (
    "Adapters={0}; DefaultRoutes={1}; SpecificRoutes={2}; Unmanaged={3}" -f
    @($discover.Adapters).Count,
    @($discover.DefaultRoutes).Count,
    @($discover.SpecificRoutes).Count,
    ([int]$discover.UnmanagedSpecificRouteCount + [int]$discover.UnmanagedProxyBypassCount)
) -ForegroundColor Green

Write-Host '3/10 多网卡 / 虚拟网络路径信息...' -ForegroundColor Cyan
foreach ($adapter in @($discover.Adapters)) {
    if ($null -eq $adapter.PSObject.Properties['Kind']) {
        throw "Discover 网卡缺少 Kind：$($adapter.Name)"
    }
    if ($null -eq $adapter.PSObject.Properties['InterfaceMetric']) {
        throw "Discover 网卡缺少 InterfaceMetric：$($adapter.Name)"
    }
}
foreach ($route in @($discover.DefaultRoutes)) {
    foreach ($property in @('AdapterKind','RouteMetric','InterfaceMetric','EffectiveMetric')) {
        if ($null -eq $route.PSObject.Properties[$property]) {
            throw "DefaultRoute 缺少 $property。"
        }
    }
}
foreach ($route in @($discover.SpecificRoutes)) {
    foreach ($property in @('AdapterKind','RouteType','Actionable','EffectiveMetric')) {
        if ($null -eq $route.PSObject.Properties[$property]) {
            throw "SpecificRoute 缺少 $property。"
        }
    }
}
Write-Host (
    "AdapterKinds={0}; MultiDefault={1}; OnLink={2}; Preferred={3}" -f
    ((@($discover.Adapters | ForEach-Object Kind | Sort-Object -Unique)) -join ','),
    [bool]$discover.HasMultipleDefaultRoutes,
    [int]$discover.OnLinkRouteCount,
    $(if ($null -eq $discover.PreferredDefaultRoute) { 'none' } else { [string]$discover.PreferredDefaultRoute.InterfaceAlias })
) -ForegroundColor Green

Write-Host '4/10 策略安全审计...' -ForegroundColor Cyan
$auditText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'Audit')) -join [Environment]::NewLine
$audit = $auditText | ConvertFrom-Json
Write-Host (
    "Audit Healthy={0}; Critical={1}; Error={2}; Warning={3}" -f
    [bool]$audit.Healthy,
    [int]$audit.Summary.Critical,
    [int]$audit.Summary.Error,
    [int]$audit.Summary.Warning
) -ForegroundColor Green

Write-Host '5/10 状态漂移检测...' -ForegroundColor Cyan
$driftText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'Drift')) -join [Environment]::NewLine
$drift = $driftText | ConvertFrom-Json
if ($null -eq $drift.PSObject.Properties['Items'] -or $null -eq $drift.PSObject.Properties['Summary']) {
    throw 'Drift 输出缺少 Items 或 Summary。'
}
Write-Host (
    "Drift Healthy={0}; DriftCount={1}; Repairable={2}; ManualOnly={3}" -f
    [bool]$drift.Healthy,
    [int]$drift.DriftCount,
    [int]$drift.Summary.Repairable,
    [int]$drift.Summary.ManualOnly
) -ForegroundColor Green

$repairable = @($drift.Items | Where-Object { [bool]$_.Repairable -and -not [string]::IsNullOrWhiteSpace([string]$_.RuleId) } | Select-Object -First 1)
if ($repairable.Count -gt 0) {
    $repairText = (Invoke-ManagerReadOnly -Arguments @('-Command','PlanRepair','-RuleId',[string]$repairable[0].RuleId)) -join [Environment]::NewLine
    $repair = $repairText | ConvertFrom-Json
    if ($null -eq $repair.PSObject.Properties['Plan'] -or [string]::IsNullOrWhiteSpace([string]$repair.Fingerprint)) {
        throw 'PlanRepair 缺少 Plan 或 Fingerprint。'
    }
    Write-Host "RepairPlan Rule=$($repair.RuleName); Action=$($repair.RecommendedAction); Allowed=$($repair.Plan.Allowed)" -ForegroundColor Green
}

Write-Host '6/10 IPv4 选路解释...' -ForegroundColor Cyan
$explainText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'ExplainAddress', '-Address', '127.0.0.1')) -join [Environment]::NewLine
$explain = $explainText | ConvertFrom-Json
if ([string]$explain.Address -ne '127.0.0.1') {
    throw 'ExplainAddress 返回地址不一致。'
}
if ([string]::IsNullOrWhiteSpace([string]$explain.SelectionRule)) {
    throw 'ExplainAddress 缺少选路原则。'
}
if ($null -ne $explain.SelectedRoute) {
    foreach ($property in @('AdapterKind','RouteMetric','InterfaceMetric','EffectiveMetric')) {
        if ($null -eq $explain.SelectedRoute.PSObject.Properties[$property]) {
            throw "ExplainAddress SelectedRoute 缺少 $property。"
        }
    }
}
Write-Host (
    "Explain Address={0}; Routes={1}; Rules={2}; Managed={3}" -f
    [string]$explain.Address,
    @($explain.CandidateRoutes).Count,
    @($explain.MatchingRules).Count,
    [bool]$explain.ManagedRuleControlsSelectedRoute
) -ForegroundColor Green

Write-Host '7/10 变更计划 Diff...' -ForegroundColor Cyan
$rulesText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'ListRules')) -join [Environment]::NewLine
$rules = @(ConvertFrom-JsonArrayText -Text $rulesText)
if ($rules.Count -gt 0) {
    $planText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'PlanRule', '-RuleId', [string]$rules[0].Id, '-Action', 'Apply')) -join [Environment]::NewLine
    $plan = $planText | ConvertFrom-Json
    if ($null -eq $plan.PSObject.Properties['Diff']) {
        throw 'PlanRule 缺少 Diff。'
    }
    if ($null -eq $plan.PSObject.Properties['SystemChangeCount']) {
        throw 'PlanRule 缺少 SystemChangeCount。'
    }
    Write-Host (
        "Plan Rule={0}; Allowed={1}; Diff={2}; SystemChanges={3}" -f
        [string]$plan.RuleName,
        [bool]$plan.Allowed,
        @($plan.Diff).Count,
        [int]$plan.SystemChangeCount
    ) -ForegroundColor Green
} else {
    Write-Host '当前没有规则，跳过 PlanRule Diff 检查。' -ForegroundColor DarkYellow
}

Write-Host '8/10 分组与整组计划...' -ForegroundColor Cyan
$groupsText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'ListGroups')) -join [Environment]::NewLine
$groups = @(ConvertFrom-JsonArrayText -Text $groupsText)
if ($groups.Count -eq 0 -and $rules.Count -gt 0) {
    throw 'ListGroups 未返回已有规则对应的分组。'
}
if ($groups.Count -gt 0) {
    $firstGroup = [string]$groups[0].Group
    $groupArgs = @('-Command', 'PlanGroup', '-Action', 'Apply')
    if (-not [string]::IsNullOrWhiteSpace($firstGroup)) {
        $groupArgs += @('-Group', $firstGroup)
    }
    $groupPlanText = (Invoke-ManagerReadOnly -Arguments $groupArgs) -join [Environment]::NewLine
    $groupPlan = $groupPlanText | ConvertFrom-Json
    if ($null -eq $groupPlan.PSObject.Properties['Plans']) {
        throw 'PlanGroup 缺少 Plans。'
    }
    Write-Host (
        "Groups={0}; First={1}; Rules={2}; Allowed={3}; SystemChanges={4}" -f
        $groups.Count,
        [string]$groups[0].DisplayName,
        [int]$groupPlan.RuleCount,
        [bool]$groupPlan.Allowed,
        [int]$groupPlan.SystemChangeCount
    ) -ForegroundColor Green
}

Write-Host '9/10 规则状态输出...' -ForegroundColor Cyan
$statusText = (Invoke-ManagerReadOnly -Arguments @('-DumpStatus')) -join [Environment]::NewLine
if (-not [string]::IsNullOrWhiteSpace($statusText)) {
    [void]($statusText | ConvertFrom-Json)
}
Write-Host '规则状态 JSON 正常。' -ForegroundColor Green

if ($Ui) {
    Write-Host '10/10 UI Smoke Test...' -ForegroundColor Cyan
    $imagePath = Join-Path $PSScriptRoot 'ui-smoke-test.png'
    Remove-Item -LiteralPath $imagePath -Force -ErrorAction SilentlyContinue
    $uiOutput = Invoke-ManagerReadOnly -Arguments @('-UiSmokeTest')
    if (-not (Test-Path -LiteralPath $imagePath)) {
        throw 'UI Smoke Test 未生成 ui-smoke-test.png。'
    }
    Write-Host "UI Smoke Test 完成：$imagePath" -ForegroundColor Green
} else {
    Write-Host '10/10 UI Smoke Test 已跳过；需要时使用 -Ui。' -ForegroundColor DarkYellow
}

if ($Mcp) {
    if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
        throw '请求 MCP 检查，但系统未找到 npm.cmd。'
    }
    foreach ($mcpRoot in $mcpRoots) {
        Push-Location $mcpRoot
        try {
            if (-not (Test-Path -LiteralPath (Join-Path $mcpRoot 'node_modules'))) {
                Write-Host "MCP 依赖不存在，执行 npm ci：$mcpRoot" -ForegroundColor Cyan
                & npm.cmd ci
                if ($LASTEXITCODE -ne 0) { throw "npm ci 失败：$mcpRoot" }
            }
            & npm.cmd run check
            if ($LASTEXITCODE -ne 0) { throw "MCP TypeScript 类型检查失败：$mcpRoot" }
            Write-Host "MCP TypeScript 检查通过：$mcpRoot" -ForegroundColor Green
        } finally {
            Pop-Location
        }
    }
}

Write-Host '全部只读检查完成。' -ForegroundColor Green
