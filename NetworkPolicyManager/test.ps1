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

Write-Host '1/6 PowerShell / 配置自检...' -ForegroundColor Cyan
$selfTest = Invoke-ManagerReadOnly -Arguments @('-SelfTest')
Write-Host ($selfTest -join [Environment]::NewLine) -ForegroundColor Green

Write-Host '2/6 自动识别接口...' -ForegroundColor Cyan
$discoverText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'Discover')) -join [Environment]::NewLine
$discover = $discoverText | ConvertFrom-Json
Write-Host (
    "Adapters={0}; DefaultRoutes={1}; SpecificRoutes={2}; Unmanaged={3}" -f
    @($discover.Adapters).Count,
    @($discover.DefaultRoutes).Count,
    @($discover.SpecificRoutes).Count,
    ([int]$discover.UnmanagedSpecificRouteCount + [int]$discover.UnmanagedProxyBypassCount)
) -ForegroundColor Green

Write-Host '3/6 策略安全审计...' -ForegroundColor Cyan
$auditText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'Audit')) -join [Environment]::NewLine
$audit = $auditText | ConvertFrom-Json
Write-Host (
    "Audit Healthy={0}; Critical={1}; Error={2}; Warning={3}" -f
    [bool]$audit.Healthy,
    [int]$audit.Summary.Critical,
    [int]$audit.Summary.Error,
    [int]$audit.Summary.Warning
) -ForegroundColor Green

Write-Host '4/6 IPv4 选路解释...' -ForegroundColor Cyan
$explainText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'ExplainAddress', '-Address', '127.0.0.1')) -join [Environment]::NewLine
$explain = $explainText | ConvertFrom-Json
if ([string]$explain.Address -ne '127.0.0.1') {
    throw 'ExplainAddress 返回地址不一致。'
}
if ([string]::IsNullOrWhiteSpace([string]$explain.SelectionRule)) {
    throw 'ExplainAddress 缺少选路原则。'
}
Write-Host (
    "Explain Address={0}; Routes={1}; Rules={2}; Managed={3}" -f
    [string]$explain.Address,
    @($explain.CandidateRoutes).Count,
    @($explain.MatchingRules).Count,
    [bool]$explain.ManagedRuleControlsSelectedRoute
) -ForegroundColor Green

Write-Host '5/6 规则状态输出...' -ForegroundColor Cyan
$statusText = (Invoke-ManagerReadOnly -Arguments @('-DumpStatus')) -join [Environment]::NewLine
if (-not [string]::IsNullOrWhiteSpace($statusText)) {
    [void]($statusText | ConvertFrom-Json)
}
Write-Host '规则状态 JSON 正常。' -ForegroundColor Green

if ($Ui) {
    Write-Host '6/6 UI Smoke Test...' -ForegroundColor Cyan
    $imagePath = Join-Path $PSScriptRoot 'ui-smoke-test.png'
    Remove-Item -LiteralPath $imagePath -Force -ErrorAction SilentlyContinue
    $uiOutput = Invoke-ManagerReadOnly -Arguments @('-UiSmokeTest')
    if (-not (Test-Path -LiteralPath $imagePath)) {
        throw 'UI Smoke Test 未生成 ui-smoke-test.png。'
    }
    Write-Host "UI Smoke Test 完成：$imagePath" -ForegroundColor Green
} else {
    Write-Host '6/6 UI Smoke Test 已跳过；需要时使用 -Ui。' -ForegroundColor DarkYellow
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
