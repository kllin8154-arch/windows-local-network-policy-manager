[CmdletBinding()]
param(
    [switch]$Ui,
    [switch]$Mcp
)

$ErrorActionPreference = 'Stop'
$manager = Join-Path $PSScriptRoot '本地网络策略管理器.ps1'
$mcpRoot = Join-Path $PSScriptRoot 'mcp'

function Invoke-ManagerReadOnly {
    param([string[]]$Arguments)

    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $manager @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($output -join [Environment]::NewLine)
    }
    $output
}

Write-Host '1/4 PowerShell / 配置自检...' -ForegroundColor Cyan
$selfTest = Invoke-ManagerReadOnly -Arguments @('-SelfTest')
Write-Host ($selfTest -join [Environment]::NewLine) -ForegroundColor Green

Write-Host '2/4 自动识别接口...' -ForegroundColor Cyan
$discoverText = (Invoke-ManagerReadOnly -Arguments @('-Command', 'Discover')) -join [Environment]::NewLine
$discover = $discoverText | ConvertFrom-Json
Write-Host (
    "Adapters={0}; DefaultRoutes={1}; SpecificRoutes={2}; Unmanaged={3}" -f
    @($discover.Adapters).Count,
    @($discover.DefaultRoutes).Count,
    @($discover.SpecificRoutes).Count,
    ([int]$discover.UnmanagedSpecificRouteCount + [int]$discover.UnmanagedProxyBypassCount)
) -ForegroundColor Green

Write-Host '3/4 规则状态输出...' -ForegroundColor Cyan
$statusText = (Invoke-ManagerReadOnly -Arguments @('-DumpStatus')) -join [Environment]::NewLine
if (-not [string]::IsNullOrWhiteSpace($statusText)) {
    [void]($statusText | ConvertFrom-Json)
}
Write-Host '规则状态 JSON 正常。' -ForegroundColor Green

if ($Ui) {
    Write-Host '4/4 UI Smoke Test...' -ForegroundColor Cyan
    $imagePath = Join-Path $PSScriptRoot 'ui-smoke-test.png'
    Remove-Item -LiteralPath $imagePath -Force -ErrorAction SilentlyContinue
    $uiOutput = Invoke-ManagerReadOnly -Arguments @('-UiSmokeTest')
    if (-not (Test-Path -LiteralPath $imagePath)) {
        throw 'UI Smoke Test 未生成 ui-smoke-test.png。'
    }
    Write-Host "UI Smoke Test 完成：$imagePath" -ForegroundColor Green
} else {
    Write-Host '4/4 UI Smoke Test 已跳过；需要时使用 -Ui。' -ForegroundColor DarkYellow
}

if ($Mcp) {
    if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
        throw '请求 MCP 检查，但系统未找到 npm.cmd。'
    }
    Push-Location $mcpRoot
    try {
        if (-not (Test-Path -LiteralPath (Join-Path $mcpRoot 'node_modules'))) {
            Write-Host 'MCP node_modules 不存在，先执行 npm install...' -ForegroundColor Cyan
            & npm.cmd install
            if ($LASTEXITCODE -ne 0) { throw 'npm install 失败。' }
        }
        & npm.cmd run check
        if ($LASTEXITCODE -ne 0) { throw 'MCP TypeScript 类型检查失败。' }
        Write-Host 'MCP TypeScript 检查通过。' -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

Write-Host '全部只读检查完成。' -ForegroundColor Green
