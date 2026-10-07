[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

if (-not (Get-Command node.exe -ErrorAction SilentlyContinue)) {
    throw '未找到 Node.js。MCP 需要 Node.js 20 或更高版本。'
}
$versionText = (& node.exe --version).Trim().TrimStart('v')
$major = [int]($versionText.Split('.')[0])
if ($major -lt 20) {
    throw "Node.js 版本过低：$versionText；需要 20 或更高版本。"
}
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    throw '未找到 npm.cmd。请确认 Node.js 安装完整。'
}

Push-Location $root
try {
    if (Test-Path -LiteralPath (Join-Path $root 'package-lock.json')) {
        & npm.cmd ci
    } else {
        & npm.cmd install
    }
    if ($LASTEXITCODE -ne 0) { throw '依赖安装失败。' }

    & npm.cmd run check
    if ($LASTEXITCODE -ne 0) { throw 'TypeScript 类型检查失败。' }
    Write-Host 'MCP 依赖安装与类型检查完成。' -ForegroundColor Green
} finally {
    Pop-Location
}
