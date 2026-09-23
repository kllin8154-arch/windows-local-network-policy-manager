[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

if (-not (Get-Command node.exe -ErrorAction SilentlyContinue)) {
    throw '未找到 Node.js。MCP 服务需要 Node.js 20 或更高版本。'
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
    & npm.cmd install
    if ($LASTEXITCODE -ne 0) { throw 'npm install 执行失败。' }
    Write-Host 'MCP 依赖安装完成。' -ForegroundColor Green
    Write-Host "测试命令：Set-Location '$root'; npm run start"
} finally {
    Pop-Location
}
