[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$source = Join-Path $PSScriptRoot 'Launcher.cs'
$manifest = Join-Path $PSScriptRoot 'app.manifest'
$output = Join-Path $root '本地网络策略管理器.exe'

if (-not (Test-Path -LiteralPath $compiler)) {
    throw "找不到 C# 编译器：$compiler"
}

& $compiler /nologo /target:winexe /optimize+ `
    /reference:System.Windows.Forms.dll `
    /win32manifest:"$manifest" `
    /out:"$output" "$source"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $output)) {
    throw '启动程序编译失败。'
}

Write-Host "已生成：$output"
