[CmdletBinding()]
param([ValidateSet('Install', 'Remove', 'Status')][string]$Action = 'Status')

$ErrorActionPreference = 'Stop'
$taskName = 'LocalNetworkPolicy-AutoRoute'
$installDirectory = Join-Path $env:ProgramFiles 'LocalNetworkPolicyManager'
$installedScript = Join-Path $installDirectory 'AutoRepair.ps1'
$sourceScript = Join-Path $PSScriptRoot 'AutoRepair.ps1'
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($Action -eq 'Status') {
    if ($null -eq $task) { '未安装后台自动修复任务。'; return }
    $task | Select-Object TaskName, State, TaskPath
    Get-ScheduledTaskInfo -TaskName $taskName | Select-Object LastRunTime, LastTaskResult, NextRunTime
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '安装或移除计划任务需要管理员权限。'
}

if ($Action -eq 'Remove') {
    if ($null -ne $task) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    if (Test-Path -LiteralPath $installedScript) {
        Remove-Item -LiteralPath $installedScript -Force
    }
    '已移除后台计划任务和安装脚本；未改动当前路由或用户规则。'
    return
}

if (-not (Test-Path -LiteralPath $sourceScript)) { throw "缺少源脚本：$sourceScript" }
if ($null -ne $task) {
    $existingActions = @($task.Actions)
    if ($existingActions.Count -ne 1 -or $existingActions[0].Arguments -notlike "*${installedScript}*") {
        throw "同名计划任务已存在但不是本程序创建：$taskName"
    }
}

if (-not (Test-Path -LiteralPath $installDirectory)) {
    New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
}
$directory = Get-Item -LiteralPath $installDirectory
if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw '安装目录是重解析点，已停止以防写入非预期位置。'
}
Copy-Item -LiteralPath $sourceScript -Destination $installedScript -Force

$taskAction = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
    -Argument ('-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $installedScript)
$repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 1)
$repeat.Repetition.Duration = $null
$repeat.Repetition.StopAtDurationEnd = $false
$logon = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger @($repeat, $logon) `
    -Principal $taskPrincipal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
"已安装 $taskName；用户登录期间每分钟核对一次，网络正常时不修改路由。"
