[CmdletBinding()]
param([ValidateSet('Check', 'Apply', 'Rollback')][string]$Action = 'Check')

$ErrorActionPreference = 'Stop'
$targets = @('59.232.4.33', '192.168.2.227', '59.232.12.34')
$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$backupPath = Join-Path $PSScriptRoot '特殊地址分流-变更前备份-20260903.json'

function Set-ProxyBypass {
    param([string]$Value)

    # 仅通过 WinINet 更新局域网连接的代理例外，不改变代理开关、服务器或自动配置。
    if (-not ('SpecialSitesProxyV2' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class SpecialSitesProxyV2 {
    [StructLayout(LayoutKind.Sequential)]
    private struct OptionList {
        public int Size;
        public IntPtr Connection;
        public int Count;
        public int Error;
        public IntPtr Options;
    }
    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    private static extern bool SetOption(IntPtr handle, int option, IntPtr buffer, int length);
    public static void SetBypass(string value) {
        int optionSize = IntPtr.Size == 8 ? 16 : 12;
        int valueOffset = IntPtr.Size == 8 ? 8 : 4;
        IntPtr text = Marshal.StringToHGlobalUni(value);
        IntPtr option = Marshal.AllocHGlobal(optionSize);
        IntPtr listBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(OptionList)));
        try {
            for (int i = 0; i < optionSize; i++) Marshal.WriteByte(option, i, 0);
            const int INTERNET_PER_CONN_PROXY_BYPASS = 3;
            Marshal.WriteInt32(option, INTERNET_PER_CONN_PROXY_BYPASS);
            Marshal.WriteIntPtr(option, valueOffset, text);
            OptionList list = new OptionList();
            list.Size = Marshal.SizeOf(typeof(OptionList));
            list.Count = 1;
            list.Options = option;
            Marshal.StructureToPtr(list, listBuffer, false);
            if (!SetOption(IntPtr.Zero, 75, listBuffer, list.Size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!SetOption(IntPtr.Zero, 39, IntPtr.Zero, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!SetOption(IntPtr.Zero, 37, IntPtr.Zero, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally {
            Marshal.FreeHGlobal(listBuffer);
            Marshal.FreeHGlobal(option);
            Marshal.FreeHGlobal(text);
        }
    }
}
'@
    }
    [SpecialSitesProxyV2]::SetBypass($Value)
}

$settings = Get-ItemProperty -LiteralPath $registryPath
$tokens = @(([string]$settings.ProxyOverride -split ';') | Where-Object { $_.Length -gt 0 })
if ($Action -ne 'Check') {
    if (-not (Test-Path -LiteralPath $backupPath)) { throw '缺少变更前备份，停止修改。' }
    $backup = Get-Content -LiteralPath $backupPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($Action -eq 'Apply') {
        $missing = @($targets | Where-Object { $_ -notin $tokens })
        Set-ProxyBypass -Value (($tokens + $missing) -join ';')
        $saved = Get-ItemProperty -LiteralPath $registryPath
        if (@($targets | Where-Object { $_ -notin ($saved.ProxyOverride -split ';') }).Count -gt 0) {
            throw '代理例外未保存成功，不能认定配置完成。'
        }
    } else {
        # 撤销仅移除本次新增的精确例外，保留随后添加的其他规则。
        $tokens = @($tokens | Where-Object { $_ -notin $backup.AddedProxyOverrideTokens })
        Set-ProxyBypass -Value ($tokens -join ';')
    }
}

$proxy = [Net.WebRequest]::GetSystemWebProxy()
$urls = @('http://59.232.4.33:17789/gisdzt/index.html#/login',
    'http://59.232.4.33:17789/hncsdz/index.html#/login',
    'http://192.168.2.227:17789/gisdzt/#/login',
    'http://192.168.2.227:17789/gishncsdz/#/login',
    'https://59.232.4.33:8443/',
    'http://59.232.12.34/',
    'https://59.232.12.34/')
$results = foreach ($url in $urls) {
    $uri = [Uri]$url
    [pscustomobject]@{地址=$url;绕过系统代理=$proxy.IsBypassed($uri)}
}
$results | Format-Table -AutoSize
