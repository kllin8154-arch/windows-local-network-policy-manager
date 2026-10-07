function Get-RuleProxyToken {
    param([Parameter(Mandatory)]$Rule)

    if (-not [bool]$Rule.BypassProxy) { return '' }
    $parts = (ConvertTo-NormalizedPrefix -Value ([string]$Rule.Destination)).Split('/')
    if ([int]$parts[1] -ne 32) {
        throw '系统代理绕过仅支持单个 IPv4（/32），不支持 CIDR 网段。'
    }
    [string]$parts[0]
}

function Test-OtherRuleUsesProxyToken {
    param(
        [Parameter(Mandatory)][object[]]$Rules,
        [Parameter(Mandatory)][string]$ExcludeRuleId,
        [Parameter(Mandatory)][string]$Token
    )

    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    @($Rules | Where-Object {
        [string]$_.Id -ne $ExcludeRuleId -and
        [bool]$_.BypassProxy -and
        $(try { (Get-RuleProxyToken -Rule $_) -eq $Token } catch { $false })
    }).Count -gt 0
}
