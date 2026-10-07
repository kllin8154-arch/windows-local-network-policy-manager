[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$core = Join-Path (Split-Path -Parent $PSScriptRoot) 'Core'
. (Join-Path $core 'NetworkMath.ps1')
. (Join-Path $core 'AdapterClassification.ps1')
. (Join-Path $core 'ProxyRules.ps1')

function Assert-Equal {
    param($Actual,$Expected,[string]$Message)
    if ([string]$Actual -ne [string]$Expected) {
        throw "$Message | expected=$Expected actual=$Actual"
    }
}
function Assert-True {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw $Message }
}

Assert-Equal (ConvertTo-NormalizedPrefix '172.16.11.205/24') '172.16.11.0/24' 'CIDR normalization'
Assert-Equal (ConvertTo-NormalizedPrefix '10.1.2.3') '10.1.2.3/32' 'Host normalization'
$routeParts = ConvertTo-RouteParts '10.10.3.9/24'
Assert-Equal $routeParts.Destination '10.10.3.0' 'Route destination'
Assert-Equal $routeParts.Mask '255.255.255.0' 'Route mask'
Assert-True (Test-PrefixOverlap '172.16.0.0/16' '172.16.11.0/24') 'Expected overlapping prefixes'
Assert-True (-not (Test-PrefixOverlap '172.16.11.0/24' '172.16.12.0/24')) 'Expected non-overlapping prefixes'
Assert-True (Test-IPv4InPrefix '172.16.11.205' '172.16.0.0/16') 'Address should match prefix'
Assert-True (-not (Test-IPv4InPrefix '10.0.0.1' '172.16.0.0/16')) 'Address should not match prefix'
$all = Get-PrefixRange '0.0.0.0/0'
Assert-Equal $all.Start 0 'Default prefix start'
Assert-Equal $all.End 4294967295 'Default prefix end'

$cases = @(
    @{
        Adapter = [pscustomobject]@{
            Name='Ethernet'; InterfaceDescription='Realtek PCIe GbE Family Controller'
            HardwareInterface=$true; Virtual=$false; MediaType='802.3'; PhysicalMediaType='802.3'
        }
        Kind='Ethernet'; Provider=''
    },
    @{
        Adapter = [pscustomobject]@{
            Name='Wi-Fi'; InterfaceDescription='Intel Wi-Fi 6 AX201'
            HardwareInterface=$true; Virtual=$false; MediaType='Native 802.11'; PhysicalMediaType='Native 802.11'
        }
        Kind='Wi-Fi'; Provider=''
    },
    @{
        Adapter = [pscustomobject]@{
            Name='vEthernet (Default Switch)'; InterfaceDescription='Hyper-V Virtual Ethernet Adapter'
            HardwareInterface=$false; Virtual=$true; MediaType='802.3'; PhysicalMediaType='Unspecified'
        }
        Kind='Virtual'; Provider='Hyper-V'
    },
    @{
        Adapter = [pscustomobject]@{
            Name='VMware Network Adapter VMnet8'; InterfaceDescription='VMware Virtual Ethernet Adapter for VMnet8'
            HardwareInterface=$false; Virtual=$true; MediaType='802.3'; PhysicalMediaType='Unspecified'
        }
        Kind='Virtual'; Provider='VMware'
    },
    @{
        Adapter = [pscustomobject]@{
            Name='WireGuard'; InterfaceDescription='Wintun Userspace Tunnel'
            HardwareInterface=$false; Virtual=$true; MediaType=''; PhysicalMediaType=''
        }
        Kind='Tunnel/VPN'; Provider='Wintun/WireGuard'
    },
    @{
        Adapter = [pscustomobject]@{
            Name='Tailscale'; InterfaceDescription='Tailscale Tunnel'
            HardwareInterface=$false; Virtual=$true; MediaType=''; PhysicalMediaType=''
        }
        Kind='Tunnel/VPN'; Provider='Tailscale'
    }
)

foreach ($case in $cases) {
    $classification = Get-AdapterClassification -Adapter $case.Adapter
    Assert-Equal $classification.Kind $case.Kind "Adapter kind: $($case.Adapter.Name)"
    Assert-Equal $classification.VirtualProvider $case.Provider "Adapter provider: $($case.Adapter.Name)"
}

$proxyRules = @(
    [pscustomobject]@{ Id='a'; Destination='10.1.2.3/32'; BypassProxy=$true },
    [pscustomobject]@{ Id='b'; Destination='10.1.2.3'; BypassProxy=$true },
    [pscustomobject]@{ Id='c'; Destination='10.1.2.4/32'; BypassProxy=$true },
    [pscustomobject]@{ Id='d'; Destination='10.1.2.3/32'; BypassProxy=$false }
)
Assert-Equal (Get-RuleProxyToken -Rule $proxyRules[0]) '10.1.2.3' 'Proxy token /32'
Assert-True (Test-OtherRuleUsesProxyToken -Rules $proxyRules -ExcludeRuleId 'a' -Token '10.1.2.3') 'Shared proxy token should be detected'
Assert-True (-not (Test-OtherRuleUsesProxyToken -Rules $proxyRules -ExcludeRuleId 'a' -Token '10.1.2.4')) 'Unshared proxy token should not be detected'
$cidrProxyRejected = $false
try {
    [void](Get-RuleProxyToken -Rule ([pscustomobject]@{ Id='x'; Destination='10.1.2.0/24'; BypassProxy=$true }))
} catch {
    $cidrProxyRejected = $true
}
Assert-True $cidrProxyRejected 'CIDR proxy bypass must be rejected'

'PURE_CORE_TEST_OK'
