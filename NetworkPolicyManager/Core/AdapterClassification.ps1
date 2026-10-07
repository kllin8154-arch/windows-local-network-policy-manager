function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if ($Object.PSObject.Properties.Name -contains $Name -and $null -ne $Object.$Name) {
        return $Object.$Name
    }
    $Default
}

function Get-AdapterClassification {
    param([Parameter(Mandatory)]$Adapter)

    $name = [string](Get-ObjectPropertyValue -Object $Adapter -Name 'Name' -Default '')
    $description = [string](Get-ObjectPropertyValue -Object $Adapter -Name 'InterfaceDescription' -Default '')
    $hardware = [bool](Get-ObjectPropertyValue -Object $Adapter -Name 'HardwareInterface' -Default $false)
    $virtualFlag = [bool](Get-ObjectPropertyValue -Object $Adapter -Name 'Virtual' -Default $false)
    $media = [string](Get-ObjectPropertyValue -Object $Adapter -Name 'MediaType' -Default '')
    $physicalMedia = [string](Get-ObjectPropertyValue -Object $Adapter -Name 'PhysicalMediaType' -Default '')
    $text = "$name $description $media $physicalMedia"

    $provider = ''
    if ($text -match '(?i)Hyper-V|vEthernet') { $provider = 'Hyper-V' }
    elseif ($text -match '(?i)VMware') { $provider = 'VMware' }
    elseif ($text -match '(?i)VirtualBox|VBox') { $provider = 'VirtualBox' }
    elseif ($text -match '(?i)WSL|Windows Subsystem for Linux') { $provider = 'WSL' }
    elseif ($text -match '(?i)Docker') { $provider = 'Docker' }
    elseif ($text -match '(?i)Tailscale') { $provider = 'Tailscale' }
    elseif ($text -match '(?i)ZeroTier') { $provider = 'ZeroTier' }
    elseif ($text -match '(?i)Wintun|WireGuard') { $provider = 'Wintun/WireGuard' }
    elseif ($text -match '(?i)OpenVPN|\bTAP\b|\bTUN\b') { $provider = 'TAP/TUN' }
    elseif ($text -match '(?i)VPN|Fortinet|AnyConnect|GlobalProtect') { $provider = 'VPN' }

    $isWireless = $text -match '(?i)802\.11|Wi-?Fi|Wireless|WLAN'
    $isBluetooth = $text -match '(?i)Bluetooth'
    $isTunnel = $text -match '(?i)Tunnel|Teredo|6to4|isatap|Wintun|WireGuard|TAP|TUN|VPN|ZeroTier|Tailscale'
    $isVirtual = $virtualFlag -or -not $hardware -or -not [string]::IsNullOrWhiteSpace($provider) -or
        $text -match '(?i)Virtual|vEthernet|VMware|VirtualBox|Hyper-V|WSL|Docker'
    $isLoopback = $text -match '(?i)Loopback'

    $kind = if ($isLoopback) { 'Loopback' }
    elseif ($isTunnel) { 'Tunnel/VPN' }
    elseif ($isVirtual) { 'Virtual' }
    elseif ($isWireless) { 'Wi-Fi' }
    elseif ($isBluetooth) { 'Bluetooth' }
    elseif ($hardware) { 'Ethernet' }
    else { 'Other' }

    [pscustomobject]@{
        Kind = $kind
        IsPhysical = [bool]($hardware -and -not $isVirtual)
        IsVirtual = [bool]$isVirtual
        IsWireless = [bool]$isWireless
        IsTunnel = [bool]$isTunnel
        VirtualProvider = $provider
        MediaType = $media
        PhysicalMediaType = $physicalMedia
    }
}
