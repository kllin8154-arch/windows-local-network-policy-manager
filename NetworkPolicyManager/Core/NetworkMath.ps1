function ConvertTo-NormalizedPrefix {
    param([Parameter(Mandatory)][string]$Value)

    $trimmed = $Value.Trim()
    if ($trimmed -notmatch '/') { $trimmed += '/32' }
    $parts = $trimmed.Split('/')
    if ($parts.Count -ne 2) { throw "无效的 IPv4/CIDR：$Value" }

    $address = $null
    if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$address) -or $address.AddressFamily -ne 'InterNetwork') {
        throw "无效的 IPv4 地址：$Value"
    }

    $prefixLength = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefixLength) -or $prefixLength -lt 0 -or $prefixLength -gt 32) {
        throw "无效的 IPv4 前缀长度：$Value"
    }

    $bytes = $address.GetAddressBytes()
    $network = [byte[]]::new(4)
    for ($i = 0; $i -lt 4; $i++) {
        $remaining = $prefixLength - ($i * 8)
        $mask = if ($remaining -ge 8) { 255 } elseif ($remaining -le 0) { 0 } else {
            [int](256 - [Math]::Pow(2, 8 - $remaining))
        }
        $network[$i] = [byte]($bytes[$i] -band $mask)
    }
    '{0}/{1}' -f ([Net.IPAddress]::new($network)).ToString(), $prefixLength
}

function ConvertTo-RouteParts {
    param([Parameter(Mandatory)][string]$Prefix)

    $normalized = ConvertTo-NormalizedPrefix -Value $Prefix
    $parts = $normalized.Split('/')
    $prefixLength = [int]$parts[1]
    $maskBytes = [byte[]]::new(4)
    for ($i = 0; $i -lt 4; $i++) {
        $remaining = $prefixLength - ($i * 8)
        $maskBytes[$i] = if ($remaining -ge 8) { 255 } elseif ($remaining -le 0) { 0 } else {
            [byte](256 - [Math]::Pow(2, 8 - $remaining))
        }
    }
    [pscustomobject]@{
        Destination = $parts[0]
        Mask = ([Net.IPAddress]::new($maskBytes)).ToString()
        PrefixLength = $prefixLength
    }
}

function Test-IPv4Address {
    param([Parameter(Mandatory)][string]$Value)
    $address = $null
    [Net.IPAddress]::TryParse($Value, [ref]$address) -and $address.AddressFamily -eq 'InterNetwork'
}

function ConvertTo-IPv4UInt64 {
    param([Parameter(Mandatory)][string]$Address)
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork') {
        throw "无效的 IPv4 地址：$Address"
    }
    $b = $ip.GetAddressBytes()
    ([uint64]$b[0] -shl 24) -bor ([uint64]$b[1] -shl 16) -bor ([uint64]$b[2] -shl 8) -bor [uint64]$b[3]
}

function Get-PrefixRange {
    param([Parameter(Mandatory)][string]$Prefix)
    $normalized = ConvertTo-NormalizedPrefix -Value $Prefix
    $parts = $normalized.Split('/')
    $start = ConvertTo-IPv4UInt64 -Address $parts[0]
    $length = [int]$parts[1]
    $size = if ($length -eq 0) { [uint64]4294967296 } else { [uint64]1 -shl (32 - $length) }
    [pscustomobject]@{
        Prefix = $normalized
        PrefixLength = $length
        Start = $start
        End = $start + $size - 1
    }
}

function Test-PrefixOverlap {
    param(
        [Parameter(Mandatory)][string]$Left,
        [Parameter(Mandatory)][string]$Right
    )
    $a = Get-PrefixRange -Prefix $Left
    $b = Get-PrefixRange -Prefix $Right
    $a.Start -le $b.End -and $b.Start -le $a.End
}

function Test-IPv4InPrefix {
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$Prefix
    )
    if (-not (Test-IPv4Address -Value $Address)) { throw "无效的 IPv4 地址：$Address" }
    $value = ConvertTo-IPv4UInt64 -Address $Address
    $range = Get-PrefixRange -Prefix $Prefix
    $value -ge $range.Start -and $value -le $range.End
}
