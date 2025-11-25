<#
    Network Scanner
    Version 3.19 Build 2025.16
    Author: Devon Dumas
    
    Features:
    - VLAN/SUBNET DISCOVERY: RFC1918 bruteforce gateway detection!
      * Probes all private gateway IPs (.1 addresses)
      * Detects hidden VLANs via ICMP responses
      * Discovers routed but unreachable subnets
    - DEVICE FINGERPRINTING: Advanced identification!
      * OS Detection (TTL-based: Windows/Linux/Cisco/Mac)
      * Device Classification (Router/Server/PC/Mobile/IoT/Printer)
      * Confidence levels
    - EXPORT CAPABILITIES: Save results (CSV/JSON/TXT)
    - ENHANCED DETECTION: Multi-source network discovery
    - TURBO MODE: Parallel scanning
    - INTEGRATED DISCOVERY: Ping + Stealth methods
    - Stable and production-ready!
#>

# Error handling
$ErrorActionPreference = "Continue"

try {
    $Host.UI.RawUI.WindowTitle = "Network Scanner v3.19 Build 2025.16 - by Devon Dumas"
} catch {
    # Ignore if can't set title
}

# Version Information
$Global:AppVersion = "3.19"
$Global:AppBuild = "2025.16"
$Global:AppAuthor = "Devon Dumas"
$Global:AppName = "Network Scanner"

# ==================== CONFIGURATION ====================

$Global:Config = @{
    InterfaceExcludePatterns = @(
        "Hyper-V", "vEthernet", "Virtual", "VPN", 
        "Loopback", "Docker", "Wi-Fi Direct", "Bluetooth"
    )
    FastScanMaxHosts = 64
    PingTimeout = 500  # Reduced from 1000ms for faster LAN scanning
    MaxConcurrentPings = 100  # Increased for runspace implementation
    PortScanTimeout = 500  # Reduced from 1000ms
    CommonPorts = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443)
    UseRunspaces = $true  # Enable runspace-based parallel scanning
    MaxRunspaces = 100  # Maximum parallel runspaces
    UseIntegratedDiscovery = $true  # Automatically add stealth discovery to scans
}

$Global:ScanState = @{
    IsScanning = $false
    CancelRequested = $false
    FoundHosts = $null
    TotalScanned = 0
    TotalHosts = 0
}

# ==================== IP/CIDR UTILITIES ====================

function ConvertTo-Uint32 {
    param([string]$IpAddress)
    
    try {
        $parts = $IpAddress.Split('.')
        if ($parts.Count -ne 4) {
            throw "Invalid IPv4 address: $IpAddress"
        }
        
        return [uint32](
            ([uint32]$parts[0] -shl 24) -bor
            ([uint32]$parts[1] -shl 16) -bor
            ([uint32]$parts[2] -shl 8)  -bor
            ([uint32]$parts[3])
        )
    } catch {
        Write-Host "Error converting IP to Uint32: $IpAddress - $($_.Exception.Message)" -ForegroundColor Red
        return 0
    }
}

function ConvertFrom-Uint32 {
    param([uint32]$Value)
    
    try {
        $b1 = ($Value -shr 24) -band 0xFF
        $b2 = ($Value -shr 16) -band 0xFF
        $b3 = ($Value -shr 8)  -band 0xFF
        $b4 = $Value -band 0xFF
        
        return "$b1.$b2.$b3.$b4"
    } catch {
        Write-Host "Error converting Uint32 to IP: $Value - $($_.Exception.Message)" -ForegroundColor Red
        return "0.0.0.0"
    }
}

function Get-SubnetMaskFromPrefix {
    param([int]$PrefixLength)
    
    try {
        if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) {
            throw "Invalid prefix length: $PrefixLength"
        }
        
        $mask = [uint32]0
        for ($i = 0; $i -lt $PrefixLength; $i++) {
            $mask = $mask -bor ([uint32]1 -shl (31 - $i))
        }
        
        return ConvertFrom-Uint32 $mask
    } catch {
        Write-Host "Error getting subnet mask: $($_.Exception.Message)" -ForegroundColor Red
        return "255.255.255.0"
    }
}

function Get-NetworkAddress {
    param(
        [string]$IpAddress,
        [int]$PrefixLength
    )
    
    try {
        $ipUint   = ConvertTo-Uint32 $IpAddress
        $maskUint = ConvertTo-Uint32 (Get-SubnetMaskFromPrefix $PrefixLength)
        $network  = $ipUint -band $maskUint
        
        return ConvertFrom-Uint32 $network
    } catch {
        Write-Host "Error getting network address: $($_.Exception.Message)" -ForegroundColor Red
        return "0.0.0.0"
    }
}

function Get-HostIpsFromCidr {
    param([string]$Cidr)
    
    try {
        if ($Cidr -notmatch '^(\d{1,3}(\.\d{1,3}){3})\/(\d{1,2})$') {
            throw "Invalid CIDR notation: $Cidr"
        }
        
        $baseIp = $matches[1]
        $prefix = [int]$matches[3]
        
        if ($prefix -lt 1 -or $prefix -gt 30) {
            throw "Prefix length $prefix not supported (must be 1-30)."
        }
        
        $baseUint   = ConvertTo-Uint32 $baseIp
        $maskUint   = ConvertTo-Uint32 (Get-SubnetMaskFromPrefix $prefix)
        $networkUint = $baseUint -band $maskUint
        $hostBits    = 32 - $prefix
        $hostCount   = [uint32]([math]::Pow(2, $hostBits)) - 2
        $broadcast   = $networkUint + $hostCount + 1
        
        $ips = New-Object System.Collections.ArrayList
        for ([uint32]$i = $networkUint + 1; $i -lt $broadcast; $i++) {
            [void]$ips.Add((ConvertFrom-Uint32 $i))
        }
        
        return $ips
    } catch {
        Write-Host "Error parsing CIDR: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-IPsFromInput {
    param([string]$InputString)
    
    try {
        $InputString = $InputString.Trim()
        
        if ([string]::IsNullOrWhiteSpace($InputString)) {
            throw "Input cannot be empty"
        }
        
        # Check if it's a CIDR notation
        if ($InputString -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$') {
            Write-Host "  [i] Detected CIDR format: $InputString" -ForegroundColor DarkGray
            return Get-HostIpsFromCidr -Cidr $InputString
        }
        
        # Check if it's a single IP address
        if ($InputString -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
            # Validate IP address octets
            $octets = @($matches[1], $matches[2], $matches[3], $matches[4])
            foreach ($octet in $octets) {
                $octetInt = [int]$octet
                if ($octetInt -lt 0 -or $octetInt -gt 255) {
                    throw "Invalid IP address: Octet $octet is out of range (0-255)"
                }
            }
            
            Write-Host "  [i] Detected single IP: $InputString" -ForegroundColor DarkGray
            $ips = New-Object System.Collections.ArrayList
            [void]$ips.Add($InputString)
            return $ips
        }
        
        # Check if it's a comma-separated list of IPs
        if ($InputString -match ',') {
            Write-Host "  [i] Detected IP list format" -ForegroundColor DarkGray
            $ipList = $InputString -split ',' | ForEach-Object { $_.Trim() }
            $ips = New-Object System.Collections.ArrayList
            
            foreach ($ip in $ipList) {
                if ($ip -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
                    $octets = @($matches[1], $matches[2], $matches[3], $matches[4])
                    $valid = $true
                    foreach ($octet in $octets) {
                        $octetInt = [int]$octet
                        if ($octetInt -lt 0 -or $octetInt -gt 255) {
                            Write-Host "  [!] Skipping invalid IP: $ip" -ForegroundColor Yellow
                            $valid = $false
                            break
                        }
                    }
                    if ($valid) {
                        [void]$ips.Add($ip)
                    }
                }
            }
            
            if ($ips.Count -gt 0) {
                Write-Host "  [i] Parsed $($ips.Count) valid IP(s)" -ForegroundColor DarkGray
                return $ips
            } else {
                throw "No valid IPs found in the list"
            }
        }
        
        throw "Invalid format. Expected: Single IP (10.24.254.12), CIDR (192.168.1.0/24), or IP list (192.168.1.1, 192.168.1.5)"
    } catch {
        Write-Host "  [X] Error: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ==================== DEVICE FINGERPRINTING ====================

function Get-OSFromTTL {
    <#
    .SYNOPSIS
    Detect operating system from TTL value
    .DESCRIPTION
    Uses Time-To-Live from ping response to identify OS
    #>
    param([int]$TTL)
    
    if ($TTL -le 0) { return "Unknown" }
    
    # TTL patterns by OS
    if ($TTL -ge 250 -and $TTL -le 255) { return "Cisco/Network" }
    if ($TTL -ge 128 -and $TTL -le 129) { return "Windows" }
    if ($TTL -ge 64 -and $TTL -le 65) { return "Linux/Unix/Mac" }
    if ($TTL -ge 60 -and $TTL -le 64) { return "Linux/Unix" }
    
    return "Unknown"
}

function Get-DeviceType {
    <#
    .SYNOPSIS
    Classify device type based on multiple factors
    .DESCRIPTION
    Analyzes vendor, hostname, OS, and discovery methods to classify device
    #>
    param(
        [string]$Vendor,
        [string]$Hostname,
        [string]$OS,
        [array]$DiscoveryMethods
    )
    
    # Router/Gateway detection
    if ($Vendor -match "(Cisco|Juniper|Mikrotik|Ubiquiti|TP-Link|Netgear|Asus|D-Link|Linksys)") {
        return @{ Type = "Router/Gateway"; Confidence = "High" }
    }
    if ($Hostname -match "(router|gateway|gw|firewall|edge)") {
        return @{ Type = "Router/Gateway"; Confidence = "Medium" }
    }
    if ($OS -eq "Cisco/Network") {
        return @{ Type = "Router/Gateway"; Confidence = "High" }
    }
    
    # Mobile device detection
    if ($Vendor -match "(Apple|Samsung|Google|Huawei|Xiaomi|OnePlus|LG|Motorola)") {
        if ($DiscoveryMethods -contains "mDNS") {
            if ($Vendor -eq "Apple") {
                return @{ Type = "Mobile (iOS)"; Confidence = "High" }
            } else {
                return @{ Type = "Mobile (Android)"; Confidence = "High" }
            }
        }
    }
    
    # IoT/Smart device detection
    if ($Vendor -match "(Amazon|Ring|Nest|Philips|Sonos|Roku|Chromecast|Alexa)") {
        return @{ Type = "IoT/Smart"; Confidence = "High" }
    }
    if ($DiscoveryMethods -contains "SSDP") {
        return @{ Type = "IoT/Smart"; Confidence = "Medium" }
    }
    
    # Printer detection
    if ($Vendor -match "(HP|Canon|Epson|Brother|Xerox|Lexmark)") {
        return @{ Type = "Printer"; Confidence = "High" }
    }
    if ($Hostname -match "print") {
        return @{ Type = "Printer"; Confidence = "Medium" }
    }
    
    # Server detection (has hostname pattern)
    if ($Hostname -match "(server|srv|web|db|sql|dc|dns|dhcp)") {
        return @{ Type = "Server"; Confidence = "Medium" }
    }
    
    # PC/Workstation detection
    if ($OS -eq "Windows") {
        return @{ Type = "PC (Windows)"; Confidence = "Medium" }
    }
    if ($OS -match "Linux") {
        return @{ Type = "PC/Server (Linux)"; Confidence = "Low" }
    }
    
    # Mac detection
    if ($Vendor -eq "Apple" -and $OS -match "Unix") {
        return @{ Type = "Mac"; Confidence = "High" }
    }
    
    # Default
    return @{ Type = "Unknown"; Confidence = "Low" }
}

function Add-DeviceFingerprint {
    <#
    .SYNOPSIS
    Adds OS and device type fingerprinting to a device object
    .DESCRIPTION
    Enriches device data with OS detection and classification
    #>
    param(
        [PSCustomObject]$Device,
        [int]$TTL = 0
    )
    
    # Get OS from TTL
    $os = Get-OSFromTTL -TTL $TTL
    
    # Get device type
    $classification = Get-DeviceType -Vendor $Device.Vendor -Hostname $Device.Hostname -OS $os -DiscoveryMethods $Device.DiscoveryMethods
    
    # Add new properties
    $Device | Add-Member -NotePropertyName "OS" -NotePropertyValue $os -Force
    $Device | Add-Member -NotePropertyName "DeviceType" -NotePropertyValue $classification.Type -Force
    $Device | Add-Member -NotePropertyName "Confidence" -NotePropertyValue $classification.Confidence -Force
    
    return $Device
}

# ==================== RFC1918 VLAN/SUBNET DISCOVERY ====================

function Get-RFC1918GatewayCandidates {
    <#
    .SYNOPSIS
    Generates all possible gateway IPs in RFC1918 private address space
    .DESCRIPTION
    Creates list of .1 gateway candidates for bruteforce VLAN discovery
    #>
    
    $candidates = New-Object System.Collections.ArrayList
    
    Write-Host "  [+] Generating RFC1918 gateway candidates..." -ForegroundColor Cyan
    
    # 192.168.0.1 -> 192.168.255.1 (256 candidates)
    for ($b = 0; $b -le 255; $b++) {
        [void]$candidates.Add("192.168.$b.1")
    }
    
    # 172.16.0.1 -> 172.31.255.1 (4096 candidates)
    for ($b = 16; $b -le 31; $b++) {
        for ($c = 0; $c -le 255; $c++) {
            [void]$candidates.Add("172.$b.$c.1")
        }
    }
    
    # 10.0.0.1 -> 10.255.255.1 (65536 candidates)
    for ($b = 0; $b -le 255; $b++) {
        for ($c = 0; $c -le 255; $c++) {
            [void]$candidates.Add("10.$b.$c.1")
        }
    }
    
    Write-Host "      Generated $($candidates.Count) gateway candidates" -ForegroundColor Green
    return $candidates
}

function Test-GatewayICMP {
    <#
    .SYNOPSIS
    Probes a gateway candidate with ICMP and interprets status
    .DESCRIPTION
    Sends single ICMP echo and evaluates reply status to detect subnet existence
    #>
    param(
        [string]$IPAddress,
        [int]$Timeout = 300
    )
    
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($IPAddress, $Timeout)
        
        # Interpret status codes
        # Success = gateway exists
        # DestinationHostUnreachable = subnet exists, host down
        # DestinationNetworkUnreachable = router knows network
        # DestinationProhibited = firewall blocks, but route exists
        
        $validStatuses = @(
            'Success',
            'DestinationHostUnreachable',
            'DestinationNetworkUnreachable', 
            'DestinationProhibited'
        )
        
        if ($validStatuses -contains $reply.Status) {
            return @{
                IsHit = $true
                Status = $reply.Status.ToString()
                TTL = if ($reply.Options) { $reply.Options.Ttl } else { 0 }
                ResponseTime = $reply.RoundtripTime
            }
        }
        
        return @{ IsHit = $false; Status = $reply.Status.ToString() }
        
    } catch {
        return @{ IsHit = $false; Status = "Error" }
    }
}

function Start-RFC1918Discovery {
    <#
    .SYNOPSIS
    Discovers hidden VLANs/subnets by probing RFC1918 gateway addresses
    .DESCRIPTION
    Bruteforce scans all private gateway IPs to detect routed subnets
    #>
    param(
        [string]$RangeMode = ""  # "", "Quick", "Full", "192", "172", "10"
    )
    
    try {
        Clear-Host
        Write-Host ""
        Write-Host "  =======================================================================" -ForegroundColor Magenta
        Write-Host "  ||              RFC1918 VLAN/SUBNET DISCOVERY                       ||" -ForegroundColor Magenta
        Write-Host "  =======================================================================" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "  This feature bruteforces private gateway IPs to discover:" -ForegroundColor White
        Write-Host "    - Hidden VLANs" -ForegroundColor Yellow
        Write-Host "    - Routed but unreachable subnets" -ForegroundColor Yellow
        Write-Host "    - Isolated network segments" -ForegroundColor Yellow
        Write-Host ""
        
        # Show range selection menu if not specified
        if ([string]::IsNullOrEmpty($RangeMode)) {
            Write-Host "  =======================================================================" -ForegroundColor Cyan
            Write-Host "  ||                    SELECT SCAN RANGE                             ||" -ForegroundColor Cyan
            Write-Host "  =======================================================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  [1] Quick Mode" -ForegroundColor Green
            Write-Host "      Scans: 192.168.x.1 + 10.x.0.1 + 172.x.0.1" -ForegroundColor Gray
            Write-Host "      Count: ~500 gateways" -ForegroundColor Gray
            Write-Host "      Time:  2-5 minutes" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [2] Full Scan (All RFC1918)" -ForegroundColor Yellow
            Write-Host "      Scans: ALL private gateways" -ForegroundColor Gray
            Write-Host "      Count: ~70,000 gateways" -ForegroundColor Gray
            Write-Host "      Time:  10-30 minutes" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [3] 192.168.0.0/16 Range Only" -ForegroundColor Cyan
            Write-Host "      Scans: 192.168.0.1 -> 192.168.255.1" -ForegroundColor Gray
            Write-Host "      Count: 256 gateways" -ForegroundColor Gray
            Write-Host "      Time:  1-2 minutes" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [4] 172.16.0.0/12 Range Only" -ForegroundColor Cyan
            Write-Host "      Scans: 172.16.0.1 -> 172.31.255.1" -ForegroundColor Gray
            Write-Host "      Count: ~4,000 gateways" -ForegroundColor Gray
            Write-Host "      Time:  3-8 minutes" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [5] 10.0.0.0/8 Range Only" -ForegroundColor Cyan
            Write-Host "      Scans: 10.0.0.1 -> 10.255.255.1" -ForegroundColor Gray
            Write-Host "      Count: ~65,000 gateways" -ForegroundColor Gray
            Write-Host "      Time:  8-25 minutes" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [0] Cancel" -ForegroundColor Red
            Write-Host ""
            Write-Host "  =======================================================================" -ForegroundColor Cyan
            Write-Host ""
            
            $choice = Read-Host "  Select range"
            
            switch ($choice) {
                "1" { $RangeMode = "Quick" }
                "2" { $RangeMode = "Full" }
                "3" { $RangeMode = "192" }
                "4" { $RangeMode = "172" }
                "5" { $RangeMode = "10" }
                "0" { 
                    Write-Host "  Scan cancelled" -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                    return @()
                }
                default {
                    Write-Host "  Invalid choice" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                    return @()
                }
            }
            
            Write-Host ""
        }
        
        # Ask for gateway position preference
        Write-Host "  =======================================================================" -ForegroundColor Cyan
        Write-Host "  ||                SELECT GATEWAY POSITION(S)                        ||" -ForegroundColor Cyan
        Write-Host "  =======================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Most routers use .1, but some use different addresses:" -ForegroundColor White
        Write-Host ""
        Write-Host "  [1] .1 only (Standard)" -ForegroundColor Green
        Write-Host "      Example: 192.168.1.1, 10.0.0.1" -ForegroundColor Gray
        Write-Host "      Fastest - most common" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [2] Common positions (.1, .254, .100, .10)" -ForegroundColor Yellow
        Write-Host "      Example: 192.168.1.1, 192.168.1.254, 192.168.1.100" -ForegroundColor Gray
        Write-Host "      Medium - covers 90% of routers" -ForegroundColor Gray
        Write-Host "      4x slower than .1 only" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [3] Extended scan (.1, .254, .100, .10, .2, .250, .200)" -ForegroundColor Magenta
        Write-Host "      Covers unusual configurations" -ForegroundColor Gray
        Write-Host "      7x slower than .1 only" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [4] Full subnet scan (all 254 addresses)" -ForegroundColor Red
        Write-Host "      WARNING: 254x slower!" -ForegroundColor Yellow
        Write-Host "      Only use if other methods fail" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  =======================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        $gwChoice = Read-Host "  Select gateway position(s)"
        
        $gatewayPositions = @()
        switch ($gwChoice) {
            "1" { 
                $gatewayPositions = @(1)
                $gwMode = ".1 only (standard)"
            }
            "2" { 
                $gatewayPositions = @(1, 254, 100, 10)
                $gwMode = "Common positions"
            }
            "3" { 
                $gatewayPositions = @(1, 254, 100, 10, 2, 250, 200)
                $gwMode = "Extended scan"
            }
            "4" { 
                $gatewayPositions = 1..254
                $gwMode = "Full subnet (all 254)"
            }
            default { 
                $gatewayPositions = @(1)
                $gwMode = ".1 only (standard)"
            }
        }
        
        Write-Host ""
        
        # Display selected mode
        $modeDisplay = switch ($RangeMode) {
            "Quick" { "[QUICK MODE] Common ranges" }
            "Full" { "[FULL SCAN] All RFC1918 ranges" }
            "192" { "[192.168.x.x] Class C private range" }
            "172" { "[172.16-31.x.x] Class B private range" }
            "10" { "[10.x.x.x] Class A private range" }
        }
        
        Write-Host "  $modeDisplay" -ForegroundColor Cyan
        Write-Host "  Gateway positions: $gwMode" -ForegroundColor Cyan
        Write-Host ""
        
        $startTime = Get-Date
        $discovered = New-Object System.Collections.ArrayList
        $candidates = @()
        
        # ==================== FIRST: ADD CURRENT NETWORK ====================
        Write-Host "  [+] Detecting current network..." -ForegroundColor Cyan
        $currentNet = Get-CurrentNetwork
        
        if ($currentNet) {
            Write-Host "      Current network detected: " -NoNewline -ForegroundColor Green
            Write-Host $currentNet.Cidr -ForegroundColor White
            Write-Host "      Gateway: " -NoNewline -ForegroundColor Green
            Write-Host $currentNet.Gateway -ForegroundColor White
            Write-Host ""
            
            # Add current network to discovered list
            $currentSubnet = [PSCustomObject]@{
                GatewayIP = $currentNet.Gateway
                AssumedCIDR = $currentNet.Cidr
                Status = "LocalNetwork"
                Confidence = "High"
                TTL = 0
                ResponseTime = 0
                Source = "Current-Network"
            }
            
            [void]$discovered.Add($currentSubnet)
            Write-Host "  [+] Current network added to discovery list" -ForegroundColor Green
            Write-Host ""
        } else {
            Write-Host "      No active network detected" -ForegroundColor Yellow
            Write-Host ""
        }
        
        # ==================== SECOND: RFC1918 DISCOVERY ====================
        # Generate candidates based on mode
        Write-Host "  [+] Generating RFC1918 gateway candidates..." -ForegroundColor Cyan
        
        switch ($RangeMode) {
            "Quick" {
                # 192.168.x.GW
                for ($b = 0; $b -le 255; $b++) {
                    foreach ($gw in $gatewayPositions) {
                        $candidates += "192.168.$b.$gw"
                    }
                }
                
                # 10.x.0.GW (only .0.GW in each /16)
                for ($b = 0; $b -le 255; $b++) {
                    foreach ($gw in $gatewayPositions) {
                        $candidates += "10.$b.0.$gw"
                    }
                }
                
                # 172.x.0.GW (only .0.GW in each /16)
                for ($b = 16; $b -le 31; $b++) {
                    foreach ($gw in $gatewayPositions) {
                        $candidates += "172.$b.0.$gw"
                    }
                }
            }
            
            "Full" {
                # 192.168.x.GW
                for ($b = 0; $b -le 255; $b++) {
                    foreach ($gw in $gatewayPositions) {
                        $candidates += "192.168.$b.$gw"
                    }
                }
                
                # 172.16-31.x.GW
                for ($b = 16; $b -le 31; $b++) {
                    for ($c = 0; $c -le 255; $c++) {
                        foreach ($gw in $gatewayPositions) {
                            $candidates += "172.$b.$c.$gw"
                        }
                    }
                }
                
                # 10.x.x.GW
                for ($b = 0; $b -le 255; $b++) {
                    for ($c = 0; $c -le 255; $c++) {
                        foreach ($gw in $gatewayPositions) {
                            $candidates += "10.$b.$c.$gw"
                        }
                    }
                }
            }
            
            "192" {
                # 192.168.x.GW
                for ($b = 0; $b -le 255; $b++) {
                    foreach ($gw in $gatewayPositions) {
                        $candidates += "192.168.$b.$gw"
                    }
                }
            }
            
            "172" {
                # 172.16-31.x.GW
                for ($b = 16; $b -le 31; $b++) {
                    for ($c = 0; $c -le 255; $c++) {
                        foreach ($gw in $gatewayPositions) {
                            $candidates += "172.$b.$c.$gw"
                        }
                    }
                }
            }
            
            "10" {
                # 10.x.x.GW
                for ($b = 0; $b -le 255; $b++) {
                    for ($c = 0; $c -le 255; $c++) {
                        foreach ($gw in $gatewayPositions) {
                            $candidates += "10.$b.$c.$gw"
                        }
                    }
                }
            }
        }
        
        Write-Host "      Generated $($candidates.Count) gateway candidates" -ForegroundColor Green
        
        $total = $candidates.Count
        $checked = 0
        $hits = 0
        
        Write-Host ""
        Write-Host "  [+] Probing gateways (timeout: 300ms per IP)..." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Controls: " -NoNewline -ForegroundColor Yellow
        Write-Host "[P] Pause  [C] Continue  [X] Cancel & Keep Results" -ForegroundColor White
        Write-Host ""
        
        $progressInterval = [Math]::Max(1, [Math]::Floor($total / 100))
        $isPaused = $false
        $Global:ScanState.IsScanning = $true
        $Global:ScanState.CancelRequested = $false
        
        foreach ($ip in $candidates) {
            # Check for pause/cancel
            while ($isPaused) {
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'C') {
                        $isPaused = $false
                        Write-Host "`r  [+] Resuming VLAN discovery..." -ForegroundColor Green
                        Write-Host ""
                    } elseif ($key.Key -eq 'X') {
                        $Global:ScanState.CancelRequested = $true
                        $isPaused = $false
                    }
                }
                Start-Sleep -Milliseconds 100
            }
            
            # Check for cancel
            if ($Global:ScanState.CancelRequested) {
                break
            }
            
            # Check for keyboard input (pause/cancel)
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq 'P') {
                    $isPaused = $true
                    Write-Host "`r  [!] PAUSED - Press [C] to continue or [X] to cancel..." -ForegroundColor Yellow
                } elseif ($key.Key -eq 'X') {
                    $Global:ScanState.CancelRequested = $true
                    break
                }
            }
            
            $result = Test-GatewayICMP -IPAddress $ip -Timeout 300
            $checked++
            
            if ($result.IsHit) {
                $hits++
                
                # Extract network from gateway IP (works with any last octet)
                if ($ip -match '^(\d+\.\d+\.\d+)\.\d+$') {
                    $network = "$($matches[1]).0"
                    
                    # Check if this gateway was already discovered (avoid duplicates)
                    $alreadyDiscovered = $false
                    foreach ($existingSubnet in $discovered) {
                        if ($existingSubnet.GatewayIP -eq $ip) {
                            $alreadyDiscovered = $true
                            break
                        }
                    }
                    
                    if (-not $alreadyDiscovered) {
                        # Determine confidence
                        $confidence = if ($result.Status -eq 'Success') { 
                            'High' 
                        } elseif ($result.Status -match 'Unreachable') { 
                            'Medium' 
                        } else { 
                            'Low' 
                        }
                        
                        $subnet = [PSCustomObject]@{
                            GatewayIP = $ip
                            AssumedCIDR = "$network/24"
                            Status = $result.Status
                            Confidence = $confidence
                            TTL = $result.TTL
                            ResponseTime = $result.ResponseTime
                            Source = "RFC1918-Bruteforce"
                        }
                        
                        [void]$discovered.Add($subnet)
                        
                        # Show discovery in real-time
                        Write-Host "  [FOUND] " -NoNewline -ForegroundColor Green
                        Write-Host "$ip " -NoNewline -ForegroundColor White
                        Write-Host "-> $network/24 " -NoNewline -ForegroundColor Cyan
                        Write-Host "($($result.Status))" -ForegroundColor Yellow
                    }
                }
            }
            
            # Progress indicator every N checks
            if ($checked % $progressInterval -eq 0 -and -not $isPaused) {
                $pct = [Math]::Round(($checked / $total) * 100, 1)
                Write-Host "`r  Progress: $checked/$total ($pct%) - Discovered: $hits" -NoNewline -ForegroundColor Gray
            }
        }
        
        $Global:ScanState.IsScanning = $false
        
        # Clear progress line
        Write-Host "`r" -NoNewline
        Write-Host (" " * 80) -NoNewline
        Write-Host "`r" -NoNewline
        
        $elapsed = (Get-Date) - $startTime
        
        Write-Host ""
        Write-Host "  =======================================================================" -ForegroundColor Magenta
        Write-Host ""
        
        if ($Global:ScanState.CancelRequested) {
            Write-Host "  [!] Discovery canceled by user" -ForegroundColor Yellow
            Write-Host "  [+] Kept $($discovered.Count) discovered subnet(s) before cancellation" -ForegroundColor Green
        } else {
            Write-Host "  [+] Discovery complete!" -ForegroundColor Green
        }
        
        Write-Host "      Probed:      $checked / $total gateway candidates" -ForegroundColor White
        Write-Host "      Discovered:  $($discovered.Count) hidden subnets" -ForegroundColor White
        Write-Host "      Time:        $([Math]::Round($elapsed.TotalSeconds, 1)) seconds" -ForegroundColor White
        if ($checked -gt 0) {
            Write-Host "      Speed:       $([Math]::Round($checked / $elapsed.TotalSeconds, 0)) IPs/sec" -ForegroundColor White
        }
        Write-Host ""
        
        if ($discovered.Count -gt 0) {
            Write-Host "  DISCOVERED SUBNETS:" -ForegroundColor Green
            Write-Host "  " -NoNewline
            Write-Host ("-" * 85) -ForegroundColor Gray
            Write-Host ("  {0,-15} {1,-18} {2,-25} {3,-12} {4}" -f "GATEWAY", "SUBNET", "STATUS", "CONFIDENCE", "TTL") -ForegroundColor Yellow
            Write-Host "  " -NoNewline
            Write-Host ("-" * 85) -ForegroundColor Gray
            
            foreach ($subnet in ($discovered | Sort-Object GatewayIP)) {
                $color = switch ($subnet.Confidence) {
                    'High' { 'Green' }
                    'Medium' { 'Yellow' }
                    default { 'Gray' }
                }
                
                Write-Host ("  {0,-15} {1,-18} {2,-25} {3,-12} {4}" -f 
                    $subnet.GatewayIP,
                    $subnet.AssumedCIDR,
                    $subnet.Status,
                    $subnet.Confidence,
                    $subnet.TTL) -ForegroundColor $color
            }
            
            Write-Host "  " -NoNewline
            Write-Host ("-" * 85) -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host "  =======================================================================" -ForegroundColor Magenta
        Write-Host ""
        
        return $discovered
        
    } catch {
        Write-Host ""
        Write-Host "  [X] Error during RFC1918 discovery: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ==================== EXPORT FUNCTIONS ====================

function Export-ToCSV {
    param($Results, $Path)
    try {
        $Results | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        return $true
    } catch {
        Write-Host "  Export failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Export-ToJSON {
    param($Results, $Path)
    try {
        $data = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Version = "$Global:AppVersion Build $Global:AppBuild"
            Results = $Results
        }
        $data | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        return $true
    } catch {
        Write-Host "  Export failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Export-ToTXT {
    param($Results, $Path, $Title)
    try {
        $report = @"
================================================================================
NETWORK SCANNER REPORT
================================================================================

Title:     $Title
Date:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Version:   $Global:AppVersion Build $Global:AppBuild
Author:    $Global:AppAuthor
Results:   $($Results.Count)

================================================================================
"@
        $report | Out-File -FilePath $Path -Encoding UTF8
        $Results | Format-Table -AutoSize | Out-File -FilePath $Path -Append -Encoding UTF8
        return $true
    } catch {
        Write-Host "  Export failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Export-PortScanToCSV {
    param($Results, $Path)
    try {
        # Flatten port scan results for CSV
        $flatResults = @()
        foreach ($host in $Results) {
            foreach ($port in $host.OpenPorts) {
                $flatResults += [PSCustomObject]@{
                    IP = $host.IP
                    Hostname = $host.Hostname
                    Port = $port.Port
                    State = $port.State
                    Service = $port.Service
                }
            }
        }
        $flatResults | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        return $true
    } catch {
        Write-Host "  Export failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Export-PortScanToJSON {
    param($Results, $Path)
    try {
        $data = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Version = "$Global:AppVersion Build $Global:AppBuild"
            ScanType = "Port Scan"
            TotalHosts = $Results.Count
            TotalOpenPorts = ($Results | ForEach-Object { $_.OpenPorts.Count } | Measure-Object -Sum).Sum
            Results = $Results
        }
        $data | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        return $true
    } catch {
        Write-Host "  Export failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Export-PortScanToTXT {
    param($Results, $Path)
    try {
        $report = @"
================================================================================
PORT SCAN REPORT
================================================================================

Date:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Version:   $Global:AppVersion Build $Global:AppBuild
Author:    $Global:AppAuthor

Hosts Scanned:    $($Results.Count)
Total Open Ports: $(($Results | ForEach-Object { $_.OpenPorts.Count } | Measure-Object -Sum).Sum)

================================================================================

SUMMARY BY HOST:

"@
        $report | Out-File -FilePath $Path -Encoding UTF8
        
        # Add each host's details
        foreach ($host in $Results) {
            $hostLine = if ($host.Hostname -ne "-") {
                "$($host.IP) ($($host.Hostname))"
            } else {
                $host.IP
            }
            
            Add-Content -Path $Path -Value $hostLine -Encoding UTF8
            foreach ($port in $host.OpenPorts) {
                Add-Content -Path $Path -Value "  - Port $($port.Port): $($port.Service)" -Encoding UTF8
            }
            Add-Content -Path $Path -Value "" -Encoding UTF8
        }
        
        Add-Content -Path $Path -Value "================================================================================`n" -Encoding UTF8
        return $true
    } catch {
        Write-Host "  Export failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Show-ExportMenu {
    param($Results, $ScanType)
    
    if (-not $Results -or $Results.Count -eq 0) {
        Write-Host "  No results to export" -ForegroundColor Yellow
        Start-Sleep -Seconds 1
        return
    }
    
    # Detect if this is a port scan result (has OpenPorts property)
    $isPortScan = $false
    if ($Results[0].PSObject.Properties.Name -contains "OpenPorts") {
        $isPortScan = $true
    }
    
    Write-Host ""
    Write-Host "  Export results? (Y/N)" -ForegroundColor Cyan
    $export = Read-Host "  "
    
    if ($export -ne "Y" -and $export -ne "y") {
        return
    }
    
    Write-Host ""
    Write-Host "  Export format:" -ForegroundColor Cyan
    Write-Host "    1) CSV" -ForegroundColor White
    Write-Host "    2) JSON" -ForegroundColor White
    Write-Host "    3) TXT" -ForegroundColor White
    $formatChoice = Read-Host "  Choose"
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $filename = "scan_${ScanType}_${timestamp}"
    
    $success = $false
    
    if ($isPortScan) {
        # Use specialized port scan export functions
        switch ($formatChoice) {
            "1" {
                $path = "$PWD\$filename.csv"
                $success = Export-PortScanToCSV -Results $Results -Path $path
            }
            "2" {
                $path = "$PWD\$filename.json"
                $success = Export-PortScanToJSON -Results $Results -Path $path
            }
            "3" {
                $path = "$PWD\$filename.txt"
                $success = Export-PortScanToTXT -Results $Results -Path $path
            }
            default {
                Write-Host "  Invalid choice" -ForegroundColor Red
                Start-Sleep -Seconds 1
                return
            }
        }
    } else {
        # Use standard export functions for network scans
        switch ($formatChoice) {
            "1" {
                $path = "$PWD\$filename.csv"
                $success = Export-ToCSV -Results $Results -Path $path
            }
            "2" {
                $path = "$PWD\$filename.json"
                $success = Export-ToJSON -Results $Results -Path $path
            }
            "3" {
                $path = "$PWD\$filename.txt"
                $success = Export-ToTXT -Results $Results -Path $path -Title $ScanType
            }
            default {
                Write-Host "  Invalid choice" -ForegroundColor Red
                Start-Sleep -Seconds 1
                return
            }
        }
    }
    
    if ($success) {
        Write-Host ""
        Write-Host "  Exported to: $path" -ForegroundColor Green
        Write-Host ""
        Start-Sleep -Seconds 2
    }
}

# ==================== DEVICE FINGERPRINTING ====================

function Get-OSFromTTL {
    param([int]$TTL)
    
    if ($TTL -le 0) { return "Unknown" }
    if ($TTL -ge 250 -and $TTL -le 255) { return "Cisco/Network Device" }
    if ($TTL -ge 128 -and $TTL -le 129) { return "Windows" }
    if ($TTL -ge 64 -and $TTL -le 65) { return "Linux/Unix" }
    if ($TTL -ge 60 -and $TTL -le 64) { return "Linux/Unix/macOS" }
    return "Unknown"
}

function Get-DeviceTypeFromVendor {
    param(
        [string]$Vendor,
        [string]$Hostname,
        [string]$OS
    )
    
    $type = "Unknown"
    $confidence = "Low"
    
    # Router/Gateway Detection
    if ($Vendor -match "(Cisco|Juniper|Mikrotik|Ubiquiti|TP-Link|Netgear|Asus|D-Link)" -or
        $Hostname -match "(router|gateway|gw|firewall|edge)" -or
        $OS -eq "Cisco/Network Device") {
        $type = "Router/Gateway"
        $confidence = "High"
    }
    # Mobile Device Detection
    elseif ($Vendor -match "(Apple|Samsung|Google|Huawei|Xiaomi|OnePlus|Motorola)") {
        if ($Vendor -eq "Apple") {
            $type = "Mobile (iOS)"
        } else {
            $type = "Mobile (Android)"
        }
        $confidence = "High"
    }
    # IoT Device Detection
    elseif ($Vendor -match "(Amazon|Ring|Nest|Philips|Sonos|Roku|Chromecast)") {
        $type = "IoT/Smart Device"
        $confidence = "High"
    }
    # Printer Detection
    elseif ($Vendor -match "(HP|Canon|Epson|Brother|Xerox)") {
        $type = "Printer"
        $confidence = "High"
    }
    # PC/Workstation Detection
    elseif ($OS -match "Windows") {
        $type = "PC/Workstation"
        $confidence = "Medium"
    }
    # Mac Computer Detection
    elseif ($Vendor -eq "Apple" -and $OS -match "Unix") {
        $type = "Mac"
        $confidence = "High"
    }
    # Linux/Unix System
    elseif ($OS -match "Linux") {
        $type = "Server/Workstation"
        $confidence = "Medium"
    }
    
    return @{
        Type = $type
        Confidence = $confidence
    }
}

function Get-VulnerabilityHints {
    param(
        [array]$OpenPorts,
        [string]$OS
    )
    
    $vulns = @()
    
    # Check for common vulnerabilities based on open ports
    if ($OpenPorts -contains 445) {
        if ($OS -match "Windows") {
            $vulns += [PSCustomObject]@{
                Severity = "CRITICAL"
                Service = "SMB (445)"
                Issue = "SMB exposed - potential EternalBlue"
                Recommendation = "Update Windows, disable SMBv1"
            }
        }
    }
    
    if ($OpenPorts -contains 23) {
        $vulns += [PSCustomObject]@{
            Severity = "HIGH"
            Service = "Telnet (23)"
            Issue = "Unencrypted remote access"
            Recommendation = "Replace with SSH"
        }
    }
    
    if ($OpenPorts -contains 21) {
        $vulns += [PSCustomObject]@{
            Severity = "MEDIUM"
            Service = "FTP (21)"
            Issue = "Unencrypted file transfer"
            Recommendation = "Use SFTP or FTPS"
        }
    }
    
    if ($OpenPorts -contains 3389) {
        $vulns += [PSCustomObject]@{
            Severity = "MEDIUM"
            Service = "RDP (3389)"
            Issue = "Remote Desktop exposed"
            Recommendation = "Use VPN, enable NLA"
        }
    }
    
    if ($OpenPorts -contains 3306 -or $OpenPorts -contains 5432) {
        $service = if ($OpenPorts -contains 3306) { "MySQL (3306)" } else { "PostgreSQL (5432)" }
        $vulns += [PSCustomObject]@{
            Severity = "MEDIUM"
            Service = $service
            Issue = "Database port exposed"
            Recommendation = "Bind to localhost only"
        }
    }
    
    return $vulns
}

function Show-EnhancedDeviceInfo {
    param([PSCustomObject]$Device)
    
    Clear-Host
    Write-Host ""
    Write-Host "  ====================================================================" -ForegroundColor Cyan
    Write-Host "                    DEVICE ANALYSIS & FINGERPRINTING                  " -ForegroundColor Cyan
    Write-Host "  ====================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Basic Information
    Write-Host "  BASIC INFORMATION:" -ForegroundColor Green
    Write-Host "  " -NoNewline
    Write-Host ("-" * 70) -ForegroundColor Gray
    Write-Host ("    IP Address:      {0}" -f $Device.IP) -ForegroundColor White
    Write-Host ("    MAC Address:     {0}" -f $(if ($Device.MAC -and $Device.MAC -ne "-") { $Device.MAC } else { "Not available" })) -ForegroundColor White
    Write-Host ("    Vendor:          {0}" -f $(if ($Device.Vendor -and $Device.Vendor -ne "-") { $Device.Vendor } else { "Unknown" })) -ForegroundColor White
    Write-Host ("    Hostname:        {0}" -f $(if ($Device.Hostname -and $Device.Hostname -ne "-") { $Device.Hostname } else { "Not resolved" })) -ForegroundColor White
    
    if ($Device.ResponseTime) {
        Write-Host ("    Response Time:   {0}ms" -f $Device.ResponseTime) -ForegroundColor White
    }
    Write-Host ""
    
    # OS Detection
    $detectedOS = "Unknown"
    if ($Device.TTL -and $Device.TTL -gt 0) {
        $detectedOS = Get-OSFromTTL -TTL $Device.TTL
        
        Write-Host "  OS DETECTION:" -ForegroundColor Green
        Write-Host "  " -NoNewline
        Write-Host ("-" * 70) -ForegroundColor Gray
        Write-Host ("    Detected OS:     {0}" -f $detectedOS) -ForegroundColor White
        Write-Host ("    TTL Value:       {0}" -f $Device.TTL) -ForegroundColor Gray
        Write-Host ""
    }
    
    # Device Classification
    $classification = Get-DeviceTypeFromVendor -Vendor $Device.Vendor -Hostname $Device.Hostname -OS $detectedOS
    
    Write-Host "  DEVICE CLASSIFICATION:" -ForegroundColor Green
    Write-Host "  " -NoNewline
    Write-Host ("-" * 70) -ForegroundColor Gray
    
    $typeColor = switch ($classification.Type) {
        "Router/Gateway" { "Cyan" }
        "Server/Workstation" { "Yellow" }
        "PC/Workstation" { "White" }
        "Mobile (iOS)" { "Magenta" }
        "Mobile (Android)" { "Magenta" }
        "IoT/Smart Device" { "Blue" }
        "Printer" { "Gray" }
        "Mac" { "Magenta" }
        default { "White" }
    }
    
    Write-Host ("    Device Type:     {0}" -f $classification.Type) -ForegroundColor $typeColor
    Write-Host ("    Confidence:      {0}" -f $classification.Confidence) -ForegroundColor Gray
    Write-Host ""
    
    # Discovery Methods
    if ($Device.DiscoveryMethods) {
        Write-Host "  DISCOVERY METHODS:" -ForegroundColor Green
        Write-Host "  " -NoNewline
        Write-Host ("-" * 70) -ForegroundColor Gray
        $methods = if ($Device.DiscoveryMethods -is [array]) { 
            $Device.DiscoveryMethods -join ", " 
        } else { 
            $Device.DiscoveryMethods 
        }
        Write-Host ("    Found by:        {0}" -f $methods) -ForegroundColor White
        Write-Host ""
    }
    
    # Open Ports (if available)
    if ($Device.OpenPorts -and $Device.OpenPorts.Count -gt 0) {
        Write-Host "  OPEN PORTS:" -ForegroundColor Green
        Write-Host "  " -NoNewline
        Write-Host ("-" * 70) -ForegroundColor Gray
        $portList = ($Device.OpenPorts | Sort-Object) -join ", "
        Write-Host ("    Ports:           {0}" -f $portList) -ForegroundColor White
        Write-Host ""
        
        # Vulnerability Assessment
        $vulns = Get-VulnerabilityHints -OpenPorts $Device.OpenPorts -OS $detectedOS
        
        if ($vulns.Count -gt 0) {
            Write-Host "  SECURITY ASSESSMENT:" -ForegroundColor Yellow
            Write-Host "  " -NoNewline
            Write-Host ("-" * 70) -ForegroundColor Gray
            
            $criticalCount = ($vulns | Where-Object { $_.Severity -eq "CRITICAL" }).Count
            $highCount = ($vulns | Where-Object { $_.Severity -eq "HIGH" }).Count
            
            $riskLevel = if ($criticalCount -gt 0) { "CRITICAL" }
                         elseif ($highCount -gt 0) { "HIGH" }
                         elseif ($vulns.Count -gt 0) { "MEDIUM" }
                         else { "LOW" }
            
            $riskColor = switch ($riskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                default { "Green" }
            }
            
            Write-Host ("    Risk Level:      {0}" -f $riskLevel) -ForegroundColor $riskColor
            Write-Host ("    Issues Found:    {0}" -f $vulns.Count) -ForegroundColor White
            Write-Host ""
            
            foreach ($vuln in $vulns) {
                $severityColor = switch ($vuln.Severity) {
                    "CRITICAL" { "Red" }
                    "HIGH" { "Yellow" }
                    "MEDIUM" { "Cyan" }
                    default { "White" }
                }
                
                Write-Host ("    [{0}] {1}" -f $vuln.Severity, $vuln.Service) -ForegroundColor $severityColor
                Write-Host ("          Issue: {0}" -f $vuln.Issue) -ForegroundColor Gray
                Write-Host ("          Fix:   {0}" -f $vuln.Recommendation) -ForegroundColor DarkGray
                Write-Host ""
            }
        } else {
            Write-Host "  SECURITY ASSESSMENT:" -ForegroundColor Green
            Write-Host "  " -NoNewline
            Write-Host ("-" * 70) -ForegroundColor Gray
            Write-Host ("    Risk Level:      LOW") -ForegroundColor Green
            Write-Host ("    No obvious vulnerabilities detected") -ForegroundColor Gray
            Write-Host ""
        }
    }
    
    Write-Host "  ====================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Press Enter to continue..." -ForegroundColor Gray
    Read-Host | Out-Null
}

# ==================== NETWORK DETECTION ====================

function Should-ExcludeInterface {
    param([string]$InterfaceAlias)
    
    if ([string]::IsNullOrWhiteSpace($InterfaceAlias)) {
        return $true
    }
    
    foreach ($pattern in $Global:Config.InterfaceExcludePatterns) {
        if ($InterfaceAlias -match $pattern) {
            return $true
        }
    }
    return $false
}

function Get-CurrentNetwork {
    try {
        # Find the default route - get the FIRST active one
        $defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -ne "0.0.0.0" } |
            Sort-Object -Property RouteMetric |
            Select-Object -First 1
        
        if (-not $defaultRoute) {
            return $null
        }
        
        # Get ALL IP configurations for this interface
        $ipConfigs = Get-NetIPAddress -InterfaceIndex $defaultRoute.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { 
                $_.IPAddress -notlike "169.254.*" -and 
                $_.IPAddress -notlike "127.*" -and
                $_.AddressState -eq "Preferred"
            } |
            Sort-Object -Property @{Expression={$_.PrefixLength}; Descending=$true}
        
        if (-not $ipConfigs -or $ipConfigs.Count -eq 0) {
            return $null
        }
        
        # Use the first valid IP configuration
        $ipConfig = $ipConfigs | Select-Object -First 1
        
        # Get interface details
        $interface = Get-NetAdapter -InterfaceIndex $defaultRoute.ifIndex -ErrorAction SilentlyContinue
        
        # Get DNS servers
        $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $defaultRoute.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty ServerAddresses
        $dnsString = if ($dnsServers) { $dnsServers -join ", " } else { "None" }
        
        # Get hostname of this machine
        $myHostname = $env:COMPUTERNAME
        if (-not $myHostname) {
            try {
                $myHostname = [System.Net.Dns]::GetHostName()
            } catch {
                $myHostname = "Unknown"
            }
        }
        
        $network = Get-NetworkAddress $ipConfig.IPAddress $ipConfig.PrefixLength
        $mask = Get-SubnetMaskFromPrefix $ipConfig.PrefixLength
        $cidr = "$network/$($ipConfig.PrefixLength)"
        
        $hostBits = 32 - $ipConfig.PrefixLength
        $hostCount = [uint32]([math]::Pow(2, $hostBits)) - 2
        
        return [pscustomobject]@{
            Cidr         = $cidr
            Network      = $network
            SubnetMask   = $mask
            PrefixLength = $ipConfig.PrefixLength
            MyIP         = $ipConfig.IPAddress
            MyHostname   = $myHostname
            Gateway      = $defaultRoute.NextHop
            DNS          = $dnsString
            HostCount    = $hostCount
            Interface    = if ($interface) { $interface.InterfaceAlias } else { "Unknown" }
            InterfaceIndex = $defaultRoute.ifIndex
            RouteMetric  = $defaultRoute.RouteMetric
            Status       = if ($interface) { $interface.Status } else { "Unknown" }
            Speed        = if ($interface) { $interface.LinkSpeed } else { "Unknown" }
            AddressState = $ipConfig.AddressState
        }
    } catch {
        return $null
    }
}

function Test-PrivateIPRange {
    <#
    .SYNOPSIS
    Check if an IP address or network is in private (RFC1918) or link-local ranges
    .DESCRIPTION
    Returns true for private, link-local, or loopback addresses
    #>
    param([string]$IPAddress)
    
    try {
        # Extract just the IP if it's in CIDR format
        if ($IPAddress -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
            $ip = $matches[1]
        } else {
            $ip = $IPAddress
        }
        
        $octets = $ip -split '\.'
        if ($octets.Count -ne 4) { return $false }
        
        $first = [int]$octets[0]
        $second = [int]$octets[1]
        
        # Private ranges (RFC1918)
        # 10.0.0.0/8
        if ($first -eq 10) { return $true }
        
        # 172.16.0.0/12
        if ($first -eq 172 -and $second -ge 16 -and $second -le 31) { return $true }
        
        # 192.168.0.0/16
        if ($first -eq 192 -and $second -eq 168) { return $true }
        
        # Link-local (169.254.0.0/16)
        if ($first -eq 169 -and $second -eq 254) { return $true }
        
        # Loopback (127.0.0.0/8)
        if ($first -eq 127) { return $true }
        
        # Carrier-grade NAT (100.64.0.0/10)
        if ($first -eq 100 -and $second -ge 64 -and $second -le 127) { return $true }
        
        return $false
    } catch {
        return $false
    }
}

function Get-RouteTableNetworks {
    <#
    .SYNOPSIS
    Discover user-created networks from routing table
    .DESCRIPTION
    Analyzes Windows routing table to find private/local networks only (no internet routes)
    #>
    
    try {
        $networks = New-Object System.Collections.ArrayList
        
        # Get routing table
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue
        
        foreach ($route in $routes) {
            # Skip default routes, loopback, and link-local
            if ($route.DestinationPrefix -match '^(0\.0\.0\.0/0|127\.|169\.254\.)') {
                continue
            }
            
            # ONLY include private IP ranges (RFC1918 + carrier-grade NAT)
            if (-not (Test-PrivateIPRange -IPAddress $route.DestinationPrefix)) {
                continue
            }
            
            # Skip routes we want to exclude
            $skip = $false
            foreach ($pattern in $Global:Config.InterfaceExcludePatterns) {
                if ($route.InterfaceAlias -match $pattern) {
                    $skip = $true
                    break
                }
            }
            if ($skip) { continue }
            
            # Parse CIDR
            if ($route.DestinationPrefix -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$') {
                $network = $matches[1]
                $prefix = [int]$matches[2]
                
                # Calculate network details
                $mask = Get-SubnetMaskFromPrefix $prefix
                $hostBits = 32 - $prefix
                $hostCount = [uint32]([math]::Pow(2, $hostBits)) - 2
                
                # Determine if this is directly connected or routed
                $isDirect = ($route.NextHop -eq "0.0.0.0")
                
                [void]$networks.Add([PSCustomObject]@{
                    Network = $network
                    CIDR = $route.DestinationPrefix
                    SubnetMask = $mask
                    PrefixLength = $prefix
                    HostCount = $hostCount
                    Gateway = $route.NextHop
                    Interface = $route.InterfaceAlias
                    Metric = $route.RouteMetric
                    Type = if ($isDirect) { "Direct" } else { "Routed" }
                    Source = "RouteTable"
                })
            }
        }
        
        return $networks
    } catch {
        Write-Host "  [!] Error reading route table: $($_.Exception.Message)" -ForegroundColor Yellow
        return @()
    }
}

function Get-ArpDiscoveredNetworks {
    <#
    .SYNOPSIS
    Discover user networks from ARP table analysis
    .DESCRIPTION
    Analyzes ARP cache to identify private networks with active devices only
    #>
    
    try {
        $networks = @{}
        
        # Get ARP table
        $arpOutput = arp -a
        
        foreach ($line in $arpOutput) {
            # Match IP addresses in ARP table
            if ($line -match '\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})') {
                $ip = $matches[1]
                $mac = $matches[2]
                
                # ONLY process private IP addresses
                if (-not (Test-PrivateIPRange -IPAddress $ip)) {
                    continue
                }
                
                # Skip multicast/broadcast
                if ($mac -match '^(FF:FF|01:00|33:33)') { continue }
                
                # Try to determine network by analyzing IP patterns
                $octets = $ip -split '\.'
                
                # Common network assumptions based on IP patterns
                $possibleNetworks = @()
                
                # /24 network (most common)
                $network24 = "$($octets[0]).$($octets[1]).$($octets[2]).0/24"
                $possibleNetworks += $network24
                
                # /16 network (for larger private networks)
                if ($octets[0] -eq "10") {
                    $network16 = "$($octets[0]).$($octets[1]).0.0/16"
                    $possibleNetworks += $network16
                } elseif ($octets[0] -eq "172" -and $octets[1] -ge 16 -and $octets[1] -le 31) {
                    $network16 = "$($octets[0]).$($octets[1]).0.0/16"
                    $possibleNetworks += $network16
                }
                
                # Count IPs in each network
                foreach ($net in $possibleNetworks) {
                    if (-not $networks.ContainsKey($net)) {
                        $networks[$net] = @{
                            IPs = New-Object System.Collections.ArrayList
                            MACs = New-Object System.Collections.ArrayList
                        }
                    }
                    if (-not $networks[$net].IPs.Contains($ip)) {
                        [void]$networks[$net].IPs.Add($ip)
                        [void]$networks[$net].MACs.Add($mac)
                    }
                }
            }
        }
        
        # Convert to network objects
        $result = New-Object System.Collections.ArrayList
        foreach ($net in $networks.Keys) {
            $parts = $net -split '/'
            $networkAddr = $parts[0]
            $prefix = [int]$parts[1]
            
            $mask = Get-SubnetMaskFromPrefix $prefix
            $hostBits = 32 - $prefix
            $hostCount = [uint32]([math]::Pow(2, $hostBits)) - 2
            
            [void]$result.Add([PSCustomObject]@{
                Network = $networkAddr
                CIDR = $net
                SubnetMask = $mask
                PrefixLength = $prefix
                HostCount = $hostCount
                ActiveDevices = $networks[$net].IPs.Count
                Source = "ARP"
                Confidence = if ($networks[$net].IPs.Count -ge 3) { "High" } else { "Medium" }
            })
        }
        
        return $result
    } catch {
        Write-Host "  [!] Error analyzing ARP table: $($_.Exception.Message)" -ForegroundColor Yellow
        return @()
    }
}

function Get-DhcpGatewayInfo {
    <#
    .SYNOPSIS
    Extract gateway and DHCP information from ipconfig /all
    .DESCRIPTION
    Parses ipconfig output to find default gateways and DHCP-provided network hints
    #>
    
    try {
        $gateways = @{}
        $dhcpServers = @{}
        
        # Run ipconfig /all
        $ipconfigOutput = ipconfig /all
        
        $currentAdapter = $null
        $currentIP = $null
        
        foreach ($line in $ipconfigOutput) {
            # Detect adapter
            if ($line -match '^([^:]+adapter[^:]+):') {
                $currentAdapter = $matches[1].Trim()
                $currentIP = $null
            }
            
            # IPv4 Address
            if ($line -match 'IPv4 Address.*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                $currentIP = $matches[1]
            }
            
            # Default Gateway
            if ($line -match 'Default Gateway.*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                $gateway = $matches[1]
                if ($currentIP -and $gateway -ne "0.0.0.0") {
                    $gateways[$gateway] = @{
                        IP = $gateway
                        Interface = $currentAdapter
                        LocalIP = $currentIP
                    }
                }
            }
            
            # DHCP Server
            if ($line -match 'DHCP Server.*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                $dhcpServer = $matches[1]
                if ($currentIP) {
                    $dhcpServers[$dhcpServer] = @{
                        IP = $dhcpServer
                        Interface = $currentAdapter
                        ClientIP = $currentIP
                    }
                }
            }
        }
        
        return @{
            Gateways = $gateways
            DhcpServers = $dhcpServers
        }
    } catch {
        return @{
            Gateways = @{}
            DhcpServers = @{}
        }
    }
}

function Get-GatewayNetworksFromArp {
    <#
    .SYNOPSIS
    Detect networks by analyzing gateway MACs in ARP table
    .DESCRIPTION
    Finds duplicate MAC addresses (same MAC, different IPs) which indicates routing/gateway
    #>
    
    try {
        $macToIPs = @{}
        
        # Parse ARP table
        $arpOutput = arp -a
        
        foreach ($line in $arpOutput) {
            if ($line -match '\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})') {
                $ip = $matches[1]
                $mac = $matches[2].Replace('-', ':').ToUpper()
                
                # Skip multicast/broadcast
                if ($mac -match '^(FF:FF|01:00|33:33)') { continue }
                
                # Only process private IPs
                if (-not (Test-PrivateIPRange -IPAddress $ip)) { continue }
                
                if (-not $macToIPs.ContainsKey($mac)) {
                    $macToIPs[$mac] = New-Object System.Collections.ArrayList
                }
                [void]$macToIPs[$mac].Add($ip)
            }
        }
        
        # Find gateways (MACs with multiple IPs = routing between networks)
        $gatewayNetworks = New-Object System.Collections.ArrayList
        
        foreach ($mac in $macToIPs.Keys) {
            $ips = $macToIPs[$mac]
            
            # If same MAC has IPs in different subnets, it's a gateway/router
            if ($ips.Count -gt 1) {
                $subnets = @{}
                
                foreach ($ip in $ips) {
                    $octets = $ip -split '\.'
                    $subnet24 = "$($octets[0]).$($octets[1]).$($octets[2]).0/24"
                    
                    if (-not $subnets.ContainsKey($subnet24)) {
                        $subnets[$subnet24] = $true
                        
                        [void]$gatewayNetworks.Add([PSCustomObject]@{
                            Network = "$($octets[0]).$($octets[1]).$($octets[2]).0"
                            CIDR = $subnet24
                            GatewayIP = $ip
                            GatewayMAC = $mac
                            Source = "ARP-Gateway"
                        })
                    }
                }
            }
        }
        
        return $gatewayNetworks
    } catch {
        return @()
    }
}

function Get-IPv6RaPrefixes {
    <#
    .SYNOPSIS
    Extract IPv6 Router Advertisement prefixes
    .DESCRIPTION
    Finds IPv6 network prefixes from RA (Router Advertisements)
    #>
    
    try {
        $ipv6Prefixes = New-Object System.Collections.ArrayList
        
        # Get IPv6 addresses
        $ipv6Addrs = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue
        
        foreach ($addr in $ipv6Addrs) {
            # Skip link-local (fe80::) and loopback (::1)
            if ($addr.IPAddress -match '^(fe80:|::1)') { continue }
            
            # Skip excluded interfaces
            $skip = $false
            foreach ($pattern in $Global:Config.InterfaceExcludePatterns) {
                if ($addr.InterfaceAlias -match $pattern) {
                    $skip = $true
                    break
                }
            }
            if ($skip) { continue }
            
            # Extract prefix
            $prefix = $addr.IPAddress
            $prefixLength = $addr.PrefixLength
            
            # Common IPv6 prefixes from RA
            if ($prefix -match '^(2[0-9a-f]{3}:|fd[0-9a-f]{2}:)') {
                $cidr = "$prefix/$prefixLength"
                
                [void]$ipv6Prefixes.Add([PSCustomObject]@{
                    Prefix = $prefix
                    PrefixLength = $prefixLength
                    CIDR = $cidr
                    Interface = $addr.InterfaceAlias
                    Type = if ($prefix -match '^fd') { "ULA" } else { "Global" }
                    Source = "IPv6-RA"
                })
            }
        }
        
        return $ipv6Prefixes
    } catch {
        return @()
    }
}

function Get-AllDetectedNetworks {
    <#
    .SYNOPSIS
    Comprehensive network detection using multiple sources
    .DESCRIPTION
    Uses route print, ipconfig /all, arp -a gateway analysis, and IPv6 RA prefixes
    #>
    
    try {
        $allNetworks = @{}
        
        # Source 1: Routing Table (route print)
        Write-Host "  [1/4] Reading routing table (route print)..." -ForegroundColor Cyan
        
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $routeCount = 0
        
        foreach ($route in $routes) {
            # Skip default routes (0.0.0.0/0)
            if ($route.DestinationPrefix -eq "0.0.0.0/0") {
                continue
            }
            
            # Skip loopback and link-local
            if ($route.DestinationPrefix -match '^(127\.|169\.254\.)') {
                continue
            }
            
            # ONLY include private IP ranges (RFC1918)
            if (-not (Test-PrivateIPRange -IPAddress $route.DestinationPrefix)) {
                continue
            }
            
            # Skip excluded interfaces
            $skip = $false
            foreach ($pattern in $Global:Config.InterfaceExcludePatterns) {
                if ($route.InterfaceAlias -match $pattern) {
                    $skip = $true
                    break
                }
            }
            if ($skip) { continue }
            
            # Parse CIDR
            if ($route.DestinationPrefix -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$') {
                $network = $matches[1]
                $prefix = [int]$matches[2]
                
                # Calculate network details
                $mask = Get-SubnetMaskFromPrefix $prefix
                $hostBits = 32 - $prefix
                $hostCount = [uint32]([math]::Pow(2, $hostBits)) - 2
                
                # Skip networks too small to be useful (less than 3 usable hosts)
                if ($hostCount -lt 3) {
                    continue
                }
                
                # Skip if already added
                if ($allNetworks.ContainsKey($route.DestinationPrefix)) {
                    continue
                }
                
                # Determine connection type
                $isDirect = ($route.NextHop -eq "0.0.0.0")
                $gateway = if ($isDirect) { "-" } else { $route.NextHop }
                
                $allNetworks[$route.DestinationPrefix] = [PSCustomObject]@{
                    CIDR = $route.DestinationPrefix
                    Network = $network
                    SubnetMask = $mask
                    PrefixLength = $prefix
                    HostCount = $hostCount
                    Interface = $route.InterfaceAlias
                    Gateway = $gateway
                    DhcpServer = "-"
                    Type = if ($isDirect) { "Direct" } else { "Routed" }
                    Metric = $route.RouteMetric
                    ActiveDevices = 0
                    Sources = @("RouteTable")
                    IPv6 = $false
                }
                $routeCount++
            }
        }
        
        Write-Host "        Found: $routeCount private subnet(s)" -ForegroundColor Green
        
        # Source 2: DHCP/Gateway Info (ipconfig /all)
        Write-Host "  [2/4] Analyzing DHCP and gateway info (ipconfig /all)..." -ForegroundColor Cyan
        
        $dhcpInfo = Get-DhcpGatewayInfo
        $dhcpCount = 0
        
        # Enrich existing networks with DHCP server info
        foreach ($dhcpServer in $dhcpInfo.DhcpServers.Values) {
            $clientIP = $dhcpServer.ClientIP
            
            # Find which network this belongs to
            foreach ($netKey in $allNetworks.Keys) {
                if (Test-IPInSubnet -IPAddress $clientIP -Subnet $netKey) {
                    if (-not $allNetworks[$netKey].Sources.Contains("DHCP")) {
                        $allNetworks[$netKey].Sources += "DHCP"
                    }
                    $allNetworks[$netKey].DhcpServer = $dhcpServer.IP
                    break
                }
            }
        }
        
        # Identify gateway networks
        foreach ($gateway in $dhcpInfo.Gateways.Values) {
            $gatewayIP = $gateway.IP
            
            # Find network for this gateway
            foreach ($netKey in $allNetworks.Keys) {
                if (Test-IPInSubnet -IPAddress $gatewayIP -Subnet $netKey) {
                    if (-not $allNetworks[$netKey].Sources.Contains("Gateway")) {
                        $allNetworks[$netKey].Sources += "Gateway"
                        $dhcpCount++
                    }
                    break
                }
            }
        }
        
        Write-Host "        Enhanced: $dhcpCount network(s) with gateway/DHCP info" -ForegroundColor Green
        
        # Source 3: Gateway MAC Analysis (arp -a)
        Write-Host "  [3/4] Analyzing gateway MACs (arp -a)..." -ForegroundColor Cyan
        
        $gatewayNetworks = Get-GatewayNetworksFromArp
        $arpGatewayCount = 0
        
        foreach ($gwNet in $gatewayNetworks) {
            if ($allNetworks.ContainsKey($gwNet.CIDR)) {
                # Enhance existing entry
                if (-not $allNetworks[$gwNet.CIDR].Sources.Contains("ARP-Gateway")) {
                    $allNetworks[$gwNet.CIDR].Sources += "ARP-Gateway"
                    $arpGatewayCount++
                }
            } else {
                # New network discovered via gateway MAC
                $mask = Get-SubnetMaskFromPrefix 24
                
                $allNetworks[$gwNet.CIDR] = [PSCustomObject]@{
                    CIDR = $gwNet.CIDR
                    Network = $gwNet.Network
                    SubnetMask = $mask
                    PrefixLength = 24
                    HostCount = 254
                    Interface = "Detected"
                    Gateway = $gwNet.GatewayIP
                    DhcpServer = "-"
                    Type = "Gateway-Detected"
                    Metric = 999
                    ActiveDevices = 0
                    Sources = @("ARP-Gateway")
                    IPv6 = $false
                }
                $arpGatewayCount++
            }
        }
        
        Write-Host "        Found: $arpGatewayCount network(s) via gateway MAC analysis" -ForegroundColor Green
        
        # Source 4: IPv6 RA Prefixes
        Write-Host "  [4/4] Detecting IPv6 networks (Router Advertisements)..." -ForegroundColor Cyan
        
        $ipv6Prefixes = Get-IPv6RaPrefixes
        $ipv6Count = 0
        
        foreach ($v6prefix in $ipv6Prefixes) {
            # Add IPv6 networks separately (they're informational)
            $cidrKey = "IPv6:$($v6prefix.CIDR)"
            
            if (-not $allNetworks.ContainsKey($cidrKey)) {
                $allNetworks[$cidrKey] = [PSCustomObject]@{
                    CIDR = $v6prefix.CIDR
                    Network = $v6prefix.Prefix
                    SubnetMask = "-"
                    PrefixLength = $v6prefix.PrefixLength
                    HostCount = "-"
                    Interface = $v6prefix.Interface
                    Gateway = "-"
                    DhcpServer = "-"
                    Type = $v6prefix.Type
                    Metric = 0
                    ActiveDevices = 0
                    Sources = @("IPv6-RA")
                    IPv6 = $true
                }
                $ipv6Count++
            }
        }
        
        Write-Host "        Found: $ipv6Count IPv6 prefix(es)" -ForegroundColor Green
        
        # Count active devices (optional enrichment)
        try {
            $arpOutput = arp -a
            foreach ($netKey in $allNetworks.Keys) {
                if ($allNetworks[$netKey].IPv6) { continue }
                
                $deviceCount = 0
                foreach ($line in $arpOutput) {
                    if ($line -match '\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-])') {
                        $arpIP = $matches[1]
                        if (Test-IPInSubnet -IPAddress $arpIP -Subnet $allNetworks[$netKey].CIDR) {
                            $deviceCount++
                        }
                    }
                }
                $allNetworks[$netKey].ActiveDevices = $deviceCount
            }
        } catch { }
        
        # Convert to array and sort
        $result = $allNetworks.Values | Sort-Object { 
            # IPv4 first, then IPv6
            if ($_.IPv6) {
                $priority = 2
            } elseif ($_.Type -eq "Direct") {
                $priority = 0
            } else {
                $priority = 1
            }
            "$priority-$($_.Metric.ToString().PadLeft(10, '0'))"
        }
        
        return $result
        
    } catch {
        Write-Host "  [X] Error detecting networks: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ==================== PORT SCANNING ====================

function Test-TcpPort {
    param(
        [string]$IpAddress,
        [int]$Port,
        [int]$Timeout = 1000
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($IpAddress, $Port, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout, $false)
        
        if ($wait) {
            try {
                $tcpClient.EndConnect($asyncResult)
                $tcpClient.Close()
                return $true
            } catch {
                $tcpClient.Close()
                return $false
            }
        } else {
            $tcpClient.Close()
            return $false
        }
    } catch {
        return $false
    }
}

function Get-PortServiceName {
    param([int]$Port)
    
    $commonServices = @{
        21 = "FTP"
        22 = "SSH"
        23 = "Telnet"
        25 = "SMTP"
        53 = "DNS"
        80 = "HTTP"
        110 = "POP3"
        135 = "RPC"
        139 = "NetBIOS"
        143 = "IMAP"
        443 = "HTTPS"
        445 = "SMB"
        3306 = "MySQL"
        3389 = "RDP"
        5432 = "PostgreSQL"
        5900 = "VNC"
        8080 = "HTTP-Alt"
        8443 = "HTTPS-Alt"
    }
    
    if ($commonServices.ContainsKey($Port)) {
        return $commonServices[$Port]
    }
    return "Unknown"
}

function Start-PortScan {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$IPAddresses,
        
        [int[]]$Ports,
        
        [switch]$CommonPorts,
        
        [string]$PortRange
    )
    
    try {
        $Global:ScanState.IsScanning = $true
        $Global:ScanState.CancelRequested = $false
        $isPaused = $false
        
        # Determine which ports to scan
        $portsToScan = @()
        if ($CommonPorts) {
            $portsToScan = $Global:Config.CommonPorts
        } elseif ($PortRange) {
            if ($PortRange -match '^(\d+)-(\d+)$') {
                $startPort = [int]$matches[1]
                $endPort = [int]$matches[2]
                if ($startPort -gt $endPort) {
                    throw "Invalid port range: start port is greater than end port"
                }
                if ($startPort -lt 1 -or $endPort -gt 65535) {
                    throw "Port numbers must be between 1 and 65535"
                }
                $portsToScan = $startPort..$endPort
            } else {
                throw "Invalid port range format. Use: 1-1024"
            }
        } elseif ($Ports) {
            $portsToScan = $Ports
        } else {
            $portsToScan = $Global:Config.CommonPorts
        }
        
        $totalChecks = $IPAddresses.Count * $portsToScan.Count
        $useRunspaces = $Global:Config.UseRunspaces -and $totalChecks -gt 20
        
        # Modern clean interface
        Clear-Host
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host "                        PORT SCAN IN PROGRESS                          " -ForegroundColor Cyan
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Target IPs:    " -NoNewline -ForegroundColor Gray
        Write-Host "$($IPAddresses.Count)" -ForegroundColor White
        Write-Host "  Ports:         " -NoNewline -ForegroundColor Gray
        Write-Host "$($portsToScan.Count)" -ForegroundColor White
        Write-Host "  Total checks:  " -NoNewline -ForegroundColor Gray
        Write-Host "$totalChecks" -ForegroundColor White
        Write-Host "  Mode:          " -NoNewline -ForegroundColor Gray
        if ($useRunspaces) {
            Write-Host "TURBO (Parallel Runspaces)" -ForegroundColor Green
        } else {
            Write-Host "Sequential" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  Controls: " -NoNewline -ForegroundColor Yellow
        Write-Host "[P] Pause  [C] Continue  [X] Cancel & Keep Results" -ForegroundColor White
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        $startTime = Get-Date
        $foundPorts = New-Object System.Collections.ArrayList
        
        if ($useRunspaces) {
            # ========== TURBO MODE: RUNSPACE-BASED PORT SCANNING ==========
            
            # Create runspace pool
            $runspacePool = [runspacefactory]::CreateRunspacePool(1, $Global:Config.MaxRunspaces)
            $runspacePool.Open()
            
            # Script block for port checking
            $scriptBlock = {
                param($ip, $port, $timeout)
                
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $asyncResult = $tcpClient.BeginConnect($ip, $port, $null, $null)
                    $wait = $asyncResult.AsyncWaitHandle.WaitOne($timeout, $false)
                    
                    if ($wait) {
                        try {
                            $tcpClient.EndConnect($asyncResult)
                            $tcpClient.Close()
                            
                            # Determine service name
                            $services = @{
                                21 = "FTP"; 22 = "SSH"; 23 = "Telnet"; 25 = "SMTP"
                                53 = "DNS"; 80 = "HTTP"; 110 = "POP3"; 135 = "RPC"
                                139 = "NetBIOS"; 143 = "IMAP"; 443 = "HTTPS"; 445 = "SMB"
                                3306 = "MySQL"; 3389 = "RDP"; 5432 = "PostgreSQL"
                                5900 = "VNC"; 8080 = "HTTP-Alt"; 8443 = "HTTPS-Alt"
                            }
                            $service = if ($services.ContainsKey($port)) { $services[$port] } else { "Unknown" }
                            
                            return [pscustomobject]@{
                                Success = $true
                                IP = $ip
                                Port = $port
                                Service = $service
                            }
                        } catch {
                            $tcpClient.Close()
                        }
                    } else {
                        $tcpClient.Close()
                    }
                } catch { }
                
                return [pscustomobject]@{
                    Success = $false
                    IP = $ip
                    Port = $port
                }
            }
            
            # Create jobs for all IP/Port combinations
            $jobs = New-Object System.Collections.ArrayList
            
            foreach ($ip in $IPAddresses) {
                foreach ($port in $portsToScan) {
                    $powershell = [powershell]::Create().AddScript($scriptBlock).AddArgument($ip).AddArgument($port).AddArgument($Global:Config.PortScanTimeout)
                    $powershell.RunspacePool = $runspacePool
                    
                    [void]$jobs.Add([pscustomobject]@{
                        Pipe = $powershell
                        Result = $powershell.BeginInvoke()
                        IP = $ip
                        Port = $port
                        Processed = $false
                    })
                }
            }
            
            # Print table header
            Write-Host "  OPEN PORTS DISCOVERED:" -ForegroundColor Green
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            Write-Host "  " -NoNewline
            Write-Host (" #  ").PadRight(5) -NoNewline -ForegroundColor Yellow
            Write-Host ("IP ADDRESS").PadRight(18) -NoNewline -ForegroundColor Yellow
            Write-Host ("PORT").PadRight(8) -NoNewline -ForegroundColor Yellow
            Write-Host ("SERVICE") -ForegroundColor Yellow
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            
            $deviceDisplayLines = 10
            $tableStartLine = [Console]::CursorTop
            
            for ($i = 0; $i -lt $deviceDisplayLines; $i++) {
                Write-Host ""
            }
            
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            Write-Host ""
            Write-Host ""
            Write-Host ""
            
            $progressStartLine = [Console]::CursorTop - 2
            $bufferHeight = $Host.UI.RawUI.BufferSize.Height
            
            # Poll for results
            $completed = 0
            $foundCount = 0
            
            while ($completed -lt $jobs.Count) {
                # Check for keypress
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'X') {
                        $Global:ScanState.CancelRequested = $true
                        break
                    } elseif ($key.Key -eq 'P') {
                        $isPaused = $true
                        $pauseLine = [Math]::Min($progressStartLine + 4, $bufferHeight - 2)
                        [Console]::SetCursorPosition(0, $pauseLine)
                        Write-Host "  [||] PAUSED - Press [C] to Continue or [X] to Cancel" -ForegroundColor Yellow
                        
                        while ($isPaused) {
                            if ([Console]::KeyAvailable) {
                                $key2 = [Console]::ReadKey($true)
                                if ($key2.Key -eq 'C') {
                                    $isPaused = $false
                                    [Console]::SetCursorPosition(0, $pauseLine)
                                    Write-Host (" " * 70)
                                } elseif ($key2.Key -eq 'X') {
                                    $Global:ScanState.CancelRequested = $true
                                    $isPaused = $false
                                    break
                                }
                            }
                            Start-Sleep -Milliseconds 100
                        }
                    }
                }
                
                if ($Global:ScanState.CancelRequested) {
                    break
                }
                
                # Check completed jobs
                foreach ($job in $jobs) {
                    if ($job.Result.IsCompleted -and -not $job.Processed) {
                        $job.Processed = $true
                        $completed++
                        
                        try {
                            $result = $job.Pipe.EndInvoke($job.Result)
                            
                            if ($result -and $result.Success) {
                                $foundCount++
                                
                                [void]$foundPorts.Add([pscustomobject]@{
                                    IP = $result.IP
                                    Port = $result.Port
                                    Service = $result.Service
                                })
                                
                                # Update device table
                                $startIdx = [Math]::Max(0, $foundCount - $deviceDisplayLines)
                                $portsToShow = $foundPorts[$startIdx..($foundCount - 1)]
                                
                                if ($tableStartLine -lt $bufferHeight) {
                                    [Console]::SetCursorPosition(0, $tableStartLine)
                                    
                                    $lineNum = 0
                                    foreach ($p in $portsToShow) {
                                        $displayNum = $startIdx + $lineNum + 1
                                        Write-Host "  " -NoNewline
                                        Write-Host (" $displayNum").PadRight(5) -NoNewline -ForegroundColor White
                                        Write-Host ($p.IP).PadRight(18) -NoNewline -ForegroundColor Cyan
                                        Write-Host ($p.Port.ToString()).PadRight(8) -NoNewline -ForegroundColor Green
                                        $serviceText = $p.Service.Substring(0, [Math]::Min(37, $p.Service.Length))
                                        Write-Host $serviceText -ForegroundColor White
                                        $lineNum++
                                    }
                                    
                                    for ($i = $lineNum; $i -lt $deviceDisplayLines; $i++) {
                                        Write-Host "  " -NoNewline
                                        Write-Host (" " * 68)
                                    }
                                }
                            }
                        } catch { }
                        
                        $job.Pipe.Dispose()
                    }
                }
                
                # Update progress
                $percent = [int](($completed / $totalChecks) * 100)
                $barLength = 50
                $filledLength = [int](($percent / 100) * $barLength)
                $bar = "#" * $filledLength + "-" * ($barLength - $filledLength)
                
                $elapsed = (Get-Date) - $startTime
                $speed = if ($completed -gt 0) { $completed / $elapsed.TotalSeconds } else { 0 }
                $remaining = if ($speed -gt 0) { ($totalChecks - $completed) / $speed } else { 0 }
                
                if ($progressStartLine -lt $bufferHeight - 2) {
                    [Console]::SetCursorPosition(0, $progressStartLine)
                    Write-Host "  PROGRESS: " -NoNewline -ForegroundColor Yellow
                    Write-Host "[$bar] " -NoNewline -ForegroundColor Cyan
                    Write-Host "$percent% " -NoNewline -ForegroundColor White
                    Write-Host "($completed/$totalChecks)" -ForegroundColor Gray
                    
                    $statsLine = $progressStartLine + 1
                    if ($statsLine -lt $bufferHeight - 1) {
                        [Console]::SetCursorPosition(0, $statsLine)
                        Write-Host "  " -NoNewline
                        Write-Host "Open Ports: " -NoNewline -ForegroundColor Gray
                        Write-Host "$foundCount " -NoNewline -ForegroundColor Green
                        Write-Host "| ETA: " -NoNewline -ForegroundColor Gray
                        Write-Host "$([int]$remaining)s " -NoNewline -ForegroundColor Yellow
                        Write-Host "| Speed: " -NoNewline -ForegroundColor Gray
                        Write-Host "$([Math]::Round($speed, 1)) checks/sec" -NoNewline -ForegroundColor White
                        Write-Host (" " * 10)
                    }
                }
                
                Start-Sleep -Milliseconds 50
            }
            
            # Cleanup
            $runspacePool.Close()
            $runspacePool.Dispose()
            
        } else {
            # ========== SEQUENTIAL MODE (Fallback) ==========
            
            Write-Host "  OPEN PORTS DISCOVERED:" -ForegroundColor Green
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            Write-Host "  " -NoNewline
            Write-Host (" #  ").PadRight(5) -NoNewline -ForegroundColor Yellow
            Write-Host ("IP ADDRESS").PadRight(18) -NoNewline -ForegroundColor Yellow
            Write-Host ("PORT").PadRight(8) -NoNewline -ForegroundColor Yellow
            Write-Host ("SERVICE") -ForegroundColor Yellow
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            
            $deviceDisplayLines = 10
            $tableStartLine = [Console]::CursorTop
            
            for ($i = 0; $i -lt $deviceDisplayLines; $i++) {
                Write-Host ""
            }
            
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            Write-Host ""
            Write-Host ""
            Write-Host ""
            
            $progressStartLine = [Console]::CursorTop - 2
            $bufferHeight = $Host.UI.RawUI.BufferSize.Height
            
            $completed = 0
            $foundCount = 0
            
            foreach ($ip in $IPAddresses) {
                foreach ($port in $portsToScan) {
                    if ([Console]::KeyAvailable) {
                        $key = [Console]::ReadKey($true)
                        if ($key.Key -eq 'X') {
                            $Global:ScanState.CancelRequested = $true
                            break
                        }
                    }
                    
                    if ($Global:ScanState.CancelRequested) { break }
                    
                    $completed++
                    
                    if (Test-TcpPort -IpAddress $ip -Port $port -Timeout $Global:Config.PortScanTimeout) {
                        $foundCount++
                        $service = Get-PortServiceName -Port $port
                        
                        [void]$foundPorts.Add([pscustomobject]@{
                            IP = $ip
                            Port = $port
                            Service = $service
                        })
                        
                        # Update table
                        $startIdx = [Math]::Max(0, $foundCount - $deviceDisplayLines)
                        $portsToShow = $foundPorts[$startIdx..($foundCount - 1)]
                        
                        if ($tableStartLine -lt $bufferHeight) {
                            [Console]::SetCursorPosition(0, $tableStartLine)
                            
                            $lineNum = 0
                            foreach ($p in $portsToShow) {
                                $displayNum = $startIdx + $lineNum + 1
                                Write-Host "  " -NoNewline
                                Write-Host (" $displayNum").PadRight(5) -NoNewline -ForegroundColor White
                                Write-Host ($p.IP).PadRight(18) -NoNewline -ForegroundColor Cyan
                                Write-Host ($p.Port.ToString()).PadRight(8) -NoNewline -ForegroundColor Green
                                Write-Host $p.Service -ForegroundColor White
                                $lineNum++
                            }
                            
                            for ($i = $lineNum; $i -lt $deviceDisplayLines; $i++) {
                                Write-Host "  " -NoNewline
                                Write-Host (" " * 68)
                            }
                        }
                    }
                    
                    # Update progress
                    $percent = [int](($completed / $totalChecks) * 100)
                    $barLength = 50
                    $filledLength = [int](($percent / 100) * $barLength)
                    $bar = "#" * $filledLength + "-" * ($barLength - $filledLength)
                    
                    $elapsed = (Get-Date) - $startTime
                    $speed = if ($completed -gt 0) { $completed / $elapsed.TotalSeconds } else { 0 }
                    $remaining = if ($speed -gt 0) { ($totalChecks - $completed) / $speed } else { 0 }
                    
                    if ($progressStartLine -lt $bufferHeight - 2) {
                        [Console]::SetCursorPosition(0, $progressStartLine)
                        Write-Host "  PROGRESS: " -NoNewline -ForegroundColor Yellow
                        Write-Host "[$bar] " -NoNewline -ForegroundColor Cyan
                        Write-Host "$percent% " -NoNewline -ForegroundColor White
                        Write-Host "($completed/$totalChecks)" -ForegroundColor Gray
                        
                        $statsLine = $progressStartLine + 1
                        if ($statsLine -lt $bufferHeight - 1) {
                            [Console]::SetCursorPosition(0, $statsLine)
                            Write-Host "  " -NoNewline
                            Write-Host "Open Ports: " -NoNewline -ForegroundColor Gray
                            Write-Host "$foundCount " -NoNewline -ForegroundColor Green
                            Write-Host "| ETA: " -NoNewline -ForegroundColor Gray
                            Write-Host "$([int]$remaining)s " -NoNewline -ForegroundColor Yellow
                            Write-Host "| Speed: " -NoNewline -ForegroundColor Gray
                            Write-Host "$([Math]::Round($speed, 1)) checks/sec" -NoNewline -ForegroundColor White
                            Write-Host (" " * 10)
                        }
                    }
                }
                if ($Global:ScanState.CancelRequested) { break }
            }
        }
        
        # Final display
        $finalLine = [Math]::Min($progressStartLine + 4, $bufferHeight - 5)
        [Console]::SetCursorPosition(0, $finalLine)
        
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        
        $Global:ScanState.IsScanning = $false
        
        $elapsed = (Get-Date) - $startTime
        $speed = if ($totalChecks -gt 0) { $totalChecks / $elapsed.TotalSeconds } else { 0 }
        
        Write-Host ""
        if ($Global:ScanState.CancelRequested) {
            Write-Host "  [!] Scan canceled by user" -ForegroundColor Yellow
            Write-Host "  [+] Kept $($foundPorts.Count) open port(s) found before cancellation" -ForegroundColor Green
        } else {
            Write-Host "  [+] Scan complete!" -ForegroundColor Green
        }
        
        # Group results by IP
        $resultsByIP = $foundPorts | Group-Object IP
        
        Write-Host "      Open Ports: $($foundPorts.Count)" -ForegroundColor White
        Write-Host "      Hosts:      $($resultsByIP.Count) with open ports" -ForegroundColor White
        Write-Host "      Time:       $([Math]::Round($elapsed.TotalSeconds, 2)) seconds" -ForegroundColor White
        Write-Host "      Speed:      $([Math]::Round($speed, 1)) checks/sec" -ForegroundColor White
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        # Display summary by host
        if ($foundPorts.Count -gt 0) {
            Write-Host "  SUMMARY BY HOST:" -ForegroundColor Cyan
            Write-Host ""
            
            foreach ($group in $resultsByIP) {
                $ip = $group.Name
                
                # Try to resolve hostname
                $hostname = "-"
                try {
                    $hostEntry = [System.Net.Dns]::GetHostEntry($ip)
                    if ($hostEntry -and $hostEntry.HostName) {
                        $hostname = $hostEntry.HostName
                    }
                } catch {
                    # Hostname resolution failed, use IP only
                }
                
                # Display IP and hostname
                if ($hostname -ne "-") {
                    Write-Host "  $ip ($hostname)" -ForegroundColor White
                } else {
                    Write-Host "  $ip" -ForegroundColor White
                }
                
                foreach ($port in $group.Group) {
                    Write-Host "    - Port $($port.Port): $($port.Service)" -ForegroundColor Gray
                }
                Write-Host ""
            }
        } else {
            Write-Host "  No open ports found on any host" -ForegroundColor Yellow
            Write-Host ""
        }
        
        # Return results in format compatible with existing code
        $results = @()
        foreach ($group in $resultsByIP) {
            # Resolve hostname for export
            $hostname = "-"
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($group.Name)
                if ($hostEntry -and $hostEntry.HostName) {
                    $hostname = $hostEntry.HostName
                }
            } catch {
                # Hostname resolution failed
            }
            
            # Create detailed port list for export
            $portList = @()
            foreach ($port in $group.Group) {
                $portList += [PSCustomObject]@{
                    Port = $port.Port
                    State = $port.State
                    Service = $port.Service
                }
            }
            
            $results += [PSCustomObject]@{
                IP = $group.Name
                Hostname = $hostname
                OpenPorts = $portList
                PortCount = $group.Count
            }
        }
        
        return $results
        
    } catch {
        Write-Host ""
        Write-Host "  [X] Error during port scan: $($_.Exception.Message)" -ForegroundColor Red
        $Global:ScanState.IsScanning = $false
        return @()
    }
}

# ==================== STEALTH DISCOVERY ====================

function Test-IPInSubnet {
    <#
    .SYNOPSIS
    Check if an IP address belongs to a specific subnet
    #>
    param(
        [string]$IPAddress,
        [string]$Subnet  # Format: 192.168.1.0/24
    )
    
    try {
        if ($Subnet -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$') {
            $networkAddr = $matches[1]
            $prefixLength = [int]$matches[2]
            
            # Convert IP and network to integers for comparison
            $ipParts = $IPAddress -split '\.'
            $netParts = $networkAddr -split '\.'
            
            if ($ipParts.Count -ne 4 -or $netParts.Count -ne 4) {
                return $false
            }
            
            $ipInt = ([uint32]$ipParts[0] -shl 24) + ([uint32]$ipParts[1] -shl 16) + ([uint32]$ipParts[2] -shl 8) + [uint32]$ipParts[3]
            $netInt = ([uint32]$netParts[0] -shl 24) + ([uint32]$netParts[1] -shl 16) + ([uint32]$netParts[2] -shl 8) + [uint32]$netParts[3]
            
            # Create subnet mask
            $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, (32 - $prefixLength)))
            
            # Check if IP is in subnet
            return (($ipInt -band $mask) -eq ($netInt -band $mask))
        }
        
        return $false
    } catch {
        return $false
    }
}

function Get-ArpTable {
    <#
    .SYNOPSIS
    Get devices from ARP cache (Layer 2 discovery)
    .DESCRIPTION
    Finds devices that responded to any network traffic, even if they don't respond to pings
    #>
    param(
        [string]$TargetSubnet = $null  # Optional: filter to specific subnet (e.g. "192.168.1.0/24")
    )
    
    try {
        $arpDevices = New-Object System.Collections.ArrayList
        
        # Get ARP table using arp command
        $arpOutput = arp -a
        
        foreach ($line in $arpOutput) {
            # Match IP and MAC pattern: "  192.168.1.1           00-11-22-33-44-55     dynamic"
            if ($line -match '\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})') {
                $ip = $matches[1]
                $mac = $matches[2].Replace('-', ':').ToUpper()
                
                # Filter by subnet if specified
                if ($TargetSubnet -and -not (Test-IPInSubnet -IPAddress $ip -Subnet $TargetSubnet)) {
                    continue
                }
                
                # Skip multicast and broadcast addresses
                if ($mac -notmatch '^(FF:FF|01:00|33:33)') {
                    [void]$arpDevices.Add([PSCustomObject]@{
                        IP = $ip
                        MAC = $mac
                        DiscoveryMethod = "ARP"
                    })
                }
            }
        }
        
        return $arpDevices
    } catch {
        Write-Host "  [!] Error reading ARP table: $($_.Exception.Message)" -ForegroundColor Yellow
        return @()
    }
}

function Get-MdnsDevices {
    <#
    .SYNOPSIS
    Discover devices via mDNS/Bonjour (mobile devices, Apple products, smart devices)
    .DESCRIPTION
    Sends mDNS queries to find devices advertising services
    #>
    param(
        [string]$TargetSubnet = $null  # Optional: filter to specific subnet
    )
    
    try {
        $mdnsDevices = New-Object System.Collections.ArrayList
        
        # mDNS multicast address and port
        $mdnsIP = "224.0.0.251"
        $mdnsPort = 5353
        
        # Get local IP to bind
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $_.IPAddress -notmatch '^(127\.|169\.254)' -and $_.PrefixOrigin -ne "WellKnown"
        } | Select-Object -First 1).IPAddress
        
        if (-not $localIP) {
            return @()
        }
        
        # Create UDP client with better error handling
        $udpClient = $null
        try {
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $udpClient.Client.ReceiveTimeout = 2000
            $udpClient.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, 
                                               [System.Net.Sockets.SocketOptionName]::ReuseAddress, 
                                               $true)
            
            $localEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($localIP), 0)
            $udpClient.Client.Bind($localEndpoint)
            
            # Try to join multicast group - may fail on some networks
            $multicastAddress = [System.Net.IPAddress]::Parse($mdnsIP)
            try {
                $udpClient.JoinMulticastGroup($multicastAddress, [System.Net.IPAddress]::Parse($localIP))
            } catch {
                # Multicast not supported on this network - skip mDNS
                if ($udpClient) { $udpClient.Close() }
                return @()
            }
            
            # Build mDNS query for _services._dns-sd._udp.local
            $query = @(
                0x00, 0x00,  # Transaction ID
                0x00, 0x00,  # Flags
                0x00, 0x01,  # Questions: 1
                0x00, 0x00,  # Answer RRs
                0x00, 0x00,  # Authority RRs
                0x00, 0x00   # Additional RRs
            )
            
            # Add question: _services._dns-sd._udp.local
            $name = "_services._dns-sd._udp.local"
            foreach ($part in $name.Split('.')) {
                $query += $part.Length
                $query += [System.Text.Encoding]::ASCII.GetBytes($part)
            }
            $query += 0x00  # End of name
            $query += 0x00, 0x0C  # Type: PTR
            $query += 0x00, 0x01  # Class: IN
            
            # Send query
            $endpoint = New-Object System.Net.IPEndPoint($multicastAddress, $mdnsPort)
            try {
                [void]$udpClient.Send($query, $query.Length, $endpoint)
            } catch {
                # Can't send to multicast - skip
                if ($udpClient) { $udpClient.Close() }
                return @()
            }
            
            # Listen for responses
            $remoteEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $startTime = Get-Date
            
            while (((Get-Date) - $startTime).TotalSeconds -lt 3) {
                try {
                    if ($udpClient.Available -gt 0) {
                        $data = $udpClient.Receive([ref]$remoteEndpoint)
                        $ip = $remoteEndpoint.Address.ToString()
                        
                        if ($ip -ne $localIP -and $ip -notmatch '^(127\.|224\.)') {
                            # Filter by subnet if specified
                            if ($TargetSubnet -and -not (Test-IPInSubnet -IPAddress $ip -Subnet $TargetSubnet)) {
                                continue
                            }
                            
                            # Parse device name from response (simplified)
                            $deviceName = "mDNS Device"
                            
                            [void]$mdnsDevices.Add([PSCustomObject]@{
                                IP = $ip
                                Hostname = $deviceName
                                DiscoveryMethod = "mDNS"
                            })
                        }
                    }
                    Start-Sleep -Milliseconds 100
                } catch {
                    # Timeout or error receiving
                    break
                }
            }
            
            if ($udpClient) { $udpClient.Close() }
            
            # Remove duplicates
            return ($mdnsDevices | Sort-Object IP -Unique)
            
        } catch {
            if ($udpClient) { $udpClient.Close() }
            return @()
        }
        
    } catch {
        return @()
    }
}

function Get-DhcpLeases {
    <#
    .SYNOPSIS
    Parse DHCP server leases (requires admin rights)
    .DESCRIPTION
    Reads DHCP lease database to find all devices that have requested IPs
    #>
    
    try {
        $leases = New-Object System.Collections.ArrayList
        
        # Check if running as admin
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            return @()
        }
        
        # Try to get DHCP leases using PowerShell cmdlet (Windows Server)
        try {
            $dhcpLeases = Get-DhcpServerv4Lease -ComputerName localhost -ErrorAction SilentlyContinue
            
            foreach ($lease in $dhcpLeases) {
                [void]$leases.Add([PSCustomObject]@{
                    IP = $lease.IPAddress.ToString()
                    MAC = $lease.ClientId
                    Hostname = $lease.HostName
                    DiscoveryMethod = "DHCP"
                })
            }
        } catch {
            # Not a DHCP server or cmdlet not available
        }
        
        # Alternative: Parse Windows DHCP lease file (for clients)
        $dhcpFile = "$env:SystemRoot\System32\dhcp\dhcp.mdb"
        if (Test-Path $dhcpFile) {
            # DHCP database parsing would go here (complex, requires DB library)
            # Skipping for now as it requires additional dependencies
        }
        
        return $leases
        
    } catch {
        return @()
    }
}

function Get-SsdpDevices {
    <#
    .SYNOPSIS
    Discover UPnP/SSDP devices (smart TVs, IoT devices, media servers)
    .DESCRIPTION
    Sends SSDP discovery packets to find UPnP devices on the network
    #>
    param(
        [string]$TargetSubnet = $null  # Optional: filter to specific subnet
    )
    
    try {
        $ssdpDevices = New-Object System.Collections.ArrayList
        
        # SSDP multicast address and port
        $ssdpIP = "239.255.255.250"
        $ssdpPort = 1900
        
        # Create UDP client with better error handling
        $udpClient = $null
        try {
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $udpClient.Client.ReceiveTimeout = 3000
            $udpClient.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, 
                                               [System.Net.Sockets.SocketOptionName]::ReuseAddress, 
                                               $true)
            
            # Bind to local endpoint
            $localEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $udpClient.Client.Bind($localEndpoint)
            
            # Build SSDP M-SEARCH packet
            $searchMessage = @"
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 2
ST: ssdp:all

"@ -replace "`n", "`r`n"
            
            $searchBytes = [System.Text.Encoding]::ASCII.GetBytes($searchMessage)
            
            # Send discovery packet - may fail if multicast not supported
            $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ssdpIP), $ssdpPort)
            try {
                [void]$udpClient.Send($searchBytes, $searchBytes.Length, $endpoint)
            } catch {
                # Can't send to multicast - skip
                if ($udpClient) { $udpClient.Close() }
                return @()
            }
            
            # Listen for responses
            $remoteEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $startTime = Get-Date
            $seenIPs = @{}
            
            while (((Get-Date) - $startTime).TotalSeconds -lt 4) {
                try {
                    if ($udpClient.Available -gt 0) {
                        $data = $udpClient.Receive([ref]$remoteEndpoint)
                        $response = [System.Text.Encoding]::ASCII.GetString($data)
                        $ip = $remoteEndpoint.Address.ToString()
                        
                        if (-not $seenIPs.ContainsKey($ip)) {
                            # Filter by subnet if specified
                            if ($TargetSubnet -and -not (Test-IPInSubnet -IPAddress $ip -Subnet $TargetSubnet)) {
                                continue
                            }
                            
                            $seenIPs[$ip] = $true
                            
                            # Parse device info from response
                            $deviceType = "UPnP Device"
                            $server = ""
                            
                            if ($response -match "SERVER:\s*(.+)") {
                                $server = $matches[1].Trim()
                            }
                            
                            if ($response -match "ST:\s*(.+)") {
                                $deviceType = $matches[1].Trim()
                            }
                            
                            [void]$ssdpDevices.Add([PSCustomObject]@{
                                IP = $ip
                                DeviceType = $deviceType
                                Server = $server
                                DiscoveryMethod = "SSDP"
                            })
                        }
                    }
                    Start-Sleep -Milliseconds 100
                } catch {
                    # Timeout
                    break
                }
            }
            
            if ($udpClient) { $udpClient.Close() }
            return $ssdpDevices
            
        } catch {
            if ($udpClient) { $udpClient.Close() }
            return @()
        }
        
    } catch {
        return @()
    }
}

function Get-MacVendor {
    <#
    .SYNOPSIS
    Get vendor name from MAC address (OUI lookup)
    #>
    param([string]$MacAddress)
    
    # Extract OUI (first 3 octets)
    $oui = ($MacAddress -split ':')[0..2] -join ''
    
    # Common OUI database (subset - full database would be large)
    $vendors = @{
        '000000' = 'Xerox'
        '000001' = 'Xerox'
        '000393' = 'Apple'
        '000502' = 'Apple'
        '000A27' = 'Apple'
        '000A95' = 'Apple'
        '000D93' = 'Apple'
        '001124' = 'Apple'
        '0016CB' = 'Apple'
        '0017F2' = 'Apple'
        '0019E3' = 'Apple'
        '001B63' = 'Apple'
        '001CB3' = 'Apple'
        '001D4F' = 'Apple'
        '001E52' = 'Apple'
        '001EC2' = 'Apple'
        '001F5B' = 'Apple'
        '0021E9' = 'Apple'
        '002312' = 'Apple'
        '002332' = 'Apple'
        '002436' = 'Apple'
        '0025BC' = 'Apple'
        '0026B0' = 'Apple'
        '002608' = 'Apple'
        '0050E4' = 'Apple'
        '006171' = 'Apple'
        '0452F3' = 'Apple'
        '10DD B1' = 'Apple'
        '18AF61' = 'Apple'
        '28CFE9' = 'Apple'
        '2CF0EE' = 'Apple'
        '30F7C5' = 'Apple'
        '34159E' = 'Apple'
        '3C0754' = 'Apple'
        '40A6D9' = 'Apple'
        '5C5948' = 'Apple'
        '685B35' = 'Apple'
        '6C4008' = 'Apple'
        '6C709F' = 'Apple'
        '7073CB' = 'Apple'
        '80EA96' = 'Apple'
        '84788B' = 'Apple'
        '8863DF' = 'Apple'
        '8C006D' = 'Apple'
        'A45E60' = 'Apple'
        'B8E856' = 'Apple'
        'C82A14' = 'Apple'
        'D023DB' = 'Apple'
        'F0989D' = 'Apple'
        'F82793' = 'Apple'
        '0026BB' = 'Samsung'
        '002566' = 'Samsung'
        '28E347' = 'Samsung'
        '3C5A37' = 'Samsung'
        '503F4B' = 'Samsung'
        '5C0A5B' = 'Samsung'
        '88329B' = 'Samsung'
        'E8508B' = 'Samsung'
        'F4B549' = 'Samsung'
        '18F46A' = 'Google'
        '3C5AB4' = 'Google'
        '54605D' = 'Google'
        '680771' = 'Google'
        '6C5AB5' = 'Google'
        '783A84' = 'Google'
        '84F5A4' = 'Google'
        'A0D795' = 'Google'
        'B0EE7B' = 'Google'
        'F4F5D8' = 'Google'
        '000C29' = 'VMware'
        '005056' = 'VMware'
        '000569' = 'VMware'
        '00155D' = 'Microsoft'
        '000BDB' = 'Microsoft'
        '00125A' = 'Microsoft'
        '001DD8' = 'Microsoft'
        'AC220B' = 'Nest Labs'
        '18B430' = 'Nest Labs'
        '64168D' = 'Nest Labs'
        'D8EB46' = 'Amazon'
        '84D6D0' = 'Amazon'
        '6854FD' = 'Amazon'
        '002722' = 'Linksys'
        '000C41' = 'Linksys'
        '000E08' = 'Cisco'
        '001979' = 'Cisco'
        '00409C' = 'Cisco'
        '0007EB' = 'Cisco'
        '00D0BA' = 'Cisco'
        '000B5F' = 'Cisco'
        '000C85' = 'Cisco'
    }
    
    if ($vendors.ContainsKey($oui.ToUpper())) {
        return $vendors[$oui.ToUpper()]
    }
    
    return "Unknown"
}

function Start-StealthDiscovery {
    <#
    .SYNOPSIS
    Comprehensive device discovery using multiple methods
    .DESCRIPTION
    Finds devices using ARP, mDNS, DHCP, and SSDP - catches devices that don't respond to pings!
    #>
    param(
        [string]$TargetSubnet = $null  # Optional: limit discovery to specific subnet (e.g. "192.168.1.0/24")
    )
    
    try {
        $Global:ScanState.IsScanning = $true
        $Global:ScanState.CancelRequested = $false
        
        Clear-Host
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host "                     STEALTH DISCOVERY IN PROGRESS                     " -ForegroundColor Cyan
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        if ($TargetSubnet) {
            Write-Host "  Target Subnet: $TargetSubnet" -ForegroundColor White
            Write-Host ""
        }
        Write-Host "  Finding devices using multiple discovery methods..." -ForegroundColor White
        Write-Host "  This finds mobile devices, IoT, and devices that block pings!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        $allDevices = @{}
        $startTime = Get-Date
        
        # Method 1: ARP Table
        Write-Host "  [1/4] Scanning ARP cache..." -ForegroundColor Cyan
        $arpDevices = Get-ArpTable -TargetSubnet $TargetSubnet
        Write-Host "        Found: $($arpDevices.Count) devices" -ForegroundColor Green
        
        foreach ($device in $arpDevices) {
            if (-not $allDevices.ContainsKey($device.IP)) {
                $vendor = Get-MacVendor -MacAddress $device.MAC
                $allDevices[$device.IP] = [PSCustomObject]@{
                    IP = $device.IP
                    MAC = $device.MAC
                    Vendor = $vendor
                    Hostname = "-"
                    Methods = @("ARP")
                    DeviceType = ""
                }
            }
        }
        
        # Method 2: mDNS Discovery
        Write-Host "  [2/4] Scanning mDNS/Bonjour (mobile devices)..." -ForegroundColor Cyan
        $mdnsDevices = Get-MdnsDevices -TargetSubnet $TargetSubnet
        Write-Host "        Found: $($mdnsDevices.Count) devices" -ForegroundColor Green
        
        foreach ($device in $mdnsDevices) {
            if ($allDevices.ContainsKey($device.IP)) {
                $allDevices[$device.IP].Methods += "mDNS"
                if ($device.Hostname -ne "mDNS Device") {
                    $allDevices[$device.IP].Hostname = $device.Hostname
                }
            } else {
                $allDevices[$device.IP] = [PSCustomObject]@{
                    IP = $device.IP
                    MAC = "-"
                    Vendor = "-"
                    Hostname = $device.Hostname
                    Methods = @("mDNS")
                    DeviceType = ""
                }
            }
        }
        
        # Method 3: DHCP Leases
        Write-Host "  [3/4] Checking DHCP leases..." -ForegroundColor Cyan
        $dhcpDevices = Get-DhcpLeases
        if ($dhcpDevices.Count -eq 0) {
            Write-Host "        Skipped (requires DHCP server or admin rights)" -ForegroundColor Yellow
        } else {
            Write-Host "        Found: $($dhcpDevices.Count) devices" -ForegroundColor Green
        }
        
        foreach ($device in $dhcpDevices) {
            # Filter DHCP results by subnet if specified
            if ($TargetSubnet -and -not (Test-IPInSubnet -IPAddress $device.IP -Subnet $TargetSubnet)) {
                continue
            }
            
            if ($allDevices.ContainsKey($device.IP)) {
                $allDevices[$device.IP].Methods += "DHCP"
                if ($device.MAC -ne "-") {
                    $allDevices[$device.IP].MAC = $device.MAC
                    $allDevices[$device.IP].Vendor = Get-MacVendor -MacAddress $device.MAC
                }
                if ($device.Hostname) {
                    $allDevices[$device.IP].Hostname = $device.Hostname
                }
            } else {
                $vendor = if ($device.MAC) { Get-MacVendor -MacAddress $device.MAC } else { "-" }
                $allDevices[$device.IP] = [PSCustomObject]@{
                    IP = $device.IP
                    MAC = $device.MAC
                    Vendor = $vendor
                    Hostname = $device.Hostname
                    Methods = @("DHCP")
                    DeviceType = ""
                }
            }
        }
        
        # Method 4: SSDP/UPnP Discovery
        Write-Host "  [4/4] Scanning SSDP/UPnP (smart devices)..." -ForegroundColor Cyan
        $ssdpDevices = Get-SsdpDevices -TargetSubnet $TargetSubnet
        Write-Host "        Found: $($ssdpDevices.Count) devices" -ForegroundColor Green
        
        foreach ($device in $ssdpDevices) {
            if ($allDevices.ContainsKey($device.IP)) {
                $allDevices[$device.IP].Methods += "SSDP"
                $allDevices[$device.IP].DeviceType = $device.DeviceType
            } else {
                $allDevices[$device.IP] = [PSCustomObject]@{
                    IP = $device.IP
                    MAC = "-"
                    Vendor = "-"
                    Hostname = "-"
                    Methods = @("SSDP")
                    DeviceType = $device.DeviceType
                }
            }
        }
        
        $elapsed = (Get-Date) - $startTime
        
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [+] Discovery complete!" -ForegroundColor Green
        Write-Host "      Total devices: $($allDevices.Count)" -ForegroundColor White
        Write-Host "      Time: $([Math]::Round($elapsed.TotalSeconds, 1)) seconds" -ForegroundColor White
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        # Display results
        if ($allDevices.Count -eq 0) {
            Write-Host "  No devices found" -ForegroundColor Yellow
            Write-Host ""
        } else {
            Write-Host "  DISCOVERED DEVICES:" -ForegroundColor Green
            Write-Host "  " -NoNewline
            Write-Host ("-" * 100) -ForegroundColor Gray
            Write-Host ("  {0,-15} {1,-17} {2,-15} {3,-20} {4}" -f "IP ADDRESS", "MAC ADDRESS", "VENDOR", "HOSTNAME", "METHODS") -ForegroundColor Yellow
            Write-Host "  " -NoNewline
            Write-Host ("-" * 100) -ForegroundColor Gray
            
            # Sort by IP
            $sortedDevices = $allDevices.Values | Sort-Object { 
                $parts = $_.IP.Split('.')
                [long]$parts[0] * 16777216 + [long]$parts[1] * 65536 + [long]$parts[2] * 256 + [long]$parts[3]
            }
            
            foreach ($device in $sortedDevices) {
                $methods = $device.Methods -join ", "
                $hostname = if ($device.Hostname.Length -gt 20) { $device.Hostname.Substring(0, 17) + "..." } else { $device.Hostname }
                $vendor = if ($device.Vendor.Length -gt 15) { $device.Vendor.Substring(0, 12) + "..." } else { $device.Vendor }
                
                Write-Host ("  {0,-15} {1,-17} {2,-15} {3,-20} {4}" -f 
                    $device.IP,
                    $device.MAC,
                    $vendor,
                    $hostname,
                    $methods) -ForegroundColor White
            }
            
            Write-Host "  " -NoNewline
            Write-Host ("-" * 100) -ForegroundColor Gray
            Write-Host ""
            
            # Summary by discovery method
            Write-Host "  SUMMARY BY METHOD:" -ForegroundColor Cyan
            $methodCounts = @{}
            foreach ($device in $sortedDevices) {
                foreach ($method in $device.Methods) {
                    if (-not $methodCounts.ContainsKey($method)) {
                        $methodCounts[$method] = 0
                    }
                    $methodCounts[$method]++
                }
            }
            
            foreach ($method in ($methodCounts.Keys | Sort-Object)) {
                Write-Host ("    {0,-10} : {1} devices" -f $method, $methodCounts[$method]) -ForegroundColor Gray
            }
            Write-Host ""
        }
        
        $Global:ScanState.IsScanning = $false
        
        # Convert to format compatible with existing code and add fingerprinting
        $results = New-Object System.Collections.ArrayList
        foreach ($device in $allDevices.Values) {
            # Classify device
            $classification = Get-DeviceType -Vendor $device.Vendor -Hostname $device.Hostname -OS "Unknown" -DiscoveryMethods $device.Methods
            
            [void]$results.Add([PSCustomObject]@{
                IP = $device.IP
                MAC = $device.MAC
                Vendor = $device.Vendor
                Hostname = $device.Hostname
                OS = "Unknown"
                DeviceType = $classification.Type
                Confidence = $classification.Confidence
                DiscoveryMethods = $device.Methods
            })
        }
        
        return $results
        
    } catch {
        Write-Host ""
        Write-Host "  [X] Error during stealth discovery: $($_.Exception.Message)" -ForegroundColor Red
        $Global:ScanState.IsScanning = $false
        return @()
    }
}

function Merge-ScanResults {
    <#
    .SYNOPSIS
    Merge ping scan results with stealth discovery results
    .DESCRIPTION
    Combines results from multiple discovery methods into comprehensive output
    #>
    param(
        [array]$PingResults,
        [array]$StealthResults,
        [string]$Network
    )
    
    try {
        $mergedDevices = @{}
        
        # Add ping results first
        foreach ($device in $PingResults) {
            $ttl = if ($device.TTL) { $device.TTL } else { 0 }
            
            $mergedDevices[$device.IP] = [PSCustomObject]@{
                IP = $device.IP
                Hostname = $device.Hostname
                ResponseTime = if ($device.ResponseTime) { $device.ResponseTime } else { $null }
                TTL = $ttl
                MAC = "-"
                Vendor = "-"
                OS = Get-OSFromTTL -TTL $ttl
                DeviceType = "Unknown"
                Confidence = "Low"
                DiscoveryMethods = @("Ping")
            }
        }
        
        # Now run quick stealth discovery on the network
        if ($Global:Config.UseIntegratedDiscovery) {
            Write-Host ""
            Write-Host "  [+] Running stealth discovery on target subnet..." -ForegroundColor Cyan
            
            # Quick ARP scan - filtered to target subnet
            $arpDevices = Get-ArpTable -TargetSubnet $Network
            foreach ($device in $arpDevices) {
                if ($mergedDevices.ContainsKey($device.IP)) {
                    $mergedDevices[$device.IP].MAC = $device.MAC
                    $mergedDevices[$device.IP].Vendor = Get-MacVendor -MacAddress $device.MAC
                    $mergedDevices[$device.IP].DiscoveryMethods += "ARP"
                } else {
                    $vendor = Get-MacVendor -MacAddress $device.MAC
                    $mergedDevices[$device.IP] = [PSCustomObject]@{
                        IP = $device.IP
                        Hostname = "-"
                        ResponseTime = $null
                        TTL = 0
                        MAC = $device.MAC
                        Vendor = $vendor
                        OS = "Unknown"
                        DeviceType = "Unknown"
                        Confidence = "Low"
                        DiscoveryMethods = @("ARP")
                    }
                }
            }
            
            # Quick mDNS scan - filtered to target subnet
            Write-Host "  [+] Checking for mDNS devices in subnet..." -ForegroundColor Cyan
            $mdnsDevices = Get-MdnsDevices -TargetSubnet $Network
            foreach ($device in $mdnsDevices) {
                if ($mergedDevices.ContainsKey($device.IP)) {
                    if ($device.Hostname -ne "mDNS Device" -and $mergedDevices[$device.IP].Hostname -eq "-") {
                        $mergedDevices[$device.IP].Hostname = $device.Hostname
                    }
                    $mergedDevices[$device.IP].DiscoveryMethods += "mDNS"
                } else {
                    $mergedDevices[$device.IP] = [PSCustomObject]@{
                        IP = $device.IP
                        Hostname = $device.Hostname
                        ResponseTime = $null
                        TTL = 0
                        MAC = "-"
                        Vendor = "-"
                        OS = "Unknown"
                        DeviceType = "Unknown"
                        Confidence = "Low"
                        DiscoveryMethods = @("mDNS")
                    }
                }
            }
            
            # Quick SSDP scan - filtered to target subnet
            Write-Host "  [+] Checking for SSDP/UPnP devices in subnet..." -ForegroundColor Cyan
            $ssdpDevices = Get-SsdpDevices -TargetSubnet $Network
            foreach ($device in $ssdpDevices) {
                if ($mergedDevices.ContainsKey($device.IP)) {
                    $mergedDevices[$device.IP].DiscoveryMethods += "SSDP"
                } else {
                    $mergedDevices[$device.IP] = [PSCustomObject]@{
                        IP = $device.IP
                        Hostname = "-"
                        ResponseTime = $null
                        TTL = 0
                        MAC = "-"
                        Vendor = "-"
                        OS = "Unknown"
                        DeviceType = "Unknown"
                        Confidence = "Low"
                        DiscoveryMethods = @("SSDP")
                    }
                }
            }
        }
        
        # Convert to sorted array
        $results = New-Object System.Collections.ArrayList
        foreach ($device in $mergedDevices.Values) {
            [void]$results.Add($device)
        }
        
        # Enrich all devices with fingerprinting
        foreach ($device in $results) {
            $classification = Get-DeviceType -Vendor $device.Vendor -Hostname $device.Hostname -OS $device.OS -DiscoveryMethods $device.DiscoveryMethods
            $device.DeviceType = $classification.Type
            $device.Confidence = $classification.Confidence
        }
        
        # Sort by IP
        $results = $results | Sort-Object { 
            $parts = $_.IP.Split('.')
            [long]$parts[0] * 16777216 + [long]$parts[1] * 65536 + [long]$parts[2] * 256 + [long]$parts[3]
        }
        
        return $results
        
    } catch {
        Write-Host "  [!] Error merging results: $($_.Exception.Message)" -ForegroundColor Yellow
        return $PingResults
    }
}

# ==================== SCANNING ENGINE ====================

function Start-NetworkScan {
    param(
        [string]$Target,
        [switch]$AutoOptimize
    )
    
    try {
        # Reset scan state
        $Global:ScanState.IsScanning = $true
        $Global:ScanState.CancelRequested = $false
        $Global:ScanState.FoundHosts = New-Object System.Collections.ArrayList
        $Global:ScanState.TotalScanned = 0
        $isPaused = $false
        
        Write-Host ""
        Write-Host "  [i] Parsing target: $Target" -ForegroundColor DarkGray
        
        $ips = Get-IPsFromInput -InputString $Target
        
        if ($ips.Count -eq 0) {
            Write-Host ""
            Write-Host "  [X] No valid IPs to scan" -ForegroundColor Red
            Write-Host "  [i] Target was: $Target" -ForegroundColor Yellow
            $Global:ScanState.IsScanning = $false
            return @()
        }
        
        Write-Host "  [i] Will scan $($ips.Count) IP(s)" -ForegroundColor DarkGray
        
        # Check if runspaces should be used
        $useRunspaces = $Global:Config.UseRunspaces -and $ips.Count -gt 10
        
        if ($useRunspaces) {
            Write-Host "  [i] Using parallel runspace scanning (FAST MODE)" -ForegroundColor Green
        } else {
            Write-Host "  [i] Using sequential scanning" -ForegroundColor Yellow
        }
        Write-Host ""
        
        $total = $ips.Count
        
        # Auto-optimize for large networks
        if ($AutoOptimize -and $total -gt $Global:Config.FastScanMaxHosts) {
            Write-Host "  [i] Auto-optimizing: Limiting to first $($Global:Config.FastScanMaxHosts) hosts" -ForegroundColor Yellow
            $ips = $ips[0..($Global:Config.FastScanMaxHosts - 1)]
            $total = $ips.Count
        }
        
        $Global:ScanState.TotalHosts = $total
        
        # Modern clean interface
        Clear-Host
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host "                        NETWORK SCAN IN PROGRESS                       " -ForegroundColor Cyan
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Target: " -NoNewline -ForegroundColor Gray
        Write-Host $Target -ForegroundColor White
        Write-Host "  Mode:   " -NoNewline -ForegroundColor Gray
        if ($useRunspaces) {
            Write-Host "TURBO (Parallel Runspaces - Up to $($Global:Config.MaxRunspaces) concurrent)" -ForegroundColor Green
        } elseif ($AutoOptimize) {
            Write-Host "Smart (Optimized to $total hosts)" -ForegroundColor Yellow
        } else {
            Write-Host "Full Scan ($total hosts)" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  Controls: " -NoNewline -ForegroundColor Yellow
        Write-Host "[P] Pause  [C] Continue  [X] Cancel & Keep Results" -ForegroundColor White
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        $startTime = Get-Date
        
        if ($useRunspaces) {
            # ========== RUNSPACE-BASED FAST SCANNING ==========
            
            # Create runspace pool
            $runspacePool = [runspacefactory]::CreateRunspacePool(1, $Global:Config.MaxRunspaces)
            $runspacePool.Open()
            
            # Script block for each runspace
            $scriptBlock = {
                param($ip, $timeout)
                
                try {
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    $reply = $ping.Send($ip, $timeout)
                    
                    if ($reply.Status -eq 'Success') {
                        $hostname = "-"
                        try {
                            $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName
                        } catch {
                            # Hostname lookup failed
                        }
                        
                        # Capture TTL for OS detection
                        $ttl = 0
                        try {
                            if ($reply.Options) {
                                $ttl = $reply.Options.Ttl
                            }
                        } catch {
                            # TTL not available
                        }
                        
                        return [pscustomobject]@{
                            Success = $true
                            IP = $ip
                            Hostname = $hostname
                            ResponseTime = $reply.RoundtripTime
                            TTL = $ttl
                        }
                    }
                } catch {
                    # Ping failed
                }
                
                return [pscustomobject]@{
                    Success = $false
                    IP = $ip
                }
            }
            
            # Create jobs
            $jobs = New-Object System.Collections.ArrayList
            
            foreach ($ip in $ips) {
                $powershell = [powershell]::Create().AddScript($scriptBlock).AddArgument($ip).AddArgument($Global:Config.PingTimeout)
                $powershell.RunspacePool = $runspacePool
                
                [void]$jobs.Add([pscustomobject]@{
                    Pipe = $powershell
                    Result = $powershell.BeginInvoke()
                    IP = $ip
                    Processed = $false
                })
            }
            
            # Print table header
            Write-Host "  DISCOVERED DEVICES:" -ForegroundColor Green
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            Write-Host "  " -NoNewline
            Write-Host (" #  ").PadRight(5) -NoNewline -ForegroundColor Yellow
            Write-Host ("IP ADDRESS").PadRight(18) -NoNewline -ForegroundColor Yellow
            Write-Host ("RESPONSE").PadRight(12) -NoNewline -ForegroundColor Yellow
            Write-Host ("HOSTNAME") -ForegroundColor Yellow
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            
            $deviceDisplayLines = 10
            $tableStartLine = [Console]::CursorTop
            
            for ($i = 0; $i -lt $deviceDisplayLines; $i++) {
                Write-Host ""
            }
            
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            Write-Host ""
            Write-Host ""
            Write-Host ""
            
            $progressStartLine = [Console]::CursorTop - 2
            $bufferHeight = $Host.UI.RawUI.BufferSize.Height
            
            # Poll for results
            $completed = 0
            $foundCount = 0
            
            while ($completed -lt $jobs.Count) {
                # Check for keypress
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'X') {
                        $Global:ScanState.CancelRequested = $true
                        break
                    } elseif ($key.Key -eq 'P') {
                        $isPaused = $true
                        $pauseLine = [Math]::Min($progressStartLine + 4, $bufferHeight - 2)
                        [Console]::SetCursorPosition(0, $pauseLine)
                        Write-Host "  [||] PAUSED - Press [C] to Continue or [X] to Cancel" -ForegroundColor Yellow
                        
                        while ($isPaused) {
                            if ([Console]::KeyAvailable) {
                                $key2 = [Console]::ReadKey($true)
                                if ($key2.Key -eq 'C') {
                                    $isPaused = $false
                                    [Console]::SetCursorPosition(0, $pauseLine)
                                    Write-Host (" " * 70)
                                } elseif ($key2.Key -eq 'X') {
                                    $Global:ScanState.CancelRequested = $true
                                    $isPaused = $false
                                    break
                                }
                            }
                            Start-Sleep -Milliseconds 100
                        }
                    }
                }
                
                if ($Global:ScanState.CancelRequested) {
                    break
                }
                
                # Check completed jobs
                foreach ($job in $jobs) {
                    if ($job.Result.IsCompleted -and -not $job.Processed) {
                        $job.Processed = $true
                        $completed++
                        
                        try {
                            $result = $job.Pipe.EndInvoke($job.Result)
                            
                            if ($result -and $result.Success) {
                                $foundCount++
                                
                                [void]$Global:ScanState.FoundHosts.Add([pscustomobject]@{
                                    IP = $result.IP
                                    Hostname = $result.Hostname
                                    ResponseTime = $result.ResponseTime
                                })
                                
                                # Update device table
                                $startIdx = [Math]::Max(0, $foundCount - $deviceDisplayLines)
                                $devicesToShow = $Global:ScanState.FoundHosts[$startIdx..($foundCount - 1)]
                                
                                if ($tableStartLine -lt $bufferHeight) {
                                    [Console]::SetCursorPosition(0, $tableStartLine)
                                    
                                    $lineNum = 0
                                    foreach ($dev in $devicesToShow) {
                                        $displayNum = $startIdx + $lineNum + 1
                                        Write-Host "  " -NoNewline
                                        Write-Host (" $displayNum").PadRight(5) -NoNewline -ForegroundColor White
                                        Write-Host ($dev.IP).PadRight(18) -NoNewline -ForegroundColor Cyan
                                        Write-Host ("$($dev.ResponseTime)ms").PadRight(12) -NoNewline -ForegroundColor Green
                                        $hostnameText = $dev.Hostname.Substring(0, [Math]::Min(33, $dev.Hostname.Length))
                                        Write-Host $hostnameText -ForegroundColor White
                                        $lineNum++
                                    }
                                    
                                    for ($i = $lineNum; $i -lt $deviceDisplayLines; $i++) {
                                        Write-Host "  " -NoNewline
                                        Write-Host (" " * 68)
                                    }
                                }
                            }
                        } catch {
                            # Error processing result
                        }
                        
                        $job.Pipe.Dispose()
                    }
                }
                
                # Update progress
                $percent = [int](($completed / $total) * 100)
                $barLength = 50
                $filledLength = [int](($percent / 100) * $barLength)
                $bar = "#" * $filledLength + "-" * ($barLength - $filledLength)
                
                $elapsed = (Get-Date) - $startTime
                $speed = if ($completed -gt 0) { $completed / $elapsed.TotalSeconds } else { 0 }
                $remaining = if ($speed -gt 0) { ($total - $completed) / $speed } else { 0 }
                
                if ($progressStartLine -lt $bufferHeight - 2) {
                    [Console]::SetCursorPosition(0, $progressStartLine)
                    Write-Host "  PROGRESS: " -NoNewline -ForegroundColor Yellow
                    Write-Host "[$bar] " -NoNewline -ForegroundColor Cyan
                    Write-Host "$percent% " -NoNewline -ForegroundColor White
                    Write-Host "($completed/$total)" -ForegroundColor Gray
                    
                    $statsLine = $progressStartLine + 1
                    if ($statsLine -lt $bufferHeight - 1) {
                        [Console]::SetCursorPosition(0, $statsLine)
                        Write-Host "  " -NoNewline
                        Write-Host "Found: " -NoNewline -ForegroundColor Gray
                        Write-Host "$foundCount devices " -NoNewline -ForegroundColor Green
                        Write-Host "| ETA: " -NoNewline -ForegroundColor Gray
                        Write-Host "$([int]$remaining)s " -NoNewline -ForegroundColor Yellow
                        Write-Host "| Speed: " -NoNewline -ForegroundColor Gray
                        Write-Host "$([Math]::Round($speed, 1)) hosts/sec" -NoNewline -ForegroundColor White
                        Write-Host (" " * 10)
                    }
                }
                
                Start-Sleep -Milliseconds 50
            }
            
            # Cleanup
            $runspacePool.Close()
            $runspacePool.Dispose()
            
        } else {
            # ========== SEQUENTIAL SCANNING (Fallback) ==========
            
            Write-Host "  DISCOVERED DEVICES:" -ForegroundColor Green
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            Write-Host "  " -NoNewline
            Write-Host (" #  ").PadRight(5) -NoNewline -ForegroundColor Yellow
            Write-Host ("IP ADDRESS").PadRight(18) -NoNewline -ForegroundColor Yellow
            Write-Host ("HOSTNAME") -ForegroundColor Yellow
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            
            $deviceDisplayLines = 10
            $tableStartLine = [Console]::CursorTop
            
            for ($i = 0; $i -lt $deviceDisplayLines; $i++) {
                Write-Host ""
            }
            
            Write-Host "  " -NoNewline
            Write-Host ("-" * 68) -ForegroundColor Gray
            Write-Host ""
            Write-Host ""
            Write-Host ""
            
            $progressStartLine = [Console]::CursorTop - 2
            $bufferHeight = $Host.UI.RawUI.BufferSize.Height
            
            $completed = 0
            $foundCount = 0
            
            foreach ($ip in $ips) {
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'P') { 
                        $isPaused = $true
                        $pauseLine = [Math]::Min($progressStartLine + 4, $bufferHeight - 2)
                        [Console]::SetCursorPosition(0, $pauseLine)
                        Write-Host "  [||] PAUSED - Press [C] to Continue or [X] to Cancel" -ForegroundColor Yellow
                        
                        while ($isPaused) {
                            if ([Console]::KeyAvailable) {
                                $key2 = [Console]::ReadKey($true)
                                if ($key2.Key -eq 'C') {
                                    $isPaused = $false
                                    [Console]::SetCursorPosition(0, $pauseLine)
                                    Write-Host (" " * 70)
                                } elseif ($key2.Key -eq 'X') {
                                    $Global:ScanState.CancelRequested = $true
                                    $isPaused = $false
                                    break
                                }
                            }
                            Start-Sleep -Milliseconds 100
                        }
                    } elseif ($key.Key -eq 'X') { 
                        $Global:ScanState.CancelRequested = $true
                        break
                    }
                }
                
                if ($Global:ScanState.CancelRequested) {
                    break
                }
                
                $completed++
                
                try {
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    $reply = $ping.Send($ip, $Global:Config.PingTimeout)
                    
                    if ($reply.Status -eq 'Success') {
                        $foundCount++
                        
                        $hostname = "-"
                        try {
                            $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName
                        } catch { }
                        
                        [void]$Global:ScanState.FoundHosts.Add([pscustomobject]@{
                            IP = $ip
                            Hostname = $hostname
                        })
                        
                        $startIdx = [Math]::Max(0, $foundCount - $deviceDisplayLines)
                        $devicesToShow = $Global:ScanState.FoundHosts[$startIdx..($foundCount - 1)]
                        
                        if ($tableStartLine -lt $bufferHeight) {
                            [Console]::SetCursorPosition(0, $tableStartLine)
                            
                            $lineNum = 0
                            foreach ($dev in $devicesToShow) {
                                $displayNum = $startIdx + $lineNum + 1
                                Write-Host "  " -NoNewline
                                Write-Host (" $displayNum").PadRight(5) -NoNewline -ForegroundColor White
                                Write-Host ($dev.IP).PadRight(18) -NoNewline -ForegroundColor Cyan
                                $hostnameText = $dev.Hostname.Substring(0, [Math]::Min(44, $dev.Hostname.Length))
                                Write-Host $hostnameText -ForegroundColor White
                                $lineNum++
                            }
                            
                            for ($i = $lineNum; $i -lt $deviceDisplayLines; $i++) {
                                Write-Host "  " -NoNewline
                                Write-Host (" " * 68)
                            }
                        }
                    }
                } catch { }
                
                $percent = [int](($completed / $total) * 100)
                $barLength = 50
                $filledLength = [int](($percent / 100) * $barLength)
                $bar = "#" * $filledLength + "-" * ($barLength - $filledLength)
                
                $elapsed = (Get-Date) - $startTime
                $speed = if ($completed -gt 0) { $completed / $elapsed.TotalSeconds } else { 0 }
                $remaining = if ($speed -gt 0) { ($total - $completed) / $speed } else { 0 }
                
                if ($progressStartLine -lt $bufferHeight - 2) {
                    [Console]::SetCursorPosition(0, $progressStartLine)
                    Write-Host "  PROGRESS: " -NoNewline -ForegroundColor Yellow
                    Write-Host "[$bar] " -NoNewline -ForegroundColor Cyan
                    Write-Host "$percent% " -NoNewline -ForegroundColor White
                    Write-Host "($completed/$total)" -ForegroundColor Gray
                    
                    $statsLine = $progressStartLine + 1
                    if ($statsLine -lt $bufferHeight - 1) {
                        [Console]::SetCursorPosition(0, $statsLine)
                        Write-Host "  " -NoNewline
                        Write-Host "Found: " -NoNewline -ForegroundColor Gray
                        Write-Host "$foundCount devices " -NoNewline -ForegroundColor Green
                        Write-Host "| ETA: " -NoNewline -ForegroundColor Gray
                        Write-Host "$([int]$remaining)s " -NoNewline -ForegroundColor Yellow
                        Write-Host "| Speed: " -NoNewline -ForegroundColor Gray
                        Write-Host "$([Math]::Round($speed, 1)) hosts/sec" -NoNewline -ForegroundColor White
                        Write-Host (" " * 10)
                    }
                }
            }
        }
        
        # Final display
        $finalLine = [Math]::Min($progressStartLine + 4, $bufferHeight - 5)
        [Console]::SetCursorPosition(0, $finalLine)
        
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        
        $Global:ScanState.IsScanning = $false
        
        $elapsed = (Get-Date) - $startTime
        $speed = if ($total -gt 0) { $total / $elapsed.TotalSeconds } else { 0 }
        
        Write-Host ""
        if ($Global:ScanState.CancelRequested) {
            Write-Host "  [!] Scan canceled by user" -ForegroundColor Yellow
            Write-Host "  [+] Kept $($Global:ScanState.FoundHosts.Count) device(s) found before cancellation" -ForegroundColor Green
        } else {
            Write-Host "  [+] Ping scan complete!" -ForegroundColor Green
        }
        Write-Host "      Ping responses: $($Global:ScanState.FoundHosts.Count)" -ForegroundColor White
        Write-Host "      Time:  $([Math]::Round($elapsed.TotalSeconds, 2)) seconds" -ForegroundColor White
        Write-Host "      Speed: $([Math]::Round($speed, 1)) hosts/sec" -ForegroundColor White
        
        # Merge with stealth discovery results
        $pingResults = $Global:ScanState.FoundHosts
        $mergedResults = Merge-ScanResults -PingResults $pingResults -Network $Target
        
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [+] COMPREHENSIVE RESULTS (Ping + Stealth Discovery):" -ForegroundColor Green
        Write-Host "      Total devices: $($mergedResults.Count)" -ForegroundColor White
        Write-Host "      Ping only: $($pingResults.Count)" -ForegroundColor Gray
        Write-Host "      Additional (stealth): $($mergedResults.Count - $pingResults.Count)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        # Visual Summary Card
        Write-Host "  =======================================================================" -ForegroundColor Green
        Write-Host "  ||                       SCAN SUMMARY                               ||" -ForegroundColor Green
        Write-Host "  =======================================================================" -ForegroundColor Green
        
        # Calculate statistics
        $routerCount = ($mergedResults | Where-Object { $_.DeviceType -match "Router" }).Count
        $pcCount = ($mergedResults | Where-Object { $_.DeviceType -match "PC" }).Count
        $mobileCount = ($mergedResults | Where-Object { $_.DeviceType -match "Mobile" }).Count
        $iotCount = ($mergedResults | Where-Object { $_.DeviceType -match "IoT" }).Count
        $printerCount = ($mergedResults | Where-Object { $_.DeviceType -match "Printer" }).Count
        $serverCount = ($mergedResults | Where-Object { $_.DeviceType -match "Server" }).Count
        $unknownCount = ($mergedResults | Where-Object { $_.DeviceType -eq "Unknown" }).Count
        
        $windowsCount = ($mergedResults | Where-Object { $_.OS -eq "Windows" }).Count
        $linuxCount = ($mergedResults | Where-Object { $_.OS -match "Linux" }).Count
        $ciscoCount = ($mergedResults | Where-Object { $_.OS -match "Cisco" }).Count
        
        Write-Host "  ||  Total Devices:    " -NoNewline -ForegroundColor Green
        Write-Host ("{0,3}" -f $mergedResults.Count) -NoNewline -ForegroundColor White
        Write-Host "                                             ||" -ForegroundColor Green
        Write-Host "  ||  Ping Responses:   " -NoNewline -ForegroundColor Green
        Write-Host ("{0,3}" -f $pingResults.Count) -NoNewline -ForegroundColor White
        Write-Host "                                             ||" -ForegroundColor Green
        Write-Host "  ||  Stealth Only:     " -NoNewline -ForegroundColor Green
        Write-Host ("{0,3}" -f ($mergedResults.Count - $pingResults.Count)) -NoNewline -ForegroundColor Yellow
        Write-Host "                                             ||" -ForegroundColor Green
        Write-Host "  =======================================================================" -ForegroundColor Green
        
        if ($routerCount + $pcCount + $mobileCount + $iotCount + $serverCount + $printerCount -gt 0) {
            Write-Host "  ||  Device Types:                                                 ||" -ForegroundColor Green
            if ($routerCount -gt 0) {
                Write-Host "  ||    [NET] Routers/Gateways: " -NoNewline -ForegroundColor Green
                Write-Host ("{0,2}" -f $routerCount) -NoNewline -ForegroundColor Cyan
                Write-Host "                                        ||" -ForegroundColor Green
            }
            if ($serverCount -gt 0) {
                Write-Host "  ||    [SVR] Servers:          " -NoNewline -ForegroundColor Green
                Write-Host ("{0,2}" -f $serverCount) -NoNewline -ForegroundColor Yellow
                Write-Host "                                        ||" -ForegroundColor Green
            }
            if ($pcCount -gt 0) {
                Write-Host "  ||    [PC ] PCs/Workstations: " -NoNewline -ForegroundColor Green
                Write-Host ("{0,2}" -f $pcCount) -NoNewline -ForegroundColor White
                Write-Host "                                        ||" -ForegroundColor Green
            }
            if ($mobileCount -gt 0) {
                Write-Host "  ||    [MOB] Mobile Devices:   " -NoNewline -ForegroundColor Green
                Write-Host ("{0,2}" -f $mobileCount) -NoNewline -ForegroundColor Magenta
                Write-Host "                                        ||" -ForegroundColor Green
            }
            if ($iotCount -gt 0) {
                Write-Host "  ||    [IOT] IoT/Smart:        " -NoNewline -ForegroundColor Green
                Write-Host ("{0,2}" -f $iotCount) -NoNewline -ForegroundColor Blue
                Write-Host "                                        ||" -ForegroundColor Green
            }
            if ($printerCount -gt 0) {
                Write-Host "  ||    [PRT] Printers:         " -NoNewline -ForegroundColor Green
                Write-Host ("{0,2}" -f $printerCount) -NoNewline -ForegroundColor Gray
                Write-Host "                                        ||" -ForegroundColor Green
            }
            if ($unknownCount -gt 0) {
                Write-Host "  ||    [ ? ] Unknown:          " -NoNewline -ForegroundColor Green
                Write-Host ("{0,2}" -f $unknownCount) -NoNewline -ForegroundColor DarkGray
                Write-Host "                                        ||" -ForegroundColor Green
            }
        }
        
        if ($windowsCount + $linuxCount + $ciscoCount -gt 0) {
            Write-Host "  =======================================================================" -ForegroundColor Green
            Write-Host "  ||  Operating Systems:                                            ||" -ForegroundColor Green
            if ($windowsCount -gt 0) {
                Write-Host "  ||    [WIN] Windows:          " -NoNewline -ForegroundColor Green
                Write-Host ("{0,2}" -f $windowsCount) -NoNewline -ForegroundColor Cyan
                Write-Host "                                        ||" -ForegroundColor Green
            }
            if ($linuxCount -gt 0) {
                Write-Host "  ||    [LNX] Linux/Unix:       " -NoNewline -ForegroundColor Green
                Write-Host ("{0,2}" -f $linuxCount) -NoNewline -ForegroundColor Yellow
                Write-Host "                                        ||" -ForegroundColor Green
            }
            if ($ciscoCount -gt 0) {
                Write-Host "  ||    [NET] Cisco/Network:    " -NoNewline -ForegroundColor Green
                Write-Host ("{0,2}" -f $ciscoCount) -NoNewline -ForegroundColor Magenta
                Write-Host "                                        ||" -ForegroundColor Green
            }
        }
        
        Write-Host "  =======================================================================" -ForegroundColor Green
        Write-Host ""
        
        # Display comprehensive table with fingerprinting
        if ($mergedResults.Count -gt 0) {
            Write-Host "  ALL DISCOVERED DEVICES:" -ForegroundColor Green
            Write-Host "  " -NoNewline
            Write-Host ("-" * 120) -ForegroundColor Gray
            Write-Host ("  {0,-15} {1,-17} {2,-12} {3,-18} {4,-16} {5,-15} {6}" -f "IP ADDRESS", "MAC ADDRESS", "VENDOR", "HOSTNAME", "OS", "DEVICE TYPE", "FOUND BY") -ForegroundColor Yellow
            Write-Host "  " -NoNewline
            Write-Host ("-" * 120) -ForegroundColor Gray
            
            foreach ($device in $mergedResults) {
                # Use already computed OS and DeviceType
                $os = if ($device.OS -and $device.OS -ne "Unknown") { $device.OS } else { "Unknown" }
                if ($os.Length -gt 16) { $os = $os.Substring(0, 13) + "..." }
                
                # Use already computed DeviceType
                $deviceType = if ($device.DeviceType) { $device.DeviceType } else { "Unknown" }
                if ($deviceType.Length -gt 15) { $deviceType = $deviceType.Substring(0, 12) + "..." }
                
                $methods = ($device.DiscoveryMethods | Select-Object -Unique) -join ", "
                $hostname = if ($device.Hostname.Length -gt 18) { $device.Hostname.Substring(0, 15) + "..." } else { $device.Hostname }
                $vendor = if ($device.Vendor.Length -gt 12) { $device.Vendor.Substring(0, 9) + "..." } else { $device.Vendor }
                $mac = if ($device.MAC.Length -gt 17) { $device.MAC.Substring(0, 17) } else { $device.MAC }
                
                # Color code by discovery method
                $color = if ($device.DiscoveryMethods -contains "Ping") { "White" } else { "Yellow" }
                
                Write-Host ("  {0,-15} {1,-17} {2,-12} {3,-18} {4,-16} {5,-15} {6}" -f 
                    $device.IP,
                    $mac,
                    $vendor,
                    $hostname,
                    $os,
                    $deviceType,
                    $methods) -ForegroundColor $color
            }
            
            Write-Host "  " -NoNewline
            Write-Host ("-" * 120) -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Legend: " -NoNewline -ForegroundColor Gray
            Write-Host "White" -NoNewline -ForegroundColor White
            Write-Host " = Responds to ping | " -NoNewline -ForegroundColor Gray
            Write-Host "Yellow" -NoNewline -ForegroundColor Yellow
            Write-Host " = Stealth only (hidden from ping)" -ForegroundColor Gray
            Write-Host "  💡 NEW: OS and Device Type detected automatically!" -ForegroundColor Cyan
            Write-Host ""
        }
        
        # Sort results by IP
        $results = $mergedResults | Sort-Object { 
            $parts = $_.IP.Split('.')
            [long]$parts[0] * 16777216 + [long]$parts[1] * 65536 + [long]$parts[2] * 256 + [long]$parts[3]
        }
        
        return $results
        
    } catch {
        Write-Host ""
        Write-Host "  [X] Scan error: $($_.Exception.Message)" -ForegroundColor Red
        $Global:ScanState.IsScanning = $false
        return @()
    }
}

# ==================== UI COMPONENTS ====================

function Show-Header {
    Clear-Host
    
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    Write-Host ""
    Write-Host "  ========================================================================" -ForegroundColor Cyan
    Write-Host "  ||                                                                    ||" -ForegroundColor Cyan
    Write-Host "  ||                       NETWORK SCANNER                             ||" -ForegroundColor White
    Write-Host "  ||                                                                    ||" -ForegroundColor Cyan
    Write-Host "  ||                 Version $Global:AppVersion Build $Global:AppBuild                        ||" -ForegroundColor White
    Write-Host "  ||                                                                    ||" -ForegroundColor Cyan
    Write-Host "  ========================================================================" -ForegroundColor Cyan
    Write-Host "  ||  Author:  $Global:AppAuthor" -NoNewline -ForegroundColor Cyan
    Write-Host (" " * (54 - "$Global:AppAuthor".Length)) -NoNewline
    Write-Host "||" -ForegroundColor Cyan
    
    if ($isAdmin) {
        Write-Host "  ||  Status:  " -NoNewline -ForegroundColor Cyan
        Write-Host "[ADMIN] Running as Administrator" -NoNewline -ForegroundColor Green
        Write-Host "                       ||" -ForegroundColor Cyan
    } else {
        Write-Host "  ||  Status:  " -NoNewline -ForegroundColor Cyan
        Write-Host "[LIMITED] Not running as Admin" -NoNewline -ForegroundColor Yellow
        Write-Host "                        ||" -ForegroundColor Cyan
    }
    
    Write-Host "  ========================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-CurrentNetwork {
    param([switch]$Brief)
    
    try {
        $current = Get-CurrentNetwork
        
        if (-not $current) {
            Write-Host "  [!] No active network connection detected" -ForegroundColor Red
            Write-Host "  Please connect to a network and try again." -ForegroundColor Yellow
            return $null
        }
        
        if ($Brief) {
            # Brief display for main menu
            Write-Host "  ---- CURRENT NETWORK ------------------------------------------------" -ForegroundColor Yellow
            Write-Host "   Hostname     : $($current.MyHostname)" -ForegroundColor White
            Write-Host "   IP Address   : $($current.MyIP)" -ForegroundColor White
            Write-Host "   Subnet Mask  : $($current.SubnetMask)" -ForegroundColor White
            Write-Host "   DNS Servers  : $($current.DNS)" -ForegroundColor White
            Write-Host "  ---------------------------------------------------------------------" -ForegroundColor Yellow
        } else {
            # Full display for Option 1
            Write-Host "  ---- CURRENT NETWORK (FULL DETAILS) ---------------------------------" -ForegroundColor Yellow
            Write-Host "   Interface    : $($current.Interface)" -ForegroundColor White
            Write-Host "   Status       : $($current.Status)" -ForegroundColor Green
            Write-Host "   Speed        : $($current.Speed)" -ForegroundColor White
            Write-Host ""
            Write-Host "   My Hostname  : $($current.MyHostname)" -ForegroundColor White
            Write-Host "   My IP        : $($current.MyIP)" -ForegroundColor White
            Write-Host "   Network      : $($current.Network)" -ForegroundColor White
            Write-Host "   Subnet Mask  : $($current.SubnetMask)" -ForegroundColor White
            Write-Host "   CIDR         : $($current.Cidr)" -ForegroundColor White
            Write-Host ""
            Write-Host "   Gateway      : $($current.Gateway)" -ForegroundColor White
            Write-Host "   DNS Servers  : $($current.DNS)" -ForegroundColor White
            Write-Host "   Usable Hosts : $($current.HostCount)" -ForegroundColor White
            Write-Host "  ---------------------------------------------------------------------" -ForegroundColor Yellow
        }
        
        return $current
    } catch {
        Write-Host "  [X] Error displaying network info: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Show-DebugInfo {
    Write-Host ""
    Write-Host "  =====================================================================" -ForegroundColor Magenta
    Write-Host "                        DEBUG INFORMATION                              " -ForegroundColor Magenta
    Write-Host "  =====================================================================" -ForegroundColor Magenta
    Write-Host ""
    
    # Application Info
    Write-Host "  ---- APPLICATION INFO -----------------------------------------------" -ForegroundColor Yellow
    Write-Host "   App Name     : $Global:AppName" -ForegroundColor White
    Write-Host "   Version      : $Global:AppVersion" -ForegroundColor White
    Write-Host "   Build        : $Global:AppBuild" -ForegroundColor White
    Write-Host "   Script Path  : $PSCommandPath" -ForegroundColor White
    Write-Host ""
    
    # PowerShell Environment
    Write-Host "  ---- POWERSHELL ENVIRONMENT -----------------------------------------" -ForegroundColor Yellow
    Write-Host "   PS Version   : $($PSVersionTable.PSVersion)" -ForegroundColor White
    Write-Host "   PS Edition   : $($PSVersionTable.PSEdition)" -ForegroundColor White
    Write-Host "   OS           : $($PSVersionTable.OS)" -ForegroundColor White
    Write-Host "   Computer     : $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "   Username     : $env:USERNAME" -ForegroundColor White
    Write-Host "   Domain       : $env:USERDOMAIN" -ForegroundColor White
    Write-Host ""
    
    # Console Info
    Write-Host "  ---- CONSOLE INFORMATION --------------------------------------------" -ForegroundColor Yellow
    Write-Host "   Window Size  : $($Host.UI.RawUI.WindowSize.Width) x $($Host.UI.RawUI.WindowSize.Height)" -ForegroundColor White
    Write-Host "   Buffer Size  : $($Host.UI.RawUI.BufferSize.Width) x $($Host.UI.RawUI.BufferSize.Height)" -ForegroundColor White
    Write-Host "   Cursor Pos   : $($Host.UI.RawUI.CursorPosition.X), $($Host.UI.RawUI.CursorPosition.Y)" -ForegroundColor White
    Write-Host ""
    
    # Network Detection Details
    Write-Host "  ---- NETWORK DETECTION DETAILS --------------------------------------" -ForegroundColor Yellow
    $current = Get-CurrentNetwork
    if ($current) {
        Write-Host "   Interface Index  : $($current.InterfaceIndex)" -ForegroundColor White
        Write-Host "   Interface Alias  : $($current.Interface)" -ForegroundColor White
        Write-Host "   Interface Status : $($current.Status)" -ForegroundColor White
        Write-Host "   Interface Speed  : $($current.Speed)" -ForegroundColor White
        Write-Host "   Route Metric     : $($current.RouteMetric)" -ForegroundColor White
        Write-Host "   Address State    : $($current.AddressState)" -ForegroundColor White
        Write-Host ""
        Write-Host "   My Hostname      : $($current.MyHostname)" -ForegroundColor White
        Write-Host "   My IP            : $($current.MyIP)" -ForegroundColor White
        Write-Host "   Network Address  : $($current.Network)" -ForegroundColor White
        Write-Host "   Subnet Mask      : $($current.SubnetMask)" -ForegroundColor White
        Write-Host "   CIDR Notation    : $($current.Cidr)" -ForegroundColor White
        Write-Host "   Prefix Length    : /$($current.PrefixLength)" -ForegroundColor White
        Write-Host "   Gateway          : $($current.Gateway)" -ForegroundColor White
        Write-Host "   DNS Servers      : $($current.DNS)" -ForegroundColor White
        Write-Host "   Usable Hosts     : $($current.HostCount)" -ForegroundColor White
    } else {
        Write-Host "   [!] No network detected" -ForegroundColor Red
    }
    Write-Host ""
    
    # All Network Interfaces
    Write-Host "  ---- ALL NETWORK INTERFACES -----------------------------------------" -ForegroundColor Yellow
    try {
        $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne "Disabled" }
        foreach ($adapter in $allAdapters) {
            $ipInfo = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -notlike "127.*" } |
                Select-Object -First 1
            
            if ($ipInfo) {
                Write-Host "   [$($adapter.ifIndex)] $($adapter.Name)" -ForegroundColor Cyan
                Write-Host "       Status: $($adapter.Status) | Speed: $($adapter.LinkSpeed)" -ForegroundColor Gray
                Write-Host "       IP: $($ipInfo.IPAddress)/$($ipInfo.PrefixLength)" -ForegroundColor Gray
            }
        }
    } catch {
        Write-Host "   [X] Error listing interfaces: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # Scan State
    Write-Host "  ---- SCAN STATE -----------------------------------------------------" -ForegroundColor Yellow
    Write-Host "   Is Scanning      : $($Global:ScanState.IsScanning)" -ForegroundColor White
    Write-Host "   Cancel Requested : $($Global:ScanState.CancelRequested)" -ForegroundColor White
    Write-Host "   Total Scanned    : $($Global:ScanState.TotalScanned)" -ForegroundColor White
    Write-Host "   Total Hosts      : $($Global:ScanState.TotalHosts)" -ForegroundColor White
    Write-Host "   Found Hosts      : $($Global:ScanState.FoundHosts.Count)" -ForegroundColor White
    Write-Host ""
    
    # Configuration
    Write-Host "  ---- CONFIGURATION --------------------------------------------------" -ForegroundColor Yellow
    Write-Host "   Fast Scan Max    : $($Global:Config.FastScanMaxHosts) hosts" -ForegroundColor White
    Write-Host "   Ping Timeout     : $($Global:Config.PingTimeout) ms" -ForegroundColor White
    Write-Host "   Port Scan Timeout: $($Global:Config.PortScanTimeout) ms" -ForegroundColor White
    Write-Host "   Max Concurrent   : $($Global:Config.MaxConcurrentPings) pings" -ForegroundColor White
    Write-Host "   Use Runspaces    : $($Global:Config.UseRunspaces)" -ForegroundColor White
    Write-Host "   Max Runspaces    : $($Global:Config.MaxRunspaces)" -ForegroundColor White
    Write-Host "   Exclude Patterns : $($Global:Config.InterfaceExcludePatterns -join ', ')" -ForegroundColor White
    Write-Host ""
    
    Write-Host "  =====================================================================" -ForegroundColor Magenta
    Write-Host ""
}

function Show-AllNetworks {
    try {
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host "                 ROUTING TABLE NETWORK DETECTION                       " -ForegroundColor Cyan
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        $networks = Get-AllDetectedNetworks
        
        if ($networks.Count -eq 0) {
            Write-Host "  No private networks found in routing table" -ForegroundColor Red
            Write-Host ""
            return
        }
        
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [+] Networks from Route Table: $($networks.Count)" -ForegroundColor Green
        Write-Host ""
        
        # Group by type
        $directNetworks = $networks | Where-Object { $_.Type -eq "Direct" }
        $routedNetworks = $networks | Where-Object { $_.Type -eq "Routed" }
        
        if ($directNetworks.Count -gt 0) {
            Write-Host "  Direct Routes:   $($directNetworks.Count) (locally connected)" -ForegroundColor White
        }
        if ($routedNetworks.Count -gt 0) {
            Write-Host "  Routed Subnets:  $($routedNetworks.Count) (via gateway)" -ForegroundColor White
        }
        
        Write-Host ""
        Write-Host "  =====================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        # Display table
        Write-Host "  NETWORKS IN ROUTING TABLE:" -ForegroundColor Green
        Write-Host "  " -NoNewline
        Write-Host ("-" * 105) -ForegroundColor Gray
        Write-Host ("  {0,-4} {1,-20} {2,-15} {3,-10} {4,-20} {5,-12} {6}" -f 
            "TYPE", "CIDR", "SUBNET MASK", "HOSTS", "INTERFACE", "GATEWAY", "DEVICES") -ForegroundColor Yellow
        Write-Host "  " -NoNewline
        Write-Host ("-" * 105) -ForegroundColor Gray
        
        foreach ($net in $networks) {
            # Determine color based on type
            $color = switch ($net.Type) {
                "Direct" { "Green" }
                "Routed" { "Cyan" }
                default { "White" }
            }
            
            # Format type
            $typeSymbol = switch ($net.Type) {
                "Direct" { "[D]" }
                "Routed" { "[R]" }
                default { "[?]" }
            }
            
            # Format interface
            $interface = $net.Interface
            if ($interface.Length -gt 20) {
                $interface = $interface.Substring(0, 17) + "..."
            }
            
            # Format gateway
            $gateway = $net.Gateway
            if ($gateway.Length -gt 12) {
                $gateway = $gateway.Substring(0, 9) + "..."
            }
            
            # Format active devices
            $devices = if ($net.ActiveDevices -gt 0) { "$($net.ActiveDevices) active" } else { "-" }
            
            Write-Host ("  {0,-4} {1,-20} {2,-15} {3,-10} {4,-20} {5,-12} {6}" -f 
                $typeSymbol,
                $net.CIDR,
                $net.SubnetMask,
                $net.HostCount,
                $interface,
                $gateway,
                $devices) -ForegroundColor $color
        }
        
        Write-Host "  " -NoNewline
        Write-Host ("-" * 105) -ForegroundColor Gray
        Write-Host ""
        
        # Legend
        Write-Host "  LEGEND:" -ForegroundColor Cyan
        Write-Host "    [D] = Direct Route         " -NoNewline -ForegroundColor Green
        Write-Host "(locally connected, gateway 0.0.0.0)"  -ForegroundColor Gray
        Write-Host "    [R] = Routed Subnet        " -NoNewline -ForegroundColor Cyan
        Write-Host "(reachable via specific gateway)"  -ForegroundColor Gray
        Write-Host ""
        
        Write-Host "  NOTES:" -ForegroundColor Cyan
        Write-Host "    • All networks shown are from Windows routing table (route print)" -ForegroundColor Gray
        Write-Host "    • Only private IP ranges displayed (10.x, 172.16-31.x, 192.168.x)" -ForegroundColor Gray
        Write-Host "    • Device count shows active IPs found in ARP cache" -ForegroundColor Gray
        Write-Host "    • Use these networks for scanning (options 3 & 4)" -ForegroundColor Gray
        Write-Host ""
        
        # Helpful tip
        if ($routedNetworks.Count -gt 0) {
            Write-Host "  TIP:" -ForegroundColor Yellow
            Write-Host "    Routed networks may require proper network configuration" -ForegroundColor Gray
            Write-Host "    Check connectivity with 'ping <gateway>' before scanning" -ForegroundColor Gray
            Write-Host ""
        }
        
    } catch {
        Write-Host "  [X] Error displaying networks: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-Menu {
    Write-Host ""
    Write-Host "  ======================================================================" -ForegroundColor Cyan
    Write-Host "  ||                          MAIN MENU                              ||" -ForegroundColor Cyan
    Write-Host "  ======================================================================" -ForegroundColor Cyan
    Write-Host "  ||                                                                  ||" -ForegroundColor Cyan
    Write-Host "  ||   " -NoNewline -ForegroundColor Cyan
    Write-Host "[1] Show current network details" -NoNewline -ForegroundColor White
    Write-Host "                           ||" -ForegroundColor Cyan
    Write-Host "  ||   " -NoNewline -ForegroundColor Cyan
    Write-Host "[2] Show all detected networks" -NoNewline -ForegroundColor White
    Write-Host "                             ||" -ForegroundColor Cyan
    Write-Host "  ||                                                                  ||" -ForegroundColor Cyan
    Write-Host "  ||   " -NoNewline -ForegroundColor Cyan
    Write-Host "[3] Scan network (Ping + Stealth)" -NoNewline -ForegroundColor Green
    Write-Host "                          ||" -ForegroundColor Cyan
    Write-Host "  ||   " -NoNewline -ForegroundColor Cyan
    Write-Host "[4] Custom scan (IP/CIDR + Stealth)" -NoNewline -ForegroundColor Green
    Write-Host "                        ||" -ForegroundColor Cyan
    Write-Host "  ||   " -NoNewline -ForegroundColor Cyan
    Write-Host "[5] Port scan" -NoNewline -ForegroundColor Yellow
    Write-Host "                                                  ||" -ForegroundColor Cyan
    Write-Host "  ||   " -NoNewline -ForegroundColor Cyan
    Write-Host "[6] Stealth discovery only (ARP/mDNS/SSDP)" -NoNewline -ForegroundColor Cyan
    Write-Host "                 ||" -ForegroundColor Cyan
    Write-Host "  ||   " -NoNewline -ForegroundColor Cyan
    Write-Host "[7] Analyze device (fingerprinting)" -NoNewline -ForegroundColor Magenta
    Write-Host "                        ||" -ForegroundColor Cyan
    Write-Host "  ||                                                                  ||" -ForegroundColor Cyan
    Write-Host "  ||   " -NoNewline -ForegroundColor Cyan
    Write-Host "[8] Debug information" -NoNewline -ForegroundColor DarkGray
    Write-Host "                                      ||" -ForegroundColor Cyan
    Write-Host "  ||   " -NoNewline -ForegroundColor Cyan
    Write-Host "[9] Discover hidden VLANs (RFC1918 bruteforce)" -NoNewline -ForegroundColor Magenta
    Write-Host "            ||" -ForegroundColor Cyan
    Write-Host "  ||   " -NoNewline -ForegroundColor Cyan
    Write-Host "[0] Exit" -NoNewline -ForegroundColor Red
    Write-Host "                                                       ||" -ForegroundColor Cyan
    Write-Host "  ||                                                                  ||" -ForegroundColor Cyan
    Write-Host "  ======================================================================" -ForegroundColor Cyan
    Write-Host "   v$Global:AppVersion Build $Global:AppBuild - Device Fingerprinting Edition" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-ScanResults {
    param($Hosts, $Cidr)
    
    try {
        if ($Hosts.Count -eq 0) {
            Write-Host ""
            Write-Host "  No responding hosts found" -ForegroundColor Yellow
            return
        }
        
        Write-Host ""
        Write-Host "  ==================== SCAN RESULTS ====================" -ForegroundColor Green
        Write-Host "   Network: $Cidr" -ForegroundColor Green
        Write-Host "   Found: $($Hosts.Count) device(s)" -ForegroundColor Green
        Write-Host "  ======================================================" -ForegroundColor Green
        Write-Host ""
        
        foreach ($device in $Hosts) {
            Write-Host "    $($device.IP.PadRight(15)) -> $($device.Hostname)" -ForegroundColor White
        }
        
        Write-Host ""
        Write-Host "  ======================================================" -ForegroundColor Green
    } catch {
        Write-Host "  [X] Error displaying results: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ==================== PORT SCAN MENU ====================

function Show-PortScanMenu {
    param([array]$AvailableHosts)
    
    $lastScanResults = $AvailableHosts
    
    while ($true) {
        Show-Header
        $currentNetwork = Show-CurrentNetwork -Brief
        
        Write-Host ""
        Write-Host "  ==================== PORT SCAN MENU ====================" -ForegroundColor Magenta
        Write-Host ""
        
        if ($lastScanResults -and $lastScanResults.Count -gt 0) {
            Write-Host "  Available online hosts: $($lastScanResults.Count)" -ForegroundColor Green
            Write-Host ""
        }
        
        Write-Host "  Scan Options:" -ForegroundColor White
        Write-Host "    [1] Scan from previous ping results" -ForegroundColor Gray
        Write-Host "    [2] Scan specific IP/CIDR" -ForegroundColor Gray
        Write-Host "    [B] Back to main menu" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  ========================================================" -ForegroundColor Magenta
        Write-Host ""
        
        $choice = Read-Host "  Select option"
        
        switch ($choice.ToUpper()) {
            "1" {
                if (-not $lastScanResults -or $lastScanResults.Count -eq 0) {
                    Write-Host ""
                    Write-Host "  [!] No hosts from previous scan. Run a ping scan first." -ForegroundColor Yellow
                    Read-Host "  Press Enter to continue" | Out-Null
                    continue
                }
                
                # Configure port scan
                Write-Host ""
                Write-Host "  Port Selection:" -ForegroundColor Cyan
                Write-Host "    [1] Common ports (21,22,23,80,443,3389, etc.)" -ForegroundColor Gray
                Write-Host "    [2] Port range (e.g., 1-1024)" -ForegroundColor Gray
                Write-Host "    [3] Specific ports (e.g., 80,443,8080)" -ForegroundColor Gray
                Write-Host ""
                
                $portChoice = Read-Host "  Select option"
                
                $scanParams = @{
                    IPAddresses = $lastScanResults | ForEach-Object { $_.IP }
                }
                
                switch ($portChoice) {
                    "1" {
                        $scanParams.CommonPorts = $true
                    }
                    "2" {
                        $range = Read-Host "  Enter port range (e.g., 1-1024)"
                        if ([string]::IsNullOrWhiteSpace($range)) {
                            Write-Host "  [X] Invalid input" -ForegroundColor Red
                            Start-Sleep -Seconds 2
                            continue
                        }
                        $scanParams.PortRange = $range
                    }
                    "3" {
                        $portList = Read-Host "  Enter ports separated by commas (e.g., 80,443,8080)"
                        if ([string]::IsNullOrWhiteSpace($portList)) {
                            Write-Host "  [X] Invalid input" -ForegroundColor Red
                            Start-Sleep -Seconds 2
                            continue
                        }
                        try {
                            $scanParams.Ports = $portList -split ',' | ForEach-Object { [int]$_.Trim() }
                        } catch {
                            Write-Host "  [X] Invalid port format" -ForegroundColor Red
                            Start-Sleep -Seconds 2
                            continue
                        }
                    }
                    default {
                        Write-Host "  [X] Invalid option" -ForegroundColor Red
                        Start-Sleep -Seconds 2
                        continue
                    }
                }
                
                $results = Start-PortScan @scanParams
                
                # Offer export
                Show-ExportMenu -Results $results -ScanType "PortScan"
                
                Write-Host ""
                Write-Host "  Options: [Enter] Back  [R] Repeat  [M] Main Menu" -ForegroundColor Cyan
                $nav = Read-Host "  Choose"
                
                if ($nav -eq "R" -or $nav -eq "r") {
                    continue
                } elseif ($nav -eq "M" -or $nav -eq "m") {
                    return
                }
            }
            
            "2" {
                Write-Host ""
                Write-Host "  Enter target (IP, CIDR, or comma-separated list):" -ForegroundColor Cyan
                $target = Read-Host "  Target"
                
                if ([string]::IsNullOrWhiteSpace($target)) {
                    Write-Host "  [X] Target cannot be empty" -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                
                $ips = Get-IPsFromInput -InputString $target
                if ($ips.Count -eq 0) {
                    Write-Host "  [X] Invalid target format" -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                
                # Configure port scan
                Write-Host ""
                Write-Host "  Port Selection:" -ForegroundColor Cyan
                Write-Host "    [1] Common ports (21,22,23,80,443,3389, etc.)" -ForegroundColor Gray
                Write-Host "    [2] Port range (e.g., 1-1024)" -ForegroundColor Gray
                Write-Host "    [3] Specific ports (e.g., 80,443,8080)" -ForegroundColor Gray
                Write-Host ""
                
                $portChoice = Read-Host "  Select option"
                
                $scanParams = @{
                    IPAddresses = $ips
                }
                
                switch ($portChoice) {
                    "1" {
                        $scanParams.CommonPorts = $true
                    }
                    "2" {
                        $range = Read-Host "  Enter port range (e.g., 1-1024)"
                        if ([string]::IsNullOrWhiteSpace($range)) {
                            Write-Host "  [X] Invalid input" -ForegroundColor Red
                            Start-Sleep -Seconds 2
                            continue
                        }
                        $scanParams.PortRange = $range
                    }
                    "3" {
                        $portList = Read-Host "  Enter ports separated by commas (e.g., 80,443,8080)"
                        if ([string]::IsNullOrWhiteSpace($portList)) {
                            Write-Host "  [X] Invalid input" -ForegroundColor Red
                            Start-Sleep -Seconds 2
                            continue
                        }
                        try {
                            $scanParams.Ports = $portList -split ',' | ForEach-Object { [int]$_.Trim() }
                        } catch {
                            Write-Host "  [X] Invalid port format" -ForegroundColor Red
                            Start-Sleep -Seconds 2
                            continue
                        }
                    }
                    default {
                        Write-Host "  [X] Invalid option" -ForegroundColor Red
                        Start-Sleep -Seconds 2
                        continue
                    }
                }
                
                $results = Start-PortScan @scanParams
                
                # Offer export
                Show-ExportMenu -Results $results -ScanType "PortScan"
                
                Write-Host ""
                Write-Host "  Options: [Enter] Back  [R] Repeat  [M] Main Menu" -ForegroundColor Cyan
                $nav = Read-Host "  Choose"
                
                if ($nav -eq "R" -or $nav -eq "r") {
                    continue
                } elseif ($nav -eq "M" -or $nav -eq "m") {
                    return
                }
            }
            
            "B" {
                return
            }
            
            default {
                Write-Host ""
                Write-Host "  [X] Invalid option" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ==================== MAIN APPLICATION ====================

function Start-NetworkTool {
    $currentNetwork = $null
    
    while ($true) {
        try {
            Show-Header
            $currentNetwork = Show-CurrentNetwork -Brief
            Show-Menu
            
            $choice = Read-Host "  Select option"
            
            switch ($choice) {
                "1" {
                    Show-Header
                    $currentNetwork = Show-CurrentNetwork
                    Write-Host ""
                    Read-Host "  Press Enter to continue" | Out-Null
                }
                
                "2" {
                    Show-Header
                    Show-AllNetworks
                    Write-Host ""
                    Read-Host "  Press Enter to continue" | Out-Null
                }
                
                "3" {
                    if (-not $currentNetwork) {
                        Write-Host ""
                        Write-Host "  [!] No network connection detected" -ForegroundColor Red
                        Read-Host "  Press Enter to continue" | Out-Null
                        break
                    }
                    
                    # Determine best scan mode
                    $useOptimize = $currentNetwork.HostCount -gt $Global:Config.FastScanMaxHosts
                    
                    if ($useOptimize) {
                        Write-Host ""
                        Write-Host "  [i] Large network detected ($($currentNetwork.HostCount) hosts)" -ForegroundColor Yellow
                        Write-Host "  [i] Smart mode: Will scan first $($Global:Config.FastScanMaxHosts) hosts for speed" -ForegroundColor Yellow
                        Write-Host ""
                        $choice = Read-Host "  Press Enter to continue or type FULL for complete scan"
                        
                        if ($choice -eq "FULL" -or $choice -eq "full") {
                            $useOptimize = $false
                        }
                    }
                    
                    if ($useOptimize) {
                        $hosts = Start-NetworkScan -Target $currentNetwork.Cidr -AutoOptimize
                    } else {
                        $hosts = Start-NetworkScan -Target $currentNetwork.Cidr
                    }
                    
                    # Offer export (use $hosts not $allResults!)
                    Show-ExportMenu -Results $hosts -ScanType "Network"
                    
                    Write-Host ""
                    Write-Host "  Options: [Enter] Main Menu  [R] Repeat Scan  [4] Custom Scan  [5] Port Scan" -ForegroundColor Cyan
                    $navChoice = Read-Host "  Choose"
                    
                    if ($navChoice -eq "R" -or $navChoice -eq "r") {
                        $choice = "3"  # Repeat this option
                        continue
                    } elseif ($navChoice -eq "4") {
                        $choice = "4"  # Go to custom scan
                        continue
                    } elseif ($navChoice -eq "5") {
                        $choice = "5"  # Go to port scan
                        continue
                    }
                }
                
                "4" {
                    Write-Host ""
                    Write-Host "  ===================== CUSTOM SCAN ========================" -ForegroundColor Magenta
                    Write-Host ""
                    Write-Host "  You can scan:" -ForegroundColor White
                    Write-Host "    - Single IP:      192.168.1.100" -ForegroundColor Gray
                    Write-Host "    - CIDR Subnet:    192.168.1.0/24" -ForegroundColor Gray
                    Write-Host "    - Multiple IPs:   192.168.1.1, 192.168.1.5, 192.168.1.10" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  ==========================================================" -ForegroundColor Magenta
                    Write-Host ""
                    
                    $target = Read-Host "  Enter target (or B to go Back)"
                    
                    if ($target -eq "B" -or $target -eq "b") {
                        break  # Go back to main menu
                    }
                    
                    if ([string]::IsNullOrWhiteSpace($target)) {
                        Write-Host "  [X] Target cannot be empty" -ForegroundColor Red
                        Start-Sleep -Seconds 2
                        $choice = "4"  # Stay on this option
                        continue
                    }
                    
                    # Test if input is valid
                    $testIps = Get-IPsFromInput -InputString $target
                    if ($testIps.Count -eq 0) {
                        Write-Host "  [X] Invalid format" -ForegroundColor Red
                        Write-Host "  [i] Press Enter to try again" -ForegroundColor Yellow
                        Read-Host
                        $choice = "4"  # Stay on this option
                        continue
                    }
                    
                    # Auto-optimize for large scans
                    if ($testIps.Count -gt $Global:Config.FastScanMaxHosts) {
                        Write-Host ""
                        Write-Host "  [i] Large scan detected ($($testIps.Count) hosts)" -ForegroundColor Yellow
                        Write-Host "  [i] Recommend optimizing to first $($Global:Config.FastScanMaxHosts) hosts" -ForegroundColor Yellow
                        Write-Host ""
                        $optChoice = Read-Host "  Optimize? (Y/N, default Y)"
                        
                        if ($optChoice -eq "" -or $optChoice -eq "Y" -or $optChoice -eq "y") {
                            $hosts = Start-NetworkScan -Target $target -AutoOptimize
                        } else {
                            $hosts = Start-NetworkScan -Target $target
                        }
                    } else {
                        $hosts = Start-NetworkScan -Target $target
                    }
                    
                    # Offer export
                    Show-ExportMenu -Results $hosts -ScanType "Custom"
                    
                    Write-Host ""
                    Write-Host "  Options: [Enter] Main Menu  [R] Repeat Scan  [N] New Target  [3] Scan Network  [5] Port Scan" -ForegroundColor Cyan
                    $navChoice = Read-Host "  Choose"
                    
                    if ($navChoice -eq "R" -or $navChoice -eq "r") {
                        # Repeat same scan
                        $choice = "4"
                        continue
                    } elseif ($navChoice -eq "N" -or $navChoice -eq "n") {
                        # Stay on custom scan to enter new target
                        $choice = "4"
                        continue
                    } elseif ($navChoice -eq "3") {
                        # Go to scan network option
                        $choice = "3"
                        continue
                    } elseif ($navChoice -eq "5") {
                        # Go to port scan
                        $choice = "5"
                        continue
                    }
                }
                
                "5" {
                    Show-PortScanMenu -AvailableHosts $Global:ScanState.FoundHosts
                }
                
                "6" {
                    Show-Header
                    Write-Host "  ==================== STEALTH DISCOVERY ====================" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "  Select target for stealth discovery:" -ForegroundColor White
                    Write-Host ""
                    Write-Host "  1) Current network" -ForegroundColor White
                    Write-Host "  2) Custom subnet (enter CIDR)" -ForegroundColor White
                    Write-Host "  3) All networks (no filter)" -ForegroundColor White
                    Write-Host "  0) Back to main menu" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "  ==========================================================" -ForegroundColor Cyan
                    Write-Host ""
                    
                    $stealthChoice = Read-Host "  Choose"
                    $targetSubnet = $null
                    
                    switch ($stealthChoice) {
                        "1" {
                            # Get current network
                            $current = Get-CurrentNetwork
                            if ($current) {
                                $targetSubnet = $current.Cidr
                            } else {
                                Write-Host ""
                                Write-Host "  [!] No active network detected" -ForegroundColor Red
                                Start-Sleep -Seconds 2
                                continue
                            }
                        }
                        "2" {
                            # Custom subnet
                            Write-Host ""
                            $customSubnet = Read-Host "  Enter subnet (CIDR format, e.g. 192.168.1.0/24)"
                            
                            if ($customSubnet -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
                                $targetSubnet = $customSubnet
                            } else {
                                Write-Host ""
                                Write-Host "  [X] Invalid CIDR format" -ForegroundColor Red
                                Start-Sleep -Seconds 2
                                continue
                            }
                        }
                        "3" {
                            # No filter - scan all
                            $targetSubnet = $null
                        }
                        "0" {
                            continue
                        }
                        default {
                            Write-Host ""
                            Write-Host "  [X] Invalid option" -ForegroundColor Red
                            Start-Sleep -Seconds 1
                            continue
                        }
                    }
                    
                    $stealthResults = Start-StealthDiscovery -TargetSubnet $targetSubnet
                    
                    # Offer export
                    Show-ExportMenu -Results $stealthResults -ScanType "Stealth"
                    
                    Write-Host ""
                    Write-Host "  Options: [Enter] Main Menu  [R] Repeat  [3] Normal Scan  [5] Port Scan" -ForegroundColor Cyan
                    $navChoice = Read-Host "  Choose"
                    
                    if ($navChoice -eq "R" -or $navChoice -eq "r") {
                        $choice = "6"
                        continue
                    } elseif ($navChoice -eq "3") {
                        $choice = "3"
                        continue
                    } elseif ($navChoice -eq "5") {
                        # Convert results to format for port scanning
                        if ($stealthResults -and $stealthResults.Count -gt 0) {
                            $Global:ScanState.FoundHosts = $stealthResults
                        }
                        $choice = "5"
                        continue
                    }
                }
                
                "7" {
                    # Device Analysis - Fingerprinting
                    Show-Header
                    Write-Host "  ==================== DEVICE ANALYSIS ====================" -ForegroundColor Cyan
                    Write-Host ""
                    
                    # Check if we have any scanned devices
                    if (-not $Global:ScanState.FoundHosts -or $Global:ScanState.FoundHosts.Count -eq 0) {
                        Write-Host "  [!] No devices found yet." -ForegroundColor Yellow
                        Write-Host "  Please run a scan first (option 3, 4, or 6)" -ForegroundColor White
                        Write-Host ""
                        Read-Host "  Press Enter to continue" | Out-Null
                        continue
                    }
                    
                    Write-Host "  Recently scanned devices:" -ForegroundColor White
                    Write-Host ""
                    
                    $index = 1
                    foreach ($device in $Global:ScanState.FoundHosts | Select-Object -First 10) {
                        $displayName = if ($device.Hostname -and $device.Hostname -ne "-") {
                            "$($device.IP) ($($device.Hostname))"
                        } else {
                            $device.IP
                        }
                        Write-Host ("    {0}) {1}" -f $index, $displayName) -ForegroundColor White
                        $index++
                    }
                    
                    Write-Host ""
                    Write-Host "  ========================================================" -ForegroundColor Cyan
                    Write-Host ""
                    
                    $deviceChoice = Read-Host "  Select device number (or Enter to cancel)"
                    
                    if ($deviceChoice -match '^\d+$') {
                        $deviceIndex = [int]$deviceChoice - 1
                        if ($deviceIndex -ge 0 -and $deviceIndex -lt $Global:ScanState.FoundHosts.Count) {
                            $selectedDevice = $Global:ScanState.FoundHosts[$deviceIndex]
                            Show-EnhancedDeviceInfo -Device $selectedDevice
                        } else {
                            Write-Host ""
                            Write-Host "  [X] Invalid device number" -ForegroundColor Red
                            Start-Sleep -Seconds 2
                        }
                    }
                }
                
                "8" {
                    Show-Header
                    Show-DebugInfo
                    Write-Host ""
                    Read-Host "  Press Enter to continue" | Out-Null
                }
                
                "9" {
                    # RFC1918 VLAN Discovery
                    $discoveredSubnets = Start-RFC1918Discovery
                    
                    if ($discoveredSubnets.Count -gt 0) {
                        Write-Host ""
                        Write-Host "  Scan all discovered subnets? (Y/N)" -ForegroundColor Cyan
                        $scanChoice = Read-Host "  "
                        
                        if ($scanChoice -eq "Y" -or $scanChoice -eq "y") {
                            Write-Host ""
                            Write-Host "  [+] Scanning discovered subnets..." -ForegroundColor Green
                            Write-Host ""
                            
                            $allResults = New-Object System.Collections.ArrayList
                            
                            foreach ($subnet in $discoveredSubnets) {
                                Write-Host "  Scanning $($subnet.AssumedCIDR)..." -ForegroundColor Cyan
                                $results = Start-NetworkScan -Target $subnet.AssumedCIDR
                                
                                if ($results -and $results.Count -gt 0) {
                                    foreach ($r in $results) {
                                        [void]$allResults.Add($r)
                                    }
                                }
                            }
                            
                            Write-Host ""
                            Write-Host "  [+] Total devices found across all discovered subnets: $($allResults.Count)" -ForegroundColor Green
                            Write-Host ""
                            
                            # Offer export
                            Show-ExportMenu -Results $allResults -ScanType "VLAN_Discovery"
                        }
                    }
                    
                    Write-Host ""
                    Read-Host "  Press Enter to return to menu" | Out-Null
                }
                
                "0" {
                    Write-Host ""
                    Write-Host "  Exiting Network Tool... Goodbye!" -ForegroundColor Cyan
                    Write-Host ""
                    return
                }
                
                default {
                    Write-Host ""
                    Write-Host "  [X] Invalid option. Please select 0-9." -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }
        } catch {
            Write-Host ""
            Write-Host "  [X] Unexpected error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  Press Enter to continue..." -ForegroundColor Yellow
            Read-Host
        }
    }
}

# ==================== ENTRY POINT ====================

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  $Global:AppName" -ForegroundColor Cyan
Write-Host "  Version $Global:AppVersion Build $Global:AppBuild" -ForegroundColor Cyan
Write-Host "  Starting..." -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running with administrator privileges
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "  [i] INFO: Not running as Administrator" -ForegroundColor Yellow
        Write-Host "  Some features may be limited." -ForegroundColor Yellow
        Write-Host "  For best results, run PowerShell as Administrator." -ForegroundColor Yellow
        Write-Host ""
        Start-Sleep -Seconds 2
    }
} catch {
    Write-Host "  [!] Warning: Could not check admin status" -ForegroundColor Yellow
}

# Run the main tool
try {
    Start-NetworkTool
} catch {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "                    FATAL ERROR                             " -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    Write-Host ""
}

# Always pause before exit
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Read-Host "Press Enter to exit"