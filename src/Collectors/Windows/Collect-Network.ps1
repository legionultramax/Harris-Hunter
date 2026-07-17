# Collect-Network.ps1 - connections, listeners, DNS cache, adapters, routes, firewall, SMB.

function Collect-Network {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    # Map PID -> process name/path once for connection attribution.
    $procMap = @{}
    try {
        foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) {
            $procMap[[int]$p.ProcessId] = @{ name = $p.Name; path = $p.ExecutablePath }
        }
    } catch { }

    # --- TCP connections (+ owning process) ---
    try {
        foreach ($c in (Get-NetTCPConnection -ErrorAction Stop)) {
            $pi = $procMap[[int]$c.OwningProcess]
            $records.Add((New-EvidenceRecord -ArtifactType 'tcp_connection' -Collector 'Collect-Network' `
                -Source 'Get-NetTCPConnection' -Context $Context -Data @{
                    local_address  = $c.LocalAddress
                    local_port     = $c.LocalPort
                    remote_address = $c.RemoteAddress
                    remote_port    = $c.RemotePort
                    state          = [string]$c.State
                    pid            = $c.OwningProcess
                    process_name   = if ($pi) { $pi.name } else { $null }
                    process_path   = if ($pi) { $pi.path } else { $null }
                }))
        }
    } catch { }

    # --- UDP listeners ---
    try {
        foreach ($u in (Get-NetUDPEndpoint -ErrorAction Stop)) {
            $pi = $procMap[[int]$u.OwningProcess]
            $records.Add((New-EvidenceRecord -ArtifactType 'udp_endpoint' -Collector 'Collect-Network' `
                -Source 'Get-NetUDPEndpoint' -Context $Context -Data @{
                    local_address = $u.LocalAddress
                    local_port    = $u.LocalPort
                    pid           = $u.OwningProcess
                    process_name  = if ($pi) { $pi.name } else { $null }
                }))
        }
    } catch { }

    # --- DNS client cache ---
    try {
        foreach ($d in (Get-DnsClientCache -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'dns_cache' -Collector 'Collect-Network' `
                -Source 'Get-DnsClientCache' -Context $Context -Data @{
                    entry = $d.Entry
                    name  = $d.Name
                    data  = $d.Data
                    type  = [string]$d.Type
                    ttl   = $d.TimeToLive
                }))
        }
    } catch { }

    # --- Adapters + IP config ---
    try {
        foreach ($a in (Get-NetAdapter -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'net_adapter' -Collector 'Collect-Network' `
                -Source 'Get-NetAdapter' -Context $Context -Data @{
                    name        = $a.Name
                    description = $a.InterfaceDescription
                    mac         = $a.MacAddress
                    status      = [string]$a.Status
                    link_speed  = $a.LinkSpeed
                }))
        }
    } catch { }
    try {
        foreach ($ip in (Get-NetIPAddress -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'ip_address' -Collector 'Collect-Network' `
                -Source 'Get-NetIPAddress' -Context $Context -Data @{
                    ip_address     = $ip.IPAddress
                    prefix_length  = $ip.PrefixLength
                    address_family = [string]$ip.AddressFamily
                    interface      = $ip.InterfaceAlias
                }))
        }
    } catch { }

    # --- Routes ---
    try {
        foreach ($r in (Get-NetRoute -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'route' -Collector 'Collect-Network' `
                -Source 'Get-NetRoute' -Context $Context -Data @{
                    destination = $r.DestinationPrefix
                    next_hop    = $r.NextHop
                    interface   = $r.InterfaceAlias
                    metric      = $r.RouteMetric
                }))
        }
    } catch { }

    # --- Firewall profiles + rules (basic props; port/address joins are omitted for speed) ---
    try {
        foreach ($fp in (Get-NetFirewallProfile -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'firewall_profile' -Collector 'Collect-Network' `
                -Source 'Get-NetFirewallProfile' -Context $Context -Data @{
                    name             = $fp.Name
                    enabled          = [bool]$fp.Enabled
                    default_inbound  = [string]$fp.DefaultInboundAction
                    default_outbound = [string]$fp.DefaultOutboundAction
                }))
        }
    } catch { }
    try {
        foreach ($fr in (Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' })) {
            $records.Add((New-EvidenceRecord -ArtifactType 'firewall_rule' -Collector 'Collect-Network' `
                -Source 'Get-NetFirewallRule' -Context $Context -Data @{
                    name         = $fr.Name
                    display_name = $fr.DisplayName
                    direction    = [string]$fr.Direction
                    action       = [string]$fr.Action
                    profile      = [string]$fr.Profile
                }))
        }
    } catch { }

    # --- SMB shares + sessions ---
    try {
        foreach ($sh in (Get-SmbShare -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'smb_share' -Collector 'Collect-Network' `
                -Source 'Get-SmbShare' -Context $Context -Data @{
                    name = $sh.Name; path = $sh.Path; description = $sh.Description
                }))
        }
    } catch { }
    try {
        foreach ($ss in (Get-SmbSession -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'smb_session' -Collector 'Collect-Network' `
                -Source 'Get-SmbSession' -Context $Context -Data @{
                    client_computer = $ss.ClientComputerName
                    client_user     = $ss.ClientUserName
                    num_opens       = $ss.NumOpens
                }))
        }
    } catch { }

    return $records.ToArray()
}
