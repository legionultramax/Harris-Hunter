# Collect-Network.ps1 (Linux) - sockets, interfaces, routes, ARP, firewall, resolver config.

function Collect-Network {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    # --- Sockets (ss preferred; needs root for the process column) ---
    if (Test-HHCommand 'ss') {
        try {
            foreach ($line in (& ss -tunaHp 2>$null)) {
                if (-not $line.Trim()) { continue }
                $f = $line -split '\s+'
                if ($f.Count -lt 6) { continue }
                $procPart = ($f[6..($f.Count - 1)] -join ' ')
                $pid = $null; $pname = $null
                $pm = [regex]::Match($procPart, 'pid=(\d+)'); if ($pm.Success) { $pid = [int]$pm.Groups[1].Value }
                $nm = [regex]::Match($procPart, '"([^"]+)"'); if ($nm.Success) { $pname = $nm.Groups[1].Value }
                $records.Add((New-EvidenceRecord -ArtifactType 'socket' -Collector 'Collect-Network' `
                    -Source 'ss -tunap' -Context $Context -Data @{
                        netid = $f[0]; state = $f[1]; recv_q = $f[2]; send_q = $f[3]
                        local = $f[4]; peer = $f[5]; pid = $pid; process = $pname
                    }))
            }
        } catch { }
    }
    elseif (Test-HHCommand 'netstat') {
        try {
            foreach ($line in (& netstat -tunap 2>$null)) {
                if ($line -match '^(tcp|udp)') {
                    $records.Add((New-EvidenceRecord -ArtifactType 'socket' -Collector 'Collect-Network' `
                        -Source 'netstat -tunap' -Context $Context -Data @{ raw = $line.Trim() }))
                }
            }
        } catch { }
    }

    # --- Interfaces / addresses ---
    if (Test-HHCommand 'ip') {
        try {
            foreach ($line in (& ip -o addr 2>$null)) {
                $records.Add((New-EvidenceRecord -ArtifactType 'ip_address' -Collector 'Collect-Network' `
                    -Source 'ip -o addr' -Context $Context -Data @{ raw = $line.Trim() }))
            }
        } catch { }
        try {
            foreach ($line in (& ip route 2>$null)) {
                $records.Add((New-EvidenceRecord -ArtifactType 'route' -Collector 'Collect-Network' `
                    -Source 'ip route' -Context $Context -Data @{ raw = $line.Trim() }))
            }
        } catch { }
        try {
            foreach ($line in (& ip neigh 2>$null)) {
                $records.Add((New-EvidenceRecord -ArtifactType 'arp_neighbor' -Collector 'Collect-Network' `
                    -Source 'ip neigh' -Context $Context -Data @{ raw = $line.Trim() }))
            }
        } catch { }
    }

    # --- Firewall rules (need root) ---
    if (Test-HHCommand 'iptables') {
        try {
            $rules = & iptables -S 2>$null
            if ($rules) {
                $records.Add((New-EvidenceRecord -ArtifactType 'firewall_iptables' -Collector 'Collect-Network' `
                    -Source 'iptables -S' -Context $Context -Data @{ rules = @($rules) }))
            }
        } catch { }
    }
    if (Test-HHCommand 'nft') {
        try {
            $nft = & nft list ruleset 2>$null
            if ($nft) {
                $records.Add((New-EvidenceRecord -ArtifactType 'firewall_nftables' -Collector 'Collect-Network' `
                    -Source 'nft list ruleset' -Context $Context -Data @{ ruleset = ($nft -join "`n") }))
            }
        } catch { }
    }

    # --- Resolver + hosts (tampering with these redirects traffic) ---
    foreach ($cfg in @(@{t='resolv_conf'; p='/etc/resolv.conf'; a=@()}, @{t='hosts_file'; p='/etc/hosts'; a=@('T1565.001')})) {
        try {
            if (Test-Path -LiteralPath $cfg.p) {
                $records.Add((New-EvidenceRecord -ArtifactType $cfg.t -Collector 'Collect-Network' `
                    -Source $cfg.p -Attack $cfg.a -Context $Context -Data @{
                        path    = $cfg.p
                        content = @(Get-Content -LiteralPath $cfg.p -ErrorAction Stop | Where-Object { $_ -and $_ -notmatch '^\s*#' })
                        sha256  = (Get-HHLinuxFileEvidence -Path $cfg.p).sha256
                    }))
            }
        } catch { }
    }

    return $records.ToArray()
}
