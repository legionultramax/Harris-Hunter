# Collect-Wireless.ps1 - saved Wi-Fi profiles. Keys are collected ONLY in 'full' mode.
# ATT&CK: T1552.001 (unsecured credentials). This is credential content, so it self-limits
# based on $Context.CollectionMode to honor data-minimization for 'minimized' engagements.

function Collect-Wireless {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()
    $full = ($Context.CollectionMode -eq 'full')

    $profileNames = @()
    try {
        $out = netsh wlan show profiles 2>$null
        foreach ($line in $out) {
            $m = [regex]::Match($line, ':\s*(.+?)\s*$')
            if ($line -match 'All User Profile' -and $m.Success) { $profileNames += $m.Groups[1].Value }
        }
    } catch {
        return @()   # no WLAN service / no adapter
    }

    foreach ($name in $profileNames) {
        $auth = $null; $cipher = $null; $key = $null
        try {
            $detail = netsh wlan show profile name="$name" key=clear 2>$null
            foreach ($l in $detail) {
                if ($l -match 'Authentication\s*:\s*(.+?)\s*$') { $auth = $Matches[1] }
                elseif ($l -match 'Cipher\s*:\s*(.+?)\s*$')     { $cipher = $Matches[1] }
                elseif ($full -and $l -match 'Key Content\s*:\s*(.+?)\s*$') { $key = $Matches[1] }
            }
        } catch { }

        $data = @{
            ssid           = $name
            authentication = $auth
            cipher         = $cipher
            key_collected  = [bool]$full
        }
        if ($full) { $data['key_content'] = $key }   # credential material - full mode only

        $records.Add((New-EvidenceRecord -ArtifactType 'wifi_profile' -Collector 'Collect-Wireless' `
            -Source 'netsh wlan show profile' -Attack ($(if ($full) { @('T1552.001') } else { @() })) -Context $Context -Data $data))
    }

    return $records.ToArray()
}
