# Collect-AuthEvents.ps1 - recent Security-log authentication events.
# ATT&CK: T1078 (valid accounts), T1110 (brute force via 4625 clusters). Requires admin to
# read the Security log. Time-bounded + capped so this stays a triage snapshot, not a dump.

function Collect-AuthEvents {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $ids = @(4624, 4625, 4634, 4647, 4648, 4672, 4720, 4726, 4728, 4732, 4756)
    try { if ($Context.Constants['event_ids']['security_logon']) { $ids = @($Context.Constants['event_ids']['security_logon']) } } catch { }

    $since   = (Get-Date).AddDays(-7)
    $maxEvts = 2000

    $events = $null
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = $since } -MaxEvents $maxEvts -ErrorAction Stop
    } catch {
        # Most common cause: not elevated. Emit a single note so the gap is explicit in evidence.
        $records.Add((New-EvidenceRecord -ArtifactType 'auth_events_note' -Collector 'Collect-AuthEvents' `
            -Source 'Get-WinEvent Security' -Context $Context -Data @{
                collected = $false
                reason    = "$($_.Exception.Message)"
                hint      = 'Security log requires elevation; re-run as Administrator.'
            }))
        return $records.ToArray()
    }

    foreach ($e in $events) {
        $data = @{}
        try {
            $xml = [xml]$e.ToXml()
            foreach ($d in $xml.Event.EventData.Data) { if ($d.Name) { $data[$d.Name] = $d.'#text' } }
        } catch { }

        $attack = @()
        if ($e.Id -eq 4625) { $attack += 'T1110' }
        if ($e.Id -in 4624, 4648) { $attack += 'T1078' }

        $records.Add((New-EvidenceRecord -ArtifactType 'auth_event' -Collector 'Collect-AuthEvents' `
            -Source 'Security EVTX' -Attack $attack -Context $Context -Data @{
                event_id     = $e.Id
                time_utc     = $e.TimeCreated.ToUniversalTime().ToString('o')
                account      = $data['TargetUserName']
                domain       = $data['TargetDomainName']
                logon_type   = $data['LogonType']
                source_ip    = $data['IpAddress']
                workstation  = $data['WorkstationName']
                process_name = $data['ProcessName']
                subject_user = $data['SubjectUserName']
            }))
    }

    return $records.ToArray()
}
