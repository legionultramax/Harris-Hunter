# Collect-Process.ps1 - running processes with image hash + Authenticode signature.
# ATT&CK: T1055 (process injection), T1059 (command/scripting interpreter) - tagged where
# the command line indicates a script host, so downstream detection has a cheap starting point.

function Collect-Process {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $procs = @()
    try { $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop } catch { return @() }

    # Build a pid -> owner map in ONE call. Per-process Win32_Process.GetOwner is ~0.5s each
    # (minutes across a host); Get-Process -IncludeUserName is a single fast enumeration but
    # needs elevation. Non-elevated runs leave owner null rather than pay the per-process cost.
    $ownerMap = @{}
    try {
        Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object {
            if ($null -ne $_.Id) { $ownerMap[[int]$_.Id] = $_.UserName }
        }
    } catch { }

    foreach ($p in $procs) {
        $owner = if ($ownerMap.ContainsKey([int]$p.ProcessId)) { $ownerMap[[int]$p.ProcessId] } else { $null }

        $imagePath = $p.ExecutablePath
        if (-not $imagePath -and $p.CommandLine) { $imagePath = Resolve-HHImagePath -CommandLine $p.CommandLine }
        $ev = Get-HHFileEvidence -Path $imagePath

        $attack = @()
        if ($p.CommandLine -match '(?i)\b(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\b') { $attack += 'T1059' }
        if ($ev.exists -and -not $ev.signed) { $attack += 'T1055' }  # unsigned running image: worth a look

        $records.Add((New-EvidenceRecord -ArtifactType 'process' -Collector 'Collect-Process' `
            -Source 'Win32_Process + Get-FileHash + Get-AuthenticodeSignature' -Attack $attack -Context $Context -Data @{
                pid              = $p.ProcessId
                ppid             = $p.ParentProcessId
                name             = $p.Name
                image_path       = $ev.path
                command_line     = $p.CommandLine
                owner            = $owner
                created_utc      = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') } else { $null }
                session_id       = $p.SessionId
                sha256           = $ev.sha256
                image_size       = $ev.size
                signed           = $ev.signed
                signer           = $ev.signer
                signature_status = $ev.signature_status
            }))
    }

    return $records.ToArray()
}
