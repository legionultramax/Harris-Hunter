# Collect-InitScripts.ps1 (Linux) - init/rc + shell-profile autostart.
# ATT&CK: T1037 (boot/logon init scripts), T1546.004 (unix shell config modification).

function Collect-InitScripts {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $addFile = {
        param($path, $kind, $attack)
        try {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $ev = Get-HHLinuxFileEvidence -Path $path
                $records.Add((New-EvidenceRecord -ArtifactType 'init_script' -Collector 'Collect-InitScripts' `
                    -Source $path -Attack $attack -Context $Context -Data @{
                        path = $path; kind = $kind; sha256 = $ev.sha256; owner = $ev.owner; mtime_utc = $ev.mtime_utc
                    }))
            }
        } catch { }
    }

    # System init / rc.
    & $addFile '/etc/rc.local' 'rc.local' @('T1037.004')
    foreach ($dir in '/etc/init.d', '/etc/rc.d') {
        try { if (Test-Path -LiteralPath $dir) { Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object { & $addFile $_.FullName 'init.d' @('T1037') } } } catch { }
    }

    # System-wide shell profiles.
    & $addFile '/etc/profile' 'profile' @('T1546.004')
    & $addFile '/etc/bash.bashrc' 'bashrc' @('T1546.004')
    foreach ($dir in '/etc/profile.d') {
        try { if (Test-Path -LiteralPath $dir) { Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | ForEach-Object { & $addFile $_.FullName 'profile.d' @('T1546.004') } } } catch { }
    }

    # Per-user shell rc files.
    foreach ($u in (Get-HHLinuxUsers)) {
        if (-not $u.home -or -not (Test-Path -LiteralPath $u.home -ErrorAction SilentlyContinue)) { continue }
        foreach ($rc in '.bashrc', '.bash_profile', '.profile', '.zshrc', '.bash_login') {
            & $addFile (Join-Path $u.home $rc) "user_rc:$($u.name)" @('T1546.004')
        }
    }

    return $records.ToArray()
}
