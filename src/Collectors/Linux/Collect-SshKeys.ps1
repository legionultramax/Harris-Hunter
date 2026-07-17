# Collect-SshKeys.ps1 (Linux) - SSH authorized_keys + sshd config.
# ATT&CK: T1098.004 (SSH authorized_keys), a common backdoor persistence.

function Collect-SshKeys {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    foreach ($u in (Get-HHLinuxUsers)) {
        if (-not $u.home) { continue }
        foreach ($akf in 'authorized_keys', 'authorized_keys2') {
            $path = Join-Path (Join-Path $u.home '.ssh') $akf
            try {
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    $ev = Get-HHLinuxFileEvidence -Path $path
                    foreach ($line in (Get-Content -LiteralPath $path -ErrorAction Stop)) {
                        if (-not $line.Trim() -or $line.Trim().StartsWith('#')) { continue }
                        $parts = $line -split '\s+'
                        $comment = if ($parts.Count -ge 3) { ($parts[2..($parts.Count - 1)] -join ' ') } else { $null }
                        $records.Add((New-EvidenceRecord -ArtifactType 'ssh_authorized_key' -Collector 'Collect-SshKeys' `
                            -Source $path -Attack @('T1098.004') -Context $Context -Data @{
                                user     = $u.name
                                file     = $path
                                key_type = $parts[0]
                                comment  = $comment
                                fingerprint_line_sha256 = (Get-HHStringHash -InputString $line)
                            }))
                    }
                }
            } catch { }
        }
    }

    # sshd config - remote-access exposure (PermitRootLogin, PasswordAuthentication, etc.).
    try {
        if (Test-Path -LiteralPath '/etc/ssh/sshd_config') {
            $ev = Get-HHLinuxFileEvidence -Path '/etc/ssh/sshd_config'
            $settings = @(Get-Content -LiteralPath '/etc/ssh/sshd_config' -ErrorAction Stop |
                Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_.Trim() })
            $records.Add((New-EvidenceRecord -ArtifactType 'sshd_config' -Collector 'Collect-SshKeys' `
                -Source '/etc/ssh/sshd_config' -Context $Context -Data @{
                    path = '/etc/ssh/sshd_config'; settings = $settings; sha256 = $ev.sha256
                }))
        }
    } catch { }

    return $records.ToArray()
}
