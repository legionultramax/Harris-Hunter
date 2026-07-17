# Collect-Accounts.ps1 - local users and group membership (esp. privileged groups).

function Collect-Accounts {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    # --- Local users ---
    try {
        foreach ($u in (Get-LocalUser -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'local_user' -Collector 'Collect-Accounts' `
                -Source 'Get-LocalUser' -Context $Context -Data @{
                    name               = $u.Name
                    enabled            = [bool]$u.Enabled
                    sid                = $u.SID.Value
                    description        = $u.Description
                    last_logon_utc     = if ($u.LastLogon) { $u.LastLogon.ToUniversalTime().ToString('o') } else { $null }
                    password_required  = [bool]$u.PasswordRequired
                    password_last_set  = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToUniversalTime().ToString('o') } else { $null }
                    password_expires   = if ($u.PasswordExpires) { $u.PasswordExpires.ToUniversalTime().ToString('o') } else { $null }
                    user_may_change_pw = [bool]$u.UserMayChangePassword
                }))
        }
    } catch { }

    # --- Local groups + members (membership is where privilege escalation shows up) ---
    try {
        foreach ($g in (Get-LocalGroup -ErrorAction Stop)) {
            $members = @()
            try {
                $members = @(Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | ForEach-Object {
                    [ordered]@{ name = $_.Name; sid = $_.SID.Value; type = [string]$_.ObjectClass; source = [string]$_.PrincipalSource }
                })
            } catch { }
            # ATT&CK T1098 (account manipulation) is a cheap tag for privileged-group membership.
            $attack = if ($g.Name -match '(?i)admin|remote desktop|backup operators') { @('T1098') } else { @() }
            $records.Add((New-EvidenceRecord -ArtifactType 'local_group' -Collector 'Collect-Accounts' `
                -Source 'Get-LocalGroup + Get-LocalGroupMember' -Attack $attack -Context $Context -Data @{
                    name        = $g.Name
                    sid         = $g.SID.Value
                    description = $g.Description
                    members     = $members
                }))
        }
    } catch { }

    return $records.ToArray()
}
