# Normalize.ps1 - detection normalization layer.
# Turns raw collection evidence records (artifact_type/collector/data{}) into normalized
# EVENTS the detection engines consume: each event is tagged with a Sigma `logsource.category`
# and carries a finding.v1 artifact sub-object (persistence|process|network|auth_event|file|...)
# whose fields use a stable taxonomy (see docs/field-taxonomy.md). Pure - no I/O; the orchestrator
# reads artifacts/*.json and passes records in. Records may be PSCustomObjects (parsed JSON) or
# ordered hashtables (in-memory), so all field access goes through Get-HHField.

# --- artifact_type -> Sigma logsource category ------------------------------------------------
$script:HHCategoryMap = @{
    # persistence_inventory
    autorun_run_key='persistence_inventory'; autorun_startup_folder='persistence_inventory'
    autorun_active_setup='persistence_inventory'; autorun_ifeo='persistence_inventory'
    autorun_winlogon='persistence_inventory'; autorun_appinit_dlls='persistence_inventory'
    autorun_appcert_dlls='persistence_inventory'; autorun_print_monitor='persistence_inventory'
    autorun_screensaver='persistence_inventory'; autorun_lsa='persistence_inventory'
    service='persistence_inventory'; scheduled_task='persistence_inventory'
    wmi_event_filter='persistence_inventory'; wmi_event_consumer='persistence_inventory'
    wmi_binding='persistence_inventory'; systemd_service='persistence_inventory'
    systemd_timer='persistence_inventory'; systemd_unit_file='persistence_inventory'
    cron_job='persistence_inventory'; init_script='persistence_inventory'
    ssh_authorized_key='persistence_inventory'; bits_job='persistence_inventory'
    # process
    process='process'
    # network
    tcp_connection='network'; udp_endpoint='network'; socket='network'; dns_cache='network'
    route='network'; arp_neighbor='network'; ip_address='network'; net_adapter='network'
    firewall_rule='network'; firewall_iptables='network'; firewall_nftables='network'
    firewall_profile='network'; smb_share='network'; smb_session='network'
    # auth
    auth_event='auth_event'
    # file
    suid_sgid_file='file'; file_capability='file'; world_writable_file='file'; tmp_file='file'
    dropped_file='file'; prefetch='file'; amcache_pointer='file'; system_log='file'
    login_record_binary='file'; package_verify='file'
    # account
    local_user='account'; local_group='account'; shadow_meta='account'; sudoers='account'
    # security tooling / kernel / host (informational, but matchable)
    defender_status='security_tooling'; defender_preferences='security_tooling'
    defender_detection='security_tooling'; kernel_module='kernel'; kernel_taint='kernel'
    os_info='host'; hardware='host'; hotfix='host'; memory_summary='host'; pagefile='host'
}

# category -> finding.v1 artifact sub-object key
$script:HHCategoryKind = @{
    persistence_inventory='persistence'; process='process'; network='network'
    auth_event='auth_event'; file='file'; account='account'
    security_tooling='security_tooling'; kernel='kernel'; host='host'
}

# persistence artifact_type -> normalized mechanism name
$script:HHPersistenceMechanism = @{
    autorun_run_key='registry_run'; autorun_startup_folder='startup_folder'
    autorun_active_setup='active_setup'; autorun_ifeo='ifeo'; autorun_winlogon='winlogon'
    autorun_appinit_dlls='appinit_dlls'; autorun_appcert_dlls='appcert_dlls'
    autorun_print_monitor='print_monitor'; autorun_screensaver='screensaver'; autorun_lsa='lsa'
    service='service'; scheduled_task='scheduled_task'; wmi_event_filter='wmi_subscription'
    wmi_event_consumer='wmi_subscription'; wmi_binding='wmi_subscription'; systemd_service='systemd'
    systemd_timer='systemd_timer'; systemd_unit_file='systemd'; cron_job='cron'; init_script='init'
    ssh_authorized_key='authorized_keys'; bits_job='bits'
}

function Get-HHField {
    # Read a named field from a record/data object regardless of whether it is a PSCustomObject
    # (parsed JSON) or an IDictionary (in-memory ordered hashtable). Returns $null if absent.
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) {
        if ($Obj.Contains($Name)) { return $Obj[$Name] } else { return $null }
    }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-HHFirst {
    # First non-null / non-empty value from the candidates.
    param([object[]]$Values)
    foreach ($v in $Values) { if ($null -ne $v -and "$v" -ne '') { return $v } }
    return $null
}

function Protect-HHSensitiveString {
    # Data-minimization (blueprint §20): mask payment-card-like digit runs (13-19 digits),
    # keeping the last 4, in any free-text field we retain (command lines, persistence values).
    param([string]$Value)
    if (-not $Value) { return $Value }
    return [regex]::Replace($Value, '\b\d{13,19}\b', {
        param($m) ('*' * ($m.Value.Length - 4)) + $m.Value.Substring($m.Value.Length - 4)
    })
}

function Get-HHLogsourceCategory {
    param([string]$ArtifactType)
    if (-not $ArtifactType) { return 'other' }
    if ($script:HHCategoryMap.ContainsKey($ArtifactType)) { return $script:HHCategoryMap[$ArtifactType] }
    return 'other'
}

# --- artifact sub-object builders (finding.v1 taxonomy) --------------------------------------

function Get-HHPersistenceValues {
    # The suspicious string(s) for a persistence artifact. Some records hold an ARRAY (e.g. a
    # cron file's lines); those explode into one event per entry so per-line rules can match.
    param([string]$ArtifactType, $Data)
    switch ($ArtifactType) {
        'cron_job'               { return @(Get-HHField $Data 'entries') }
        'autorun_run_key'        { return @(Get-HHField $Data 'command') }
        'autorun_startup_folder' { return @(Get-HHField $Data 'image') }
        'autorun_active_setup'   { return @(Get-HHField $Data 'stub_path') }
        'autorun_ifeo'           { return @(Get-HHField $Data 'debugger') }
        'autorun_winlogon'       { return @((Get-HHField $Data 'shell'), (Get-HHField $Data 'userinit')) }
        'autorun_appinit_dlls'   { return @(Get-HHField $Data 'appinit_dlls') }
        'autorun_screensaver'    { return @(Get-HHField $Data 'scrnsave') }
        'service'                { return @(Get-HHField $Data 'path_name') }
        'scheduled_task'         { return @(Get-HHField $Data 'actions') }
        'systemd_service'        { return @((Get-HHField $Data 'exec_start'), (Get-HHField $Data 'path')) }
        'systemd_unit_file'      { return @(Get-HHField $Data 'path') }
        'init_script'            { return @(Get-HHField $Data 'path') }
        'ssh_authorized_key'     { return @((Get-HHField $Data 'options'), (Get-HHField $Data 'key_type')) }
        'bits_job'               { return @((Get-HHField $Data 'command'), (Get-HHField $Data 'remote_url')) }
        default                  { return @(Get-HHFirst @((Get-HHField $Data 'value'), (Get-HHField $Data 'command'))) }
    }
}

function New-HHPersistenceObject {
    param([string]$ArtifactType, $Data, $Source, [string]$Value)
    $mechanism = if ($script:HHPersistenceMechanism.ContainsKey($ArtifactType)) {
        $script:HHPersistenceMechanism[$ArtifactType]
    } else { $ArtifactType }
    $location = Get-HHFirst @(
        (Get-HHField $Data 'location'), (Get-HHField $Data 'task_path'),
        (Get-HHField $Data 'path'), (Get-HHField $Data 'file'), $Source
    )
    $created = Get-HHFirst @(
        (Get-HHField $Data 'created'), (Get-HHField $Data 'created_utc'),
        (Get-HHField $Data 'mtime_utc'), (Get-HHField $Data 'last_run_utc'),
        (Get-HHField $Data 'install_date_utc')
    )
    [ordered]@{
        mechanism = $mechanism
        location  = $location
        value     = Protect-HHSensitiveString ([string]$Value)
        created   = $created
    }
}

function New-HHProcessObject {
    param($Data)
    [ordered]@{
        pid           = Get-HHField $Data 'pid'
        ppid          = Get-HHField $Data 'ppid'
        image_path    = Get-HHFirst @((Get-HHField $Data 'image_path'), (Get-HHField $Data 'exe'))
        command_line  = Protect-HHSensitiveString ([string](Get-HHField $Data 'command_line'))
        user          = Get-HHFirst @((Get-HHField $Data 'owner'), (Get-HHField $Data 'user'))
        start_time    = Get-HHFirst @((Get-HHField $Data 'created_utc'), (Get-HHField $Data 'start_time'))
        image_sha256  = Get-HHField $Data 'sha256'
        image_deleted = [bool](Get-HHFirst @((Get-HHField $Data 'exe_deleted'), $false))
        image_signed  = Get-HHField $Data 'signed'
        parent_image  = Get-HHField $Data 'parent_image'
        parent_name   = Get-HHFirst @((Get-HHField $Data 'parent_name'), (Get-HHField $Data 'parent_comm'))
        child_count   = Get-HHField $Data 'child_count'
    }
}

function New-HHNetworkObject {
    param($Data)
    [ordered]@{
        direction   = Get-HHField $Data 'direction'
        local_addr  = Get-HHFirst @((Get-HHField $Data 'local_address'), (Get-HHField $Data 'local'))
        local_port  = Get-HHField $Data 'local_port'
        remote_addr = Get-HHFirst @((Get-HHField $Data 'remote_address'), (Get-HHField $Data 'peer'))
        remote_port = Get-HHField $Data 'remote_port'
        protocol    = Get-HHFirst @((Get-HHField $Data 'protocol'), (Get-HHField $Data 'netid'))
        state       = Get-HHField $Data 'state'
        owning_pid  = Get-HHFirst @((Get-HHField $Data 'pid'), (Get-HHField $Data 'owning_pid'))
        process     = Get-HHFirst @((Get-HHField $Data 'process_name'), (Get-HHField $Data 'process'))
    }
}

function New-HHAuthEventObject {
    param($Data)
    [ordered]@{
        event_type   = Get-HHField $Data 'event_type'
        username     = Get-HHFirst @((Get-HHField $Data 'username'), (Get-HHField $Data 'user'))
        source_ip    = Get-HHFirst @((Get-HHField $Data 'source_ip'), (Get-HHField $Data 'ip'))
        count        = Get-HHField $Data 'count'
        window_start = Get-HHField $Data 'window_start'
        window_end   = Get-HHField $Data 'window_end'
        raw          = Protect-HHSensitiveString ([string](Get-HHField $Data 'line'))
    }
}

function New-HHFileObject {
    param($Data)
    [ordered]@{
        path  = Get-HHFirst @((Get-HHField $Data 'path'), (Get-HHField $Data 'image'))
        sha256 = Get-HHField $Data 'sha256'
        size  = Get-HHField $Data 'size'
        mtime = Get-HHFirst @((Get-HHField $Data 'mtime_utc'), (Get-HHField $Data 'mtime'))
        owner = Get-HHField $Data 'owner'
        mode  = Get-HHField $Data 'mode'
    }
}

function ConvertTo-HHNormalizedEvent {
    # Returns an ARRAY of normalized events for one evidence record (usually 1; more when a
    # record holds a list of entries, e.g. cron lines).
    param([Parameter(Mandatory)]$Record, [int]$Index = 0)

    $atype = Get-HHField $Record 'artifact_type'
    if (-not $atype) { return @() }
    $data     = Get-HHField $Record 'data'
    $source   = Get-HHField $Record 'source'
    $category = Get-HHLogsourceCategory -ArtifactType $atype
    $kind     = if ($script:HHCategoryKind.ContainsKey($category)) { $script:HHCategoryKind[$category] } else { 'other' }
    $collected = Get-HHField $Record 'collected_at_utc'

    # Build the (kind, artifactObj, observed_at) tuples - persistence may fan out to several.
    $units = [System.Collections.Generic.List[object]]::new()
    switch ($kind) {
        'persistence' {
            $values = @(Get-HHPersistenceValues -ArtifactType $atype -Data $data | ForEach-Object { $_ } | Where-Object { $null -ne $_ -and "$_" -ne '' })
            if ($values.Count -eq 0) { $values = @($null) }
            foreach ($v in $values) {
                $obj = New-HHPersistenceObject -ArtifactType $atype -Data $data -Source $source -Value $v
                $units.Add(@{ obj = $obj; observed = $obj.created })
            }
        }
        'process'    { $o = New-HHProcessObject   -Data $data; $units.Add(@{ obj=$o; observed=$o.start_time }) }
        'network'    { $o = New-HHNetworkObject   -Data $data; $units.Add(@{ obj=$o; observed=$null }) }
        'auth_event' { $o = New-HHAuthEventObject  -Data $data; $units.Add(@{ obj=$o; observed=$o.window_end }) }
        'file'       { $o = New-HHFileObject       -Data $data; $units.Add(@{ obj=$o; observed=$o.mtime }) }
        default      { $units.Add(@{ obj = $data; observed = $null }) }   # generic passthrough
    }

    $events = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $units) {
        $ev = [ordered]@{
            category      = $category
            artifact_type = $atype
            artifact_kind = $kind
            collector     = Get-HHField $Record 'collector'
            collected_at  = $collected
            observed_at   = Get-HHFirst @($u.observed, $collected)
            host          = Get-HHField $Record 'host'
            engagement_id = Get-HHField $Record 'engagement_id'
            attack        = @(Get-HHField $Record 'attack')
            source        = $source
            ref_index     = $Index
        }
        $ev[$kind] = $u.obj
        $events.Add($ev)
    }
    return $events.ToArray()
}

function ConvertTo-HHNormalizedEvents {
    # Normalize a whole set of evidence records into a flat event list. Records are grouped by
    # artifact_type only to assign a stable ref_index (position within that type's artifact file).
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records)
    $events = [System.Collections.Generic.List[object]]::new()
    $idx = @{}
    foreach ($r in $Records) {
        $atype = Get-HHField $r 'artifact_type'
        if (-not $atype) { continue }
        $i = if ($idx.ContainsKey($atype)) { $idx[$atype] } else { 0 }
        $idx[$atype] = $i + 1
        foreach ($ev in (ConvertTo-HHNormalizedEvent -Record $r -Index $i)) { $events.Add($ev) }
    }
    return $events.ToArray()
}
