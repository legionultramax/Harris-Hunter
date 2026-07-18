# HAARIS-HUNTER — Detection field taxonomy

The detection engine does not match rules against raw collector output. It first **normalizes**
every evidence record (`src/Detection/Normalize.ps1`) into an *event* tagged with a Sigma
`logsource.category` and carrying a `finding.v1` **artifact sub-object** with stable field names.
Sigma/native rules reference those field names (e.g. `persistence.value|contains: 'curl '`), so
this taxonomy is the contract between collectors and detection. Design ref: CGD-CA-DESIGN-001
§§10–13, §24.

## Event envelope

Every normalized event carries:

| Field | Meaning |
|---|---|
| `category` | Sigma `logsource.category` (routing key) |
| `artifact_type` | original collector artifact_type (provenance) |
| `artifact_kind` | which sub-object is populated (`persistence`/`process`/…) |
| `collector` | producing collector |
| `collected_at` | when the collector ran (UTC ISO-8601) |
| `observed_at` | best artifact-activity time (created/mtime/start), falls back to `collected_at` |
| `host` | normalized host block |
| `engagement_id` | provenance back to the authorization |
| `attack[]` | cheap ATT&CK tags applied at collection time |
| `source` | the cmdlet/path the record came from |
| `ref_index` | position within its `artifacts/<type>.json` (for `evidence_refs`) |
| `<artifact_kind>` | the artifact sub-object (see below) |

## Categories

| category | artifact_types (examples) | artifact_kind |
|---|---|---|
| `persistence_inventory` | autorun_* , service, scheduled_task, wmi_*, systemd_*, cron_job, init_script, ssh_authorized_key, bits_job | `persistence` |
| `process` | process | `process` |
| `network` | tcp_connection, udp_endpoint, socket, dns_cache, route, arp_neighbor, firewall_* , smb_* | `network` |
| `auth_event` | auth_event | `auth_event` |
| `file` | suid_sgid_file, file_capability, world_writable_file, tmp_file, dropped_file, prefetch, system_log, login_record_binary, package_verify | `file` |
| `account` | local_user, local_group, shadow_meta, sudoers | `account` |
| `security_tooling` / `kernel` / `host` | defender_*, kernel_*, os_info… | generic passthrough |
| `other` | anything unmapped | raw `data` passthrough |

## Artifact sub-objects (field names rules match on)

**persistence** — `mechanism` (registry_run, startup_folder, active_setup, ifeo, winlogon,
appinit_dlls, appcert_dlls, print_monitor, screensaver, lsa, service, scheduled_task,
wmi_subscription, systemd, systemd_timer, cron, init, authorized_keys, bits), `location`,
`value` (the suspicious string — command/path/exec line), `created`.
Records holding a list (e.g. a cron file's lines) **explode into one event per entry**.

**process** — `pid`, `ppid`, `image_path`, `command_line`, `user`, `start_time`, `image_sha256`,
`image_deleted`, `image_signed`, `parent_image`, `parent_name`, `child_count`.

**network** — `direction`, `local_addr`, `local_port`, `remote_addr`, `remote_port`, `protocol`,
`state`, `owning_pid`, `process`.

**auth_event** — `event_type`, `username`, `source_ip`, `count`, `window_start`, `window_end`, `raw`.

**file** — `path`, `sha256`, `size`, `mtime`, `owner`, `mode`.

## Data minimization (§20)

Free-text fields retained for detection (`persistence.value`, `process.command_line`,
`auth_event.raw`) are passed through `Protect-HHSensitiveString`, which masks payment-card-like
digit runs (13–19 digits) keeping only the last 4. Credential material is never collected in the
default profile (enforced upstream in the collectors), so it never reaches normalization.
