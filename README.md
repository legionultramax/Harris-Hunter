# HAARIS-HUNTER

> Cross-platform compromise-assessment & forensic-triage platform · **CGD-CA-DESIGN-001** · Cyber Gate Defense DFIR

HAARIS-HUNTER is a modular, **authorization-gated**, chain-of-custody forensic collection
framework for **Windows and Linux**. Every run emits a **hashed, normalized JSON evidence
bundle** — the ingestion contract for the downstream
*Normalize → Detect → Risk → Report → Central platform* pipeline — with a self-contained HTML
triage view rendered from it.

Runs on **Windows PowerShell 5.1 and PowerShell 7+** (no install on stock Windows hosts) and on
**Linux via PowerShell 7 (`pwsh`)**.

## Status

| Area | State |
|---|---|
| **Core Framework** | Complete — schema, config, authorization gate, logging + SHA-256, hash-chained chain-of-custody + time integrity, statistics, evidence writer (+ AES), evidence-file sink |
| **Windows collectors** | 16 collectors — verified on a live host (deep run: 16 collectors, ~5.6k records, 0 failed, bundle re-verifies) |
| **Linux collectors** | 17 collectors — built + parse-clean; **field-test pending** (dev host had no Linux runtime) |
| **Framework verifier** | `tools/Verify-Framework.ps1` — **38/38 checks, exit 0** on PS 5.1 (OS-neutral) |
| **Detection engine (Phase 2)** | Not started — consumes the JSON bundle |

## Design principles

- **Modular** — a small Core Framework plus pluggable, OS-specific collectors.
- **JSON-first** — the normalized JSON bundle is canonical; the HTML report is a rendered view.
- **Authorization-gated** — operator + host-scope + time-window are enforced before any collection.
- **Provable integrity** — per-file SHA-256, a deterministic bundle hash, and a hash-chained custody ledger.
- **Separation of concerns** — collectors *only collect*; detection, correlation, and risk are later phases that consume the bundle.

## What a run produces

Every run writes a self-contained evidence bundle:

```
HH_<engagement>_<host>_<timestamp>/
├── manifest.json      # sealed head: engagement, host, time integrity, authorization,
│                      #   per-file hashes, deterministic bundle_sha256
├── artifacts/
│   └── <type>.json    # one file per collector, each individually SHA-256'd
├── files/             # raw evidence files (exported .evtx, captured browser DBs, …)
│   └── evtx/ …        #   each SHA-256'd and folded into the manifest + bundle hash + ledger
├── bundle.json        # convenience: manifest + all records inline (ingestion-ready)
├── coc.jsonl          # append-only, hash-chained chain-of-custody ledger
├── haaris-hunter.log  # run log
└── report.html        # self-contained triage view rendered from the bundle
```

## Quick start

```powershell
Import-Module ./HaarisHunter.psd1

# 1. Copy the template and fill in your engagement authorization + scope
Copy-Item ./config/engagement.template.json ./config/engagement.CGD-ENG-1234.json
#   edit engagement_id, client, authorization_reference, authorized_operators,
#   authorized_scope (hostnames/ips), valid_from/valid_to, collection_mode

# 2. Run collection (profiles: quick | standard | deep)
Invoke-HaarisHunter -EngagementFile ./config/engagement.CGD-ENG-1234.json -Profile standard

# 3. Re-verify a bundle's integrity at any time
Test-EvidenceBundle -BundlePath ./HH_CGD-ENG-1234_<host>_<stamp>

# 4. (optional) Encrypt the bundle for transport
Protect-EvidenceBundle -BundlePath ./HH_...   # prompts for a passphrase
```

On **Linux**: `sudo pwsh -c "Import-Module ./HaarisHunter.psd1; Invoke-HaarisHunter -EngagementFile ./config/engagement.CGD-ENG-1234.json -Profile standard"`.

Switches: `-OutputPath <dir>`, `-Include c1,c2`, `-Exclude c3`, `-Encrypt`, `-DryRun`
(proceed even when unauthorized, producing an explicitly-marked *unauthorized* bundle — testing
only), `-LogLevel Debug|Info|Warn|Error`.

## The authorization gate

Collection refuses to run unless the engagement authorizes it. Before anything is gathered,
`Assert-Authorization` checks that:

- the **running operator** matches `authorized_operators` (Windows: USERNAME / DOMAIN\user / UPN; Linux: `$USER` / `id` / `whoami`),
- the **host** matches `authorized_scope` (hostname or IP, wildcards allowed), and
- **now** falls inside `valid_from`…`valid_to`.

On failure the run aborts (use `-DryRun` to override for testing). The `engagement_id` is stamped
on every record and the manifest, giving unbroken provenance.

## Integrity model

- **Per-file hash** — each `artifacts/<type>.json` and each raw file in `files/` is SHA-256'd into the manifest.
- **Bundle hash** — `bundle_sha256` is a deterministic hash over the sorted set of all file hashes (artifacts + evidence files), so it is independent of collection order.
- **Custody ledger** — `coc.jsonl` is append-only and hash-chained: every entry embeds the previous entry's hash, so any edit/removal/reorder is detectable.
- **Manifest anchor** — the `bundle_sealed` ledger event records `manifest.json`'s hash, so re-verification cross-checks the manifest against the tamper-evident ledger. This catches a *consistent* edit of an artifact + manifest (one that keeps the manifest internally self-consistent).
- **Re-verification** — `Test-EvidenceBundle` re-hashes every artifact and evidence file, recomputes the bundle hash, walks the custody chain, and anchors the manifest to the ledger. `Test-ChainOfCustody` checks the ledger alone.

> **Tamper-evident, not tamper-proof:** the custody ledger has no external anchor, so an attacker
> who controls the sealed bundle and recomputes the whole chain could still forge it. True
> tamper-proofing requires the roadmap's **WORM evidence tier** or an **offline signature** over
> `bundle_sha256`. The optional AES-256-CBC transport encryption protects confidentiality in
> transit; it is not itself authenticated — rely on the in-bundle hashes for integrity after decryption.

## Data minimization

`collection_mode` in the engagement controls collection scope:

- `full` — includes credential/user-content artifacts (Windows: Wi-Fi keys, browser history; Linux: shell history). **Confirm written client authorization explicitly covers this.**
- `minimized` — metadata + hashes only; credential/content collectors self-limit.

Regardless of mode: everything collected is hashed and recorded in the custody ledger, and
`/etc/shadow` is **always** captured as metadata only (never password hashes).

## Windows collectors

Each collector is fault-isolated (a failure is logged to the custody ledger and skipped, never
aborting the run) and emits normalized records via `New-EvidenceRecord`, tagging MITRE ATT&CK
where it is cheap.

| Collector | Artifacts | ATT&CK |
|---|---|---|
| System | OS, hardware, boot time, hotfixes | — |
| Process | processes + image SHA-256 + Authenticode + cmdline + owner | T1055, T1059 |
| Network | TCP/UDP + owning process, DNS cache, adapters, routes, firewall, SMB | — |
| Autoruns | Run/RunOnce, IFEO, Winlogon, LSA | T1547, T1546 |
| Services | services + binary hash/signature | T1543.003 |
| ScheduledTasks | tasks, actions, triggers | T1053.005 |
| WmiPersistence | `__EventFilter`/`__EventConsumer`/binding | T1546.003 |
| Accounts | local users, group membership, privileges | T1098 |
| AuthEvents | recent Security logon events (capped, 7d) | T1078, T1110 |
| EventLogs | log inventory + capped PowerShell/Sysmon/System events; **raw .evtx export in `deep`** | T1059.001 |
| Filesystem | Prefetch, drop-dir executables, Amcache pointer | T1204 |
| DefenderState | status, **exclusions**, threat history, tamper protection | T1562.001 |
| BitsJobs | BITS transfer jobs + URLs | T1197 |
| MemoryHints | pagefile/RAM/crash-dump config (pointers, not capture) | — |
| Wireless | Wi-Fi profiles (keys **only in `full` mode**) | T1552.001 |
| BrowserHistory | raw DB capture + extracted URL/domain IOC surface (**`full` mode only**) | T1217 |

> **Performance:** file evidence (SHA-256 + Authenticode) is cached per image path. Process owner
> attribution uses a single `Get-Process -IncludeUserName` call (fast, needs elevation) instead of
> per-process WMI `GetOwner` (~0.5s each), so a full run is typically under a minute. Raw `.evtx`
> export (`deep`) adds bundle size proportional to log volume.

## Linux collectors

Loaded only on Linux; run under `pwsh` 7, ideally as root for full coverage. Core Framework,
schema, chain-of-custody, evidence-file sink, and reporting are shared with Windows.

| Collector | Artifacts | ATT&CK |
|---|---|---|
| System | /etc/os-release, kernel, uptime, boot time | — |
| Process | /proc processes + hash + **deleted-executable** detection | T1059.004, T1070.004 |
| Network | ss sockets + iface/route/ARP, iptables/nft, hosts/resolv.conf | T1565.001 |
| SystemdUnits | service unit files + timers + /etc unit files | T1543.002, T1053.006 |
| Cron | /etc/crontab, cron.d/daily/…, per-user crontabs | T1053.003 |
| InitScripts | rc.local, init.d, profile.d, per-user shell rc | T1037, T1546.004 |
| SshKeys | authorized_keys (per key) + sshd_config | T1098.004 |
| Accounts | passwd/group + **shadow metadata only** (no hashes) | T1136, T1078 |
| Sudoers | /etc/sudoers(.d) + **NOPASSWD** flagging | T1548.003 |
| AuthLogs | journald/auth.log/secure — failed/accepted/sudo (capped) | T1078, T1110 |
| ShellHistory | bash/zsh/python history (**`full` mode only**) | T1552.003 |
| SuidSgid | setuid/setgid files + file capabilities | T1548.001 |
| KernelModules | /proc/modules + taint state | T1547.006 |
| PackageIntegrity | rpm -Va / debsums / dpkg --verify | T1565.001 |
| Filesystem | tmp/var-tmp/dev-shm + world-writable files | T1204, T1222 |
| MemoryHints | /proc/meminfo, swaps, kcore (pointers, not capture) | — |
| Containers | docker/podman ps | T1610, T1611 |

> **Field-test status:** the Linux collectors are built and parse-clean but were authored on a
> Windows host with no Linux runtime, so they are **not yet functionally verified**. Validate on a
> Linux host: `sudo pwsh -File tools/Invoke-Example.ps1 -Profile standard` (runs collection and
> re-verifies the bundle).

## Requirements

- Windows PowerShell 5.1 **or** PowerShell 7+ (Linux needs PowerShell 7 / `pwsh`)
- **Run elevated (Administrator / root)** for full coverage — some artifacts (Security log, Prefetch,
  Defender/WMI on Windows; `/etc/shadow`, sudoers, other users' data on Linux) require it. Without
  elevation those collectors degrade gracefully and record an explicit note rather than failing.
- No third-party modules required at runtime (Pester 5 only for the CI tests)

## Verify

```powershell
# Dependency-free, OS-neutral, runs on PS 5.1 and 7+, exits non-zero on failure:
pwsh -File ./tools/Verify-Framework.ps1        # or: powershell -File ...

# Example / field-test run (creates a permissive engagement, collects, re-verifies):
pwsh -File ./tools/Invoke-Example.ps1 -Profile standard

# CI (requires Pester 5):
Invoke-Pester -Path ./tests/HaarisHunter.Tests.ps1
```

`Verify-Framework.ps1` proves (**39 checks**): module import + public surface, hashing, schema
(incl. empty-attack normalization), all authorization paths, end-to-end seal, bundle
re-verification (artifacts + evidence files), same-name evidence de-collision, artifact +
evidence-file + **manifest-anchor** + custody-ledger tamper detection, and the AES round-trip.

## Layout

```
HaarisHunter.psd1 / .psm1     module manifest + OS-aware loader
Invoke-HaarisHunter.ps1       orchestrator / entry point
config/                       constants, per-OS collection profiles, engagement template
src/Core/                     Platform, EvidenceSchema, Configuration, AuthorizationGate, Logging,
                              Statistics, ChainOfCustody, EvidenceFiles, EvidenceWriter
src/Reporting/                JSON bundle writer + HTML report
src/Collectors/Windows/       16 collectors + _CollectorHelpers.ps1
src/Collectors/Linux/         17 collectors + _LinuxHelpers.ps1 (loaded only on Linux)
tests/                        Pester 5 tests
tools/Verify-Framework.ps1    dependency-free framework verification (OS-neutral)
tools/Invoke-Example.ps1      cross-platform example / field-test runner
```

## Architecture

Collectors **only gather** (return normalized records; the orchestrator owns hashing, I/O, and
custody). The evidence bundle is the stable contract between phases:

- **Phase 1** — Core Framework + Windows collectors. ✅ Done.
- **Phase 1.5** — Linux collectors on the same framework. ✅ Built (field-test pending on a Linux host).
- **Phase 2** — Detection engine consuming the JSON bundle (IOC, Sigma, YARA, native cross-artifact DSL, ATT&CK mapping; C2 / ransomware / lateral-movement / credential-abuse detections).
- **Phase 3+** — Correlation/dedup → Risk engine → Central platform (ingestion API, PostgreSQL findings DB, WORM store, RBAC, multi-tenant).

## Notes

- `Seal-EvidenceBundle` uses the non-standard verb "Seal" (evidence sealing is the domain term);
  PowerShell emits a cosmetic "unapproved verb" warning on import. Intentional.
- Legal: HAARIS-HUNTER is for **authorized** compromise-assessment engagements only. The
  authorization gate is a safeguard, not a substitute for written client authorization.

_© Cyber Gate Defense. Internal DFIR tooling._
