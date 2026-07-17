# HAARIS-HUNTER — Phase 1 (Core Framework + Windows Collection)

> Compromise-assessment & forensic-triage platform · **CGD-CA-DESIGN-001** · Cyber Gate Defense DFIR

HAARIS-HUNTER is a modular, **authorization-gated**, chain-of-custody forensic collection
framework for Windows. It re-imagines the collection value of
[Live-Forensicator](https://github.com/Johnng007/Live-Forensicator) on the HAARIS-HUNTER
architecture: instead of a monolithic script that produces an HTML report, every run
emits a **hashed, normalized JSON evidence bundle** that is the ingestion contract for the
downstream *Normalize → Detect → Risk → Report → Central platform* pipeline.

Phase 1 delivers the **Core Framework** and the **Windows collectors**. It runs on
**Windows PowerShell 5.1 and PowerShell 7+** (no install required on stock Windows hosts).

## Why not just use Live-Forensicator?

| Live-Forensicator | HAARIS-HUNTER Phase 1 |
|---|---|
| One monolithic `Forensicator.ps1` | Modular Core Framework + pluggable collectors |
| HTML report is the primary output | **Normalized JSON bundle** is canonical; HTML is a rendered view |
| No engagement/scope control | **Authorization gate**: operator + host-scope + time-window enforced before any collection |
| Hashing + optional AES | Per-artifact SHA-256 + deterministic bundle hash + **hash-chained custody ledger** + optional AES |
| Detection welded into collection | Collectors *only collect*; detection is a separate Phase 2 engine that consumes the bundle |

## What Phase 1 produces

Every run writes an evidence bundle directory:

```
HH_<engagement>_<host>_<timestamp>/
├── manifest.json      # sealed head: engagement, host, time integrity, authorization,
│                      #   per-artifact hashes, deterministic bundle_sha256
├── artifacts/
│   └── <type>.json    # one file per artifact type, each individually SHA-256'd
├── bundle.json        # convenience: manifest + all records inline (ingestion-ready)
├── coc.jsonl          # append-only, hash-chained chain-of-custody ledger
├── haaris-hunter.log  # run log
└── report.html        # self-contained triage view rendered from the bundle
```

## Collectors (Phase 1)

Each collector is fault-isolated (a failure is logged to the custody ledger and skipped,
never aborting the run) and emits normalized records via `New-EvidenceRecord`, tagging MITRE
ATT&CK where it is cheap.

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
| EventLogs | log inventory + capped PowerShell/Sysmon/System events | T1059.001 |
| Filesystem | Prefetch, drop-dir executables, Amcache pointer | T1204 |
| DefenderState | status, **exclusions**, threat history, tamper protection | T1562.001 |
| BitsJobs | BITS transfer jobs + URLs | T1197 |
| MemoryHints | pagefile/RAM/crash-dump config (pointers, not capture) | — |
| Wireless | Wi-Fi profiles (keys **only in `full` mode**) | T1552.001 |
| BrowserHistory | history-store files + hashes (**`full` mode only**) | T1217 |

## Requirements

- Windows PowerShell 5.1 **or** PowerShell 7+
- **Run elevated (Administrator)** for full coverage — `AuthEvents` (Security log), `Prefetch`,
  and some Defender/WMI data require it; without elevation those collectors degrade gracefully
  and record an explicit note rather than failing the run.
- No third-party modules required at runtime (Pester 5 is only needed to run the CI tests)

> **Performance note:** `Process` and `Services` compute a SHA-256 **and an Authenticode
> signature** for every image; Authenticode does online certificate-revocation lookups, so a
> full run can take several minutes on a busy host (hashes are cached per path). Parallel
> hashing / an offline-revocation fast path is a Phase 1.x optimization.

## Quick start

```powershell
Import-Module .\HaarisHunter.psd1

# 1. Copy the template and fill in your engagement authorization + scope
Copy-Item .\config\engagement.template.json .\config\engagement.CGD-ENG-1234.json
#   edit engagement_id, client, authorization_reference, authorized_operators,
#   authorized_scope (hostnames/ips), valid_from/valid_to, collection_mode

# 2. Run collection (profiles: quick | standard | deep)
Invoke-HaarisHunter -EngagementFile .\config\engagement.CGD-ENG-1234.json -Profile standard

# 3. Re-verify a bundle's integrity at any time
Test-EvidenceBundle -BundlePath .\HH_CGD-ENG-1234_<host>_<stamp>

# 4. (optional) Encrypt the bundle for transport
Protect-EvidenceBundle -BundlePath .\HH_...   # prompts for a passphrase
```

Useful switches: `-OutputPath <dir>`, `-Include c1,c2`, `-Exclude c3`, `-Encrypt`,
`-DryRun` (proceed even when unauthorized, producing an explicitly-marked *unauthorized*
bundle — for testing only), `-LogLevel Debug|Info|Warn|Error`.

## The authorization gate

Collection refuses to run unless the engagement authorizes it. Before anything is gathered,
`Assert-Authorization` checks that:

- the **running operator** matches `authorized_operators` (USERNAME / DOMAIN\user / UPN),
- the **host** matches `authorized_scope` (hostname or IP, wildcards allowed), and
- **now** falls inside `valid_from`…`valid_to`.

On failure the run aborts (use `-DryRun` to override for testing). The `engagement_id` is
stamped on every record and the manifest, giving unbroken provenance.

## Integrity model

- **Per-artifact hash** — each `artifacts/<type>.json` is SHA-256'd into the manifest.
- **Bundle hash** — `bundle_sha256` is a deterministic hash over the sorted artifact hashes.
- **Custody ledger** — `coc.jsonl` is append-only and hash-chained: every entry embeds the
  previous entry's hash, so any edit/removal/reorder is detectable.
- **Re-verification** — `Test-EvidenceBundle` re-hashes every artifact, recomputes the
  bundle hash, and walks the custody chain. `Test-ChainOfCustody` checks the ledger alone.

## Data minimization

`collection_mode` in the engagement controls scope of collection:

- `full` — includes credential/user-content artifacts (Wi-Fi keys, browser history), as
  Live-Forensicator does. **Confirm written client authorization explicitly covers this.**
- `minimized` — metadata + hashes only; credential/content collectors self-limit.

Everything collected is hashed and recorded in the custody ledger regardless of mode.

## Verify the framework

```powershell
# Dependency-free, runs on 5.1 and 7+, exits non-zero on failure:
pwsh -File .\tools\Verify-Framework.ps1      # or: powershell -File ...

# CI (requires Pester 5):
Invoke-Pester -Path .\tests\HaarisHunter.Tests.ps1
```

`Verify-Framework.ps1` proves: module import, schema, hashing, all authorization paths,
end-to-end seal, bundle re-verification, artifact + custody-ledger tamper detection, and
the AES round-trip (33 checks).

## Layout

```
HaarisHunter.psd1 / .psm1     module manifest + loader
Invoke-HaarisHunter.ps1       orchestrator / entry point
config/                       constants, collection profiles, engagement template
src/Core/                     EvidenceSchema, Configuration, AuthorizationGate, Logging,
                              Statistics, ChainOfCustody, EvidenceWriter
src/Reporting/                JSON bundle writer + HTML report
src/Collectors/Windows/       16 collectors + _CollectorHelpers.ps1 (see that folder's README)
tests/                        Pester 5 tests
tools/Verify-Framework.ps1    dependency-free verification
```

## Roadmap

- **Phase 1 (this repo)** — Core Framework + Windows collectors. ✅ Done.
- **Phase 1.5** — Linux collectors on the same framework (PowerShell 7 cross-platform).
- **Phase 2** — Detection engine consuming the JSON bundle (IOC, Sigma, YARA, cross-artifact
  DSL, ATT&CK mapping, C2/ransomware/lateral/cred-abuse).
- **Phase 3+** — Correlation/dedup → Risk engine → Central platform (ingestion API,
  PostgreSQL findings DB, WORM store, RBAC, multi-tenant).

## Notes

- `Seal-EvidenceBundle` uses the non-standard verb "Seal" (evidence sealing is the domain
  term); PowerShell emits a cosmetic "unapproved verb" warning on import. This is intentional.
- Legal: HAARIS-HUNTER is for **authorized** compromise-assessment engagements only. The
  authorization gate is a safeguard, not a substitute for written client authorization.

_© Cyber Gate Defense. Internal DFIR tooling._
