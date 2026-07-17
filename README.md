# HAARIS-HUNTER — Phase 1 (Core Framework + Windows Collection)

> Compromise-assessment & forensic-triage platform · **CGD-CA-DESIGN-001** · Cyber Gate Defense DFIR

HAARIS-HUNTER is a modular, **authorization-gated**, chain-of-custody forensic collection
framework for Windows. It re-imagines the collection value of
[Live-Forensicator](https://github.com/Johnng007/Live-Forensicator) on the HAARIS-HUNTER
architecture: instead of a monolithic script that produces an HTML report, every run
emits a **hashed, normalized JSON evidence bundle** that is the ingestion contract for the
downstream *Normalize → Detect → Risk → Report → Central platform* pipeline.

Phase 1 delivers the **Core Framework** and the Windows collection skeleton. It runs on
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

## Requirements

- Windows PowerShell 5.1 **or** PowerShell 7+
- Run elevated (Administrator) for full artifact coverage
- No third-party modules required at runtime (Pester 5 is only needed to run the CI tests)

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
src/Collectors/Windows/       collectors (Phase 1 build target — see that folder's README)
tests/                        Pester 5 tests
tools/Verify-Framework.ps1    dependency-free verification
```

## Roadmap

- **Phase 1 (this repo)** — Core Framework + Windows collectors.
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
