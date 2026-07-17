# Windows collectors

Phase 1 collectors live here. Each collector is a single file named `Collect-<Name>.ps1`
defining a function `Collect-<Name>` with this contract:

```powershell
function Collect-<Name> {
    param($Context)          # run context: Host, EngagementId, CollectionMode, Constants
    # gather artifacts, then emit ONE OR MORE records via New-EvidenceRecord:
    New-EvidenceRecord -ArtifactType '<type>' -Collector 'Collect-<Name>' `
        -Source '<cmdlet/query used>' -Attack @('T1059') -Data @{ ... } -Context $Context
}
```

Rules:
- **Collect only. No I/O, no detection.** Return records; the orchestrator hashes them,
  writes them, and updates the chain of custody.
- **Fault-isolated.** The orchestrator wraps each collector in try/catch; a failure is
  logged to the custody ledger and skipped, never aborting the run. Still, guard risky
  calls so partial data is returned rather than nothing.
- **Respect collection mode.** In `$Context.CollectionMode -eq 'minimized'`, do not
  collect credentials or user content (e.g. Wi-Fi keys, browser history) — emit metadata
  and hashes only.
- **Tag ATT&CK where it is free** (e.g. autoruns -> T1547), but leave real detection to
  the Phase 2 engine.

The orchestrator discovers collectors dynamically: a name listed in the active profile
(`config/default-profile.json`) is run if a matching `Collect-<Name>` function is loaded.
Planned Phase 1 set: System, Process, Network, Autoruns, Services, ScheduledTasks,
WmiPersistence, Accounts, AuthEvents, EventLogs, Filesystem, DefenderState, BitsJobs,
MemoryHints, Wireless, BrowserHistory.
