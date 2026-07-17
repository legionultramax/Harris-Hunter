# Write-HtmlReport.ps1 - self-contained HTML triage view rendered FROM the sealed bundle.
# The JSON bundle is the source of truth; this is a human-readable rendering of it.

function ConvertTo-HHHtmlEncoded {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Write-HtmlReport {
    <#
    .SYNOPSIS
        Render manifest + collected records into a single self-contained report.html.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)]$Collected,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$FileName = 'report.html'
    )

    $e = { param($v) ConvertTo-HHHtmlEncoded $v }

    $authClass = if ($Manifest.authorized -eq $true) { 'ok' } elseif ($null -eq $Manifest.authorized) { 'unknown' } else { 'bad' }
    $authText  = if ($Manifest.authorized -eq $true) { 'AUTHORIZED' } elseif ($null -eq $Manifest.authorized) { 'NOT EVALUATED' } else { 'UNAUTHORIZED (dry-run)' }
    $authReasons = ''
    if ($Manifest.authorization -and $Manifest.authorization.reasons -and @($Manifest.authorization.reasons).Count -gt 0) {
        $authReasons = '<ul class="reasons">' + (($Manifest.authorization.reasons | ForEach-Object { "<li>$(& $e $_)</li>" }) -join '') + '</ul>'
    }

    # Artifact table rows.
    $artRows = ''
    foreach ($a in @($Manifest.artifacts)) {
        $artRows += "<tr><td>$(& $e $a.artifact_type)</td><td class='num'>$(& $e $a.records)</td><td class='mono'>$(& $e $a.file)</td><td class='mono hash'>$(& $e $a.sha256)</td></tr>"
    }
    if (-not $artRows) {
        $artRows = "<tr><td colspan='4' class='empty'>No collectors ran (framework-only run).</td></tr>"
    }

    # ATT&CK technique tally across all records.
    $attackTally = @{}
    foreach ($type in $Collected.Keys) {
        foreach ($rec in @($Collected[$type])) {
            foreach ($t in @($rec.attack)) {
                if ($t) { $attackTally[$t] = ([int]$attackTally[$t]) + 1 }
            }
        }
    }
    $attackRows = ''
    foreach ($k in ($attackTally.Keys | Sort-Object)) {
        $attackRows += "<tr><td class='mono'>$(& $e $k)</td><td class='num'>$($attackTally[$k])</td></tr>"
    }
    if (-not $attackRows) { $attackRows = "<tr><td colspan='2' class='empty'>None tagged.</td></tr>" }

    $ti = $Manifest.time_integrity
    $stats = $Manifest.run_stats

    $ipList = if ($Manifest.host.ips) { (@($Manifest.host.ips) | ForEach-Object { & $e $_ }) -join ', ' } else { '' }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HAARIS-HUNTER Report - $(& $e $Manifest.engagement.engagement_id)</title>
<style>
:root{--bg:#0f1419;--card:#1a212b;--line:#2a3441;--fg:#e6edf3;--muted:#8b98a5;--ok:#2ea043;--bad:#da3633;--warn:#d29922;--accent:#388bfd}
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--fg);line-height:1.5}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
header{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:24px}
h1{font-size:22px;margin:0 0 4px} h1 small{color:var(--muted);font-weight:400;font-size:13px}
.sub{color:var(--muted);font-size:13px}
.banner{display:inline-block;padding:6px 14px;border-radius:6px;font-weight:700;letter-spacing:.5px;margin-top:12px}
.banner.ok{background:rgba(46,160,67,.15);color:var(--ok);border:1px solid var(--ok)}
.banner.bad{background:rgba(218,54,51,.15);color:var(--bad);border:1px solid var(--bad)}
.banner.unknown{background:rgba(210,153,34,.12);color:var(--warn);border:1px solid var(--warn)}
.reasons{margin:8px 0 0;font-size:13px;color:var(--warn)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px}
.card h2{font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin:0 0 12px}
.kv{display:flex;justify-content:space-between;gap:12px;padding:4px 0;font-size:13px;border-bottom:1px dashed var(--line)}
.kv:last-child{border-bottom:none}
.kv .k{color:var(--muted)} .kv .v{text-align:right;word-break:break-word}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.5px}
td.num{text-align:right} .mono{font-family:'Cascadia Code',Consolas,monospace;font-size:12px}
.hash{color:var(--muted);word-break:break-all} .empty{color:var(--muted);text-align:center;font-style:italic}
.section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:24px}
.section h2{font-size:14px;margin:0 0 12px}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:32px;border-top:1px solid var(--line);padding-top:16px}
.bundlehash{font-family:'Cascadia Code',Consolas,monospace;font-size:12px;color:var(--accent);word-break:break-all}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>HAARIS-HUNTER <small>&mdash; forensic triage report &middot; $(& $e $Manifest.design_ref)</small></h1>
  <div class="sub">Engagement <b>$(& $e $Manifest.engagement.engagement_id)</b> &middot; $(& $e $Manifest.engagement.client) &middot; auth ref $(& $e $Manifest.engagement.authorization_reference)</div>
  <div class="sub">Bundle $(& $e $Manifest.bundle_id) &middot; generated $(& $e $Manifest.created_utc) &middot; tool v$(& $e $Manifest.tool_version) &middot; mode: $(& $e $Manifest.collection_mode)</div>
  <div class="banner $authClass">$authText</div>
  $authReasons
</header>

<div class="grid">
  <div class="card">
    <h2>Host</h2>
    <div class="kv"><span class="k">Hostname</span><span class="v">$(& $e $Manifest.host.hostname)</span></div>
    <div class="kv"><span class="k">FQDN</span><span class="v">$(& $e $Manifest.host.fqdn)</span></div>
    <div class="kv"><span class="k">Host ID</span><span class="v mono">$(& $e $Manifest.host.host_id)</span></div>
    <div class="kv"><span class="k">OS</span><span class="v">$(& $e $Manifest.host.os) ($(& $e $Manifest.host.os_version))</span></div>
    <div class="kv"><span class="k">Domain</span><span class="v">$(& $e $Manifest.host.domain)</span></div>
    <div class="kv"><span class="k">IPv4</span><span class="v">$ipList</span></div>
  </div>
  <div class="card">
    <h2>Time integrity</h2>
    <div class="kv"><span class="k">UTC</span><span class="v mono">$(& $e $ti.utc)</span></div>
    <div class="kv"><span class="k">Local</span><span class="v mono">$(& $e $ti.local)</span></div>
    <div class="kv"><span class="k">Timezone</span><span class="v">$(& $e $ti.timezone) (UTC$(& $e $ti.utc_offset))</span></div>
    <div class="kv"><span class="k">NTP source</span><span class="v">$(& $e $ti.ntp_server)</span></div>
    <div class="kv"><span class="k">Clock skew</span><span class="v">$(& $e $ti.ntp_skew_seconds) s ($(& $e $ti.ntp_status))</span></div>
  </div>
  <div class="card">
    <h2>Run statistics</h2>
    <div class="kv"><span class="k">Collectors run</span><span class="v">$(& $e $stats.CollectorsRun)</span></div>
    <div class="kv"><span class="k">Failed</span><span class="v">$(& $e $stats.CollectorsFailed)</span></div>
    <div class="kv"><span class="k">Skipped</span><span class="v">$(& $e $stats.CollectorsSkipped)</span></div>
    <div class="kv"><span class="k">Total records</span><span class="v">$(& $e $stats.TotalRecords)</span></div>
    <div class="kv"><span class="k">Operator</span><span class="v">$(& $e $Manifest.authorization.operator)</span></div>
  </div>
</div>

<div class="section">
  <h2>Collected artifacts</h2>
  <table>
    <thead><tr><th>Artifact type</th><th class="num">Records</th><th>File</th><th>SHA-256</th></tr></thead>
    <tbody>$artRows</tbody>
  </table>
</div>

<div class="section">
  <h2>MITRE ATT&amp;CK tags observed</h2>
  <table>
    <thead><tr><th>Technique</th><th class="num">Records tagged</th></tr></thead>
    <tbody>$attackRows</tbody>
  </table>
</div>

<div class="section">
  <h2>Integrity</h2>
  <div class="kv"><span class="k">Bundle SHA-256</span><span class="v bundlehash">$(& $e $Manifest.bundle_sha256)</span></div>
  <div class="kv"><span class="k">Custody ledger</span><span class="v mono">$(& $e $Manifest.coc_ledger)</span></div>
  <div class="sub" style="margin-top:8px">Re-verify with <span class="mono">Test-EvidenceBundle -BundlePath &lt;dir&gt;</span></div>
</div>

<footer>HAARIS-HUNTER $(& $e $Manifest.design_ref) &middot; This report is a rendering of the signed JSON evidence bundle. The bundle and custody ledger are the authoritative record.</footer>
</div>
</body>
</html>
"@

    $target = Join-Path $OutputPath $FileName
    Set-Content -LiteralPath $target -Value $html -Encoding utf8
    return $target
}
