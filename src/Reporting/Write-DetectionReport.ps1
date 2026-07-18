# Write-DetectionReport.ps1 - self-contained HTML detection report (blueprint sec 13/21/22).
# Renders host risk band, integrity badges, an ATT&CK tactic heatmap, and per-finding cards with
# the risk computation breakdown. All dynamic content is HTML-encoded (attacker-controlled command
# lines / paths appear here), so the report is safe to open.

function ConvertTo-HHHtml { param($Value) return [System.Net.WebUtility]::HtmlEncode([string]$Value) }

function Get-HHFindingDetailHtml {
    # A short, human-readable description of what the finding is about.
    param($Finding)
    $art  = $Finding['artifact']
    $kind = @(Get-HHKeys $art)[0]
    $o    = if ($kind) { $art[$kind] } else { $null }
    switch ($kind) {
        'persistence' { return ("<b>{0}</b> @ {1}<br><code>{2}</code>" -f (ConvertTo-HHHtml (Get-HHField $o 'mechanism')), (ConvertTo-HHHtml (Get-HHField $o 'location')), (ConvertTo-HHHtml (Get-HHField $o 'value'))) }
        'process'     { return ("<code>{0}</code><br>image: {1}  sha256: {2}" -f (ConvertTo-HHHtml (Get-HHField $o 'command_line')), (ConvertTo-HHHtml (Get-HHField $o 'image_path')), (ConvertTo-HHHtml (Get-HHField $o 'image_sha256'))) }
        'network'     { return ("{0} -&gt; {1}:{2} ({3}) pid {4}" -f (ConvertTo-HHHtml (Get-HHField $o 'direction')), (ConvertTo-HHHtml (Get-HHField $o 'remote_addr')), (ConvertTo-HHHtml (Get-HHField $o 'remote_port')), (ConvertTo-HHHtml (Get-HHField $o 'process')), (ConvertTo-HHHtml (Get-HHField $o 'owning_pid'))) }
        'file'        { return ("{0}<br>sha256: {1}" -f (ConvertTo-HHHtml (Get-HHField $o 'path')), (ConvertTo-HHHtml (Get-HHField $o 'sha256'))) }
        'auth_event'  { return ("{0} user={1} src={2} count={3}" -f (ConvertTo-HHHtml (Get-HHField $o 'event_type')), (ConvertTo-HHHtml (Get-HHField $o 'username')), (ConvertTo-HHHtml (Get-HHField $o 'source_ip')), (ConvertTo-HHHtml (Get-HHField $o 'count'))) }
        default       { return (ConvertTo-HHHtml ($o | ConvertTo-Json -Compress -Depth 6)) }
    }
}

function Write-DetectionReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Summary,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory)][string]$Path
    )
    $sevColor = @{ critical = '#b3005c'; high = '#c0392b'; medium = '#d68910'; low = '#2e86c1'; informational = '#7f8c8d' }
    $bandColor = @{ clean = '#2e7d32'; low = '#2e86c1'; suspicious = '#d68910'; likely_compromise = '#c0392b'; confirmed_critical = '#b3005c'; unknown = '#7f8c8d' }
    $hs   = $Summary['host_score']
    $hostObj = $Summary['host']
    $band = [string]$hs['band']
    $bc   = if ($bandColor.ContainsKey($band)) { $bandColor[$band] } else { '#7f8c8d' }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(@"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>HAARIS-HUNTER Detection Report</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}
 .wrap{max-width:1100px;margin:0 auto;padding:24px}
 h1{font-size:20px;margin:0 0 4px} h2{font-size:15px;border-bottom:1px solid #263140;padding-bottom:6px;margin-top:28px}
 .muted{color:#8aa0b4;font-size:12px}
 .band{display:inline-block;padding:10px 18px;border-radius:8px;color:#fff;font-weight:700;font-size:22px;background:$bc}
 .badge{display:inline-block;padding:3px 9px;border-radius:10px;color:#fff;font-size:11px;margin-right:4px}
 .grid{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
 .tac{padding:8px 12px;border-radius:6px;background:#1b2530;border:1px solid #2b3a4a;font-size:12px}
 .tac b{display:block;font-size:16px;color:#fff}
 .card{background:#161d26;border:1px solid #263140;border-left-width:5px;border-radius:6px;padding:12px 14px;margin:10px 0}
 code{background:#0c1116;padding:1px 5px;border-radius:3px;color:#9ecbff;word-break:break-all}
 table{border-collapse:collapse;width:100%;font-size:12px} td,th{padding:3px 6px;text-align:left}
 .bd{color:#8aa0b4;font-size:11px;margin-top:6px}
 .ok{background:#2e7d32}.bad{background:#c0392b}
</style></head><body><div class='wrap'>
"@)
    [void]$sb.Append("<h1>HAARIS-HUNTER &mdash; Detection Report</h1>")
    [void]$sb.Append("<div class='muted'>Host <b>$(ConvertTo-HHHtml $hostObj['hostname'])</b> ($(ConvertTo-HHHtml $hostObj['os_family'])) &middot; scan $(ConvertTo-HHHtml $Summary['scan_id']) &middot; engagement $(ConvertTo-HHHtml $Summary['engagement_id']) &middot; completed $(ConvertTo-HHHtml $Summary['completed_at'])</div>")

    # Host score + integrity
    [void]$sb.Append("<div style='margin:16px 0'><span class='band'>$($hs['score']) / 100 &mdash; $(ConvertTo-HHHtml ($band -replace '_',' '))</span></div>")
    $intg = $Summary['integrity']
    $bvCls = if ($intg['bundle_valid']) { 'ok' } else { 'bad' }
    $cvCls = if ($intg['coc_valid'])    { 'ok' } else { 'bad' }
    [void]$sb.Append("<div><span class='badge $bvCls'>bundle integrity: $(if($intg['bundle_valid']){'VALID'}else{'FAILED'})</span><span class='badge $cvCls'>chain of custody: $(if($intg['coc_valid']){'VALID'}else{'FAILED'})</span><span class='muted'>$(ConvertTo-HHHtml $intg['bundle_sha256'])</span></div>")

    # ATT&CK heatmap
    [void]$sb.Append("<h2>ATT&amp;CK tactic coverage</h2><div class='grid'>")
    $byTactic = $Summary['totals']['by_tactic']
    if (@(Get-HHKeys $byTactic).Count -eq 0) { [void]$sb.Append("<div class='muted'>No tactics with findings.</div>") }
    foreach ($t in (Get-HHKeys $byTactic | Sort-Object)) {
        [void]$sb.Append("<div class='tac'><b>$($byTactic[$t])</b>$(ConvertTo-HHHtml ($t -replace '-',' '))</div>")
    }
    [void]$sb.Append("</div>")

    # Findings (severity/score desc)
    $sevRank = @{ critical = 4; high = 3; medium = 2; low = 1; informational = 0 }
    $ordered = @($Findings | Sort-Object @{e={[int]$_['risk_score']};desc=$true}, @{e={$sevRank[[string]$_['severity']]};desc=$true})
    [void]$sb.Append("<h2>Findings ($($ordered.Count))</h2>")
    if ($ordered.Count -eq 0) { [void]$sb.Append("<div class='muted'>No findings. (Absence of evidence is not evidence of absence.)</div>") }
    foreach ($f in $ordered) {
        $sev = [string]$f['severity']; $sc = if ($sevColor.ContainsKey($sev)) { $sevColor[$sev] } else { '#7f8c8d' }
        $techs = @(); foreach ($m in @($f['detection']['mitre_attack'])) { $techs += ("{0} ({1})" -f (Get-HHField $m 'technique'), (Get-HHField $m 'tactic')) }
        $mods = @(); foreach ($mo in @($f['risk_breakdown']['modifiers'])) { $mods += ("{0} {1:+0;-0}" -f (Get-HHField $mo 'name'), (Get-HHField $mo 'delta')) }
        $corr = if ($f.Contains('corroborated') -and $f['corroborated']) { " &middot; <b style='color:#f39c12'>corroborated</b>" } else { '' }
        [void]$sb.Append("<div class='card' style='border-left-color:$sc'>")
        [void]$sb.Append("<div><span class='badge' style='background:$sc'>$(ConvertTo-HHHtml $sev)</span> <b>$(ConvertTo-HHHtml $f['finding_type'])</b> &middot; score <b>$($f['risk_score'])</b> &middot; confidence $(ConvertTo-HHHtml $f['confidence']) &middot; x$($f['occurrences'])$corr</div>")
        [void]$sb.Append("<div class='muted' style='margin:4px 0'>$(ConvertTo-HHHtml $f['detection']['rule_title']) [$(ConvertTo-HHHtml $f['detection']['rule_id'])] &middot; engine $(ConvertTo-HHHtml $f['detection']['engine']) &middot; observed $(ConvertTo-HHHtml $f['observed_at'])</div>")
        [void]$sb.Append("<div>$(Get-HHFindingDetailHtml -Finding $f)</div>")
        [void]$sb.Append("<div class='bd'>ATT&amp;CK: $(ConvertTo-HHHtml ($techs -join ', '))</div>")
        [void]$sb.Append("<div class='bd'>score: base $($f['risk_breakdown']['base_severity']) x conf $($f['risk_breakdown']['confidence_factor']) = $($f['risk_breakdown']['subtotal'])$(if($mods){' ; ' + (ConvertTo-HHHtml ($mods -join ', '))}) =&gt; $($f['risk_breakdown']['final'])</div>")
        [void]$sb.Append("</div>")
    }

    [void]$sb.Append("<h2>Assurance limitation</h2><div class='muted'>$(ConvertTo-HHHtml $Summary['assurance_limitation'])</div>")
    [void]$sb.Append("</div></body></html>")

    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding utf8
    return $Path
}
