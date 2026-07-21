# Invoke-SigmaRules.ps1 - Sigma runtime evaluator.
# Loads COMPILED rule ASTs (JSON produced by tools/Convert-SigmaPack.ps1) and evaluates them
# against normalized events. No YAML is parsed here, so this runs clean on Windows PowerShell 5.1.
# Emits finding.v1 records via New-Finding. Depends on Normalize (Get-HHField/Get-HHKeys) + FindingSchema.

function Get-HHKeys {
    # Enumerate key names of an IDictionary or the property names of a PSCustomObject.
    param($Obj)
    if ($null -eq $Obj) { return @() }
    if ($Obj -is [System.Collections.IDictionary]) { return @($Obj.Keys) }
    return @($Obj.PSObject.Properties.Name)
}

function Resolve-HHEventField {
    # Resolve a dotted field path (e.g. persistence.value) against a normalized event.
    param($Event, [string]$Path)
    $cur = $Event
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        $cur = Get-HHField $cur $seg
    }
    return $cur
}

function Test-HHCidrMatch {
    param([string]$Ip, [string]$Cidr)
    try {
        $parts = $Cidr -split '/'
        if ($parts.Count -ne 2) { return $false }
        $network = [System.Net.IPAddress]::Parse($parts[0].Trim())
        $bits    = [int]$parts[1]
        $addr    = [System.Net.IPAddress]::Parse($Ip.Trim())
        if ($network.AddressFamily -ne $addr.AddressFamily) { return $false }
        $nb = $network.GetAddressBytes(); $ab = $addr.GetAddressBytes()
        $full = [int][math]::Floor($bits / 8); $rem = $bits % 8
        for ($i = 0; $i -lt $full; $i++) { if ($nb[$i] -ne $ab[$i]) { return $false } }
        if ($rem -gt 0) {
            $mask = [byte](0xFF -shl (8 - $rem))
            if (($nb[$full] -band $mask) -ne ($ab[$full] -band $mask)) { return $false }
        }
        return $true
    } catch { return $false }
}

function ConvertTo-HHUtcDateTime {
    # Coerce a value to a UTC [datetime], or $null if it is not a date. Accepts a native
    # [datetime]/[datetimeoffset] (PowerShell 7's ConvertFrom-Json yields these from ISO strings)
    # AND an ISO-8601 string (5.1 keeps strings). Parsing is culture-INVARIANT with RoundtripKind so
    # a non-US host locale (e.g. dd/MM) never misreads MM/dd, and offsets are normalized to UTC.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime])       { return ([datetime]$Value).ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return ([datetimeoffset]$Value).UtcDateTime }
    $s = [string]$Value
    # A bare number ("10", "9500.2") is a numeric threshold, not a date - invariant parsing would
    # otherwise read "9500.2" as the year 9500. Let those fall through to the numeric comparison.
    $ic = [System.Globalization.CultureInfo]::InvariantCulture
    $dummy = 0.0
    if ([double]::TryParse($s, [System.Globalization.NumberStyles]::Any, $ic, [ref]$dummy)) { return $null }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($s, $ic, $styles, [ref]$d)) {
        return $d
    }
    return $null
}

function Compare-HHRuleValue {
    # 3-way compare for gte/lte. Resolves scan-window tokens, then tries datetime, then numeric,
    # then ordinal string. Returns <0, 0, >0 or $null when incomparable.
    param($FieldValue, $RuleValue, $Ctx)
    $rv = $RuleValue
    if ($RuleValue -eq 'scan_window_start') { $rv = $Ctx.ScanWindowStart }
    elseif ($RuleValue -eq 'scan_window_end') { $rv = $Ctx.ScanWindowEnd }
    if ($null -eq $FieldValue -or $null -eq $rv) { return $null }

    # Date comparison first (the common case for gte/lte: recency/timeframe filters). Both operands
    # are coerced to UTC datetimes so the compare is correct regardless of PS version or host locale.
    $df = ConvertTo-HHUtcDateTime $FieldValue
    $dv = ConvertTo-HHUtcDateTime $rv
    if ($null -ne $df -and $null -ne $dv) { return $df.CompareTo($dv) }

    $nf = 0.0; $nv = 0.0
    $ic = [System.Globalization.CultureInfo]::InvariantCulture
    $ns = [System.Globalization.NumberStyles]::Any
    if ([double]::TryParse([string]$FieldValue, $ns, $ic, [ref]$nf) -and [double]::TryParse([string]$rv, $ns, $ic, [ref]$nv)) {
        return $nf.CompareTo($nv)
    }
    # Only reached when neither operand is a date or number. Ordinal string compare is a last resort,
    # NOT a silent fallback for a date that failed to parse (that path is handled above).
    return [string]::Compare([string]$FieldValue, [string]$rv, $true)
}

function Test-HHScalarMatch {
    param($FieldValue, $RuleValue, [string]$Op, $Ctx)
    if ($null -eq $FieldValue) {
        # a null field only "matches" nothing (gte/lte/contains/etc. all false)
        return $false
    }
    switch ($Op) {
        'contains'   { return ([string]$FieldValue).ToLower().Contains(([string]$RuleValue).ToLower()) }
        'startswith' { return ([string]$FieldValue).ToLower().StartsWith(([string]$RuleValue).ToLower()) }
        'endswith'   { return ([string]$FieldValue).ToLower().EndsWith(([string]$RuleValue).ToLower()) }
        're'         { try { return [regex]::IsMatch([string]$FieldValue, [string]$RuleValue) } catch { return $false } }
        'cidr'       { return (Test-HHCidrMatch -Ip ([string]$FieldValue) -Cidr ([string]$RuleValue)) }
        'gte'        { $c = Compare-HHRuleValue $FieldValue $RuleValue $Ctx; return ($null -ne $c -and $c -ge 0) }
        'lte'        { $c = Compare-HHRuleValue $FieldValue $RuleValue $Ctx; return ($null -ne $c -and $c -le 0) }
        default      { return (([string]$FieldValue).ToLower() -eq ([string]$RuleValue).ToLower()) }  # eq / no modifier
    }
}

function Test-HHFieldSpec {
    # A field spec matches when the field satisfies the modifiers against the value list.
    # Value list is OR by default; the 'all' modifier makes it AND. Array field values match if
    # ANY element matches (e.g. host.ip_addresses).
    param($Spec, $Event, $Ctx)
    $field = [string](Get-HHField $Spec 'field')
    $mods  = @(Get-HHField $Spec 'modifiers')
    $values = @(Get-HHField $Spec 'values')
    $combineAll = ($mods -contains 'all')
    $op = ($mods | Where-Object { $_ -ne 'all' } | Select-Object -First 1)
    if (-not $op) { $op = 'eq' }

    $fieldVal = Resolve-HHEventField -Event $Event -Path $field
    $fieldItems = if ($fieldVal -is [array]) { @($fieldVal) } else { @($fieldVal) }

    $perValue = foreach ($v in $values) {
        $hit = $false
        foreach ($fi in $fieldItems) { if (Test-HHScalarMatch -FieldValue $fi -RuleValue $v -Op $op -Ctx $Ctx) { $hit = $true; break } }
        $hit
    }
    $perValue = @($perValue)
    if ($values.Count -eq 0) { return $false }
    if ($combineAll) { return (@($perValue | Where-Object { -not $_ }).Count -eq 0) }
    return (@($perValue | Where-Object { $_ }).Count -ge 1)
}

function Test-HHSelection {
    # A selection is a list of field specs, all of which must match (AND).
    param($Specs, $Event, $Ctx)
    foreach ($spec in @($Specs)) { if (-not (Test-HHFieldSpec -Spec $spec -Event $Event -Ctx $Ctx)) { return $false } }
    return $true
}

function Get-HHQuantifierMatch {
    param([string]$Target, $SelResults, [bool]$RequireAll)
    $names = if ($Target -eq 'them') {
        @($SelResults.Keys)
    } else {
        $pat = '^' + ([regex]::Escape($Target).Replace('\*', '.*')) + '$'
        @($SelResults.Keys | Where-Object { $_ -match $pat })
    }
    if ($names.Count -eq 0) { return $false }
    $trues = @($names | Where-Object { $SelResults[$_] })
    if ($RequireAll) { return ($trues.Count -eq $names.Count) }
    return ($trues.Count -ge 1)
}

function Test-HHConditionAst {
    param($Ast, $SelResults)
    if ($null -eq $Ast) { return $false }
    $type = [string](Get-HHField $Ast 'type')
    switch ($type) {
        'and'   { return ((Test-HHConditionAst (Get-HHField $Ast 'left') $SelResults) -and (Test-HHConditionAst (Get-HHField $Ast 'right') $SelResults)) }
        'or'    { return ((Test-HHConditionAst (Get-HHField $Ast 'left') $SelResults) -or  (Test-HHConditionAst (Get-HHField $Ast 'right') $SelResults)) }
        'not'   { return (-not (Test-HHConditionAst (Get-HHField $Ast 'child') $SelResults)) }
        'sel'   { $n = [string](Get-HHField $Ast 'name'); return [bool]$SelResults[$n] }
        'oneof' { return (Get-HHQuantifierMatch -Target ([string](Get-HHField $Ast 'target')) -SelResults $SelResults -RequireAll $false) }
        'allof' { return (Get-HHQuantifierMatch -Target ([string](Get-HHField $Ast 'target')) -SelResults $SelResults -RequireAll $true) }
        default { return $false }
    }
}

function Import-HHCompiledRules {
    # Load compiled *.json rule ASTs from a directory.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $rules = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    foreach ($f in (Get-ChildItem -LiteralPath $Path -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
        try { $rules.Add((Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json)) } catch { }
    }
    return $rules.ToArray()
}

function Invoke-SigmaRules {
    <#
    .SYNOPSIS
        Evaluate compiled Sigma rules against normalized events; return finding.v1 records.
    .PARAMETER Events
        Normalized events from ConvertTo-HHNormalizedEvents.
    .PARAMETER Rules / RulePath
        Pre-loaded compiled rule objects, or a directory of compiled *.json to load.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Events,
        [object[]]$Rules,
        [string]$RulePath,
        [datetime]$ScanWindowStart = ([DateTime]::UtcNow.AddDays(-7)),
        [datetime]$ScanWindowEnd   = ([DateTime]::UtcNow),
        [hashtable]$FindingArgs = @{}
    )
    if (-not $Rules -and $RulePath) { $Rules = Import-HHCompiledRules -Path $RulePath }
    $Rules = @($Rules)
    $ctx = @{ ScanWindowStart = $ScanWindowStart.ToString('o'); ScanWindowEnd = $ScanWindowEnd.ToString('o') }

    # Index events by logsource category for fast rule routing.
    $byCat = @{}
    foreach ($ev in $Events) {
        $cat = [string](Get-HHField $ev 'category')
        if (-not $byCat.ContainsKey($cat)) { $byCat[$cat] = [System.Collections.Generic.List[object]]::new() }
        $byCat[$cat].Add($ev)
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $Rules) {
        $cat = [string](Get-HHField (Get-HHField $rule 'logsource') 'category')
        $candidates = if ($cat -and $byCat.ContainsKey($cat)) { $byCat[$cat] } elseif ($cat) { @() } else { $Events }

        $selections = Get-HHField $rule 'selections'
        $selNames   = Get-HHKeys $selections
        $ast        = Get-HHField $rule 'condition_ast'

        foreach ($ev in $candidates) {
            $selResults = @{}
            foreach ($sn in $selNames) { $selResults[$sn] = (Test-HHSelection -Specs (Get-HHField $selections $sn) -Event $ev -Ctx $ctx) }
            if (Test-HHConditionAst -Ast $ast -SelResults $selResults) {
                $args = @{
                    Event       = $ev
                    FindingType = [string](Get-HHField $rule 'finding_type')
                    Severity    = [string](Get-HHField $rule 'severity')
                    Confidence  = [string](Get-HHField $rule 'confidence')
                    Engine      = 'sigma'
                    RuleId      = [string](Get-HHField $rule 'id')
                    RuleTitle   = [string](Get-HHField $rule 'title')
                    RuleVersion = [string](Get-HHField $rule 'status')
                    Attack      = @(Get-HHField $rule 'attack')
                }
                foreach ($k in $FindingArgs.Keys) { $args[$k] = $FindingArgs[$k] }
                $findings.Add((New-Finding @args))
            }
        }
    }
    return $findings.ToArray()
}
