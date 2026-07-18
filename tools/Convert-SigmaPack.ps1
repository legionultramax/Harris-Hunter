<#
.SYNOPSIS
    Compile Sigma rules (YAML) into the internal JSON rule AST the runtime engine consumes.
.DESCRIPTION
    HAARIS-HUNTER's endpoint runtime must run on Windows PowerShell 5.1, which has no YAML
    parser - and installing modules is disallowed. Blueprint CGD-CA-DESIGN-001 section 11 calls
    for compiling Sigma -> internal DSL "at pack-build time". This tool is that build step: it
    parses a constrained Sigma-dialect YAML in pure PowerShell and emits config/detection/rules/
    compiled/<id>.json. The endpoint never parses YAML - it loads the compiled JSON only.

    Supported Sigma subset: logsource.category routing; detection selection maps; field modifiers
    contains|startswith|endswith|re|gte|lte|cidr|all|eq; value lists (OR) and maps (AND);
    condition grammar (and/or/not, parentheses, "1 of sel*", "all of sel*", "... of them").
.PARAMETER SourceDir
    Directory of *.yml Sigma rules. Default: config/detection/rules/sigma
.PARAMETER OutDir
    Output directory for compiled *.json. Default: config/detection/rules/compiled
#>
[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$OutDir,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $SourceDir) { $SourceDir = Join-Path $repoRoot 'config/detection/rules/sigma' }
if (-not $OutDir)    { $OutDir    = Join-Path $repoRoot 'config/detection/rules/compiled' }

# ==============================  Minimal YAML (Sigma subset)  ==============================

function Remove-HHYamlComment {
    param([string]$Line)
    $inS = $false; $inD = $false
    for ($i = 0; $i -lt $Line.Length; $i++) {
        $c = $Line[$i]
        if ($c -eq "'" -and -not $inD) { $inS = -not $inS }
        elseif ($c -eq '"' -and -not $inS) { $inD = -not $inD }
        elseif ($c -eq '#' -and -not $inS -and -not $inD) {
            if ($i -eq 0 -or $Line[$i - 1] -eq ' ' -or $Line[$i - 1] -eq "`t") { return $Line.Substring(0, $i) }
        }
    }
    return $Line
}

function ConvertFrom-HHYamlScalar {
    param([string]$V)
    $v = $V.Trim()
    if ($v.Length -ge 2 -and $v.StartsWith("'") -and $v.EndsWith("'")) { return $v.Substring(1, $v.Length - 2).Replace("''", "'") }
    if ($v.Length -ge 2 -and $v.StartsWith('"') -and $v.EndsWith('"')) { return $v.Substring(1, $v.Length - 2) }
    if ($v -eq 'true')  { return $true }
    if ($v -eq 'false') { return $false }
    if ($v -eq 'null' -or $v -eq '~') { return $null }
    if ($v -match '^-?\d+$') { return [int]$v }
    return $v
}

function ConvertFrom-HHYamlFlowList {
    param([string]$V)
    $inner = $V.Trim().TrimStart('[').TrimEnd(']')
    if (-not $inner.Trim()) { return @() }
    return @($inner -split ',' | ForEach-Object { ConvertFrom-HHYamlScalar $_ })
}

function ConvertFrom-HHYaml {
    <#
    .SYNOPSIS
        Parse a constrained YAML document into ordered hashtables / arrays / scalars.
        Handles maps, block lists, flow lists, quoted scalars. Not a general YAML parser.
    #>
    param([string]$Text)
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($raw in (($Text -replace "`r", '') -split "`n")) {
        $line = Remove-HHYamlComment $raw
        if ($line.Trim() -eq '' -or $line.Trim() -eq '---') { continue }
        $indent = $line.Length - $line.TrimStart(' ').Length
        $items.Add([pscustomobject]@{ indent = $indent; text = $line.Trim() })
    }
    $script:HHYamlItems = $items
    $script:HHYamlPos = 0
    if ($items.Count -eq 0) { return [ordered]@{} }
    return (Read-HHYamlBlock -MinIndent $items[0].indent)
}

function Read-HHYamlBlock {
    param([int]$MinIndent)
    if ($script:HHYamlPos -ge $script:HHYamlItems.Count) { return $null }
    $first = $script:HHYamlItems[$script:HHYamlPos]
    if ($first.indent -lt $MinIndent) { return $null }
    if ($first.text.StartsWith('- ') -or $first.text -eq '-') { return (Read-HHYamlList  -Indent $first.indent) }
    return (Read-HHYamlMap -Indent $first.indent)
}

function Read-HHYamlMap {
    param([int]$Indent)
    $map = [ordered]@{}
    while ($script:HHYamlPos -lt $script:HHYamlItems.Count) {
        $it = $script:HHYamlItems[$script:HHYamlPos]
        if ($it.indent -ne $Indent) { break }
        $ci = $it.text.IndexOf(':')
        if ($ci -lt 0) { break }   # not a map line
        $key = $it.text.Substring(0, $ci).Trim()
        $val = if ($ci + 1 -lt $it.text.Length) { $it.text.Substring($ci + 1).Trim() } else { '' }
        $script:HHYamlPos++
        if ($val -eq '') {
            # nested block if the next line is deeper; else null
            if ($script:HHYamlPos -lt $script:HHYamlItems.Count -and $script:HHYamlItems[$script:HHYamlPos].indent -gt $Indent) {
                $map[$key] = Read-HHYamlBlock -MinIndent $script:HHYamlItems[$script:HHYamlPos].indent
            } else { $map[$key] = $null }
        }
        elseif ($val.StartsWith('[')) { $map[$key] = ConvertFrom-HHYamlFlowList $val }
        else { $map[$key] = ConvertFrom-HHYamlScalar $val }
    }
    return $map
}

function Read-HHYamlList {
    param([int]$Indent)
    $list = [System.Collections.Generic.List[object]]::new()
    while ($script:HHYamlPos -lt $script:HHYamlItems.Count) {
        $it = $script:HHYamlItems[$script:HHYamlPos]
        if ($it.indent -ne $Indent -or -not ($it.text.StartsWith('- ') -or $it.text -eq '-')) { break }
        $content = $it.text.Substring(1).Trim()
        $script:HHYamlPos++
        if ($content -eq '') {
            if ($script:HHYamlPos -lt $script:HHYamlItems.Count -and $script:HHYamlItems[$script:HHYamlPos].indent -gt $Indent) {
                $list.Add((Read-HHYamlBlock -MinIndent $script:HHYamlItems[$script:HHYamlPos].indent))
            } else { $list.Add($null) }
        }
        elseif ($content.StartsWith('[')) { $list.Add((ConvertFrom-HHYamlFlowList $content)) }
        else { $list.Add((ConvertFrom-HHYamlScalar $content)) }
    }
    return $list.ToArray()
}

# ==============================  Condition grammar -> AST  ==============================

function ConvertTo-HHConditionTokens {
    param([string]$Cond)
    $spaced = $Cond -replace '\(', ' ( ' -replace '\)', ' ) '
    return @($spaced -split '\s+' | Where-Object { $_ -ne '' })
}

function ConvertTo-HHConditionAst {
    param([string]$Cond)
    $script:HHCondTokens = ConvertTo-HHConditionTokens $Cond
    $script:HHCondPos = 0
    if ($script:HHCondTokens.Count -eq 0) { return $null }
    return (Read-HHCondOr)
}
function Read-HHCondPeek { if ($script:HHCondPos -lt $script:HHCondTokens.Count) { return $script:HHCondTokens[$script:HHCondPos] } return $null }
function Read-HHCondNext { $t = Read-HHCondPeek; $script:HHCondPos++; return $t }
function Read-HHCondOr {
    $node = Read-HHCondAnd
    while ((Read-HHCondPeek) -eq 'or') { [void](Read-HHCondNext); $node = [ordered]@{ type = 'or'; left = $node; right = (Read-HHCondAnd) } }
    return $node
}
function Read-HHCondAnd {
    $node = Read-HHCondNot
    while ((Read-HHCondPeek) -eq 'and') { [void](Read-HHCondNext); $node = [ordered]@{ type = 'and'; left = $node; right = (Read-HHCondNot) } }
    return $node
}
function Read-HHCondNot {
    if ((Read-HHCondPeek) -eq 'not') { [void](Read-HHCondNext); return [ordered]@{ type = 'not'; child = (Read-HHCondNot) } }
    return (Read-HHCondAtom)
}
function Read-HHCondAtom {
    $t = Read-HHCondPeek
    if ($t -eq '(') {
        [void](Read-HHCondNext)
        $n = Read-HHCondOr
        if ((Read-HHCondPeek) -eq ')') { [void](Read-HHCondNext) }
        return $n
    }
    # quantifier: "1 of X" | "all of X"
    if ($t -eq '1' -or $t -eq 'all') {
        if (($script:HHCondPos + 2) -lt ($script:HHCondTokens.Count + 1) -and $script:HHCondTokens[$script:HHCondPos + 1] -eq 'of') {
            $q = Read-HHCondNext          # 1 | all
            [void](Read-HHCondNext)       # of
            $target = Read-HHCondNext     # them | selection*
            return [ordered]@{ type = $(if ($q -eq 'all') { 'allof' } else { 'oneof' }); target = $target }
        }
    }
    $name = Read-HHCondNext
    return [ordered]@{ type = 'sel'; name = $name }
}

# ==============================  Sigma -> compiled rule  ==============================

function ConvertTo-HHFieldSpec {
    # "persistence.value|contains" + value(s) -> { field, modifiers[], values[] }
    param([string]$Key, $Value)
    $parts = $Key -split '\|'
    $field = $parts[0].Trim()
    $modifiers = @()
    if ($parts.Count -gt 1) { $modifiers = @($parts[1..($parts.Count - 1)] | ForEach-Object { $_.Trim().ToLower() }) }
    $values = @()
    if ($Value -is [array]) { $values = @($Value) } elseif ($null -ne $Value) { $values = @($Value) }
    [ordered]@{ field = $field; modifiers = $modifiers; values = $values }
}

function Get-HHAttackFromTags {
    param($Tags)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($t in @($Tags)) {
        $s = [string]$t
        $m = [regex]::Match($s, '(?i)attack\.(t\d{4}(?:\.\d{3})?)')
        if ($m.Success) { $out.Add($m.Groups[1].Value.ToUpper()) }
    }
    return $out.ToArray()
}

function ConvertTo-HHCompiledRule {
    param([Parameter(Mandatory)]$Sigma, [string]$SourceFile)

    $validLevels = @('informational', 'low', 'medium', 'high', 'critical')
    $level = [string]$Sigma['level']
    $severity = if ($level -in $validLevels) { $level } else { 'medium' }
    $confidence = if ($Sigma['confidence'] -in @('low', 'medium', 'high', 'confirmed')) { [string]$Sigma['confidence'] } else { 'medium' }

    $logsource = $Sigma['logsource']
    $category = if ($logsource) { [string]$logsource['category'] } else { $null }
    $product  = if ($logsource) { [string]$logsource['product'] } else { $null }

    $findingType = if ($Sigma['finding_type']) { [string]$Sigma['finding_type'] } elseif ($category) { $category } else { 'detection.generic' }

    $detection = $Sigma['detection']
    if (-not $detection) { throw "rule '$($Sigma['title'])' has no detection block" }

    $selections = [ordered]@{}
    $condition = $null
    foreach ($k in $detection.Keys) {
        if ($k -eq 'condition') { $condition = [string]$detection[$k]; continue }
        $selMap = $detection[$k]
        $specs = [System.Collections.Generic.List[object]]::new()
        if ($selMap -is [System.Collections.IDictionary]) {
            foreach ($fk in $selMap.Keys) { $specs.Add((ConvertTo-HHFieldSpec -Key $fk -Value $selMap[$fk])) }
        }
        $selections[$k] = $specs.ToArray()
    }
    if (-not $condition) { throw "rule '$($Sigma['title'])' detection has no condition" }

    [ordered]@{
        id            = [string]$Sigma['id']
        title         = [string]$Sigma['title']
        status        = [string]$Sigma['status']
        description   = [string]$Sigma['description']
        level         = $level
        severity      = $severity
        confidence    = $confidence
        engine        = 'sigma'
        finding_type  = $findingType
        logsource     = [ordered]@{ category = $category; product = $product }
        attack        = Get-HHAttackFromTags $Sigma['tags']
        selections    = $selections
        condition     = $condition
        condition_ast = ConvertTo-HHConditionAst $condition
        source_file   = (Split-Path -Leaf $SourceFile)
        compiled_at   = [DateTime]::UtcNow.ToString('o')
    }
}

# ==============================  Main  ==============================

if (-not (Test-Path -LiteralPath $SourceDir)) { throw "Sigma source dir not found: $SourceDir" }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$ruleFiles = @(Get-ChildItem -LiteralPath $SourceDir -Filter '*.yml' -File -ErrorAction SilentlyContinue) +
             @(Get-ChildItem -LiteralPath $SourceDir -Filter '*.yaml' -File -ErrorAction SilentlyContinue)

$compiled = 0; $failed = 0
foreach ($rf in $ruleFiles) {
    try {
        $sigma = ConvertFrom-HHYaml -Text (Get-Content -LiteralPath $rf.FullName -Raw)
        $rule  = ConvertTo-HHCompiledRule -Sigma $sigma -SourceFile $rf.FullName
        $id    = if ($rule.id) { $rule.id } else { [IO.Path]::GetFileNameWithoutExtension($rf.Name) }
        $safe  = ($id -replace '[^A-Za-z0-9._-]', '_')
        $dest  = Join-Path $OutDir ("$safe.json")
        # Write UTF-8 WITHOUT BOM - compiled rules are portable artifacts a strict JSON parser
        # (e.g. the future central platform) must read; PS 5.1 Set-Content -Encoding utf8 adds a BOM.
        [IO.File]::WriteAllText($dest, ($rule | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
        $compiled++
        if (-not $Quiet) { Write-Host ("  [OK]  {0}  ->  {1}" -f $rf.Name, (Split-Path -Leaf $dest)) -ForegroundColor Green }
    } catch {
        $failed++
        if (-not $Quiet) { Write-Host ("  [ERR] {0}: {1}" -f $rf.Name, $_.Exception.Message) -ForegroundColor Red }
    }
}
if (-not $Quiet) { Write-Host ("Compiled {0} rule(s), {1} failed -> {2}" -f $compiled, $failed, $OutDir) }
return [pscustomobject]@{ Compiled = $compiled; Failed = $failed; OutDir = $OutDir }
