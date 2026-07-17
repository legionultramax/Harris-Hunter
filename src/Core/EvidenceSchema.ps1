# EvidenceSchema.ps1 - the common evidence record contract.
# Every collector emits ONLY records produced by New-EvidenceRecord. This is the
# ingestion contract consumed by later phases (normalize -> detect -> risk -> report).

$script:HHSchemaVersion = '1.0'

# Keys every well-formed record must carry.
$script:HHRequiredRecordKeys = @(
    'schema_version', 'artifact_type', 'collector', 'collected_at_utc',
    'host', 'engagement_id', 'source', 'attack', 'data'
)

function New-EvidenceRecord {
    <#
    .SYNOPSIS
        Build a single normalized evidence record.
    .DESCRIPTION
        Collectors call this for every artifact they gather. The orchestrator later
        adds per-record hashing and writes the record to disk; collectors never do I/O.
    .PARAMETER Context
        The run context (from the orchestrator) carrying host metadata + engagement id.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ArtifactType,
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)]$Data,
        [string]$Source = '',
        [string[]]$Attack = @(),
        [Parameter(Mandatory)]$Context
    )

    [ordered]@{
        schema_version   = $script:HHSchemaVersion
        artifact_type    = $ArtifactType
        collector        = $Collector
        collected_at_utc = [DateTime]::UtcNow.ToString('o')
        host             = $Context.Host
        engagement_id    = $Context.EngagementId
        source           = $Source
        attack           = @($Attack)
        data             = $Data
    }
}

function Test-EvidenceRecord {
    <#
    .SYNOPSIS
        Validate a record against the common schema. Returns $true/$false and, with
        -Detailed, the list of problems found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [switch]$Detailed
    )

    $problems = [System.Collections.Generic.List[string]]::new()

    # Records are ordered hashtables; accept any IDictionary.
    if ($Record -isnot [System.Collections.IDictionary]) {
        $problems.Add('record is not a dictionary/hashtable')
    }
    else {
        foreach ($key in $script:HHRequiredRecordKeys) {
            if (-not $Record.Contains($key)) {
                $problems.Add("missing required key: $key")
            }
        }

        if ($Record.Contains('collected_at_utc')) {
            $parsed = [datetime]::MinValue
            $ok = [datetime]::TryParse(
                $Record['collected_at_utc'], [cultureinfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)
            if (-not $ok) { $problems.Add('collected_at_utc is not a valid ISO-8601 timestamp') }
        }

        if ($Record.Contains('attack') -and $Record['attack'] -isnot [System.Collections.IEnumerable]) {
            $problems.Add('attack must be an array')
        }
    }

    if ($Detailed) {
        return [pscustomobject]@{
            Valid    = ($problems.Count -eq 0)
            Problems = $problems.ToArray()
        }
    }

    return ($problems.Count -eq 0)
}
