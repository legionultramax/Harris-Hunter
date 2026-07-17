# Collect-WmiPersistence.ps1 - WMI event subscription persistence.
# ATT&CK: T1546.003 (event-triggered execution: WMI event subscription).
# Filters + consumers + bindings in root\subscription are a classic fileless persistence.

function Collect-WmiPersistence {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    try {
        foreach ($f in (Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventFilter' -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'wmi_event_filter' -Collector 'Collect-WmiPersistence' `
                -Source 'root/subscription:__EventFilter' -Attack @('T1546.003') -Context $Context -Data @{
                    name         = $f.Name
                    query        = $f.Query
                    query_lang   = $f.QueryLanguage
                    event_ns     = $f.EventNamespace
                }))
        }
    } catch { }

    try {
        foreach ($c in (Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventConsumer' -ErrorAction Stop)) {
            $data = [ordered]@{
                name      = $c.Name
                class     = $c.CimClass.CimClassName
            }
            # Capture the payload fields that matter for the common consumer types.
            if ($c.PSObject.Properties['CommandLineTemplate']) { $data['command_line'] = $c.CommandLineTemplate }
            if ($c.PSObject.Properties['ExecutablePath'])      { $data['executable_path'] = $c.ExecutablePath }
            if ($c.PSObject.Properties['ScriptText'])          { $data['script_text'] = $c.ScriptText }
            if ($c.PSObject.Properties['ScriptingEngine'])     { $data['scripting_engine'] = $c.ScriptingEngine }
            $records.Add((New-EvidenceRecord -ArtifactType 'wmi_event_consumer' -Collector 'Collect-WmiPersistence' `
                -Source 'root/subscription:__EventConsumer' -Attack @('T1546.003') -Context $Context -Data $data))
        }
    } catch { }

    try {
        foreach ($b in (Get-CimInstance -Namespace 'root/subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'wmi_binding' -Collector 'Collect-WmiPersistence' `
                -Source 'root/subscription:__FilterToConsumerBinding' -Attack @('T1546.003') -Context $Context -Data @{
                    filter   = [string]$b.Filter
                    consumer = [string]$b.Consumer
                }))
        }
    } catch { }

    return $records.ToArray()
}
