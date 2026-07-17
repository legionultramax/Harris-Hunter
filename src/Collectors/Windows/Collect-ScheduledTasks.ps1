# Collect-ScheduledTasks.ps1 - scheduled tasks with actions and triggers.
# ATT&CK: T1053.005 (scheduled task).

function Collect-ScheduledTasks {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $tasks = @()
    try { $tasks = Get-ScheduledTask -ErrorAction Stop } catch { return @() }

    foreach ($t in $tasks) {
        $info = $null
        try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch { }

        $actions = @()
        foreach ($a in @($t.Actions)) {
            # Task actions come in several CIM types (Exec, ComHandler, ShowMessage, Email);
            # only Exec actions have Execute/Arguments. Guard property access under StrictMode.
            $exec    = if ($a.PSObject.Properties['Execute'])          { $a.Execute }          else { $null }
            $args    = if ($a.PSObject.Properties['Arguments'])        { $a.Arguments }        else { $null }
            $workDir = if ($a.PSObject.Properties['WorkingDirectory']) { $a.WorkingDirectory } else { $null }
            $classId = if ($a.PSObject.Properties['ClassId'])          { $a.ClassId }          else { $null }
            $ev = if ($exec) { Get-HHFileEvidence -Path (Resolve-HHImagePath -CommandLine $exec) } else { $null }
            $actionType = if ($a -and $a.PSObject.Properties['CimClass'] -and $a.CimClass) { $a.CimClass.CimClassName } else { $a.GetType().Name }
            $actions += [ordered]@{
                action_type = $actionType
                execute     = $exec
                arguments   = $args
                working_dir = $workDir
                com_class_id= $classId
                sha256      = if ($ev) { $ev.sha256 } else { $null }
                signed      = if ($ev) { $ev.signed } else { $null }
            }
        }

        $triggers = @(@($t.Triggers) | Where-Object { $_ } | ForEach-Object {
            if ($_.PSObject.Properties['CimClass'] -and $_.CimClass) { $_.CimClass.CimClassName } else { $_.GetType().Name }
        })

        $principal = if ($t.PSObject.Properties['Principal']) { $t.Principal } else { $null }
        $records.Add((New-EvidenceRecord -ArtifactType 'scheduled_task' -Collector 'Collect-ScheduledTasks' `
            -Source 'Get-ScheduledTask' -Attack @('T1053.005') -Context $Context -Data @{
                task_name    = $t.TaskName
                task_path    = $t.TaskPath
                state        = [string]$t.State
                author       = $t.Author
                description  = $t.Description
                run_as       = if ($principal -and $principal.PSObject.Properties['UserId']) { $principal.UserId } else { $null }
                run_level    = if ($principal -and $principal.PSObject.Properties['RunLevel']) { [string]$principal.RunLevel } else { $null }
                actions      = $actions
                triggers     = $triggers
                last_run_utc = if ($info -and $info.LastRunTime) { $info.LastRunTime.ToUniversalTime().ToString('o') } else { $null }
                next_run_utc = if ($info -and $info.NextRunTime) { $info.NextRunTime.ToUniversalTime().ToString('o') } else { $null }
                last_result  = if ($info) { $info.LastTaskResult } else { $null }
            }))
    }

    return $records.ToArray()
}
