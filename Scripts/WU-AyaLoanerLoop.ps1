#Requires -RunAsAdministrator
<#
.SYNOPSIS
  SetupComplete (SYSTEM) stages + registers an interactive logon task for local user AyaLoaner.
  At AyaLoaner logon, runs Windows Update loop with visible progress (software + drivers).
  Reboots as needed until no updates remain and no reboot required.
  Then disables AutoAdminLogon, removes task, and removes only staged script/state (keeps logs).

.NOTES
  Fixes the "InteractiveToken" LogonType error by using LogonType=Interactive, which is the valid
  ScheduledTasks cmdlet enumeration value. [1](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal?view=windowsserver2025-ps)[2](https://www.pdq.com/powershell/new-scheduledtaskprincipal/)
  Also handles systems where Microsoft.Update.AutoUpdate.Settings lacks ServiceID (skips that step).
#>

[CmdletBinding()]
param(
    [switch]$Run,

    [string]$UserName   = "AyaLoaner",
    [string]$TaskName   = "WU-AyaLoaner-Interactive",
    [string]$StagingDir = "$env:ProgramData\WUInstallLoop",
    [int]$PollSeconds   = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ----------------------------
# Paths / Logging
# ----------------------------
function Ensure-Directory { param([string]$Path) if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }
Ensure-Directory $StagingDir

$LogPath      = Join-Path $StagingDir "WU-AyaLoanerLoop.log"
$StatePath    = Join-Path $StagingDir "WU-AyaLoanerLoop.state.json"
$StagedScript = Join-Path $StagingDir "WU-AyaLoanerLoop.ps1"

function Write-Log {
    param([string]$Message, [ValidateSet("INFO","WARN","ERROR")][string]$Level="INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts][$Level] $Message"
    Write-Host $line
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 } catch {}
}

function Load-State {
    if (Test-Path $StatePath) {
        try { return (Get-Content $StatePath -Raw | ConvertFrom-Json) } catch {}
    }
    return [pscustomobject]@{
        StageComplete = $false
        PassCount     = 0
        LastAction    = ""
    }
}
function Save-State($state) {
    try { $state | ConvertTo-Json -Depth 6 | Set-Content -Path $StatePath -Encoding UTF8 } catch {}
}

# Prevent overlapping runs
function Acquire-Mutex {
    param([string]$Name = "Global\WU_AyaLoanerLoop_Mutex")
    $created = $false
    $m = New-Object System.Threading.Mutex($true, $Name, [ref]$created)
    if (-not $created) {
        Write-Log "Another instance is already running. Exiting." "WARN"
        exit 0
    }
    return $m
}

# ----------------------------
# Force-enable Microsoft Update ("Other Microsoft products") - best effort
# ----------------------------
function Enable-MicrosoftUpdateOtherProducts {
    $muServiceId = "7971f918-a847-4430-9279-4a52d1efe18d"
    Write-Log "Ensuring Microsoft Update (Other Microsoft products) is enabled..."

    # Register/ensure the Microsoft Update service
    try {
        $sm = New-Object -ComObject "Microsoft.Update.ServiceManager"
        $sm.ClientApplicationID = "WU-AyaLoanerLoop"
        try { $null = $sm.AddService2($muServiceId, 7, $null) } catch {}
        Write-Log "Microsoft Update service ensured (ServiceID: $muServiceId)."
    } catch {
        Write-Log "Failed to ensure Microsoft Update service: $($_.Exception.Message)" "WARN"
    }

    # Some builds expose AutoUpdate.Settings.ServiceID, some do not. If not present, skip safely.
    try {
        $au = New-Object -ComObject "Microsoft.Update.AutoUpdate"
        $settings = $au.Settings

        $hasServiceId =
            ($settings -ne $null) -and
            (($settings.PSObject.Properties.Name -contains "ServiceID") -or
             ($settings.PSObject.Methods.Name -contains "get_ServiceID"))

        if ($hasServiceId) {
            $settings.ServiceID = $muServiceId
            $settings.Save()
            Write-Log "Microsoft Update set as default Automatic Updates service."
        } else {
            Write-Log "AutoUpdate.Settings does not expose ServiceID on this OS; skipping default-service set (search will still target MU)." "WARN"
        }
    } catch {
        Write-Log "Failed to set AutoUpdate default service (continuing): $($_.Exception.Message)" "WARN"
    }
}

# ----------------------------
# Disable AutoAdminLogon (end only)
# ----------------------------
function Disable-AutoLogon {
    $wl = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Write-Log "Disabling AutoAdminLogon (completion cleanup)..."
    try { Set-ItemProperty -Path $wl -Name "AutoAdminLogon" -Value "0" -ErrorAction SilentlyContinue } catch {}
    try { Remove-ItemProperty -Path $wl -Name "AutoLogonCount" -ErrorAction SilentlyContinue } catch {}
    try { Remove-ItemProperty -Path $wl -Name "DefaultPassword" -ErrorAction SilentlyContinue } catch {}
}

# ----------------------------
# Scheduled Task registration (runs at logon, visible console)
#   IMPORTANT FIX: LogonType must be Interactive (not InteractiveToken) [1](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal?view=windowsserver2025-ps)[2](https://www.pdq.com/powershell/new-scheduledtaskprincipal/)
# ----------------------------
function Register-InteractiveLogonTask {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$WorkingDir,
        [Parameter(Mandatory)][int]$PollSeconds
    )

    $fullUser = "$env:COMPUTERNAME\$UserName"
    $psExe    = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

    # Visible console window
    $innerArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Run -UserName `"$UserName`" -TaskName `"$TaskName`" -StagingDir `"$WorkingDir`" -PollSeconds $PollSeconds"
    $cmdArgs   = "/c start `"`" /D `"$WorkingDir`" `"$psExe`" $innerArgs"

    try {
        Import-Module ScheduledTasks -ErrorAction Stop

        # FIX HERE: Use Interactive (valid LogonTypeEnum) [1](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal?view=windowsserver2025-ps)[2](https://www.pdq.com/powershell/new-scheduledtaskprincipal/)
        $principal = New-ScheduledTaskPrincipal -UserId $fullUser -LogonType Interactive -RunLevel Highest
        $action    = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument $cmdArgs -WorkingDirectory $WorkingDir
        $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $fullUser
        $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 12)

        try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

        Write-Log "Registered logon task via ScheduledTasks: $TaskName (User: $fullUser)"
        return
    } catch {
        Write-Log "ScheduledTasks registration failed, falling back to COM API. $($_.Exception.Message)" "WARN"
    }

    # COM fallback
    $TASK_LOGON_INTERACTIVE_TOKEN = 3
    $TASK_RUNLEVEL_HIGHEST        = 1

    $svc = New-Object -ComObject "Schedule.Service"
    $svc.Connect()
    $folder = $svc.GetFolder("\")
    try { $folder.DeleteTask($TaskName, 0) } catch {}

    $task = $svc.NewTask(0)
    $task.RegistrationInfo.Description = "WU AyaLoaner interactive update loop"

    $task.Settings.Enabled = $true
    $task.Settings.StartWhenAvailable = $true
    $task.Settings.ExecutionTimeLimit = "PT12H"

    $task.Principal.UserId    = $fullUser
    $task.Principal.LogonType = $TASK_LOGON_INTERACTIVE_TOKEN
    $task.Principal.RunLevel  = $TASK_RUNLEVEL_HIGHEST

    $trigger  = $task.Triggers.Create(9) # TASK_TRIGGER_LOGON
    $trigger.UserId = $fullUser

    $action = $task.Actions.Create(0)     # TASK_ACTION_EXEC
    $action.Path = "$env:SystemRoot\System32\cmd.exe"
    $action.Arguments = $cmdArgs
    $action.WorkingDirectory = $WorkingDir

    $folder.RegisterTaskDefinition($TaskName, $task, 6, $null, $null, $TASK_LOGON_INTERACTIVE_TOKEN, $null) | Out-Null
    Write-Log "Registered logon task via COM: $TaskName (User: $fullUser)"
}

function Remove-TaskRobust {
    param([Parameter(Mandatory)][string]$TaskName)

    try {
        Import-Module ScheduledTasks -ErrorAction Stop
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null } catch {}
        try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    } catch {}

    try { & "$env:SystemRoot\System32\schtasks.exe" /Delete /TN $TaskName /F | Out-Null } catch {}

    try {
        $svc = New-Object -ComObject "Schedule.Service"
        $svc.Connect()
        $svc.GetFolder("\").DeleteTask($TaskName, 0)
    } catch {}

    Write-Log "Removed task (best-effort): $TaskName"
}

function Try-RunTaskNow {
    param([string]$TaskName)
    try {
        Import-Module ScheduledTasks -ErrorAction Stop
        Start-ScheduledTask -TaskName $TaskName
        Write-Log "Triggered task immediately (Start-ScheduledTask): $TaskName"
        return
    } catch {}
    try {
        & "$env:SystemRoot\System32\schtasks.exe" /Run /TN $TaskName | Out-Null
        Write-Log "Triggered task immediately (schtasks /Run): $TaskName"
    } catch {}
}

# ----------------------------
# Pending reboot detection
# ----------------------------
function Test-PendingReboot {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $true } }

    try {
        $v = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction Stop
        if ($null -ne $v.PendingFileRenameOperations) { return $true }
    } catch {}
    return $false
}

# ----------------------------
# Windows Update COM loop (includes everything offered by MS to the agent)
# ----------------------------
function New-WUObjects {
    $session = New-Object -ComObject "Microsoft.Update.Session"
    $session.ClientApplicationID = "WU-AyaLoanerLoop"
    $searcher = $session.CreateUpdateSearcher()

    # Prefer Microsoft Update explicitly
    $muServiceId = "7971f918-a847-4430-9279-4a52d1efe18d"
    try {
        $searcher.ServerSelection = 3
        $searcher.ServiceID = $muServiceId
    } catch {
        Write-Log "Could not force Microsoft Update searcher; using default. $($_.Exception.Message)" "WARN"
    }

    [pscustomobject]@{ Session=$session; Searcher=$searcher }
}

function Get-UpdateSummary($u) {
    $kbs=""
    try { $kbs = ($u.KBArticleIDs -join ",") } catch {}
    $kbPart = if ($kbs) { " (KB:$kbs)" } else { "" }

    $type=""
    try { $type = $u.Type } catch {}

    $drv=""
    try {
        $parts=@()
        foreach($p in "DriverManufacturer","DriverModel","DriverClass","DriverVerDate"){
            try { $v=$u.$p; if($v){ $parts += "$p=$v" } } catch {}
        }
        if($parts.Count -gt 0){ $drv = " | " + ($parts -join " ; ") }
    } catch {}

    return "$($u.Title)$kbPart Type=$type$drv"
}

function Search-Updates($searcher) {
    $criteria = "IsInstalled=0 and IsHidden=0"
    Write-Log "Searching for updates (criteria: $criteria) ..."
    $result = $searcher.Search($criteria)

    $list = New-Object System.Collections.ArrayList
    for ($i=0; $i -lt $result.Updates.Count; $i++) {
        $u = $result.Updates.Item($i)
        try { if (-not $u.EulaAccepted) { $u.AcceptEula() } } catch {}
        [void]$list.Add($u)
    }

    $arr = @($list.ToArray())
    Write-Log ("Found {0} update(s)." -f @($arr).Count)
    return $arr
}

function Download-One($session,$u,$n,$total,$poll) {
    if ($u.IsDownloaded) { return }

    $col = New-Object -ComObject "Microsoft.Update.UpdateColl"
    $null = $col.Add($u)
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $col

    Write-Log "Downloading [$n/$total]: $($u.Title)"
    $async = $true
    try { $job = $downloader.BeginDownload($null,$null) } catch { $async = $false }

    if ($async) {
        while (-not $job.IsCompleted) {
            $pct=0
            try { $pct = [int]$job.GetProgress().PercentComplete } catch {}
            $overall = [math]::Round((($n-1)+($pct/100))/$total*100,1)

            Write-Progress -Id 1 -Activity "Windows Update (overall)" -Status "$overall% complete" -PercentComplete $overall
            Write-Progress -Id 2 -ParentId 1 -Activity "Downloading $n of $total" -Status "$pct%: $($u.Title)" -PercentComplete $pct
            Start-Sleep -Seconds $poll
        }
        $null = $downloader.EndDownload($job)
        Write-Progress -Id 2 -ParentId 1 -Completed -Activity "Downloading $n of $total"
    } else {
        $null = $downloader.Download()
    }
}

function Install-One($session,$u,$n,$total,$poll) {
    $col = New-Object -ComObject "Microsoft.Update.UpdateColl"
    $null = $col.Add($u)

    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $col
    $installer.ForceQuiet = $true
    $installer.AllowSourcePrompts = $false

    Write-Log "Installing [$n/$total]: $($u.Title)"
    $async = $true
    try { $job = $installer.BeginInstall($null,$null) } catch { $async = $false }

    if ($async) {
        while (-not $job.IsCompleted) {
            $pct=0
            try { $pct = [int]$job.GetProgress().PercentComplete } catch {}
            $overall = [math]::Round((($n-1)+($pct/100))/$total*100,1)

            Write-Progress -Id 1 -Activity "Windows Update (overall)" -Status "$overall% complete" -PercentComplete $overall
            Write-Progress -Id 2 -ParentId 1 -Activity "Installing $n of $total" -Status "$pct%: $($u.Title)" -PercentComplete $pct
            Start-Sleep -Seconds $poll
        }
        $result = $installer.EndInstall($job)
        Write-Progress -Id 2 -ParentId 1 -Completed -Activity "Installing $n of $total"
    } else {
        $result = $installer.Install()
    }

    $rc = $result.ResultCode
    $reboot = [bool]$result.RebootRequired
    $hres = ""
    try { $h = ($result.HResult -band 0xFFFFFFFF); $hres = ("0x{0:X8}" -f $h) } catch {}
    Write-Log ("Install result: ResultCode={0}, RebootRequired={1}, HResult={2}" -f $rc, $reboot, $hres)

    return [pscustomobject]@{ ResultCode=$rc; RebootRequired=$reboot }
}

# ----------------------------
# Cleanup while keeping logs
# ----------------------------
function Cleanup-KeepLogs {
    param([string]$TaskName,[string]$StatePath,[string]$StagedScript,[string]$LogPath)

    Write-Log "Cleanup: removing scheduled task and disabling autologon (keeping logs)."
    Remove-TaskRobust -TaskName $TaskName
    Disable-AutoLogon

    try { Remove-Item -Path $StatePath -Force -ErrorAction SilentlyContinue } catch {}

    Write-Log "Scheduling staged script deletion (log preserved at: $LogPath)"
    $cmd = "timeout /t 3 >nul & del /f /q `"$StagedScript`""
    Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/c", $cmd -WindowStyle Hidden
}

# ----------------------------
# MAIN
# ----------------------------
$mutex = Acquire-Mutex
try {
    $state = Load-State

    # Ensure Windows Update service running
    try {
        $svc = Get-Service -Name wuauserv -ErrorAction Stop
        if ($svc.Status -ne "Running") {
            Write-Log "Starting wuauserv..."
            Start-Service wuauserv
        }
    } catch {
        Write-Log "Could not validate/start wuauserv: $($_.Exception.Message)" "WARN"
    }

    Enable-MicrosoftUpdateOtherProducts

    if (-not $Run) {
        # ---------------- STAGE MODE (SetupComplete / SYSTEM) ----------------
        Write-Log "STAGE MODE: staging script + registering logon task for $UserName..."

        Copy-Item -Path $PSCommandPath -Destination $StagedScript -Force
        Write-Log "Staged script to: $StagedScript"

        Register-InteractiveLogonTask -TaskName $TaskName -UserName $UserName -ScriptPath $StagedScript -WorkingDir $StagingDir -PollSeconds $PollSeconds

        $state.StageComplete = $true
        $state.LastAction = "StagedAndTaskRegistered"
        Save-State $state

        # If AyaLoaner already logged on (manual execution), trigger immediately
        try {
            $q = (& quser 2>$null) -join "`n"
            if ($q -match "(?im)^\s*$([regex]::Escape($UserName))\s+") {
                Write-Log "$UserName appears logged in already. Triggering task now..."
                Try-RunTaskNow -TaskName $TaskName
            } else {
                Write-Log "$UserName not logged in yet. Task will run at logon."
            }
        } catch {
            Write-Log "Could not check sessions; task will run at logon. $($_.Exception.Message)" "WARN"
        }

        Write-Log "Stage complete."
        exit 0
    }

    # ---------------- RUN MODE (AyaLoaner interactive session) ----------------
    Write-Log "RUN MODE: update loop starting (interactive, visible progress)."
    Write-Log "Log file: $LogPath"

    $pass = 0
    while ($true) {
        $pass++
        $state.PassCount = $pass
        $state.LastAction = "PassStarted"
        Save-State $state

        Write-Log "========== PASS $pass =========="
        Enable-MicrosoftUpdateOtherProducts

        $wu = New-WUObjects
        $session  = $wu.Session
        $searcher = $wu.Searcher

        $updates = @(Search-Updates $searcher)
        $total = @($updates).Count

        if ($total -eq 0) {
            if (-not (Test-PendingReboot)) {
                Write-Log "No updates remain AND no reboot required. FINISH."
                Cleanup-KeepLogs -TaskName $TaskName -StatePath $StatePath -StagedScript $StagedScript -LogPath $LogPath
                Write-Log "DONE. (Logs preserved)"
                exit 0
            } else {
                Write-Log "No updates remain but reboot is pending. Restarting..."
                Start-Sleep 2
                Restart-Computer -Force
                return
            }
        }

        Write-Log "Updates offered:"
        for ($i=0; $i -lt $total; $i++) {
            Write-Log ("  [{0}/{1}] {2}" -f ($i+1), $total, (Get-UpdateSummary $updates[$i]))
        }

        $needsReboot = $false

        for ($i=0; $i -lt $total; $i++) {
            $u = $updates[$i]
            $n = $i + 1

            Write-Log ("Processing [{0}/{1}] {2}" -f $n, $total, (Get-UpdateSummary $u))

            Download-One $session $u $n $total $PollSeconds
            $r = Install-One  $session $u $n $total $PollSeconds

            if ($r.RebootRequired) { $needsReboot = $true }

            $overallDone = [math]::Round(($n/$total)*100,1)
            Write-Progress -Id 1 -Activity "Windows Update (overall)" -Status "$overallDone% complete" -PercentComplete $overallDone
        }

        if ($needsReboot -or (Test-PendingReboot)) {
            Write-Log "Reboot required. Restarting now..."
            Start-Sleep 2
            Restart-Computer -Force
            return
        }

        Write-Log "No reboot required. Re-scanning shortly..."
        Start-Sleep 2
    }
}
finally {
    try { $mutex.ReleaseMutex() } catch {}
}
``