#Requires -RunAsAdministrator
<#
.SYNOPSIS
  SetupComplete (SYSTEM) stages + registers an interactive logon task (runs as INTERACTIVE user).
  At AyaLoaner logon, runs Microsoft Update loop with visible progress (software + drivers).
  Reboots until fully done, then disables AutoAdminLogon, removes the task, and deletes staged script/state.
  Keeps logs in ProgramData.

.KEY FIX
  Avoids "No mapping between account names and security IDs was done" by NOT binding the task
  to AyaLoaner during SetupComplete. Instead uses INTERACTIVE group SID S-1-5-4. [3](https://www.briantist.com/errors/scheduled-task-powershell-0xfffd0000/)[1](https://stackoverflow.com/questions/58346274/register-scheduledtask-no-mapping-betwen-account-names-and-security-ids-was-do)

.NOTES
  ScheduledTasks LogonType valid values include Interactive; we use Group principal here instead. [4](https://lazyadmin.nl/it/error-0xfffd0000-after-running-powershell-scheduled-task/)
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
# Current interactive user (robust; handles quser '>' marker)
# ----------------------------
function Get-CurrentConsoleUser {
    $lines = & quser 2>$null
    if (-not $lines) { return $null }

    foreach ($line in $lines) {
        if ($line -match '^\s*USERNAME\s+') { continue }

        $norm = ($line -replace '\s+', ' ').Trim()
        if (-not $norm) { continue }

        $tok = $norm.Split(' ')[0]
        if (-not $tok) { continue }

        # active session marker
        $tok = $tok.TrimStart('>')

        # We only care about the console session typically
        if ($norm -match '\sconsole\s') {
            return $tok
        }
    }

    return $null
}

# ----------------------------
# Microsoft Update enable (best effort)
# ----------------------------
function Enable-MicrosoftUpdateOtherProducts {
    $muServiceId = "7971f918-a847-4430-9279-4a52d1efe18d"
    Write-Log "Ensuring Microsoft Update (Other Microsoft products) is enabled..."

    try {
        $sm = New-Object -ComObject "Microsoft.Update.ServiceManager"
        $sm.ClientApplicationID = "WU-AyaLoanerLoop"
        try { $null = $sm.AddService2($muServiceId, 7, $null) } catch {}
        Write-Log "Microsoft Update service ensured (ServiceID: $muServiceId)."
    } catch {
        Write-Log "Failed to ensure Microsoft Update service (continuing): $($_.Exception.Message)" "WARN"
    }

    try {
        $au = New-Object -ComObject "Microsoft.Update.AutoUpdate"
        $settings = $au.Settings

        $hasServiceId = $false
        if ($settings) {
            if ($settings.PSObject.Properties.Name -contains "ServiceID") { $hasServiceId = $true }
            elseif ($settings.PSObject.Methods.Name -contains "get_ServiceID") { $hasServiceId = $true }
        }

        if ($hasServiceId) {
            $settings.ServiceID = $muServiceId
            $settings.Save()
            Write-Log "Microsoft Update set as default Automatic Updates service."
        } else {
            Write-Log "AutoUpdate.Settings has no ServiceID on this OS; skipping default-service set (Searcher will still target MU)." "WARN"
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
# Scheduled Task registration (KEY FIX: run as INTERACTIVE group to avoid SID mapping failure)
# INTERACTIVE group SID is S-1-5-4. [3](https://www.briantist.com/errors/scheduled-task-powershell-0xfffd0000/)[1](https://stackoverflow.com/questions/58346274/register-scheduledtask-no-mapping-betwen-account-names-and-security-ids-was-do)
# ----------------------------
function Register-InteractiveLogonTask {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$WorkingDir,
        [Parameter(Mandatory)][int]$PollSeconds
    )

    $psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

    # Visible console window
    $innerArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Run -UserName `"$UserName`" -TaskName `"$TaskName`" -StagingDir `"$WorkingDir`" -PollSeconds $PollSeconds"
    $cmdArgs   = "/c start `"`" /D `"$WorkingDir`" `"$psExe`" $innerArgs"

    # Prefer ScheduledTasks module
    try {
        Import-Module ScheduledTasks -ErrorAction Stop

        # Principal: INTERACTIVE group (no username binding => no SID mapping at stage time)
        $principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-4" -RunLevel Highest

        # Trigger: any logon
        $trigger   = New-ScheduledTaskTrigger -AtLogOn

        $action    = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument $cmdArgs -WorkingDirectory $WorkingDir
        $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 12)

        try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

        Write-Log "Registered logon task via ScheduledTasks: $TaskName (Principal: INTERACTIVE S-1-5-4)"
        return
    } catch {
        Write-Log "ScheduledTasks registration failed, falling back to COM API. $($_.Exception.Message)" "WARN"
    }

    # COM fallback: Group principal
    $TASK_LOGON_GROUP      = 4
    $TASK_RUNLEVEL_HIGHEST = 1

    $svc = New-Object -ComObject "Schedule.Service"
    $svc.Connect()
    $folder = $svc.GetFolder("\")
    try { $folder.DeleteTask($TaskName, 0) } catch {}

    $task = $svc.NewTask(0)
    $task.RegistrationInfo.Description = "WU AyaLoaner interactive update loop"
    $task.Settings.Enabled = $true
    $task.Settings.StartWhenAvailable = $true
    $task.Settings.ExecutionTimeLimit = "PT12H"

    # Group principal (INTERACTIVE)
    $task.Principal.GroupId  = "S-1-5-4"
    $task.Principal.LogonType = $TASK_LOGON_GROUP
    $task.Principal.RunLevel  = $TASK_RUNLEVEL_HIGHEST

    # Trigger: logon (any user)
    $trigger = $task.Triggers.Create(9) # TASK_TRIGGER_LOGON
    # no UserId set => any logon

    # Action
    $act = $task.Actions.Create(0)
    $act.Path = "$env:SystemRoot\System32\cmd.exe"
    $act.Arguments = $cmdArgs
    $act.WorkingDirectory = $WorkingDir

    $folder.RegisterTaskDefinition($TaskName, $task, 6, $null, $null, $TASK_LOGON_GROUP, $null) | Out-Null
    Write-Log "Registered logon task via COM: $TaskName (Principal: INTERACTIVE S-1-5-4)"
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
# Windows Update COM loop
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

    return "$($u.Title)$kbPart Type=$type"
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

function Cleanup-KeepLogs {
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

    # Ensure WU service running
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
        # STAGE MODE (SetupComplete)
        Write-Log "STAGE MODE: staging script + registering INTERACTIVE logon task (no user binding)..."

        $src = $PSCommandPath
        if (-not $src) { $src = $MyInvocation.MyCommand.Path }
        if (-not $src -or -not (Test-Path $src)) { throw "Cannot resolve current script path for staging." }

        Copy-Item -Path $src -Destination $StagedScript -Force
        Write-Log "Staged script to: $StagedScript"

        Register-InteractiveLogonTask -TaskName $TaskName -ScriptPath $StagedScript -WorkingDir $StagingDir -PollSeconds $PollSeconds

        $state.StageComplete = $true
        $state.LastAction = "StagedAndTaskRegistered"
        Save-State $state

        Write-Log "Stage complete. Task will run at next interactive logon."
        exit 0
    }

    # RUN MODE (interactive)
    $current = Get-CurrentConsoleUser
    Write-Log "RUN MODE: started under console user: $current"

    # Gate: only proceed when AyaLoaner is the logged-on console user
    if (-not $current -or ($current -ine $UserName)) {
        Write-Log "Not running under $UserName console session; exiting. (This is expected until AyaLoaner logs on.)" "WARN"
        exit 0
    }

    Write-Log "Log file: $LogPath"
    Write-Log "Beginning update loop for user: $UserName"

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
                Cleanup-KeepLogs
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
    msg * "All done. The system is ready to deploy."
    try { $mutex.ReleaseMutex() } catch {}
}
