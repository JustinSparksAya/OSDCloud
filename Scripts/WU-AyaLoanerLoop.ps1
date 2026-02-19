#Requires -RunAsAdministrator
<#
.SYNOPSIS
  SetupComplete (SYSTEM) stages + registers an interactive logon task (runs as INTERACTIVE user).
  At AyaLoaner logon, runs Microsoft Update loop with visible progress (software + drivers).
  Reboots until fully done, then disables AutoAdminLogon, removes the task, and deletes staged script/state.
  Keeps logs in ProgramData.
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
        try {
            return (Get-Content $StatePath -Raw | ConvertFrom-Json)
        } catch {
            # CHANGED: log parse failure so you can see if the file is corrupt
            Write-Log "State file exists but could not be parsed. Resetting state. Error: $($_.Exception.Message)" "WARN"
        }
    }
    return [pscustomobject]@{
        StageComplete = $false
        PassCount     = 0
        LastAction    = ""
    }
}
	 
function Save-State($state) {
    # CHANGED: atomic write to avoid truncated JSON if reboot happens mid write
    try {
        $tmp = "$StatePath.tmp"
        $json = ($state | ConvertTo-Json -Depth 6)
        Set-Content -Path $tmp -Value $json -Encoding UTF8 -Force
        Move-Item -Path $tmp -Destination $StatePath -Force
    } catch {
        Write-Log "Failed to save state (continuing): $($_.Exception.Message)" "WARN"
    }
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

function Get-SanitizedSerialNumber {
    try {
        $sn = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).SerialNumber
        $sn = [string]$sn
        if ([string]::IsNullOrWhiteSpace($sn)) { throw "SerialNumber was blank." }
        # Keep only letters and digits to avoid invalid computer name chars
        $sn = ($sn.ToUpper() -replace '[^A-Z0-9]', '')
        if ([string]::IsNullOrWhiteSpace($sn)) { throw "SerialNumber became blank after sanitization." }
        return $sn
    } catch {
        throw "Failed to read serial number from Win32_BIOS: $($_.Exception.Message)"
    }
}
function Get-DesiredComputerName {
    # Requirement: FFD-<serial>, truncated to 12 chars max total, no reboot
    $prefix = 'WFD-'
    $maxLen = 12
    $serial = Get-SanitizedSerialNumber
    $serialMax = $maxLen - $prefix.Length
    if ($serialMax -lt 1) { throw "Invalid name constraints: prefix length exceeds max length." }

    $serialPart = if ($serial.Length -gt $serialMax) { $serial.Substring(0, $serialMax) } else { $serial }
    $name = ($prefix + $serialPart)

    # Final safety: enforce max length and valid chars
    $name = ($name.ToUpper() -replace '[^A-Z0-9\-]', '')
    if ($name.Length -gt $maxLen) { $name = $name.Substring(0, $maxLen) }
    if ([string]::IsNullOrWhiteSpace($name)) { throw "Desired computer name computed as blank." }

    return $name
}
function Ensure-ComputerNameNoReboot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DesiredName
    )

    $current = [string]$env:COMPUTERNAME
    $DesiredName = $DesiredName.ToUpper()

    if ($current.ToUpper() -eq $DesiredName) {
        Write-Log "Computer name already set to '$DesiredName'. No rename needed."
        $script:EffectiveComputerName = $DesiredName
        return
    }

    Write-Log "Renaming computer from '$current' to '$DesiredName' (no reboot requested)."
    try {
        Rename-Computer -NewName $DesiredName -Force -ErrorAction Stop | Out-Null
        # Rename-Computer without -Restart will not reboot; name takes effect after the next reboot.
        $script:EffectiveComputerName = $DesiredName
        Write-Log "Rename-Computer succeeded. Effective name for this run will be treated as '$DesiredName'."
    } catch {
        throw "Rename-Computer failed: $($_.Exception.Message)"
    }
}

function Install-TeamViewerHost {
    if (-not (Test-Path "C:\Program Files\TeamViewer\TeamViewer.exe")) {
        Write-Log "Installing Teamviewer Host from Winget..."
        $TVcmd="install Teamviewer.Teamviewer.Host -s winget --accept-source-agreements --accept-package-agreements -h"
        $TVProc= Start-Process winget -ArgumentList $TVcmd -NoNewWindow -PassThru -Wait
        Write-Log "TeamViewer Host Winget install complete (exit code $($TVProc.ExitCode))."
    }else {
        Write-Log "TeamViewer Host is already installed."
    }
    Return
}

function Invoke-TeamViewerAssignment {
    # Embedded and hardened version of TeamViewerHostFFUPosttInstallScript.ps1
    $TeamViewerExe = Join-Path $env:ProgramFiles 'TeamViewer\TeamViewer.exe'
    if (-not (Test-Path -LiteralPath $TeamViewerExe)) {
        throw "TeamViewer.exe not found at expected path: $TeamViewerExe"
    }

    $managementId = $null
    $regPath = 'HKLM:\SOFTWARE\TeamViewer\DeviceManagementV2'
    $tvAlias = "AyaLoaner ($env:COMPUTERNAME)"
    $assignmentName = "Aya -MDM (Default)"
    $assignmentID = '0001CoABChAX-lbQxD8R7qytiEFOIK1KEigIACAAAgAJABSqiBRKbHQ-wRU1F9pGHO7J1VR52ckJ_WIsx5FWjJ_PGkAa3kkthbKy5IqjzSa1nhuP9KU2iJgHsqJxUnPwHHi-nkosOzxCctuqarDVSqwUCTUcwMbc-_8PW1838rMciJMXIAEQsO-OjAs='
    
    if (Test-Path -LiteralPath $regPath) {
        try {
            $managementId = (Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue).'ManagementId'
        } catch {
            # Keep null, continue retrying
            $managementId = $null
        }
    } 

    if ($managementId) {
        $registrationSucceeded = $true
        Write-Log "TeamViewer registration confirmed. ManagementId present. [$tvAlias][$assignmentName]"
        Return
    } else {
        # Use the effective computer name at runtime (post-rename, post-reboot).
        Write-Log "Waiting 15 seconds for TeamViewer to initialize"
        Start-Sleep -Seconds 15
        $registrationSucceeded = $false

        for ($iCount = 1; $iCount -le 10; $iCount++) {
            $managementId = $null

            $regPath = 'HKLM:\SOFTWARE\TeamViewer\DeviceManagementV2'
            if (Test-Path -LiteralPath $regPath) {
                try {
                    $managementId = (Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue).'ManagementId'
                } catch {
                    # Keep null, continue retrying
                    $managementId = $null
                }
            } else {
                # Do NOT throw. It may not exist yet while TV is still initializing.
                Write-Log "[$iCount] TeamViewer management key not present yet: [$regPath]. Will retry."
            }

            if ($managementId) {
                $registrationSucceeded = $true
                Write-Log "[$iCount] TeamViewer registration confirmed. ManagementId present. [$tvAlias][$assignmentName]"
                break
            }

            if ($iCount -ge 10) {
                throw "TeamViewer registration aborted after $iCount attempts. ManagementId never appeared. [$tvAlias][$assignmentName]"
            }

            Write-Log "[$iCount] Attempting TeamViewer assignment. [$tvAlias][$assignmentName]"
            try {
                if (-not (Get-Process -Name 'teamviewer' -ErrorAction SilentlyContinue)) {
                    Start-Process -FilePath $TeamViewerExe | Out-Null
                    Start-Sleep -Seconds 5
                }

                $p = Start-Process -FilePath $TeamViewerExe -ArgumentList "assignment --id $assignmentID --device-alias=`"$tvAlias`" --retries=5 --timeout=120" -Wait -PassThru
                Write-Log "[$iCount] Attempted TeamViewer assignment finished. ExitCode=$($p.ExitCode). [$tvAlias][$assignmentName]"
            } catch {
                Write-Log "[$iCount] Attempted TeamViewer assignment failed: $($_.Exception.Message)"
            }

            Write-Log "[$iCount] Checking registration in 30 seconds."
            Start-Sleep -Seconds 30
        }

        if (-not $registrationSucceeded) {
            throw "Failed to register TeamViewer after retries. [$tvAlias][$assignmentName]"
        }
    }
}




# ----------------------------
# MAIN
# ----------------------------
$mutex = Acquire-Mutex
try {
    $state = Load-State

    # CHANGED: show current state at start (helps confirm PassCount is persisting)
    Write-Log ("Loaded state: StageComplete={0}, PassCount={1}, LastAction={2}" -f $state.StageComplete, $state.PassCount, $state.LastAction)

    # Install TVHost only after the renamed computer name is actually in effect.
    # The first boot may request a rename without rebooting, so the effective name
    # might still be the original name in this same session.
    if ($env:COMPUTERNAME -notmatch '^WFD-') {
        msg * "Finishing up the final deployment steps. Please wait..." /time:9999999
        Write-Log "TVHost Installation deferred: effective computer name '$($env:COMPUTERNAME)' does not start with 'WFD-'."
        # Ensure the computer is named FFD-<serial> (12 chars max). No reboot is performed here.
        $desiredName = Get-DesiredComputerName
        Ensure-ComputerNameNoReboot -DesiredName $desiredName
    } else {
        Install-TeamViewerHost
        Invoke-TeamViewerAssignment
    }    

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

	# CHANGED: initialize pass from persisted state
    $pass = 0
    try { $pass = [int]$state.PassCount } catch { $pass = 0 }

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

        if ($total -eq 0 -or $pass -ge 6 ) {
            if (-not (Test-PendingReboot)) {
                Write-Log "No updates remain AND no reboot required. FINISH."
                msg * "All done. The system is ready to deploy." /time:9999999
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
    try { $mutex.ReleaseMutex() } catch {}
}



