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

function ConvertTo-NinjaOneSafeFlowText {
    # Mirrors InstallNinjaOne.ps1 so the Power Automate flow receives the same shape of text.
    param([string]$Text)

    if ($null -eq $Text) { return '' }

    $safe = [string]$Text
    $safe = $safe -replace '[\r\n]+', ' '
    $safe = $safe -replace '\\', '/'
    $safe = $safe -replace '"', "'"
    return $safe.Trim()
}

function Get-NinjaOneLoanerSystemInfo {
    # Payload fields must match InstallNinjaOne.ps1 exactly or the flow will not bind them.
    # Location is always 'SD' for loaners, so it is set statically here rather than doing the
    # ipinfo geo lookup InstallNinjaOne.ps1 performs, which can block this loop for minutes.
    $deviceName = [string]$env:COMPUTERNAME

    $consoleUser = $null
    try { $consoleUser = Get-CurrentConsoleUser } catch {}

    if (-not $consoleUser) {
        try { $consoleUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName } catch {}
    }

    if ([string]::IsNullOrWhiteSpace($consoleUser)) {
        $consoleUser = 'Unknown'
    } elseif ($consoleUser -match '\\') {
        $consoleUser = ($consoleUser -split '\\')[-1]
    }

    return [pscustomobject]@{
        DeviceName  = $deviceName
        ConsoleUser = [string]$consoleUser
        Location    = 'SD'
        TimeStamp   = [string](Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
}

function Send-NinjaOneTeamsNotification {
    # Same Power Automate trigger used by InstallNinjaOne.ps1 (Intune NinjaOneAgent-Global).
    param(
        [ValidateSet('SUCCESS','FAILED')]
        [string]$Status,

        [psobject]$SystemInfo,

        [string]$Detail
    )

    $uri = 'https://defaultc32ce2354d9a4296a647a9edb2912a.c9.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/4e46df972c7640129718a5cb9337bf0e/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=b2aaurbKkWS2SYgkqQ4x4v6mE40cy9Vj-o9AdrIxvFs'

    if (-not $SystemInfo) { $SystemInfo = Get-NinjaOneLoanerSystemInfo }

    # InstallNinjaOne.ps1 appends the failure reason onto TimeStamp because the flow has no
    # dedicated detail field. Matching that behaviour keeps one card layout for both scripts.
    $timeStamp = [string]$SystemInfo.TimeStamp
    if ($Detail) { $timeStamp = "$timeStamp $Detail" }

    $bodyObject = [ordered]@{
        deviceName  = ConvertTo-NinjaOneSafeFlowText $SystemInfo.DeviceName
        consoleUser = ConvertTo-NinjaOneSafeFlowText $SystemInfo.ConsoleUser
        location    = ConvertTo-NinjaOneSafeFlowText $SystemInfo.Location
        status      = ConvertTo-NinjaOneSafeFlowText $Status
        timestamp   = ConvertTo-NinjaOneSafeFlowText $timeStamp
    }

    $json = $bodyObject | ConvertTo-Json -Compress
    Write-Log "Sending NinjaOne Teams payload: $json"

    Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body $json -TimeoutSec 60 -ErrorAction Stop | Out-Null
    Write-Log "NinjaOne Teams notification sent. [$Status]"
}

function Send-NinjaOneTeamsNotificationSafe {
    # A card that fails to post must never break or fail the deployment.
    param(
        [ValidateSet('SUCCESS','FAILED')]
        [string]$Status,

        [string]$Detail
    )

    try {
        $info = Get-NinjaOneLoanerSystemInfo
        Send-NinjaOneTeamsNotification -Status $Status -SystemInfo $info -Detail $Detail
    } catch {
        Write-Log "NinjaOne $Status Teams notification failed: $($_.Exception.Message)" "WARN"
    }
}

function Get-NinjaOneNodeId {
    # NinjaOne writes NodeId under the agent key only after the agent has checked in
    # and enrolled against the division. Its presence is the enrollment signal, which is
    # stronger than an install check: the MSI can land successfully and still never enroll.
    # Both hives are checked because the x86 MSI lands under WOW6432Node while the
    # x86-64 MSI may land in the native hive.
    $agentKeys = @(
        'HKLM:\SOFTWARE\NinjaRMM LLC\NinjaRMMAgent\Agent',
        'HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent\Agent'
    )

    foreach ($key in $agentKeys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }

        $nodeId = $null
        try { $nodeId = (Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue).'NodeId' } catch {}

        # Absent, empty, or 0 all mean "not enrolled yet".
        if ($null -eq $nodeId) { continue }
        $nodeIdText = ([string]$nodeId).Trim()
        if (-not $nodeIdText -or $nodeIdText -eq '0') { continue }

        return [pscustomobject]@{
            NodeId  = $nodeIdText
            RegPath = $key
        }
    }

    return $null
}

function Install-NinjaOneAgent {
    # Org/location/role are baked into this installer, so no command-line arguments
    # are needed and no separate assignment step is required.
    # NOTE: the agent version is part of the URL path. NinjaOne rotates these links on
    # agent upgrades, so a 404 here means the link needs to be regenerated in the console
    # (Add > Device > Windows > Generate Installer > Copy link).
    $installerUrl = 'https://us2.ninjarmm.com/agent/installer/61a0e9d4-9a7a-4880-be61-618d3b0584e6/14.0.8848/NinjaOne-Agent-AyaHealthcareUnmanaged-MainOffice-Auto-x86-64.msi'

    $existing = Get-NinjaOneNodeId
    if ($existing) {
        Write-Log "NinjaOne agent is already enrolled. [NodeId=$($existing.NodeId)][$($existing.RegPath)]"
        return
    }

    $msiPath = Join-Path $StagingDir 'NinjaOne-Agent.msi'
    $msiLog  = Join-Path $StagingDir 'NinjaOne-Agent.msi.log'

    # Download with retries. Transient network failures are common this early after OOBE.
    $downloaded = $false
    for ($iCount = 1; $iCount -le 5; $iCount++) {
        try {
            Write-Log "[$iCount] Downloading NinjaOne agent MSI."
            $prevProgress = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $installerUrl -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
            } finally {
                $ProgressPreference = $prevProgress
            }

            $size = (Get-Item -LiteralPath $msiPath).Length
            if ($size -lt 1MB) { throw "Downloaded file is only $size bytes. Expected an MSI." }

            $downloaded = $true
            Write-Log "[$iCount] NinjaOne agent MSI downloaded. Size=$([math]::Round($size/1MB,2)) MB."
            break
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch {}
            $statusText = if ($status) { " HTTP=$status" } else { "" }
            Write-Log "[$iCount] NinjaOne agent MSI download failed.$statusText $($_.Exception.Message)" "WARN"
            if ($status -eq 404) {
                throw "NinjaOne installer URL returned 404. The versioned link has expired and must be regenerated in the NinjaOne console."
            }
            Start-Sleep -Seconds 20
        }
    }

    if (-not $downloaded) {
        throw "Failed to download the NinjaOne agent MSI after 5 attempts."
    }

    Write-Log "Installing NinjaOne agent via msiexec."
    $msiArgs = @('/i', "`"$msiPath`"", '/qn', '/norestart', '/l*v', "`"$msiLog`"")
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
    $exit = $proc.ExitCode

    # 0 = success, 3010 = success but a reboot is pending. The WU loop reboots anyway.
    if ($exit -ne 0 -and $exit -ne 3010) {
        throw "NinjaOne agent install failed. msiexec exit code $exit. See $msiLog."
    }
    Write-Log "NinjaOne agent msiexec completed. ExitCode=$exit."

    # Wait for enrolment rather than trusting the msiexec exit code. NodeId is written only
    # after the agent has successfully checked in, so this also proves outbound connectivity.
    $enrolled = $null
    for ($iCount = 1; $iCount -le 20; $iCount++) {
        $enrolled = Get-NinjaOneNodeId
        if ($enrolled) {
            Write-Log "NinjaOne enrolment confirmed. [NodeId=$($enrolled.NodeId)][$($enrolled.RegPath)]"
            break
        }
        Write-Log "[$iCount] NinjaOne NodeId not present yet. Rechecking in 15 seconds."
        Start-Sleep -Seconds 15
    }

    if (-not $enrolled) {
        throw "NinjaOne agent installed (msiexec exit code $exit) but NodeId never appeared after 5 minutes. See $msiLog."
    }

    try { Remove-Item -LiteralPath $msiPath -Force -ErrorAction Stop } catch {}

    Send-NinjaOneTeamsNotificationSafe -Status SUCCESS
}

function Install-GoogleChromeEnterprise {
    [CmdletBinding()]
    param()

    $Url     = 'https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi'
    $MsiPath = Join-Path $env:TEMP 'GoogleChromeStandaloneEnterprise64.msi'

    Write-Log "Starting Google Chrome Enterprise installation."

    # Check if Chrome is already installed
	$chrome = $null
	$uninstallPaths = @(
	    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
	    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
	)
	
	foreach ($path in $uninstallPaths) {
	    $chrome = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
	        Where-Object {
	            $p = $_.PSObject.Properties['DisplayName']
	            $p -and $p.Value -eq 'Google Chrome'
	        } |
	        Select-Object -First 1
	
	    if ($chrome) { break }
	}

    if ($chrome -and $chrome.DisplayVersion) {
        Write-Log "Google Chrome is already installed. Version: $($chrome.DisplayVersion). Skipping install."
        return
    }

    # Disable progress bar for faster download
    $PreviousProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    try {
        Write-Log "Chrome not detected. Downloading MSI from $Url to $MsiPath"
        Invoke-WebRequest -Uri $Url -OutFile $MsiPath

        Write-Log "Download completed. Starting silent installation."
        $proc = Start-Process -FilePath "msiexec.exe" `
            -ArgumentList "/i `"$MsiPath`" /qn /norestart" `
            -Wait -PassThru

        Write-Log "msiexec exited with code: $($proc.ExitCode)"
        if ($proc.ExitCode -eq 0) {
            Write-Log "Google Chrome Enterprise installation completed successfully."
        } else {
            Write-Log "Google Chrome Enterprise installation failed. Exit code: $($proc.ExitCode)"
        }
    }
    finally {
        # Restore original progress preference
        $ProgressPreference = $PreviousProgressPreference
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

    # Install the NinjaOne agent only after the renamed computer name is actually in effect,
    # so the device enrols under its final name.
    # The first boot may request a rename without rebooting, so the effective name
    # might still be the original name in this same session.
    if ($env:COMPUTERNAME -notmatch '^WFD-') {
        msg * /TIME:9999999 "Finishing up the final deployment steps. Please wait..."
        Write-Log "NinjaOne agent installation deferred: effective computer name '$($env:COMPUTERNAME)' does not start with 'WFD-'."
        # Ensure the computer is named FFD-<serial> (12 chars max). No reboot is performed here.
        $desiredName = Get-DesiredComputerName
        Ensure-ComputerNameNoReboot -DesiredName $desiredName
    } else {
        Write-Log "Installing NinjaOne agent..."
        try {
            Install-NinjaOneAgent
        } catch {
            Send-NinjaOneTeamsNotificationSafe -Status FAILED -Detail $_.Exception.Message
            throw
        }
        Install-GoogleChromeEnterprise
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
                msg * /TIME:9999999 "All done. The system is ready to deploy."
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








