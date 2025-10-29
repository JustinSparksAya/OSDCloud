$ts = "X:\OSDCloud\Logs\Transcript_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date)
Start-Transcript -Path $ts -Force

# --- Aya OSDCloud Wrapper using latest release assets ---
Write-Host "Aya OSDCloud start"

###############################
## Start Date Time Sync Section
##vvvvvvvvvvvvvvvvvvvvvvvvvvvvv

# WinPE: NTP -> Pacific time (DST aware) with debug, no prompts

$S='pool.ntp.org'
$B=New-Object byte[] 48; $B[0]=0x1B
$U=New-Object System.Net.Sockets.UdpClient
$U.Client.ReceiveTimeout=3000
$U.Connect($S,123) | Out-Null
[void]$U.Send($B,$B.Length)
$EP=New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,0)
$R=$U.Receive([ref]$EP); $U.Close()

Write-Host "---- DEBUG: NTP packet ----"
Write-Host ("Bytes 40..47: " + [BitConverter]::ToString($R[40..47]))

# Parse big endian seconds.fraction
$sec = (([uint32]$R[40] -shl 24) -bor ([uint32]$R[41] -shl 16) -bor ([uint32]$R[42] -shl 8) -bor [uint32]$R[43])
$f   = (([uint32]$R[44] -shl 24) -bor ([uint32]$R[45] -shl 16) -bor ([uint32]$R[46] -shl 8) -bor [uint32]$R[47])

# Derive UTC via Unix epoch to avoid WinPE 1900-epoch skew
$ntpToUnixOffset = 2208988800
$unixSec = [int64]$sec - $ntpToUnixOffset
$utc = ([DateTimeOffset]::FromUnixTimeSeconds($unixSec)).UtcDateTime
$utc = $utc.AddMilliseconds([math]::Round(($f / [math]::Pow(2,32)) * 1000))

Write-Host ("UTC computed:    {0:yyyy-MM-dd HH:mm:ss.fff}Z" -f $utc)

Write-Host "---- DEBUG: System clock before ----"
$before = Get-Date
Write-Host ("System now:      {0:yyyy-MM-dd HH:mm:ss.fff} (Kind={1})" -f $before, $before.Kind)
try {
    $tz = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' -ErrorAction Stop
    Write-Host ("Registry Bias:   Bias={0} ActiveTimeBias={1} minutes" -f $tz.Bias, $tz.ActiveTimeBias)
} catch { Write-Host "No TimeZoneInformation registry values" }

# Pacific DST boundaries in UTC
$y = $utc.Year
$dMar = New-Object datetime ($y,3,1,0,0,0,[System.DateTimeKind]::Utc)
$deltaMar = (7 + [int][DayOfWeek]::Sunday - [int]$dMar.DayOfWeek) % 7
$secondSunMar = $dMar.AddDays($deltaMar + 7)

$dNov = New-Object datetime ($y,11,1,0,0,0,[System.DateTimeKind]::Utc)
$deltaNov = (7 + [int][DayOfWeek]::Sunday - [int]$dNov.DayOfWeek) % 7
$firstSunNov = $dNov.AddDays($deltaNov)

$dstStartUtc = New-Object datetime ($secondSunMar.Year,$secondSunMar.Month,$secondSunMar.Day,10,0,0,[System.DateTimeKind]::Utc) # 02:00 local while -8
$dstEndUtc   = New-Object datetime ($firstSunNov.Year,  $firstSunNov.Month,  $firstSunNov.Day,  9,0,0,[System.DateTimeKind]::Utc)  # 02:00 local while -7

if(($utc -ge $dstStartUtc) -and ($utc -lt $dstEndUtc)) { $offsetHours = -7 } else { $offsetHours = -8 }

$pacific = $utc.AddHours($offsetHours)

Write-Host "---- DEBUG: Target ----"
Write-Host ("DST window:      {0:yyyy-MM-dd HH:mm}Z -> {1:yyyy-MM-dd HH:mm}Z" -f $dstStartUtc, $dstEndUtc)
Write-Host ("Offset hours:    {0}" -f $offsetHours)
Write-Host ("Setting clock:   {0:yyyy-MM-dd HH:mm:ss}" -f $pacific)

Set-Date $pacific | Out-Null

Write-Host "---- DEBUG: System clock after ----"
$after = Get-Date
Write-Host ("System now:      {0:yyyy-MM-dd HH:mm:ss.fff}" -f $after)

##^^^^^^^^^^^^^^^^^^^^^^^^^^^
## End Date Time Sync Section
#############################


# 1. Load OSDCloud in WinPE
Invoke-Expression (Invoke-RestMethod 'https://sandbox.osdcloud.com')

# 2. Optional defaults
$ProgressPreference = 'SilentlyContinue'

# 3. Apply OS
Start-OSDCloud -OSBuild "25H2" -OSEdition "Pro" -OSLanguage "en-us" -OSLicense "Retail" -SkipAutopilot -ZTI

# 4. Locate applied Windows and prep folders
function Find-WindowsDrive {
  $d = $null
  try { $d = Get-OSDCloudOSDrive -ErrorAction SilentlyContinue } catch {}
  if ($d -and (Test-Path ($d + "\Windows"))) { return $d }
  foreach ($l in 'C','D','E','F','G','H') {
    if (Test-Path "$l`:\Windows\System32") { return "$($l):" }
  }
  return $null
}

$deadline = (Get-Date).AddSeconds(30)
do {
  $osDrive = Find-WindowsDrive
  if ($osDrive) { break }
  Start-Sleep 2
} while ((Get-Date) -lt $deadline)

if (-not $osDrive) { throw "Couldn't locate the applied Windows drive." }

$windows  = Join-Path $osDrive "Windows"
$panther  = Join-Path $windows "Panther"
$tempDir  = Join-Path $windows "Temp"
$setupDir = Join-Path $windows "Setup\Scripts"
New-Item -ItemType Directory -Path $panther,$tempDir,$setupDir -Force | Out-Null

# 5. Helper to download with retry
function Invoke-Download {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [int]$Retries = 3,
        [int]$DelaySec = 5
    )
    for ($i = 1; $i -le $Retries; $i++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
            if ((Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 0)) {
                return
            } else {
                throw "Empty or missing file after download"
            }
        } catch {
            if ($i -lt $Retries) {
                Write-Host "Download failed. Retry $i of $Retries in $DelaySec sec"
                Start-Sleep -Seconds $DelaySec
            } else {
                throw "Failed to download $Uri after $Retries attempts"
            }
        }
    }
}

# 6. Inject Unattend from main branch
Invoke-Download -Uri "https://raw.githubusercontent.com/JustinSparksAya/OSDCloud/main/Unattend/Unattend.xml" `
    -OutFile (Join-Path $panther "Unattend.xml")

# 7. Download and stage hardware tools by manufacturer
$relBase = "https://github.com/JustinSparksAya/OSDCloud/releases/latest/download"

# Detect manufacturer (fallback safe)
$manufacturer = ""
try {
    $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).Manufacturer
} catch { $manufacturer = "" }

$sys32 = Join-Path $windows "System32"

if ($manufacturer -match 'Lenovo') {
    Write-Host "Manufacturer detected: Lenovo — using LenovoDiagnostics.zip"
    $zipName    = "LenovoDiagnostics.zip"
    $extractDir = Join-Path $tempDir "LD"
} else {
    Write-Host "Manufacturer '$manufacturer' not Lenovo — using PassMark-BurnInTest.zip"
    $zipName    = "PassMark-BurnInTest.zip"
    $extractDir = Join-Path $tempDir "HD"
}

$zipPath = Join-Path $tempDir $zipName

# Download selected zip
Invoke-Download -Uri "$relBase/$zipName" -OutFile $zipPath

# Extract to target folder (.\LD or .\HD under Windows\Temp)
if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force

# Copy HD.cmd and RA.cmd to System32 if they exist in the extracted folder
foreach ($cmd in 'HD.cmd','RA.cmd') {
    $found = Get-ChildItem -Path $extractDir -Filter $cmd -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        Copy-Item $found.FullName (Join-Path $sys32 $cmd) -Force
        Write-Host "Copied $cmd to $sys32"
    } else {
        Write-Host "Notice: $cmd not found under $extractDir"
    }
}


# 8. Stage activation script
Invoke-Download -Uri "https://raw.githubusercontent.com/JustinSparksAya/OSDCloud/main/Scripts/Activate-WindowsUsignOEMProductKey.ps1" `
    -OutFile (Join-Path $tempDir "Activate-WindowsUsignOEMProductKey.ps1")

# 9. SetupComplete
$setupComplete = @"
@echo off
powershell.exe -ExecutionPolicy Bypass -File "%SystemRoot%\Temp\Activate-WindowsUsignOEMProductKey.ps1"
exit /b 0
"@
$setupComplete | Out-File -FilePath (Join-Path $setupDir "SetupComplete.cmd") -Encoding ascii -Force

Stop-Transcript
Read-Host "Press Enter to reboot"
Write-Host "Staging complete. Rebooting"
Restart-Computer
