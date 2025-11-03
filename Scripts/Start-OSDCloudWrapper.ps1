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

#########################
## Remove Device From Aya
##vvvvvvvvvvvvvvvvvvvvvvv

Write-Host "##############################"
Write-Host "###Removing Device from Aya###"
Write-Host "##############################"

# Import the certificate


Write-Host "Importing Certificate"
$CertPath = 'Z:\Scripts\OSDCloud_Certificate\osdcloud-20251103.pfx'
$cert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath,"CertPassword")
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store.Add($cert)
$store.Close()



# --- Set variables ---

$clientId = "0df5ca16-daf3-40bc-9b44-567253b54baa"
$clientThumbprint = "2C9B6CD1B27D959851505E53CCB05B7105796FB8"
$tenantId = "c32ce235-4d9a-4296-a647-a9edb2912ac9"


# Get the certificate from the certificate store
$cert = Get-Item Cert:\LocalMachine\Root\$clientThumbprint

# Create JWT header
$JWTHeader = @{
    alg = "RS256"
    typ = "JWT"
    x5t = [System.Convert]::ToBase64String($cert.GetCertHash())
}
# Create JWT payload
$JWTPayload = @{
    aud = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    iss = $clientId
    sub = $clientId
    jti = [System.Guid]::NewGuid().ToString()
    nbf = [math]::Round((Get-Date).ToUniversalTime().Subtract((Get-Date "1970-01-01T00:00:00Z").ToUniversalTime()).TotalSeconds)
    exp = [math]::Round((Get-Date).ToUniversalTime().AddMinutes(10).Subtract((Get-Date "1970-01-01T00:00:00Z").ToUniversalTime()).TotalSeconds)
}

# Encode JWT header and payload
$JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json -Compress))
$EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte) -replace '\+', '-' -replace '/', '_' -replace '='

$JWTPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json -Compress))
$EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte) -replace '\+', '-' -replace '/', '_' -replace '='

# Join header and Payload with "." to create a valid (unsigned) JWT
$JWT = $EncodedHeader + "." + $EncodedPayload

# Get the private key object of your certificate
$PrivateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert))

# Define RSA signature and hashing algorithm
$RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
$HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

# Create a signature of the JWT
$Signature = [Convert]::ToBase64String(
    $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT), $HashAlgorithm, $RSAPadding)
) -replace '\+', '-' -replace '/', '_' -replace '='

# Join the signature to the JWT with "."
$JWT = $JWT + "." + $Signature


# --- Get Serial Number ---
try {
    $serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber.Trim()
    Write-Host "Serial Number: $serialNumber"
} catch {
    Write-Host "Failed to get serial number"
    try { $null = Stop-Transcript -ErrorAction Stop | Out-Null } catch {}
    exit 1
}

# --- Get Auth Token ---
$body = @{
    grant_type    = "client_credentials"
    scope         = "https://graph.microsoft.com/.default"
    client_id     = $clientId
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_assertion = $JWT
}

Write-Host "Getting Authentication Token"

try {
    $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body
    $token = $tokenResponse.access_token
} catch {
    Write-Host "Failed to get token"
    exit 1
}

# --- Initialize ---
$azureADDeviceIds = [System.Collections.Generic.HashSet[string]]::new()

Write-Host "Removing Device from InTune..."
# --- Intune Lookup ---
$intuneUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=serialNumber eq '$serialNumber'"
try {
    $intuneResponse = Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri $intuneUri -Method Get
    if ($intuneResponse.value.Count -gt 0) {
        $deviceId = $intuneResponse.value[0].id
        $azureADDeviceId_Intune = $intuneResponse.value[0].azureADDeviceId
        if (![string]::IsNullOrWhiteSpace($azureADDeviceId_Intune)) {
            $azureADDeviceIds.Add($azureADDeviceId_Intune) | Out-Null
        }

        # Delete from Intune
        $deleteIntuneUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId"
        try {
            Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri $deleteIntuneUri -Method Delete
            Write-Host "Device $serialNumber deleted from Intune."
        } catch {
            Write-Host "Failed to delete device from Intune."
        }
    } else {
        Write-Host "No device found in Intune. Continuing with Autopilot and Entra checks."
    }
} catch {
    Write-Host "Error querying device from Intune. Continuing."
}

Write-Host "Removing Device from Autopilot..."
# --- Autopilot Lookup ---
$apUri = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$serialNumber')"
try {
    $apResponse = Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri $apUri -Method Get
    if ($apResponse.value.Count -gt 0) {
        $apId = $apResponse.value[0].id
        $azureADDeviceId_Autopilot = $apResponse.value[0].azureActiveDirectoryDeviceId
        if (![string]::IsNullOrWhiteSpace($azureADDeviceId_Autopilot)) {
            $azureADDeviceIds.Add($azureADDeviceId_Autopilot) | Out-Null
        }

        # Delete Autopilot registration
        $apDeleteUri = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$apId"
        try {
            Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri $apDeleteUri -Method Delete
            Write-Host "Autopilot registration deleted for device $serialNumber."
        } catch {
            Write-Host "Failed to delete Autopilot record. Skipping Entra deletion."
            exit 1
        }

        # Wait for deletion
        $maxWait = 60
        $elapsed = 0
        $interval = 5
        while ($elapsed -lt $maxWait) {
            Start-Sleep -Seconds $interval
            $elapsed += $interval
            try {
                $check = Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri $apUri -Method Get
                if ($check.value.Count -eq 0) {
                    Write-Host "Autopilot record fully removed."
                    break
                }
                Write-Host "Waiting for Autopilot record to clear..."
            } catch {
                Write-Host "Error checking Autopilot status."
            }
        }
    } else {
        Write-Host "No Autopilot registration found."
    }
} catch {
    Write-Host "Error querying Autopilot records."
}

Write-Host "Removing Device from EntraID..."
# --- Entra Cleanup for All Unique Device IDs ---
foreach ($azureDeviceId in $azureADDeviceIds) {
    $entraLookupUri = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$azureDeviceId'"
    try {
        $aadResponse = Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri $entraLookupUri -Method Get
        if ($aadResponse.value.Count -gt 0) {
            $objectId = $aadResponse.value[0].id
            $aadDeleteUri = "https://graph.microsoft.com/v1.0/devices/$objectId"
            try {
                Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri $aadDeleteUri -Method Delete
                Write-Host "Device with Azure ID $azureDeviceId deleted from Entra ID."
            } catch {
                Write-Host "Failed to delete device $azureDeviceId from Entra ID."
            }
        } else {
            Write-Host "No matching Entra device found for Azure ID $azureDeviceId."
        }
    } catch {
        Write-Host "Error querying Entra for Azure ID $azureDeviceId."
    }
}

if ($azureADDeviceIds.Count -eq 0) {
    Write-Host "No Azure AD Device IDs found in Intune or Autopilot."
}


##^^^^^^^^^^^^^^^^^^^^^^^
## Remove Device From Aya
#########################

Write-Host "###############################"
Write-Host "###Starting OSDCloud Process###"
Write-Host "###############################"


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


Write-Host "#######################################"
Write-Host "###Seeding Hardware Diagnostic tools###"
Write-Host "#######################################"

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

Write-Host "###############################"
Write-Host "###Staging Activation Script###"
Write-Host "###############################"


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
Write-Host "#########################"
Write-Host "###Deployment Finished###"
Write-Host "#########################"

Read-Host "Press Enter to reboot"
Write-Host "Staging complete. Rebooting"
Restart-Computer
