$ts = "X:\OSDCloud\Logs\OSDCloud_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)
Start-Transcript -Path $ts -Force

# --- Aya OSDCloud Wrapper using latest release assets ---
Write-Host "Aya OSDCloud start"

$WorkbenchSubnet = '10.40.222.*'

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

###################################################################
## If on campuse's imaging workbench Campus, Remove Device From Aya
##vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

$onSubnet = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" |
    ForEach-Object { $_.IPAddress } |
    Where-Object { $_ -match $WorkbenchSubnet }

If ($onSubnet) {
    Write-Host "`r`n##############################" -ForegroundColor Cyan
    Write-Host "###Removing Device from Aya###" -ForegroundColor Cyan
    Write-Host "##############################" -ForegroundColor Cyan

    #Connecting to Network share
    $User  = 'SysMDT'
    $Share = '\\corp-wds-02\DeploymentShare2'
    $Drive = 'Z:'
    $Enc   = '76492d1116743f0423413b16050a5345MgB8AG4AQgBqAFAAYQBDAGoANwBwAG8AMgA2AGEAMQA4AE0AUABBAEkAaABDAEEAPQA9AHwAMAA2ADkANQAyAGYAMQBjADgANQBiADQAOQAzADMAYwA0AGQAMQBkAGUAMABkAGEAZAAxADIANgBhADEANQBhADMANQAxAGIAZQAwAGQAMQBjADcANAA5ADIAYwA3ADEANgAxAGUANQBlAGQANwBhAGEAMQA3AGUAZQAzADIAZgA='
    [byte[]]$Key = @(17,208,162,81,196,107,230,240,247,48,225,30,25,178,96,8,134,161,94,80,51,221,61,197,76,180,28,105,205,232,241,148)
    # ======================

    # Recreate the SecureString in memory
    $Sec = ConvertTo-SecureString -String $Enc -Key $Key

    # Extract a plain string for the native tool call
    $BSTR  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Sec)
    $Plain = [Runtime.InteropServices.Marshal]::PtrToStringUni($BSTR)

    # Map with net use
    $rc = Start-Process -FilePath net.exe `
        -ArgumentList @('use', $Drive, $Share, "/user:$User", $Plain, '/persistent:no') `
        -NoNewWindow -Wait -PassThru

    # Clean up sensitive material in memory
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    $Plain = $null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    if ($rc.ExitCode -eq 0) {
        Write-Host "Mapped $Drive to $Share as $User."
    } else {
        Write-Host "Mapping failed. Exit code: $($rc.ExitCode)"
        exit 1
    }

    # Optional verification
    if (Test-Path "$Drive\") {
        Write-Host "$Drive is accessible."
    } else {
        Write-Host "$Drive is not accessible after mapping."
        exit 1
    }

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
} Else {
    Write-Host "`r`n##############################################" -ForegroundColor Cyan
    Write-Host "###Imaging Off Campus, Skipping Aya Cleanup###" -ForegroundColor Cyan
    Write-Host "##############################################" -ForegroundColor Cyan
}

##^^^^^^^^^^^^^^^^^^^^^^^
## Remove Device From Aya
#########################

##################################
## Install the latest Curl version
##vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
$u = "https://curl.se/windows/latest.cgi?p=win64-mingw.zip"
$t = "$env:TEMP\curl.zip"
$d = "$env:TEMP\curl"

Invoke-WebRequest -Uri $u -OutFile $t -UseBasicParsing
if (Test-Path $d) { Remove-Item $d -Recurse -Force }
Expand-Archive -Path $t -DestinationPath $d -Force
$exe = Get-ChildItem -Path $d -Recurse -Filter "curl.exe" | Select-Object -First 1
if ($exe) { Copy-Item $exe.FullName "X:\Windows\System32\curl.exe" -Force 
    Write-Host "`r`n######################" -ForegroundColor Cyan
    Write-Host "### Installed Curl ###" -ForegroundColor Cyan
    Write-Host "######################" -ForegroundColor Cyan
} else {
    Write-Host "`r`n##############################" -ForegroundColor Cyan
    Write-Host "### Failed Installing Curl ###" -ForegroundColor Cyan
    Write-Host "##############################" -ForegroundColor Cyan
}
Remove-Item $t -Force

##^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
## End Install the latest Curl version
######################################


Write-Host "`r`n###############################" -ForegroundColor Cyan
Write-Host "###Starting OSDCloud Process###" -ForegroundColor Cyan
Write-Host "###############################" -ForegroundColor Cyan


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


Write-Host "`r`n#######################################" -ForegroundColor Cyan
Write-Host "###Seeding Hardware Diagnostic tools###" -ForegroundColor Cyan
Write-Host "#######################################" -ForegroundColor Cyan

# 7. Download and stage hardware tools by manufacturer
$relBase = "https://github.com/JustinSparksAya/OSDCloud/releases/latest/download"

# Detect manufacturer (fallback safe)
$manufacturer = ""
try {
    $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).Manufacturer
} catch { $manufacturer = "" }

$sys32 = Join-Path $windows "System32"

if ($manufacturer -match 'Lenovo') {
    Write-Host "Manufacturer detected: Lenovo - using LenovoDiagnostics.zip"
    $zipName    = "LenovoDiagnostics.zip"
    $extractDir = Join-Path $tempDir "LD"
} else {
    Write-Host "Manufacturer '$manufacturer' not Lenovo - using PassMark-BurnInTest.zip"
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

Write-Host "`r`n###############################" -ForegroundColor Cyan
Write-Host "###Staging Activation Script###" -ForegroundColor Cyan
Write-Host "###############################" -ForegroundColor Cyan


# 8. Stage activation script
Invoke-Download -Uri "https://raw.githubusercontent.com/JustinSparksAya/OSDCloud/main/Scripts/Activate-WindowsUsignOEMProductKey.ps1" `
    -OutFile (Join-Path $tempDir "Activate-WindowsUsignOEMProductKey.ps1")

Write-Host "`r`n#####################################" -ForegroundColor Cyan
Write-Host "###Staging WinPE Drivers for WinRE###" -ForegroundColor Cyan
Write-Host "#####################################" -ForegroundColor Cyan

# $tempDir should already be: <OSDrive>:\Windows\Temp  (offline OS)
$DestDir = Join-Path $tempDir 'WPEDrivers'
New-Item -ItemType Directory -Path $DestDir -Force | Out-Null

$Log = Join-Path $DestDir 'WinPE-ExportDrivers.log'
& dism.exe /online /export-driver "/destination:$DestDir" *> $Log

Write-Host "`r`n###############################" -ForegroundColor Cyan
Write-Host "###Staging SetupComplete.cmd###" -ForegroundColor Cyan
Write-Host "###############################" -ForegroundColor Cyan
# 8. Stage SetupComplete script
Invoke-Download -Uri "https://raw.githubusercontent.com/JustinSparksAya/OSDCloud/main/Scripts/SetupComplete.cmd" `
  -OutFile (Join-Path $setupDir "SetupComplete.cmd")

# 9. Stage Dock drivers for Lenovo laptops

# Check manufacturer
$manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
if ($manufacturer -match 'Lenovo') {
    Write-Host "Detected Lenovo system. Proceeding with Lenovo Dock Driver download..." -ForegroundColor Cyan

    # Destination folder
    $dest = 'C:\Drivers\ExtraDrivers\LenovoDock'
    New-Item -Path $dest -ItemType Directory -Force | Out-Null

    # Temp ZIP path
    $tempZip = "$env:TEMP\LenovoDockDrivers.zip"

    # Download Lenovo Dock driver package
    $zipUrl = 'https://github.com/JustinSparksAya/OSDCloud/releases/download/v1/LenovoDockDrivers.zip'
    Write-Host "Downloading Lenovo Dock driver package..."
    Invoke-WebRequest -Uri $zipUrl -OutFile $tempZip -UseBasicParsing

    # Extract to destination
    Write-Host "Extracting drivers to $dest..."
    Expand-Archive -Path $tempZip -DestinationPath $dest -Force

    # Cleanup
    Remove-Item $tempZip -Force
    Write-Host "Lenovo Dock driver package successfully downloaded and extracted to $dest" -ForegroundColor Cyan
}
else {
    Write-Host "Non-Lenovo system detected. Skipping dock driver download."
}

dism /Image:C:\ /Add-Driver /Driver:C:\Drivers\ExtraDrivers /Recurse /LogPath:'C:\Windows\Logs\DISM\LenovoExtraDrivers.log'


# 10. Send Teams Notification to OSDCloud Deployments channel 
function Send-TeamsNotificationViaWorkflow {
    param(
        [bool]$Success = $true,
        [string]$ErrorMessage = $null
    )

    # --- Hardcoded settings ---
    $flowUrl = 'https://defaultc32ce2354d9a4296a647a9edb2912a.c9.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/528d30b467aa4c65af16e8268cd077a9/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=orn6vz37XIjwkAOqfQgvwjTY3CkYPv1SNL1usPrVecg'
    $title   = 'OSDCloud Deployment'

    # --- Message and color selection based on success (char codes only) ---
    if ($Success) {
        $checkMark = "$([char]0x2705)"   # U+2705
        $message   = "$checkMark Deployment completed successfully."
        $msgColor  = 'Good'
    } else {
        $crossMark = "$([char]0x274C)"   # U+274C
        $message   = "$crossMark Deployment failed or encountered issues!"
        if ($ErrorMessage) { $message += "`n$ErrorMessage" }
        $msgColor  = 'Attention'
    }

    # --- Collect system data ---
    try {
        $bios  = Get-CimInstance Win32_BIOS
        $cs    = Get-CimInstance Win32_ComputerSystem
        $os    = Get-CimInstance Win32_OperatingSystem
        $cpu   = ((Get-CimInstance Win32_Processor)[0].Name -split '@')[0].Trim()
        $mem   = '{0:N0} GB' -f ($cs.TotalPhysicalMemory / 1GB)
        $build = '{0}.{1}' -f $os.Version, (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
        $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
        $disk  = if ($drive) { 'C: Total Size: {0:N2} GB' -f ($drive.Size / 1GB) } else { 'N/A' }

        function Get-BatteryPercent {
            $ps  = [System.Windows.Forms.SystemInformation]::PowerStatus
            $pct = [math]::Round($ps.BatteryLifePercent * 100)
            if ($pct -ge 0) { return $pct }
            try {
                $wmi = Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop
                if ($null -ne $wmi.EstimatedChargeRemaining) { return [int]$wmi.EstimatedChargeRemaining }
            } catch { }
            return $null
        }

        $pct   = Get-BatteryPercent
        $power = [System.Windows.Forms.SystemInformation]::PowerStatus

        # --- Icons (char codes only; no literal emoji) ---
        $iconBolt        = "$([char]0x26A1)"                            # U+26A1
        $iconPlug        = "$([char]0xD83D)$([char]0xDD0C)"             # U+1F50C
        $iconBattery     = "$([char]0xD83D)$([char]0xDD0B)"             # U+1F50B
        $iconLowBattery  = "$([char]0xD83E)$([char]0xDEAB)"             # U+1FAAB
        $iconWarning     = "$([char]0x26A0)$([char]0xFE0F)"             # U+26A0 U+FE0F

        # --- Power status: keep icon in LABEL only; value has no extra bolt ---
        if ($power.PowerLineStatus -eq [System.Windows.Forms.PowerLineStatus]::Online) {
            if ($pct -lt 50) {
                $powerStatus = "$iconPlug$iconLowBattery $pct`%"
            } else {
                $powerStatus = "$iconPlug$iconBattery $pct`%"
            }
        } else {
            if ($pct -lt 50) {
                $powerStatus = "$iconWarning $iconLowBattery $pct`%"
            } else {
                $powerStatus = "$iconWarning $iconBattery $pct`%"
            }
        }

        # --- Network details ---
        $net = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" |
        ForEach-Object {
            $a = Get-CimInstance Win32_NetworkAdapter -Filter "Index=$($_.Index)"
            $ipv4 = @($_.IPAddress) | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1
            if ($a.NetEnabled -and $a.NetConnectionStatus -eq 2 -and $ipv4) {
                [pscustomobject]@{
                    IPv4Address = [pscustomobject]@{ IPAddress = $ipv4 }
                    NetAdapter  = [pscustomobject]@{
                        InterfaceAlias = $a.NetConnectionID
                        MacAddress     = $a.MACAddress
                        Status         = 'Up'
                    }
                }
            }
        } | Select-Object -First 1

        $adapter = if ($net) { ($net.NetAdapter.InterfaceAlias -replace '\d+', '').Trim() } else { 'N/A' }
        $mac     = if ($net) { ($net.NetAdapter.MacAddress -replace '-', ':') } else { 'N/A' }
        $ipv4    = if ($net) { $net.IPv4Address.IPAddress } else { 'N/A' }

        # --- Connection type and icon (char codes only) ---
        $iconWifi  = "$([char]0xD83D)$([char]0xDCF6)"                    # U+1F4F6
        $iconLink  = "$([char]0xD83D)$([char]0xDD17)"                    # U+1F517
        $iconGlobe = "$([char]0xD83C)$([char]0xDF10)"                    # U+1F310

        if ($adapter -match '(wi[-\s]?fi|wifi|wlan|wireless)') {
            $connIcon = $iconWifi
            $connText = 'Wi-Fi'
        } elseif ($adapter -match '(ethernet|lan)') {
            $connIcon = $iconLink
            $connText = 'Ethernet'
        } else {
            $connIcon = $iconGlobe
            $connText = if ($adapter -and $adapter -ne 'N/A') { $adapter } else { 'Unknown' }
        }

        # --- Icons for labels (char codes only) ---
        $iconSerial  = "$([char]0xD83D)$([char]0xDCB3)"                  # U+1F4B3
        $iconMake    = "$([char]0xD83C)$([char]0xDFED)"                  # U+1F3ED
        $iconModel   = "$([char]0xD83D)$([char]0xDCBB)"                  # U+1F4BB
        $iconPC      = "$([char]0xD83D)$([char]0xDDA5)"                  # U+1F5A5
        $iconWin     = "$([char]0xD83E)$([char]0xDE9F)"                  # U+1FA9F
        $iconCPU     = "$([char]0x2699)$([char]0xFE0F)"                  # U+2699 U+FE0F
        $iconMemory  = "$([char]0xD83D)$([char]0xDCCA)"                  # U+1F4CA
        $iconStorage = "$([char]0xD83D)$([char]0xDDC4)"                  # U+1F5C4
        $iconMac     = "$([char]0xD83D)$([char]0xDD20)"                  # U+1F520
        $iconIP      = "$([char]0xD83C)$([char]0xDF10)"                  # U+1F310
        $iconPin     = "$([char]0xD83D)$([char]0xDCCD)"                  # U+1F4CD
        $iconClock   = "$([char]0xD83D)$([char]0xDD53)"                  # U+1F553

        $secondaryModel = $null
        if ($cs.Manufacturer -eq 'Lenovo') {
            $secondaryModel = (Get-CimInstance -ClassName Win32_ComputerSystemProduct -Property Version -Verbose:$VerbosePreference).Version
        }
        $model = if ($secondaryModel) { "$secondaryModel ($($cs.Model))" } else { $cs.Model }

        try {
            $region  = Invoke-RestMethod 'https://ipinfo.io/json' -TimeoutSec 5
            $country = "{0}, {1}, {2}" -f $region.city, $region.region, $region.country
        } catch { $country = 'Unknown' }

        # --- Facts with updated labels/icons (char codes only) ---
        $facts = @(
            @{ title="$iconSerial Serial Number:";      value=$bios.SerialNumber }
            @{ title="$iconMake Make:";                 value=$cs.Manufacturer }
            @{ title="$iconModel Model:";               value=$model }
            @{ title="$iconPC Computer Name:";          value=$env:COMPUTERNAME }
            @{ title="$iconWin Windows PE Version:";    value=$build }
            @{ title="$iconCPU CPU:";                   value=$cpu }
            @{ title="$iconMemory Memory:";             value=$mem }
            @{ title="$iconStorage Storage Space:";     value=$disk }
            @{ title="$iconBolt Power Status:";         value=$powerStatus }
            @{ title="$connIcon Connection Type:";      value=$connText }
            @{ title="$iconMac MAC Address:";           value=$mac }
            @{ title="$iconIP IP Address:";             value=$ipv4 }
            @{ title="$iconPin Location:";              value=$country }
            @{ title="$iconClock Time Stamp:";          value=(Get-Date).ToString('g') }
        ) | Where-Object { $_.value -and "$($_.value)".Trim() -ne '' }

    } catch {
        $facts = @(@{ title='Error:'; value='Failed to collect some system info.' })
    }

    # --- Build rows: RichTextBlock keeps label and value tight on one line ---
    $rows = foreach ($f in $facts) {
        @{
            type    = 'RichTextBlock'
            inlines = @(
                @{ type='TextRun'; text=$f.title + ' '; weight='Bolder' },
                @{ type='TextRun'; text=$f.value }
            )
            spacing = 'Small'
        }
    }

    # --- Build Adaptive Card ---
    $card = [ordered]@{
        '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
        type      = 'AdaptiveCard'
        version   = '1.4'
        body      = @(
            @{ type='TextBlock'; text=$title;   weight='Bolder'; size='Medium'; wrap=$true },
            @{ type='TextBlock'; text=$message; color=$msgColor; wrap=$true; spacing='Small' }
        ) + $rows
    }

    # --- Payload wrapper your Flow expects (Parse JSON -> Post card) ---
    $payload = @{
        content = @{
            title       = $title
            attachments = @(
                @{
                    contentType = 'application/vnd.microsoft.card.adaptive'
                    content     = $card
                }
            )
        }
    }

    # --- Send to Teams (UTF-8 safe) ---
    try {
        $json      = ($payload | ConvertTo-Json -Depth 20)
        $utf8NoBOM = New-Object System.Text.UTF8Encoding($false)
        $bodyBytes = $utf8NoBOM.GetBytes($json)

        Invoke-RestMethod -Uri $flowUrl -Method POST -ContentType 'application/json; charset=utf-8' -Body $bodyBytes -TimeoutSec 60 | Out-Null

        Write-Host "`r`n################################" -ForegroundColor Cyan 
        Write-Host "### Teams Adaptive Card sent ###" -ForegroundColor Cyan 
        Write-Host "################################" -ForegroundColor Cyan 
    } catch {
        Write-Host "Post failed: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream()) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Host ($reader.ReadToEnd()) -ForegroundColor Red
        }
    }
}




Stop-Transcript

# 11. Check logs for errors
$OSDlog = Get-Item -Path $ts -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$OSDlog = $OSDlog.FullName

$logMissing = (-not $OSDLog)

function Find-TriggerLine {
    param ($lines)

    $skipSection = $false

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        # Detect start and end of skip section
        if ($line -match "Microsoft update catalog drivers") {
            $skipSection = $true
            continue
        }
        if ($skipSection -and $line -match "Add Windows Driver with Offline Servicing") {
            $skipSection = $false
            continue
        }

        # Skip lines inside the section
        if ($skipSection) { continue }

        # Detect actual error or terminating lines outside the section
        if (($line -like "*error*" -and $line -notlike "*erroraction*") -or $line -like "*terminat*") {
            return $lines[$i]
        }
    }

    return $null
}

$Success = $false

if (!$logMissing) {
    $logContent = Get-Content -Path $OSDLog -ErrorAction SilentlyContinue
    $ErrLine = Find-TriggerLine $logContent
    if ($null -eq $ErrLine) {
        $Success = $true
    }
}

If($Success){
    Send-TeamsNotificationViaWorkflow -Success $Success
    Write-Host "`r`n#########################" -ForegroundColor Cyan 
    Write-Host "###Deployment Finished###" -ForegroundColor Cyan
    Write-Host "#########################" -ForegroundColor Cyan
    Copy-Item -Path $OSDlog -Destination "C:\Windows\Temp\" -Force
    Write-Host "`r`nRestarting in 15 seconds..." -ForegroundColor Green
    Start-Sleep 15
    Write-Host "`r`nStaging complete. Restarting..."
    Restart-Computer
} else {
    Send-TeamsNotificationViaWorkflow -Success $Success -ErrorMessage $ErrLine
    Write-Host "`r`n!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host "!!!Deployment Failed!!!" -ForegroundColor Red
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host "`r`nError line in `'$OSDlog`':" -ForegroundColor Red
    Write-Host $ErrLine -ForegroundColor Red    
    Read-Host "`r`nPress Enter to reboot"
    Restart-Computer
}

