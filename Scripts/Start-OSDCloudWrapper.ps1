# --- Aya OSDCloud Wrapper using latest release assets ---
Write-Host "Aya OSDCloud start"

# 1. Load OSDCloud in WinPE
Invoke-Expression (Invoke-RestMethod 'https://sandbox.osdcloud.com')

# 2. Optional defaults
$OSDCloudDrive = "C:"
$OSDLanguage   = "en-us"
$OSDLicense    = "Retail"

# 3. Apply OS
Start-OSDCloud -OSBuild "11" -OSEdition "Pro" -OSLanguage "en-us" -OSLicense "Retail" -SkipAutopilot -ZTI

# 4. Locate applied Windows and prep folders
$osDrive  = Get-OSDCloudOSDrive
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

# 7. Download large media from latest release
$relBase = "https://github.com/JustinSparksAya/OSDCloud/releases/latest/download"

Invoke-Download -Uri "$relBase/LenovoDiagnostics.zip" `
    -OutFile (Join-Path $tempDir "LenovoDiagnostics.zip")

Invoke-Download -Uri "$relBase/PassMark-BurnInTest.zip" `
    -OutFile (Join-Path $tempDir "PassMark-BurnInTest.zip")

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

Write-Host "Staging complete. Rebooting"
Restart-Computer
