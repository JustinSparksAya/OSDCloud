
---

## 4. Create the wrapper script

This will be your entry point for WinPE. Save as:

**`Scripts/Start-OSDCloudWrapper.ps1`**

```powershell
Write-Host "=== Aya OSDCloud Deployment ==="

# Load OSDCloud environment
Invoke-Expression (Invoke-RestMethod 'https://sandbox.osdcloud.com')

# Optional: prep variables
$OSDCloudDrive = "C:"
$OSDLanguage   = "en-us"
$OSDLicense    = "Retail"
$OSEdition     = "Professional"

# Start deployment
Start-OSDCloud -OSBuild "11" -OSEdition "Pro" -OSLanguage "en-us" -OSLicense "Retail" -SkipAutopilot -ZTI

# Inject Unattend
$targetDrive = Get-OSDCloudOSDrive
$panther = Join-Path $targetDrive "Windows\Panther"
New-Item -ItemType Directory -Path $panther -Force | Out-Null
Invoke-WebRequest "https://raw.githubusercontent.com/JustinSparksAya/OSDCloud/main/Unattend/Unattend.xml" -OutFile (Join-Path $panther "Unattend.xml")

# Copy additional scripts into the OS
$dest = Join-Path $targetDrive "Windows\Temp"
New-Item -ItemType Directory -Path $dest -Force | Out-Null
Invoke-WebRequest "https://raw.githubusercontent.com/JustinSparksAya/OSDCloud/main/Scripts/Activate-WindowsUsingOEMProductKey.ps1" -OutFile (Join-Path $dest "Activate-WindowsUsingOEMProductKey.ps1")
Invoke-WebRequest "https://raw.githubusercontent.com/JustinSparksAya/OSDCloud/main/Scripts/RemoveDeviceFromAya.ps1" -OutFile (Join-Path $dest "RemoveDeviceFromAya.ps1")

Write-Host "Deployment files staged. Rebooting..."
Restart-Computer
