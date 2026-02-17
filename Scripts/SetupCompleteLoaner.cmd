@echo off
setlocal enableextensions enabledelayedexpansion

:: === Paths / Logs ===
set "LogDir=C:\Windows\Temp"
set "Log=%LogDir%\SetupComplete.log"
set "InjectLog=%LogDir%\WinRE-Inject.log"
set "WIM=C:\Windows\System32\Recovery\Winre.wim"
set "MNT=C:\_WinRE_Mount"
set "DRV=C:\Windows\Temp\wpedrivers"


:: Timestamp
echo ==== SetupComplete START: %DATE% %TIME% ====>>"%Log%"

msg * "The Setup is continuing in the background. Please wait..."

:: --- 1) activation step ---
echo [Activate] Running Activate-WindowsUsignOEMProductKey.ps1>>"%Log%"
powershell.exe -ExecutionPolicy Bypass -File "C:\Windows\Temp\Activate-WindowsUsignOEMProductKey.ps1" >> "%LogDir%\Activate-WindowsUsignOEMProductKey.log" 2>&1
echo [Activate] Done.>>"%Log%"

:: --- 2) landscape mode step ---
echo [Activate] Running Set-LandscapeMode.ps1>>"%Log%"
powershell.exe -ExecutionPolicy Bypass -File "C:\Windows\Temp\Set-LandscapeMode.ps1" >> "%LogDir%\Set-LandscapeMode.log" 2>&1
echo [Activate] Done.>>"%Log%"

:: --- 3) Prepare WinRE injection (disable WinRE; OK if already disabled) ---
echo [WinRE] reagentc /disable>>"%Log%"
reagentc /disable >>"%Log%" 2>&1


:: --- 4) Inject drivers from %DRV% into WinRE.wim (if folder exists) ---
if exist "%DRV%\" (
  echo [WinRE] Injecting drivers from "%DRV%">>"%Log%"

  if exist "%MNT%\Windows" dism /unmount-image /mountdir:"%MNT%" /discard >>"%InjectLog%" 2>&1
  rmdir /s /q "%MNT%" 2>nul
  mkdir "%MNT%" 2>nul

  echo [WinRE] Mounting "%WIM%">>"%Log%"
  dism /mount-image /imagefile:"%WIM%" /index:1 /mountdir:"%MNT%" >>"%InjectLog%" 2>&1
  if errorlevel 1 goto :MountFail

  echo [WinRE] DISM /add-driver from "%DRV%" /recurse>>"%Log%"
  dism /image:"%MNT%" /add-driver /driver:"%DRV%" /recurse >>"%InjectLog%" 2>&1
  set "EC=!ERRORLEVEL!"

  echo [WinRE] Committing WinRE>>"%Log%"
  dism /unmount-image /mountdir:"%MNT%" /commit >>"%InjectLog%" 2>&1

  if "!EC!"=="0" (
    echo [WinRE] add-driver succeeded>>"%Log%"
  ) else (
    >>"%Log%" echo [WinRE] add-driver failed with !EC! [see WinRE-Inject.log]
  )

  rem cleanup mount directory after success
  rmdir /s /q "%MNT%" 2>nul
) else (
  >>"%Log%" echo [WinRE] Driver folder not found "%DRV%\" ; skipping injection
)

:: --- 5) Re-register and enable WinRE (online) ---
echo [WinRE] reagentc /setreimage /path C:\Windows\System32\Recovery>>"%Log%"
reagentc /setreimage /path C:\Windows\System32\Recovery >>"%Log%" 2>&1

echo [WinRE] reagentc /enable>>"%Log%"
reagentc /enable >>"%Log%" 2>&1

echo [WinRE] reagentc /info>>"%Log%"
reagentc /info >>"%Log%" 2>&1

:: --- 6) Staging Windows Update Loop script's First boot ---
echo [WULoop] Staging Windows Update Loop script's First boot>>"%Log%"
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\Setup\Scripts\WU-AyaLoanerLoop.ps1" >> "%LogDir%\StagingWU-AyaLoanerLoop.log" 2>&1
echo [WULopp] Done.>>"%Log%"


echo ==== SetupComplete END: %DATE% %TIME% ====>>"%Log%"
exit /b 0

:MountFail
echo [WinRE] MOUNT failed; cleaning and continuing [see WinRE-Inject.log]>>"%Log%"
dism /cleanup-wim >>"%InjectLog%" 2>&1
rmdir /s /q "%MNT%" 2>nul
echo ==== SetupComplete END (mount failed): %DATE% %TIME% ====>>"%Log%"
exit /b 0
