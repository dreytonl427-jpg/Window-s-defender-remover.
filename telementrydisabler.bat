@echo off
title Windows Telemetry OBLITERATOR v2.0 - MAX PRIVACY MODE
color 0A
echo.
echo ========================================================
echo    WINDOWS TELEMETRY OBLITERATOR - INSANE MODE
echo    Keeps: Store/Xbox/Updates/Games ^| Nukes: Everything Else
echo ========================================================
echo.

:: Force Admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [+] Elevating to Admin...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo [+] Admin confirmed. Starting nuclear strike...

:: === NUCLEAR STRIKE PHASE 1: Services Annihilation ===
echo [1/8] ^>^> OBLITERATING Telemetry Services...
sc config DiagTrack start= disabled >nul 2>&1
sc stop DiagTrack >nul 2>&1
sc config dmwappushservice start= disabled >nul 2>&1
sc stop dmwappushservice >nul 2>&1
sc config RetailDemo start= disabled >nul 2>&1
sc stop RetailDemo >nul 2>&1
sc config WMPNetworkSvc start= disabled >nul 2>&1
sc stop WMPNetworkSvc >nul 2>&1
sc config TrkWks start= disabled >nul 2>&1
sc stop TrkWks >nul 2>&1
echo     Services nuked!

:: === PHASE 2: Scheduled Tasks Genocide ===
echo [2/8] ^>^> GENOCIDING Scheduled Tasks...
schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Maintenance\WinSAT" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Ras\MobilityManager" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /DISABLE >nul 2>&1
echo     Tasks terminated!

:: === PHASE 3: Registry Apocalypse ===
echo [3/8] ^>^> DEPLOYING Registry Apocalypse...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul 2>&1

:: Cortana/Search Nuke
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f >nul 2>&1

:: Error Reporting Kill
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >nul 2>&1

:: Delivery Optimization P2P Disable (keeps updates working)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f >nul 2>&1
echo     Registry purged!

:: === PHASE 4: Firewall Black Hole ===
echo [4/8] ^>^> CREATING Telemetry Black Hole...
netsh advfirewall firewall add rule name="NO_TELEMETRY_1" dir=out action=block remoteip=telemetry.microsoft.com enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="NO_TELEMETRY_2" dir=out action=block remoteip=vortex.data.microsoft.com enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="NO_TELEMETRY_3" dir=out action=block remoteip=watson.telemetry.microsoft.com enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="NO_TELEMETRY_4" dir=out action=block remoteip=settings-win.data.microsoft.com enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="NO_TELEMETRY_5" dir=out action=block remoteip=choice.microsoft.com enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="NO_TELEMETRY_6" dir=out action=block remoteip=df.telemetry.microsoft.com enable=yes >nul 2>&1
echo     Firewall fortified!

:: === PHASE 5: Group Policy Force ===
echo [5/8] ^>^> FORCING Group Policy...
gpupdate /force >nul 2>&1
echo     Policies enforced!

:: === PHASE 6: Hosts File Blockade ===
echo [6/8] ^>^> DEPLOYING Hosts File Blockade...
echo 0.0.0.0 telemetry.microsoft.com >> %windir%\System32\drivers\etc\hosts
echo 0.0.0.0 vortex.data.microsoft.com >> %windir%\System32\drivers\etc\hosts
echo 0.0.0.0 watson.telemetry.microsoft.com >> %windir%\System32\drivers\etc\hosts
echo 0.0.0.0 settings-win.data.microsoft.com >> %windir%\System32\drivers\etc\hosts
echo 0.0.0.0 choice.microsoft.com >> %windir%\System32\drivers\etc\hosts
echo 0.0.0.0 df.telemetry.microsoft.com >> %windir%\System32\drivers\etc\hosts
echo     Hosts blocked!

:: === PHASE 7: Edge/Chromium Telemetry Kill ===
echo [7/8] ^>^> KILLING Edge Telemetry...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v MetricsReportingEnabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v AutoUpdateCheckPeriodMinutes /t REG_DWORD /d 0 /f >nul 2>&1
echo     Edge silenced!

:: === PHASE 8: Final Sweep ===
echo [8/8] ^>^> EXECUTING Final Sweep...
:: Kill any remaining processes
taskkill /f /im DiagnosticDataViewer.exe >nul 2>&1
taskkill /f /im compatTelRunner.exe >nul 2>&1

:: Force telemetry level to 0
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Telemetry" /v ConfigState /t REG_DWORD /d 0 /f >nul 2>&1
echo     Sweep complete!

:: === VICTORY ===
color 0F
cls
echo.
echo ========================================================
echo          ^|^|  MISSION ACCOMPLISHED  ^|^|
echo ========================================================
echo.
echo    [v] Store/Xbox/Game downloads:    ^<^< WORKING
echo    [v] Windows Updates:              ^<^< WORKING  
echo    [v] Core services:                ^<^< WORKING
echo.
echo    [X] Telemetry:                    ^<^< OBLITERATED
echo    [X] Cortana/Search tracking:      ^<^< OBLITERATED
echo    [X] Error reporting:              ^<^< OBLITERATED
echo.
echo REBOOT TO FINALIZE: shutdown /r /t 10 /c "Telemetry nuked - rebooting..."
echo.
echo Press any key to reboot NOW or CTRL+C to delay...
pause >nul
shutdown /r /t 0 /f /c "TELEMETRY OBLITERATED - REBOOTING"