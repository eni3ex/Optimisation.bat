@echo off
chcp 65001 >nul
color 0A
echo ********** Windows 10 batch optimizer (The fulfillment process may take a few minutes!)
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
		exit /b 1
    )
    exit /b 0
)
pause


REM SSD - 0, HDD - 3
set Prefetch=0


echo ********** Regystry backup COPY to C:/RegBackup/Backup.reg 
SETLOCAL
set RegBackup=%SYSTEMDRIVE%\RegBackup
IF NOT EXIST "%RegBackup%" md "%RegBackup%"
IF EXIST "%RegBackup%\HKLM.reg" DEL "%RegBackup%\HKLM.reg"
REG export HKLM "%RegBackup%\HKLM.reg"
IF EXIST "%RegBackup%\HKCU.reg" DEL "%RegBackup%\HKCU.reg"
REG export HKCU "%RegBackup%\HKCU.reg"
IF EXIST "%RegBackup%\HKCR.reg" DEL "%RegBackup%\HKCR.reg"
REG export HKCR "%RegBackup%\HKCR.reg"
IF EXIST "%RegBackup%\HKU.reg" DEL "%RegBackup%\HKU.reg"
REG export HKU "%RegBackup%\HKU.reg"
IF EXIST "%RegBackup%\HKCC.reg" DEL "%RegBackup%\HKCC.reg"
REG export HKCC "%RegBackup%\HKCC.reg"
IF EXIST "%RegBackup%\Backup.reg" DEL "%RegBackup%\Backup.reg"
COPY "%RegBackup%\HKLM.reg"+"%RegBackup%\HKCU.reg"+"%RegBackup%\HKCR.reg"+"%RegBackup%\HKU.reg"+"%RegBackup%\HKCC.reg" "%RegBackup%\Backup.reg"
DEL "%RegBackup%\HKLM.reg"
DEL "%RegBackup%\HKCU.reg"
DEL "%RegBackup%\HKCR.reg"
DEL "%RegBackup%\HKU.reg"
DEL "%RegBackup%\HKCC.reg"


echo --- Firewall/Hosts telemetry ip/domain blocking
GOTO BLOCK
:REG

echo --- Disable Evil Defender :)
if exist "%ProgramFiles%\Windows Defender Advanced Threat Protection" (
sc config WinDefend start=disabled >nul && net stop WinDefend >nul
sc config SecurityHealthService start=disabled >nul
sc config Sense start=disabled >nul
sc config WdNisDrv start=disabled >nul
sc config WdNisSvc start=disabled >nul
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >nul
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f >nul
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
for /f %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx" /s /k /f "SecHealthUI" ^| find /i "SecHealthUI" ') do (reg delete "%%i" /f >nul 2>&1)
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >nul
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "AlowFastServiceStartup" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingsOverrideSpynetReporting" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
for /f "tokens=1* delims=:" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility') do set "hidelist=%%j"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:windowsdefender;%hidelist%" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.Defender.SecurityCenter" /v "Enabled" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul
)

echo --- Clean Junk temp files and thumbcache
taskkill /f /im explorer.exe
timeout 2 /nobreak>nul
DEL /F /S /Q /A %LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db
DEL /f /s /q %systemdrive%\*.tmp
DEL /f /s /q %systemdrive%\*._mp
DEL /f /s /q %systemdrive%\*.log
DEL /f /s /q %systemdrive%\*.gid
DEL /f /s /q %systemdrive%\*.chk
DEL /f /s /q %systemdrive%\*.old
DEL /f /s /q %systemdrive%\recycled\*.*
DEL /f /s /q %systemdrive%\$Recycle.Bin\*.*
DEL /f /s /q %windir%\*.bak
DEL /f /s /q %windir%\prefetch\*.*
rd /s /q %windir%\temp & md %windir%\temp
rd /s /q %userprofile%\AppData\Local\Temp & md %userprofile%\AppData\Local\Temp
rd /s /q %userprofile%\AppData\Local\Chromium\User Data\Default\Cache & md %userprofile%\AppData\Local\Chromium\User Data\Default\Cache
rd /s /q %userprofile%\AppData\Local\Chromium\User Data\Default\Code Cache & md %userprofile%\AppData\Local\Chromium\User Data\Default\Code Cache
rd /s /q %windir%\SoftwareDistribution\Download & md %windir%\SoftwareDistribution\Download
DEL /f /q %userprofile%\cookies\*.*
DEL /f /q %userprofile%\recent\*.*
DEL /f /s /q "%userprofile%\Local Settings\Temporary Internet Files\*.*"
DEL /f /s /q "%userprofile%\Local Settings\Temp\*.*"
DEL /f /s /q "%userprofile%\recent\*.*"
Dism.exe /online /cleanup-image /AnalyzeComponentStore
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
timeout 2 /nobreak>nul
start explorer.exe

echo -- disable hibernating
powercfg -h off

echo --- Disable Customer Experience Improvement (CEIP/SQM)
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f
echo --- Disable Application Impact Telemetry (AIT)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
echo --- Disable Customer Experience Improvement Program
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
echo --- Disable telemetry in data collection policy
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /d 0 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
echo --- Disable license telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f
echo --- Disable error reporting
echo --- Disable Windows Error Reporting (WER)
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t "REG_DWORD" /d "1" /f
echo --- DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
echo --- Disable WER sending second-level data
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
echo --- Disable WER crash dialogs, popups
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
schtasks /change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /disable
schtasks /change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
sc stop "wersvc"
sc config "wersvc" start= disabled
sc stop "wercplsupport"
sc config "wercplsupport" start= disabled
echo --- Disable WAP push message routing service
sc stop "dmwappushservice"
sc config "dmwappushservice" start= disabled
echo --- Disable diagnostics hub standard collector service
stop "diagnosticshub.standardcollector.service"
sc config "diagnosticshub.standardcollector.service" start= disabled
echo --- Disable diagnostic execution service
sc stop "diagsvc"
sc config "diagsvc" start= disabled
echo --- Disable devicecensus.exe (telemetry) task
schtasks /change /TN "Microsoft\Windows\Device Information\Device" /disable
echo --- Disable devicecensus.exe (telemetry) process
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'DeviceCensus.exe'" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
echo --- Disable sending information to Customer Experience Improvement Program
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
echo --- Disable Application Impact Telemetry Agent task
schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
echo --- Disable "Disable apps to improve performance" reminder
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
echo --- Disable Microsoft Compatibility Appraiser task
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
echo --- Disable CompatTelRunner.exe (Microsoft Compatibility Appraiser) process
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'CompatTelRunner.exe'" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
echo --- Do not allow search to use location
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
echo --- Disable web search in search bar
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
echo --- Do not search the web or display web results in Search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
echo --- Disable Bing search
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
echo --- Do not allow Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
echo --- Do not allow Cortana experience
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f
echo --- Do not allow search and Cortana to search cloud sources like OneDrive and SharePoint
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
echo --- Disable Cortana speech interaction while the system is locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
echo --- Opt out from Cortana consent
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
echo --- Do not allow Cortana to be enabled
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f
echo --- Disable Cortana (Internet search results in start menu)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
echo --- Remove the Cortana taskbar icon
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "ShowCortanaButton" /t REG_DWORD /d 0 /f
echo --- Disable Cortana in ambient mode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaInAmbientMode" /t REG_DWORD /d 0 /f
echo --- Prevent Cortana from displaying history
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f
echo --- Prevent Cortana from using device history
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f
echo --- Disable "Hey Cortana" voice activation
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d 0 /f
echo --- Disable Cortana listening to commands on Windows key + C
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "VoiceShortcut" /t REG_DWORD /d 0 /f
echo --- Disable using Cortana even when device is locked
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d 0 /f
echo --- Disable automatic update of Speech Data
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d 0 /f
echo --- Disable Cortana voice support during Windows setup
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisableVoice" /t REG_DWORD /d 1 /f
echo --- Disable search indexing encrypted items / stores
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d 0 /f
echo --- Do not use automatic language detection when indexing
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AlwaysUseAutoLangDetection" /t REG_DWORD /d 0 /f
echo --- Disable ad customization with Advertising ID
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f
echo --- Turn Off Suggested Content in Settings app
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /d "0" /t REG_DWORD /f
echo --- Disable Windows Tips
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f
echo --- Disable Windows Spotlight (random wallpaper on lock screen)
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t "REG_DWORD" /d "1" /f
echo --- Disable Microsoft consumer experiences
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t "REG_DWORD" /d "1" /f
echo --- Do not allow the use of biometrics
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
echo --- Do not allow users to log on using biometrics
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f
echo --- Disable Windows Insider Service
sc stop "wisvc"
sc config "wisvc" start= disabled
echo --- Do not let Microsoft try features on this build
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableconfigFlighting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
echo --- Disable getting preview builds of Windows
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f
echo --- Remove "Windows Insider Program" from Settings
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t "REG_DWORD" /d "1" /f
echo --- Disable visual studio telemetry
reg add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d 1 /f
echo --- Disable Visual Studio feedback
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableFeedbackDialog" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableEmailInput" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableScreenshotCapture" /t REG_DWORD /d 1 /f
echo --- stop and disable Visual Studio Standard Collector Service
sc stop "VSStandardCollectorService150"
sc config "VSStandardCollectorService150" start= disabled
echo --- Disable SQM OS key
if %PROCESSOR_ARCHITECTURE%==x86 ( REM is 32 bit?
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
) else (
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
)
echo --- Disable SQM group policy
reg add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
echo --- Uninstall NVIDIA telemetry tasks
if exist "%ProgramFiles%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
)
echo --- delete NVIDIA residual telemetry files
del /s %SystemRoot%\System32\DriverStore\FileRepository\NvTelemetry*.dll
rmdir /s /q "%ProgramFiles(x86)%\NVIDIA Corporation\NvTelemetry" 2>nul
rmdir /s /q "%ProgramFiles%\NVIDIA Corporation\NvTelemetry" 2>nul
echo --- Opt out from NVIDIA telemetry
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f
echo --- Disable Nvidia Telemetry Container service
sc stop "NvTelemetryContainer"
sc config "NvTelemetryContainer" start= disabled
echo --- Disable NVIDIA telemetry services
schtasks /change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable
schtasks /change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable
schtasks /change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable
echo --- Disable NVIDIA telemetry
for /f "tokens=1 delims=," %%t in ('schtasks /Query /FO CSV ^| find /v "TaskName" ^| find "NvTmMon"') do schtasks /change /TN "%%~t" /disable >nul 2>&1
for /f "tokens=1 delims=," %%t in ('schtasks /Query /FO CSV ^| find /v "TaskName" ^| find "NvTmRep"') do schtasks /change /TN "%%~t" /disable >nul 2>&1
for /f "tokens=1 delims=," %%t in ('schtasks /Query /FO CSV ^| find /v "TaskName" ^| find "NvTmRepOnLogon"') do schtasks /change /TN "%%~t" /disable >nul 2>&1
for /f "tokens=1 delims=," %%t in ('schtasks /Query /FO CSV ^| find /v "TaskName" ^| find "NvProfileUpdaterDaily"') do schtasks /change /TN "%%~t" /disable >nul 2>&1
for /f "tokens=1 delims=," %%t in ('schtasks /Query /FO CSV ^| find /v "TaskName" ^| find "NvProfileUpdaterOnLogon"') do schtasks /change /TN "%%~t" /disable >nul 2>&1
echo --- Disable Visual Studio Code telemetry
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^"";  0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'telemetry.enableTelemetry' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
echo --- Disable Visual Studio Code crash reporting
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^"";  0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'telemetry.enableCrashReporter' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
echo --- Do not run Microsoft online experiments
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^"";  0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'workbench.enableExperiments' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
echo --- Choose manual updates over automatic updates
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^"";  0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'update.mode' -Value 'manual' -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
echo --- Show Release Notes from Microsoft online service after an update
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^"";  0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'update.showReleaseNotes' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
echo --- Automatically check extensions from Microsoft online service
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^"";  0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'extensions.autoCheckUpdates' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
echo --- Fetch recommendations from Microsoft only on demand
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^"";  0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'extensions.showRecommendationsOnlyOnDemand' -Value $true -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
echo --- Automatically fetch git commits from remote repository
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^"";  0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'git.autofetch' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
echo --- Fetch package information from NPM and Bower
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^"";  0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'npm.fetchOnlinePackageInfo' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
echo --- Disable Microsoft Office logging
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
echo --- Disable client telemetry
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
echo --- Customer Experience Improvement Program
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
echo --- Disable feedback
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
echo --- Disable telemetry agent
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /disable
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /disable
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /disable
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /disable
echo --- Disable Subscription Heartbeat
schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /disable
schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /disable
echo --- Do not send Windows Media Player statistics
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f
echo --- Disable metadata retrieval
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
echo --- Disable NET Core CLI telemetry
setx DOTNET_CLI_TELEMETRY_OPTOUT 1
echo --- Disable PowerShell 7+ telemetry
setx POWERSHELL_TELEMETRY_OPTOUT 1
echo --- Disable Adobe Acrobat update service
sc stop "AdobeARMservice"
sc config "AdobeARMservice" start= disabled
sc stop "adobeupdateservice"
sc config "adobeupdateservice" start= disabled
sc stop "adobeflashplayerupdatesvc"
sc config "adobeflashplayerupdatesvc" start= disabled
schtasks /change /tn "Adobe Acrobat Update Task" /disable
schtasks /change /tn "Adobe Flash Player Updater" /disable
echo --- Disable Razer Game Scanner Service
sc stop "Razer Game Scanner Service"
sc config "Razer Game Scanner Service" start= disabled
echo --- Disable Logitech Gaming Registry Service
sc stop "LogiRegistryService"
sc config "LogiRegistryService" start= disabled
echo --- Disable Dropbox auto update service
sc stop "dbupdate"
sc config "dbupdate" start= disabled
sc stop "dbupdatem"
sc config "dbupdatem" start= disabled
schtasks /change /disable /TN "DropboxUpdateTaskMachineCore"
schtasks /change /disable /TN "DropboxUpdateTaskMachineUA" 
echo --- Disable CCleaner Monitoring
reg add "HKCU\Software\Piriform\CCleaner" /v "Monitoring" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "HelpImproveCCleaner" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoring" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateAuto" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateCheck" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "CheckTrialOffer" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)HealthCheck" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)QuickClean" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)QuickCleanIpm" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdater" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdaterIpm" /t REG_DWORD /d 0 /f
echo --- Delivery Optimization (P2P Windows Updates)
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'DoSvc'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction stop; Write-Host "^""stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
echo --- Program Compatibility Assistant Service
sc stop "PcaSvc"
sc config "PcaSvc" start= disabled
echo --- Downloaded Maps Manager
sc stop "MapsBroker"
sc config "MapsBroker" start= disabled
echo --- Microsoft Retail Demo experience
sc stop "RetailDemo"
sc config "RetailDemo" start= disabled
echo --- Contact data indexing
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'PimIndexMaintenanceSvc'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction stop; Write-Host "^""stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'PimIndexMaintenanceSvc_*'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction stop; Write-Host "^""stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


echo --- Disabling services
sc stop "Fax"
sc config "Fax" start= disabled
sc stop "Spooler"
sc config "Spooler" start= disabled
sc stop "WbioSrvc"
sc config "WbioSrvc" start= disabled
sc stop "DiagTrack"
sc config "DiagTrack" start= disabled
sc stop "HvHost"
sc config "HvHost" start= disabled
sc stop "vmicvmsession"
sc config "vmicvmsession" start= disabled
sc stop "vmicheartbeat"
sc config "vmicheartbeat" start= disabled
sc stop "vmicguestinterface"
sc config "vmicguestinterface" start= disabled
sc stop "vmicshutdown"
sc config "vmicshutdown" start= disabled
sc stop "vmicvss"
sc config "vmicvss" start= disabled
sc stop "vmickvpexchange"
sc config "vmickvpexchange" start= disabled
sc stop "SensorService"
sc config "SensorService" start= disabled
sc stop "SensorDataService"
sc config "SensorDataService" start= disabled
sc stop "SensrSvc"
sc config "SensrSvc" start= disabled
sc stop "BDESVC"
sc config "BDESVC" start= disabled
sc stop "WSearch"
sc config "WSearch" start= disabled
sc stop "WMPNetworkSvc"
sc config "WMPNetworkSvc" start= disabled
sc stop "WdNisSvc"
sc config "WdNisSvc" start= disabled
sc stop "WalletService"
sc config "WalletService" start= disabled
sc stop "XblAuthManager"
sc config "XblAuthManager" start= disabled
sc stop "XblGameSave"
sc config "XblGameSave" start= disabled
sc stop "XboxGipSvc"
sc config "XboxGipSvc" start= disabled
sc stop "XboxNetApiSvc"
sc config "XboxNetApiSvc" start= disabled
sc stop "SharedAccess"
sc config "SharedAccess" start= disabled
sc stop "ClipSVC"
sc config "ClipSVC" start= disabled
sc stop "cloudidsvc"
sc config "cloudidsvc" start= disabled
sc stop "lfsvc"
sc config "lfsvc" start= disabled
sc stop "LibreOfficeMaintenance"
sc config "LibreOfficeMaintenance" start= disabled
sc stop "Wecsvc"
sc config "Wecsvc" start= disabled
sc stop "CaptureService"
sc config "CaptureService" start= disabled

echo --- Disable DiagTrack
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DisableAutomaticTelemetryKeywordReporting" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "TelemetryServiceDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
set F=%TEMP%\al.reg
set F2=%TEMP%\al2.reg
regedit /e "%F%" "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"
powershell -Command "Select-String -Pattern "\"Enabled\"", "\[HKEY", "Windows\sRegistry" -Path \"%F%\" | ForEach-Object {$_.Line} | Foreach-Object {$_ -replace '\"Enabled\"=dword:00000001', '\"Enabled\"=dword:00000000'} | Out-File \"%F2%\""
regedit /s "%F2%"
del "%F%" "%F2%"
del "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\*.etl" "%ProgramData%\Microsoft\Diagnosis\ETLLogs\ShutdownLogger\*.etl"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
echo --- Additional 1
schtasks /change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable
schtasks /change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
echo --- Disable Edge telemetry
sc stop edgeupdate
sc config edgeupdate start= disabled
sc delete edgeupdate
sc stop edgeupdatem
sc config edgeupdatem start= disabled
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "SendSiteInfoToImproveServices" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "SpotlightExperiencesAndRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "configureDoNotTrack" /t REG_DWORD /d "1" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "PaymentMethodQueryEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "LocalProvidersEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "WebWidgetAllowed" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "ResolveNavigationErrorsUseWebService" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "PasswordManagerEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "SiteSafetyServicesEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "TyposquattingCheckerEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "AddressBarMicrosoftSearchInBingProviderEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "AutofillAddressEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "AutofillCreditCardEnabled" /t REG_DWORD /d "0" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "NetworkPredictionOptions" /t REG_DWORD /d "2" /f
reg add "HKU\S-1-5-21-467190835-1795634448-1402218043-1004\SOFTWARE\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SendSiteInfoToImproveServices" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SpotlightExperiencesAndRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "configureDoNotTrack" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PaymentMethodQueryEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "LocalProvidersEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "WebWidgetAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ResolveNavigationErrorsUseWebService" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PasswordManagerEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SiteSafetyServicesEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "TyposquattingCheckerEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "AddressBarMicrosoftSearchInBingProviderEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "AutofillAddressEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "AutofillCreditCardEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "NetworkPredictionOptions" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /v "EnableExtendedBooksTelemetry" /t REG_DWORD /d "0" /f
echo --- Disable Firefox telemetry
sc stop MozillaMaintenance
sc config MozillaMaintenance start= disabled
sc delete MozillaMaintenance
reg add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableTelemetry" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableDefaultBrowserAgent" /t REG_DWORD /d "1" /f
echo --- Tweaks from “Win10Tweaker”
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f
takeown /f C:\Windows\System32\CompatTelRunner.exe
taskkill /im C:\Windows\System32\CompatTelRunner.exe /f
netsh advfirewall firewall add rule name=CompatTelRunner.exe dir=in action=block program=CompatTelRunner.exe & netsh advfirewall firewall add rule name=CompatTelRunner.exe dir=out action=block program=CompatTelRunner.exe
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
takeown /f C:\Windows\System32\mobsync.exe
taskkill /im C:\Windows\System32\mobsync.exe /f
netsh advfirewall firewall add rule name=mobsync.exe dir=in action=block program=mobsync.exe & netsh advfirewall firewall add rule name=mobsync.exe dir=out action=block program=mobsync.exe
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
:: -- Connected Device Platform User Service (CDPUserSvc) - синхронизация и подключение устройств. Если будут проблемы - включить!
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
echo --- Tweaks from “Flibustier”
:: -- Settings > Privacy
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Allow" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Allow" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableRemovableDriveIndexing" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingOutlook" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexOnBattery" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingEmailAttachments" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventRemoteQueries" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "EnableBackupForWin8Apps" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" /v "DisableLogging" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\PerfTrack" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f
Dism /online /disable-Feature /FeatureName:"SMB1Protocol"
Dism /online /disable-Feature /FeatureName:"SMB1Protocol-Client"
Dism /online /disable-Feature /FeatureName:"SMB1Protocol-Server"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB2" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "accesssolution" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "olksolution" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "onenotesolution" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "pptsolution" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "projectsolution" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "publishersolution" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "visiosolution" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "wdsolution" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "xlsolution" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "agave" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "appaddins" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "comaddins" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "documentfiles" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "templatefiles" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Setup" /v "ConcurrentDownloads" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
schtasks /end /tn "\Microsoft\XblGameSave\XblGameSaveTask"
schtasks /change /tn "\Microsoft\XblGameSave\XblGameSaveTask" /disable
schtasks /end /tn "\Microsoft\XblGameSave\XblGameSaveTaskLogon"
schtasks /change /tn "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask"
schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable"
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable
schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy"
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT"
schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent"
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /end /tn "\Microsoft\Windows\DiskFootprint\Diagnostics"
schtasks /change /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks"
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo"
schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific"
schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /change /TN "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /disable
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" /disable
schtasks /end /tn "\Microsoft\Windows\HelloFace\FODCleanupTask"
schtasks /change /tn "\Microsoft\Windows\HelloFace\FODCleanupTask" /disable
schtasks /end /tn "\Microsoft\Windows\Feedback\Siuf\DmClient"
schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClient" /disable
schtasks /end /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask"
schtasks /change /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable
schtasks /end /tn "\Microsoft\Windows\Device Information\Device"
schtasks /change /tn "\Microsoft\Windows\Device Information\Device" /disable
schtasks /end /tn "\Microsoft\Windows\Device Information\Device User"
schtasks /change /tn "\Microsoft\Windows\Device Information\Device User" /disable
echo --- Tweaks from “Pulse”
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f
echo --- Tweaks from “windowser”
SCHTASKS /change /TN "\Microsoft\Windows\WS\WSTask" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /disable
SCHTASKS /change /TN "\Microsoft\Windows\WOF\WIM-Hash-Validation" /disable
SCHTASKS /change /TN "\Microsoft\Windows\WOF\WIM-Hash-Management" /disable
SCHTASKS /change /TN "\Microsoft\Windows\WindowsUpdate\sih" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
SCHTASKS /change /TN "\Microsoft\Windows\WDI\ResolutionHost" /disable
SCHTASKS /change /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" /disable
SCHTASKS /change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" /disable
SCHTASKS /change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" /disable
SCHTASKS /change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /disable
SCHTASKS /change /TN "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" /disable
SCHTASKS /change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /disable
SCHTASKS /change /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /disable
SCHTASKS /change /TN "\Microsoft\Windows\PI\Sqm-Tasks" /disable
SCHTASKS /change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Maintenance\WinSAT" /disable
SCHTASKS /change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
SCHTASKS /change /TN "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /disable
SCHTASKS /change /TN "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /disable
SCHTASKS /change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
SCHTASKS /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
SCHTASKS /change /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
SCHTASKS /change /TN "\Microsoft\Windows\CertificateServicesClient\UserTask-Roam" /disable
SCHTASKS /change /TN "\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" /disable
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d %Prefetch% /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameUX" /v "DownloadGameInfo" /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\config" /v "DownloadMode" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f
REG ADD "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicitedFullControl" /t REG_DWORD /d "0" /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d "0" /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "BlockDomainPicturePassword" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d 3 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v " SpyNetReporting" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v " SubmitSamplesConsent" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
REG delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Id" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "AutoSuggest" /t REG_SZ /d "no" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion" /v "DisableContentFileUpdates" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoSecondLevelCollection" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoFileCollection" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoExternalURL" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
REG ADD "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d 127.0.0.1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Inventory" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Trace" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Compatibility-Infrastructure-Debug" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Analytic" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\ReadyBoot" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\NtfsLog" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\FaceUnlock" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\FaceRecoTel" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-System" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Audio" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableconfigFlighting" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablelogging" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enableupload" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "qmenable" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "sendcustomerdata" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "updatereliabilitydata" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "enabled" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "includescreenshot" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /v "useonlinecontent" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /v "ptwoptin" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablelogging" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enableupload" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "accesssolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "olksolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "onenotesolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "pptsolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "projectsolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "publishersolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "visiosolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "wdsolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "xlsolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "agave" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "appaddins" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "comaddins" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "documentfiles" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "templatefiles" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 2 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "TraceLevelThreshold" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype" /v "EnableTracing" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "EnableTracing" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype" /v "WPPFilePath" /t REG_SZ /d "%%SYSTEMDRIVE%%\TEMP\Tracing\WPPMedia" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "WPPFilePath" /t REG_SZ /d "%%SYSTEMDRIVE%%\TEMP\WPPMedia" /f
DEL "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /s
DEL "C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /s
ATTRIB -r "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
ECHO "" > C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
ATTRIB +r "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
ATTRIB -r "C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
ECHO "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
ATTRIB +r "C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
ECHO ********** Remove folders from This PC or MyComputer menu
REG delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}" /f
REG delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
REG delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{2B20DF75-1EDA-4039-8097-38798227D5B7}" /f
REG delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
REG delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
REG delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
REG delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
REG delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
REG delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
REG delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f
REG delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f
REG delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /f
REG delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /f
REG delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f
REG delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f
ECHO ********** Change Clock and Date formats 24H, metric (Sign out required to see changes)
REG ADD "HKCU\Control Panel\International" /v "iMeasure" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\International" /v "iNegCurr" /t REG_SZ /d "1" /f
REG ADD "HKCU\Control Panel\International" /v "iTime" /t REG_SZ /d "1" /f
REG ADD "HKCU\Control Panel\International" /v "sShortDate" /t REG_SZ /d "dd.MM.yyyy" /f
REG ADD "HKCU\Control Panel\International" /v "sShortTime" /t REG_SZ /d "HH:mm" /f
REG ADD "HKCU\Control Panel\International" /v "sTimeFormat" /t REG_SZ /d "H:mm:ss" /f
ECHO ********** Turn OFF Sticky Keys when SHIFT is pressed 5 times
REG ADD "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
GOTO RESTART
:BLOCK
ECHO ********** Block hosts
COPY "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.backup.txt"
ATTRIB -r "%WINDIR%\system32\drivers\etc\hosts"
SET HOSTS=%WINDIR%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1oavsblobprodcus350.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 37bvsblobprodcus311.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 a.ads1.msn.com>>%HOSTS%
ECHO 0.0.0.0 a.ads2.msads.net>>%HOSTS%
ECHO 0.0.0.0 a.ads2.msn.com>>%HOSTS%
ECHO 0.0.0.0 a.rad.msn.com>>%HOSTS%
ECHO 0.0.0.0 ac3.msn.com>>%HOSTS%
ECHO 0.0.0.0 adnexus.net>>%HOSTS%
ECHO 0.0.0.0 adnxs.com>>%HOSTS%
ECHO 0.0.0.0 ads.msn.com>>%HOSTS%
ECHO 0.0.0.0 ads1.msads.net>>%HOSTS%
ECHO 0.0.0.0 ads1.msn.com>>%HOSTS%
ECHO 0.0.0.0 aidps.atdmt.com>>%HOSTS%
ECHO 0.0.0.0 aka-cdn-ns.adtech.de>>%HOSTS%
ECHO 0.0.0.0 alpha.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 api.cortana.ai>>%HOSTS%
ECHO 0.0.0.0 api.edgeoffer.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 asimov-win.settings.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 azwancan.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 b.ads1.msn.com>>%HOSTS%
ECHO 0.0.0.0 b.ads2.msads.net>>%HOSTS%
ECHO 0.0.0.0 b.rad.msn.com>>%HOSTS%
ECHO 0.0.0.0 bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 blobcollector.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 bn2-ris-ap-prod-atm.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 bn2-ris-prod-atm.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 bn2wns1.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020010558.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020010560.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020010618.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020010629.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020010631.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020010635.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020010636.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020010650.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020011727.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020012850.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020020322.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020020749.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020022328.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020022335.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020022361.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101120814.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101120818.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101120911.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101120913.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121019.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121109.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121118.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121223.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121407.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121618.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121704.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121709.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121714.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121908.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101122117.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101122310.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101122312.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101122421.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101123108.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101123110.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101123202.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch102110124.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 browser.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bs.serving-sys.com>>%HOSTS%
ECHO 0.0.0.0 c.atdmt.com>>%HOSTS%
ECHO 0.0.0.0 c.msn.com>>%HOSTS%
ECHO 0.0.0.0 ca.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 cache.datamart.windows.com>>%HOSTS%
ECHO 0.0.0.0 cdn.atdmt.com>>%HOSTS%
ECHO 0.0.0.0 cds1.stn.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds10.stn.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds27.ory.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1203.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1204.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1209.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1219.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1228.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1244.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1257.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1265.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1269.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1273.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1285.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1287.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1289.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1293.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1307.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1310.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1325.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds1327.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds177.dus.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20005.stn.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20404.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20411.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20415.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20416.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20417.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20424.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20425.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20431.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20435.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20440.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20443.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20445.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20450.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20452.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20457.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20461.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20469.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20475.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20482.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20485.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds20495.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21205.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21207.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21225.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21229.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21233.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21238.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21244.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21249.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21256.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21257.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21258.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21261.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21267.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21278.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21281.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21293.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21309.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21313.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds21321.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds299.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds308.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds30027.stn.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds310.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds38.ory.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds54.ory.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds405.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds406.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds407.fra.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds416.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds421.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds422.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds425.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds426.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds447.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds458.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds459.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds46.ory.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds461.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds468.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds469.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds471.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds483.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds484.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds489.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds493.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds494.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds812.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds815.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds818.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds832.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds836.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds840.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds843.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds857.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds868.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds869.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 ceuswatcab01.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 ceuswatcab02.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 compatexchange1.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 corp.sts.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 cs1.wpc.v0cdn.net>>%HOSTS%
ECHO 0.0.0.0 cy2.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 db3aqu.atdmt.com>>%HOSTS%
ECHO 0.0.0.0 db5.settings.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 db5.settings-win.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 db5.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 db5-eap.settings-win.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 df.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 diagnostics.support.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 eaus2watcab01.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 eaus2watcab02.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 ec.atdmt.com>>%HOSTS%
ECHO 0.0.0.0 flex.msn.com>>%HOSTS%
ECHO 0.0.0.0 g.msn.com>>%HOSTS%
ECHO 0.0.0.0 geo.settings.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 geo.settings-win.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 geo.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 h1.msn.com>>%HOSTS%
ECHO 0.0.0.0 h2.msn.com>>%HOSTS%
ECHO 0.0.0.0 hk2.settings.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 hk2.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020721.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020723.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020726.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020729.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020732.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020824.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020843.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020851.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020854.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020855.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020924.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020936.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020940.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020956.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020958.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130020961.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021017.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021029.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021035.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021137.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021142.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021153.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021217.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021246.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021249.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021260.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021264.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021322.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021323.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021329.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021334.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021360.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021432.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021433.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021435.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021437.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021440.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021450.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021518.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021523.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021526.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021527.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021544.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021554.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021618.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021634.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021638.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021646.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021652.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021654.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021657.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021723.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021726.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021727.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021730.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021731.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021754.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021829.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021830.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021833.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021840.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021842.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021851.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021852.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021927.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021928.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021929.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130021958.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130022035.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130022041.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130022049.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2sch130022135.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2wns1.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 hk2wns1b.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 ieonlinews.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ieonlinews.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 insideruser.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 kmwatson.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 kmwatsonc.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 lb1.www.ms.akadns.net>>%HOSTS%
ECHO 0.0.0.0 live.rads.msn.com>>%HOSTS%
ECHO 0.0.0.0 m.adnxs.com>>%HOSTS%
ECHO 0.0.0.0 mobile.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 modern.watson.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 msedge.net>>%HOSTS%
ECHO 0.0.0.0 msntest.serving-sys.com>>%HOSTS%
ECHO 0.0.0.0 nexus.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 nexusrules.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 nw-umwatson.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 oca.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 oca.telemetry.microsoft.us>>%HOSTS%
ECHO 0.0.0.0 onecollector.cloudapp.aria.akadns.net>>%HOSTS%
ECHO 0.0.0.0 par02p.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 pre.footprintpredict.com>>%HOSTS%
ECHO 0.0.0.0 presence.teams.live.com>>%HOSTS%
ECHO 0.0.0.0 preview.msn.com>>%HOSTS%
ECHO 0.0.0.0 rad.live.com>>%HOSTS%
ECHO 0.0.0.0 rad.msn.com>>%HOSTS%
ECHO 0.0.0.0 redir.metaservices.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 romeccs.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 schemas.microsoft.akadns.net>>%HOSTS%
ECHO 0.0.0.0 secure.adnxs.com>>%HOSTS%
ECHO 0.0.0.0 secure.flashtalking.com>>%HOSTS%
ECHO 0.0.0.0 services.wes.df.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 settings-sandbox.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 settings-win-ppe.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 settings.data.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 settingsfd-geo.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 sg2p.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 spynet2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 spynetalt.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 spyneteurope.microsoft.akadns.net>>%HOSTS%
ECHO 0.0.0.0 sqm.df.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 sqm.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 ssw.live.com>>%HOSTS%
ECHO 0.0.0.0 survey.watson.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 tele.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 telecommand.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 telemetry.appex.bing.net>>%HOSTS%
ECHO 0.0.0.0 telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 telemetry.remoteapp.windowsazure.com>>%HOSTS%
ECHO 0.0.0.0 telemetry.urs.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 teredo.ipv6.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 test.activity.windows.com>>%HOSTS%
ECHO 0.0.0.0 uks.b.prd.ags.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 umwatson.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 umwatsonc.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 umwatsonc.telemetry.microsoft.us>>%HOSTS%
ECHO 0.0.0.0 v10.vortex-win.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 v10-win.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 v20.vortex-win.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 view.atdmt.com>>%HOSTS%
ECHO 0.0.0.0 vortex-sandbox.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 vortex.data.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 vortex.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 watson.live.com>>%HOSTS%
ECHO 0.0.0.0 watson.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 watson.ppe.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 watson.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 web.vortex.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 wes.df.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 weus2watcab01.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 weus2watcab02.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 win10.ipv6.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 win1710.ipv6.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 win8.ipv6.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 xblgdvrassets3010.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 ztd.dds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 www.trust.office365.com>>%HOSTS%
ECHO 0.0.0.0 www.moskisvet.com.c.footprint.net>>%HOSTS%
ECHO 0.0.0.0 www.cisco.com>>%HOSTS%
ECHO 0.0.0.0 wusonprem.ipv6.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 wdcpeurope.microsoft.akadns.net>>%HOSTS%
ECHO 0.0.0.0 watson.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 vortex-db5.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 vd.vidfuture.com>>%HOSTS%
ECHO 0.0.0.0 v4ncsi.msedge.net>>%HOSTS%
ECHO 0.0.0.0 v20-asimov-win.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 us.vortex-win.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 urs.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 trouter-neu-a.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 trouter-easia-a.dc.trouter.io>>%HOSTS%
ECHO 0.0.0.0 telemetry.appex.search.prod.ms.akadns.net>>%HOSTS%
ECHO 0.0.0.0 tapeytapey.com>>%HOSTS%
ECHO 0.0.0.0 t.urs.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 t.urs.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 statsfe2-df.ws.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 statsfe2.ws.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 statsfe2.ws.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 statsfe2.update.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 stats.update.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 static.sl-reverse.com>>%HOSTS%
ECHO 0.0.0.0 ssw.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 sqm.msn.com>>%HOSTS%
ECHO 0.0.0.0 sonybank.net>>%HOSTS%
ECHO 0.0.0.0 settings-sandbox.data.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 service.xbox.com>>%HOSTS%
ECHO 0.0.0.0 secure-ams.adnxs.com>>%HOSTS%
ECHO 0.0.0.0 sact.atdmt.com>>%HOSTS%
ECHO 0.0.0.0 s0.2mdn.net>>%HOSTS%
ECHO 0.0.0.0 s.outlook.com>>%HOSTS%
ECHO 0.0.0.0 rmads.msn.com>>%HOSTS%
ECHO 0.0.0.0 realgames.cn>>%HOSTS%
ECHO 0.0.0.0 pipe.skype.com>>%HOSTS%
ECHO 0.0.0.0 perthnow.com.au>>%HOSTS%
ECHO 0.0.0.0 osiprod-weu-snow-000.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 oca.watson.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 nt-c.ns.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 nt-b.ns.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 ns3.msft.net>>%HOSTS%
ECHO 0.0.0.0 ns3.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 ns2.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 ns1.gslb.com>>%HOSTS%
ECHO 0.0.0.0 ns1.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 nl-1.ns.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 next-services.windows.akadns.net>>%HOSTS%
ECHO 0.0.0.0 new_wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 msnbot-65-55-108-23.search.msn.com>>%HOSTS%
ECHO 0.0.0.0 msnbot-64-4-54-18.search.msn.com>>%HOSTS%
ECHO 0.0.0.0 msnbot-207-46-194-46.search.msn.com>>%HOSTS%
ECHO 0.0.0.0 msnbot-207-46-194-33.search.msn.com>>%HOSTS%
ECHO 0.0.0.0 msnbot-207-46-194-29.search.msn.com>>%HOSTS%
ECHO 0.0.0.0 msnbot-207-46-194-25.search.msn.com>>%HOSTS%
ECHO 0.0.0.0 msnbot-207-46-194-14.search.msn.com>>%HOSTS%
ECHO 0.0.0.0 ms1-ib.adnxs.com>>%HOSTS%
ECHO 0.0.0.0 mm.bing.net>>%HOSTS%
ECHO 0.0.0.0 microsoft22.com>>%HOSTS%
ECHO 0.0.0.0 microsoft21.com>>%HOSTS%
ECHO 0.0.0.0 microsoft20.com>>%HOSTS%
ECHO 0.0.0.0 microsoft17.com>>%HOSTS%
ECHO 0.0.0.0 microsoft16.com>>%HOSTS%
ECHO 0.0.0.0 microsoft15.com>>%HOSTS%
ECHO 0.0.0.0 microsoft14.com>>%HOSTS%
ECHO 0.0.0.0 microsoft13.com>>%HOSTS%
ECHO 0.0.0.0 microsoft12.com>>%HOSTS%
ECHO 0.0.0.0 microsoft11.com>>%HOSTS%
ECHO 0.0.0.0 microsoft10.com>>%HOSTS%
ECHO 0.0.0.0 microsoft09.com>>%HOSTS%
ECHO 0.0.0.0 microsoft08.com>>%HOSTS%
ECHO 0.0.0.0 microsoft07.com>>%HOSTS%
ECHO 0.0.0.0 microsoft06.com>>%HOSTS%
ECHO 0.0.0.0 microsoft05.com>>%HOSTS%
ECHO 0.0.0.0 microsoft04.com>>%HOSTS%
ECHO 0.0.0.0 microsoft03.com>>%HOSTS%
ECHO 0.0.0.0 microsoft02.com>>%HOSTS%
ECHO 0.0.0.0 microsoft01.com>>%HOSTS%
ECHO 0.0.0.0 microsoft.com>>%HOSTS%
ECHO 0.0.0.0 mediaroomsds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 media.blinkbox.com.c.footprint.net>>%HOSTS%
ECHO 0.0.0.0 legacy.watson.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 inside.microsoftmse.com>>%HOSTS%
ECHO 0.0.0.0 iact.atdmt.com>>%HOSTS%
ECHO 0.0.0.0 i4.services.social.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 i1.services.social.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 hp-comm.ca.msn.com>>%HOSTS%
ECHO 0.0.0.0 helloaddress.com>>%HOSTS%
ECHO 0.0.0.0 globalns2.appnexus.net>>%HOSTS%
ECHO 0.0.0.0 geo-prod.dodsp.mp.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 geo-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 float.2655.bm-impbus.prod.ams1.adnexus.net>>%HOSTS%
ECHO 0.0.0.0 float.2113.bm-impbus.prod.ams1.adnexus.net>>%HOSTS%
ECHO 0.0.0.0 float.1334.bm-impbus.prod.fra1.adnexus.net>>%HOSTS%
ECHO 0.0.0.0 float.1332.bm-impbus.prod.fra1.adnexus.net>>%HOSTS%
ECHO 0.0.0.0 float.1143.bm-impbus.prod.fra1.adnexus.net>>%HOSTS%
ECHO 0.0.0.0 fesweb1.ch1d.binginternal.com>>%HOSTS%
ECHO 0.0.0.0 fe3.delivery.dsp.mp.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 fd-rad-msn-com.a-0004.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 fashiontamils.com>>%HOSTS%
ECHO 0.0.0.0 exch-eu.atdmt.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 evoke-windowsservices-tas.msedge.net>>%HOSTS%
ECHO 0.0.0.0 eu.vortex-win.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 es-1.ns.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 edge-atlas-shv-01-cdg2.facebook.com>>%HOSTS%
ECHO 0.0.0.0 e8218.ce.akamaiedge.net>>%HOSTS%
ECHO 0.0.0.0 e6845.ce.akamaiedge.net>>%HOSTS%
ECHO 0.0.0.0 dub109-afx.ms.a-0009.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 dps.msn.com>>%HOSTS%
ECHO 0.0.0.0 dmd.metaservices.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 dmd.metaservices.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 diagnostics.support.microsoft.akadns.net>>%HOSTS%
ECHO 0.0.0.0 descargas.diximedia.es.c.footprint.net>>%HOSTS%
ECHO 0.0.0.0 deploy.static.akamaitechnologies.com>>%HOSTS%
ECHO 0.0.0.0 deploy.akamaitechnologies.com>>%HOSTS%
ECHO 0.0.0.0 db5.wns.notify.windows.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 db5.displaycatalog.md.mp.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 db3wns2011111.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 dart.l.doubleclick.net>>%HOSTS%
ECHO 0.0.0.0 cy2.settings.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 cs697.wac.thetacdn.net>>%HOSTS%
ECHO 0.0.0.0 cs479.wac.edgecastcdn.net>>%HOSTS%
ECHO 0.0.0.0 compatexchange.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 colonialtoolset.com>>%HOSTS%
ECHO 0.0.0.0 col130-afx.ms.a-0008.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 co4.telecommand.telemetry.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 cn.msn.fr>>%HOSTS%
ECHO 0.0.0.0 choice.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 chinamobileltd.com>>%HOSTS%
ECHO 0.0.0.0 cdn.energetichabits.com>>%HOSTS%
ECHO 0.0.0.0 cdn.deezer.com.c.footprint.net>>%HOSTS%
ECHO 0.0.0.0 cannon-construction.co.uk>>%HOSTS%
ECHO 0.0.0.0 candycrushsoda.king.com>>%HOSTS%
ECHO 0.0.0.0 c.nine.com.au>>%HOSTS%
ECHO 0.0.0.0 c.microsoft.akadns.net>>%HOSTS%
ECHO 0.0.0.0 bsnl.eyeblaster.akadns.net>>%HOSTS%
ECHO 0.0.0.0 bots.teams.skype.com>>%HOSTS%
ECHO 0.0.0.0 bn2.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 blu173-mail-live-com.a-0006.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 beta.t.urs.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bay175-mail-live-com.a-0007.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 b.ns.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 auth.nym2.appnexus.net>>%HOSTS%
ECHO 0.0.0.0 auth.lax1.appnexus.net>>%HOSTS%
ECHO 0.0.0.0 auth.ams1.appnexus.net>>%HOSTS%
ECHO 0.0.0.0 assets2.parliament.uk.c.footprint.net>>%HOSTS%
ECHO 0.0.0.0 assets.dishonline.com.c.footprint.net>>%HOSTS%
ECHO 0.0.0.0 asimov-sandbox.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 array204-prod.dodsp.mp.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 apnic.net>>%HOSTS%
ECHO 0.0.0.0 a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 ams1-ib.adnxs.com>>%HOSTS%
ECHO 0.0.0.0 ampudc.udc0.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 akadns.info>>%HOSTS%
ECHO 0.0.0.0 ad.doubleclick.net>>%HOSTS%
ECHO 0.0.0.0 acyfdr.explicit.bing.net>>%HOSTS%
ECHO 0.0.0.0 www.msn.com>>%HOSTS%
ECHO 0.0.0.0 www.msftncsi.com>>%HOSTS%
ECHO 0.0.0.0 www.msdn.com>>%HOSTS%
ECHO 0.0.0.0 www.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 www.bing.com>>%HOSTS%
ECHO 0.0.0.0 wustats.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 wns.notify.windows.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 windowsupdate.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 win10.ipv6.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 wildcard.appex-rf.msn.com.edgesuite.net>>%HOSTS%
ECHO 0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 vortex-win.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 vortex-cy2.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 vortex-bn2.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 v10.vortex-win.data.metron.life.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 ui.skype.com>>%HOSTS%
ECHO 0.0.0.0 travel.tile.appex.bing.com>>%HOSTS%
ECHO 0.0.0.0 telemetry.appex.bing.net:443>>%HOSTS%
ECHO 0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 support.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 statsfe1.ws.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 static.2mdn.net>>%HOSTS%
ECHO 0.0.0.0 sls.update.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 skydrive.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 skyapi.skyprod.akadns.net>>%HOSTS%
ECHO 0.0.0.0 skyapi.live.net>>%HOSTS%
ECHO 0.0.0.0 settings-win.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 sO.2mdn.net>>%HOSTS%
ECHO 0.0.0.0 s.gateway.messenger.live.com>>%HOSTS%
ECHO 0.0.0.0 register.mesh.com>>%HOSTS%
ECHO 0.0.0.0 pricelist.skype.com>>%HOSTS%
ECHO 0.0.0.0 office.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 msdn.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 microsoftupdate.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 microsoftupdate.com>>%HOSTS%
ECHO 0.0.0.0 m.hotmail.com>>%HOSTS%
ECHO 0.0.0.0 login.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 ipv6.msftncsi.com.edgesuite.net>>%HOSTS%
ECHO 0.0.0.0 i1.services.social.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 go.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 feedback.windows.com>>%HOSTS%
ECHO 0.0.0.0 feedback.search.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 feedback.microsoft-hohm.com>>%HOSTS%
ECHO 0.0.0.0 fe3.delivery.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 en-us.appex-rf.msn.com>>%HOSTS%
ECHO 0.0.0.0 download.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 dns.msftncsi.com>>%HOSTS%
ECHO 0.0.0.0 directory.services.live.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 client.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 cds26.ams9.msecn.net>>%HOSTS%
ECHO 0.0.0.0 bl3302geo.storage.dkyprod.akadns.net>>%HOSTS%
ECHO 0.0.0.0 bl3302.storage.live.com>>%HOSTS%
ECHO 0.0.0.0 az512334.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az361816.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 apps.skype.com>>%HOSTS%
ECHO 0.0.0.0 any.edge.bing.com>>%HOSTS%
ECHO 0.0.0.0 americas2.notify.windows.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 a978.i6g1.akamai.net>>%HOSTS%
ECHO 0.0.0.0 a-0009.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0008.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0007.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0006.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0005.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0004.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0003.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0002.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0001.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 OneSettings-bn2.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 BN1WNS2011508.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 about.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 learninglab.about.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 about-test.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 about-test-deploy.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 adlibrary.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bcp.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 beta.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 api.beta.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 beta-about.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 developers.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 dmc.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 help.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 mmcapi.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 smetric.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 status.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 tip.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 api.tip.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ucm.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ui.ads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ads-int.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clientcenter.ads-int.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 api.clientcenter.ads-int.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 dmc.ads-int.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 beta.dmc.ads-int.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 help.ads-int.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ui.ads-int.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 adsdk.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 adsstatic.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 beta.adsstatic.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 adsstatic-int.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 advertising.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 community.advertising.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 fp.advertising.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 sts.advertising.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 analyticspixel.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 academycourses.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 adinquiry.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ads.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 advertise.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 www.advertise.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 api.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 adinsight.api.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bulk.api.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 campaign.api.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clientcenter.api.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 partner.api.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 reporting.api.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 azure.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 secure.azure.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bc.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 secure.bc.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bcp.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ui.bcp.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 beta.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ch1b.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 community.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 developers.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 fd.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 help.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 reportingapi.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 sandbox.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bulk.api.sandbox.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 campaign.api.sandbox.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clientcenter.api.sandbox.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 reporting.api.sandbox.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 secure.sandbox.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 secure.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 si.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ui.si.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 tip.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ucm.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ui.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bingadseditor.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 c1.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 track.notif.careersppe.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clarity.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 adsdisplay.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 aisefs.adsdisplay.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bingads.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 si.bingads.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 track.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 dm3.track.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 analytics.pstnhub.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 www.telecommandsvc.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 microsoftadvertising.com>>%HOSTS%
ECHO 0.0.0.0 microsoftcrowdstrike.com>>%HOSTS%
ECHO 0.0.0.0 www.microsoftcrowdstrike.com>>%HOSTS%
ECHO 0.0.0.0 microsoftsupportservices.com>>%HOSTS%
ECHO 0.0.0.0 microsoft-aunz-d.openx.net>>%HOSTS%
ECHO 0.0.0.0 microsoft-d.openx.net>>%HOSTS%
ECHO 0.0.0.0 microsoftwindows.112.2o7.net>>%HOSTS%
ECHO 0.0.0.0 microsoftwlsearchcrm.112.2o7.net>>%HOSTS%
ECHO 0.0.0.0 analytics.awview.andersenwindows.com>>%HOSTS%
ECHO 0.0.0.0 a-0001.dc-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0003.dc-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0010.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0011.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-0012.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 activity.windows.com>>%HOSTS%
ECHO 0.0.0.0 array101-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array102-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array103-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array104-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array201-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array202-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array203-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array204-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array401-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array402-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array403-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array404-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array405-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array406-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array407-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 array408-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bl3301-a.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bl3301-c.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bl3301-g.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bn1304-e.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bn1306-a.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bn1306-e.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bn1306-g.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bn2b-cor001.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bn2b-cor002.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bn2b-cor003.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bn2b-cor004.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 bn3p-cor001.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 by3301-a.1drv.com>>%HOSTS%
ECHO 0.0.0.0 by3301-c.1drv.com>>%HOSTS%
ECHO 0.0.0.0 by3301-e.1drv.com>>%HOSTS%
ECHO 0.0.0.0 c-0001.dc-msedge.net>>%HOSTS%
ECHO 0.0.0.0 cds965.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 ch1-cor001.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 ch1-cor002.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 ch3301-c.1drv.com>>%HOSTS%
ECHO 0.0.0.0 ch3301-e.1drv.com>>%HOSTS%
ECHO 0.0.0.0 ch3301-g.1drv.com>>%HOSTS%
ECHO 0.0.0.0 ch3302-c.1drv.com>>%HOSTS%
ECHO 0.0.0.0 ch3302-e.1drv.com>>%HOSTS%
ECHO 0.0.0.0 continuum.dds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 cp101-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 cp201-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 cp401-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 db5.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101100122.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101100127.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101100831.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101100835.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101100917.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101100925.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101100928.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101100938.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101001.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101022.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101024.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101031.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101034.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101042.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101044.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101122.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101123.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101125.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101128.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101129.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101133.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101145.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101209.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101221.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101228.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101231.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101237.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101317.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101324.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101329.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101333.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101334.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101338.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101419.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101424.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101426.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101427.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101430.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101445.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101511.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101519.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101529.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101535.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101541.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101543.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101608.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101618.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101629.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101631.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101633.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101640.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101711.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101722.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101739.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101745.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101813.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101820.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101826.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101828.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101835.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101837.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101844.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101902.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101907.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101910.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101914.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101929.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101939.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101101941.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101102015.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101102017.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101102019.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101102023.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101102025.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101102032.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101102033.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110108.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110109.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110114.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110135.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110142.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110204.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110206.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110214.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110225.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110232.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110245.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110315.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110323.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110325.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110328.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110331.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110341.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110343.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110345.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110403.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110419.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110428.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110435.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110438.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110442.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110501.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110510.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110518.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110527.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110533.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110618.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110621.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110622.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110624.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110626.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110634.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110705.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110713.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110724.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110729.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110740.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110810.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110816.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110821.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110822.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110825.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110828.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110829.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110831.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110835.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110919.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110921.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110923.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110929.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103081814.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103081913.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103082011.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103082111.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103082308.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103082406.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103082409.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103082609.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103082611.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103082709.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103082712.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103082806.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103090115.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103090210.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103090414.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103090415.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103090513.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103090515.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103090608.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103090806.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103090814.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103090906.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091011.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091012.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091106.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091108.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091212.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091311.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091313.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091414.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091511.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091609.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091617.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091715.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091817.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091908.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103091911.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103092010.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103092108.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103092109.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103092209.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103092210.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103092509.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103100117.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103100121.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103100221.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103100313.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103100314.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103100412.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103100510.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103100511.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103100611.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103100712.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101105.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101208.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101212.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101314.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101411.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101413.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101513.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101610.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101611.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101705.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101711.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101813.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101909.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103101914.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102009.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102112.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102203.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102209.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102310.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102404.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102410.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102609.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102610.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102710.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102711.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102805.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5wns1d.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090104.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090109.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090112.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090116.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090122.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090203.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090206.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090208.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090209.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090210.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090211.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090212.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090305.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090306.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090308.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090311.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090313.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090410.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090412.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090504.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090510.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090512.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090513.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090514.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090519.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090613.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090619.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090810.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090811.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090902.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090905.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090907.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090908.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090910.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102090911.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091003.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091007.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091008.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091009.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091011.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091103.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091105.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091204.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091205.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091209.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091305.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091307.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091308.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091309.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091314.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091412.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091503.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091507.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091508.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091602.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091603.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091606.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db6sch102091607.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 dev.virtualearth.net>>%HOSTS%
ECHO 0.0.0.0 disc101-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 disc201-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 disc401-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ecn.dev.virtualearth.net>>%HOSTS%
ECHO 0.0.0.0 eu.vortex.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 fs.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 geover-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 i-bl6p-cor001.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 i-bl6p-cor002.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 i-bn3p-cor001.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 i-by3p-cor001.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 i-by3p-cor002.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 i-ch1-cor001.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 i-ch1-cor002.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 i-sn2-cor001.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 i-sn2-cor002.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 inference.location.live.net>>%HOSTS%
ECHO 0.0.0.0 kv101-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 kv201-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 kv401-prod.do.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ls2web.redmond.corp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 onesettings-bn2.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 onesettings-cy2.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 onesettings-db5.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 onesettings-hk2.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 settings.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 sn3301-c.1drv.com>>%HOSTS%
ECHO 0.0.0.0 sn3301-e.1drv.com>>%HOSTS%
ECHO 0.0.0.0 sn3301-g.1drv.com>>%HOSTS%
ECHO 0.0.0.0 storecatalogrevocation.storequality.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 t0.ssl.ak.dynamic.tiles.virtualearth.net>>%HOSTS%
ECHO 0.0.0.0 t0.ssl.ak.tiles.virtualearth.net>>%HOSTS%
ECHO 0.0.0.0 tsfe.trafficshaping.dsp.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 v10.vortex-win.data.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 version.hybrid.api.here.com>>%HOSTS%
ECHO 0.0.0.0 vortex-hk2.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 vortex-win.data.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 vortex.data.metron.live.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 www.msedge.net>>%HOSTS%
ECHO 0.0.0.0 answers.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ars.smartscreen.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 blob.weather.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 cdn.content.prod.cms.msn.com>>%HOSTS%
ECHO 0.0.0.0 cdn.onenote.net>>%HOSTS%
ECHO 0.0.0.0 choice.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 client-s.gateway.messenger.live.com>>%HOSTS%
ECHO 0.0.0.0 clientconfig.passport.net>>%HOSTS%
ECHO 0.0.0.0 device.auth.xboxlive.com>>%HOSTS%
ECHO 0.0.0.0 g.live.com>>%HOSTS%
ECHO 0.0.0.0 iecvlist.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 img-s-msn-com.akamaized.net>>%HOSTS%
ECHO 0.0.0.0 insiderppe.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 insiderservice.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 licensing.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 login.live.com>>%HOSTS%
ECHO 0.0.0.0 mediaredirect.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 msftncsi.com>>%HOSTS%
ECHO 0.0.0.0 officeclient.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 oneclient.sfx.ms>>%HOSTS%
ECHO 0.0.0.0 pti.store.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 query.prod.cms.rt.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 register.cdpcs.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 search.msn.com>>%HOSTS%
ECHO 0.0.0.0 settings-ssl.xboxlive.com>>%HOSTS%
ECHO 0.0.0.0 storage.live.com>>%HOSTS%
ECHO 0.0.0.0 store-images.s-microsoft.com>>%HOSTS%
ECHO 0.0.0.0 storeedgefd.dsx.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 tile-service.weather.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 time.windows.com>>%HOSTS%
ECHO 0.0.0.0 tk2.plt.msn.com>>%HOSTS%
ECHO 0.0.0.0 urs.smartscreen.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 wdcp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 wdcpalt.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 win10-trt.msedge.net>>%HOSTS%
ECHO 0.0.0.0 wscont.apps.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 www.msftconnecttest.com>>%HOSTS%
ECHO 0.0.0.0 000202-1.l.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 0002c3-1.l.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 0002fd-1.l.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 00149f-1.l.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 001891-1.l.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 001f23-1.l.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 002062-1.l.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 0021d0-1.l.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 au.download.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 au.v4.download.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 ctldl.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 db5sch101110408.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 db5sch103102516.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 displaycatalog.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 dl.delivery.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 download.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 emdl.ws.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 fe2.update.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 fe2.update.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 fg.ds.b1.download.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 fg.v4.download.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 microsoftwindowsupdate.net>>%HOSTS%
ECHO 0.0.0.0 sls.update.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 tlu.dl.delivery.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 v4.download.windowsupdate.com>>%HOSTS%
ECHO 0.0.0.0 windowupdate.org>>%HOSTS%
ECHO 0.0.0.0 adl.windows.com>>%HOSTS%
ECHO 0.0.0.0 activation.sls.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 activation-v2.sls.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 api.bing.com>>%HOSTS%
ECHO 0.0.0.0 appex-rf.msn.com>>%HOSTS%
ECHO 0.0.0.0 co2.sls.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 crl.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 finance.services.appex.bing.com>>%HOSTS%
ECHO 0.0.0.0 foodanddrink.tile.appex.bing.com>>%HOSTS%
ECHO 0.0.0.0 fr-fr.appex-rf.msn.com>>%HOSTS%
ECHO 0.0.0.0 g.bing.com>>%HOSTS%
ECHO 0.0.0.0 global.sam.msn.com>>%HOSTS%
ECHO 0.0.0.0 img.stb.s-msn.com>>%HOSTS%
ECHO 0.0.0.0 next-services.apps.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 otf.msn.com>>%HOSTS%
ECHO 0.0.0.0 r20swj13mr.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 service.weather.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 uhf.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 urs.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 validation.sls.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 validation-v2.sls.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 w.apprep.smartscreen.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 wscont.apps.microsoft.com.edgesuite.net>>%HOSTS%
ECHO 0.0.0.0 wscont2.apps.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 wscont1.apps.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 www.windowssearch.com>>%HOSTS%
ECHO 0.0.0.0 0bj2epfqn1.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 0mo5a70cqa.adobe.io>>%HOSTS%
ECHO 0.0.0.0 0n8wirm0nv.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 100.24.211.130>>%HOSTS%
ECHO 0.0.0.0 124hzdrtoi.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 13.227.103.57>>%HOSTS%
ECHO 0.0.0.0 162.247.242.20>>%HOSTS%
ECHO 0.0.0.0 17ov1u3gio.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 17vpu0xkm6.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 18.207.85.246>>%HOSTS%
ECHO 0.0.0.0 18.228.243.121>>%HOSTS%
ECHO 0.0.0.0 18.230.164.221>>%HOSTS%
ECHO 0.0.0.0 192.150.14.69>>%HOSTS%
ECHO 0.0.0.0 192.150.18.101>>%HOSTS%
ECHO 0.0.0.0 192.150.18.108>>%HOSTS%
ECHO 0.0.0.0 192.150.22.40>>%HOSTS%
ECHO 0.0.0.0 192.150.8.100>>%HOSTS%
ECHO 0.0.0.0 192.150.8.118>>%HOSTS%
ECHO 0.0.0.0 199.232.114.137>>%HOSTS%
ECHO 0.0.0.0 199.7.52.190>>%HOSTS%
ECHO 0.0.0.0 199.7.52.190:80>>%HOSTS%
ECHO 0.0.0.0 199.7.54.72>>%HOSTS%
ECHO 0.0.0.0 199.7.54.72:80>>%HOSTS%
ECHO 0.0.0.0 1b9khekel6.adobe.io>>%HOSTS%
ECHO 0.0.0.0 1ei1f4k9yk.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 1hzopx6nz7.adobe.io>>%HOSTS%
ECHO 0.0.0.0 1qwiekvkux.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 1tw2l9x7xb.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 1unk1rv07w.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 1xuyy0mk2p.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 209-34-83-73.ood.opsource.net>>%HOSTS%
ECHO 0.0.0.0 209.34.83.67>>%HOSTS%
ECHO 0.0.0.0 209.34.83.67:43>>%HOSTS%
ECHO 0.0.0.0 209.34.83.67:443>>%HOSTS%
ECHO 0.0.0.0 209.34.83.73>>%HOSTS%
ECHO 0.0.0.0 209.34.83.73:43>>%HOSTS%
ECHO 0.0.0.0 209.34.83.73:443>>%HOSTS%
ECHO 0.0.0.0 220zxtbjjl.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 23.22.30.141>>%HOSTS%
ECHO 0.0.0.0 23ynjitwt5.adobe.io>>%HOSTS%
ECHO 0.0.0.0 2621x1nzeq.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 28t4psttw7.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 2dhh9vsp39.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 2eiuxr4ky7.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 2ftem87osk.adobe.io>>%HOSTS%
ECHO 0.0.0.0 2o3c6rbyfr.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 2qj10f8rdg.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 2qjz50z5lf.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 3.208.248.199>>%HOSTS%
ECHO 0.0.0.0 3.216.32.253>>%HOSTS%
ECHO 0.0.0.0 3.219.243.226>>%HOSTS%
ECHO 0.0.0.0 3.220.11.113>>%HOSTS%
ECHO 0.0.0.0 3.221.72.231>>%HOSTS%
ECHO 0.0.0.0 31q40256l4.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 34.192.151.90>>%HOSTS%
ECHO 0.0.0.0 34.215.42.13>>%HOSTS%
ECHO 0.0.0.0 34.237.241.83>>%HOSTS%
ECHO 0.0.0.0 34u96h6rvn.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 3aqshzqv3w.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 3ca52znvmj.adobe.io>>%HOSTS%
ECHO 0.0.0.0 3d3wqt96ht.adobe.io>>%HOSTS%
ECHO 0.0.0.0 3dns-1.adobe.com>>%HOSTS%
ECHO 0.0.0.0 3dns-2.adobe.com>>%HOSTS%
ECHO 0.0.0.0 3dns-3.adobe.com>>%HOSTS%
ECHO 0.0.0.0 3dns-4.adobe.com>>%HOSTS%
ECHO 0.0.0.0 3dns-5.adobe.com>>%HOSTS%
ECHO 0.0.0.0 3dns.adobe.com>>%HOSTS%
ECHO 0.0.0.0 3jq65qgxeh.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 3odrrlydxt.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 3u6k9as4bj.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 3uyby7kphu.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 3xuuprv9lg.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 41yq116gxd.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 44.240.189.42>>%HOSTS%
ECHO 0.0.0.0 4dviy9tb3o.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 4fmzz4au8r.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 4l6gggpz15.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 4vzokhpsbs.adobe.io>>%HOSTS%
ECHO 0.0.0.0 4yw5exucf6.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 50sxgwgngu.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 52.10.49.85>>%HOSTS%
ECHO 0.0.0.0 52.20.222.155>>%HOSTS%
ECHO 0.0.0.0 52.208.86.132>>%HOSTS%
ECHO 0.0.0.0 52.6.155.20>>%HOSTS%
ECHO 0.0.0.0 52.84.156.37>>%HOSTS%
ECHO 0.0.0.0 54.156.135.114>>%HOSTS%
ECHO 0.0.0.0 54.208.86.132>>%HOSTS%
ECHO 0.0.0.0 54.221.228.134>>%HOSTS%
ECHO 0.0.0.0 54.224.241.105>>%HOSTS%
ECHO 0.0.0.0 54cu4v5twu.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 561r5c3bz1.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 5ky0dijg73.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 5m62o8ud26.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 5pawwgngcc.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 5zcrcdpvlp.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 5zgzzv92gn.adobe.io>>%HOSTS%
ECHO 0.0.0.0 63.140.38.120>>%HOSTS%
ECHO 0.0.0.0 63.140.38.160>>%HOSTS%
ECHO 0.0.0.0 63.140.38.169>>%HOSTS%
ECHO 0.0.0.0 63.140.38.219>>%HOSTS%
ECHO 0.0.0.0 65.8.207.109>>%HOSTS%
ECHO 0.0.0.0 69rxfbohle.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 69tu0xswvq.adobe.io>>%HOSTS%
ECHO 0.0.0.0 6dnh2pnz6e.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 6eidhihhci.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 6j0onv1tde.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 6purj8tuwe.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 6y6ozj4sot.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 7g2gzgk9g1.adobe.io>>%HOSTS%
ECHO 0.0.0.0 7k1t5im229.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 7l4xxjhvkt.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 7m31guub0q.adobe.io>>%HOSTS%
ECHO 0.0.0.0 7sj9n87sls.adobe.io>>%HOSTS%
ECHO 0.0.0.0 7tu619a87v.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 83x20gw5jk.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 85n85uoa1h.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 8ncdzpmmrg.adobe.io>>%HOSTS%
ECHO 0.0.0.0 8tegcsplp5.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 98c6c096dd.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 99pfl4vazm.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 9g12qgnfe4.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 9iay914wzy.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 9ngulmtgqi.adobe.io>>%HOSTS%
ECHO 0.0.0.0 9uffo0j6wj.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 9wm8di7ifk.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 a1y2b7wsna.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 activate-sea.adobe.com>>%HOSTS%
ECHO 0.0.0.0 activate-sea.adobe.de>>%HOSTS%
ECHO 0.0.0.0 activate-sjc0.adobe.com>>%HOSTS%
ECHO 0.0.0.0 activate-sjc0.adobe.de>>%HOSTS%
ECHO 0.0.0.0 activate.adobe.com>>%HOSTS%
ECHO 0.0.0.0 activate.adobe.de>>%HOSTS%
ECHO 0.0.0.0 activate.wip.adobe.com>>%HOSTS%
ECHO 0.0.0.0 activate.wip1.adobe.com>>%HOSTS%
ECHO 0.0.0.0 activate.wip2.adobe.com>>%HOSTS%
ECHO 0.0.0.0 activate.wip3.adobe.com>>%HOSTS%
ECHO 0.0.0.0 activate.wip3.adobe.de>>%HOSTS%
ECHO 0.0.0.0 activate.wip4.adobe.com>>%HOSTS%
ECHO 0.0.0.0 adobe-dns-01.adobe.com>>%HOSTS%
ECHO 0.0.0.0 adobe-dns-1.adobe.com>>%HOSTS%
ECHO 0.0.0.0 adobe-dns-2.adobe.com>>%HOSTS%
ECHO 0.0.0.0 adobe-dns-2.adobe.de>>%HOSTS%
ECHO 0.0.0.0 adobe-dns-3.adobe.com>>%HOSTS%
ECHO 0.0.0.0 adobe-dns-3.adobe.de>>%HOSTS%
ECHO 0.0.0.0 adobe-dns-4.adobe.com>>%HOSTS%
ECHO 0.0.0.0 adobe-dns.adobe.com>>%HOSTS%
ECHO 0.0.0.0 adobe-dns.adobe.de>>%HOSTS%
ECHO 0.0.0.0 adobe.activate.com>>%HOSTS%
ECHO 0.0.0.0 adobe.demdex.net>>%HOSTS%
ECHO 0.0.0.0 adobe.tt.omtrdc.net>>%HOSTS%
ECHO 0.0.0.0 adobedc.demdex.net>>%HOSTS%
ECHO 0.0.0.0 adobeereg.com>>%HOSTS%
ECHO 0.0.0.0 adobeid-na1.services.adobe.com>>%HOSTS%
ECHO 0.0.0.0 ag0ak456at.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 agxqobl83f.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ah5otkl8ie.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 altz51db7t.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 anl33sxvkb.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 aoorovjtha.adobe.io>>%HOSTS%
ECHO 0.0.0.0 assets.adobedtm.com>>%HOSTS%
ECHO 0.0.0.0 auth-cloudfront.prod.ims.adobejanus.com>>%HOSTS%
ECHO 0.0.0.0 auth.services.adobe.com>>%HOSTS%
ECHO 0.0.0.0 b5kbg2ggog.adobe.io>>%HOSTS%
ECHO 0.0.0.0 bam.nr-data.net>>%HOSTS%
ECHO 0.0.0.0 bbraowhh29.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 bjooauydoa.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 bk7y1gneyk.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 bk8pzmo8g4.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 bpvcty7ry7.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 bs2yhuojzm.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 c474kdh1ky.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 c4dpyxapo7.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 cai-splunk-proxy.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cc-api-data.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cc-cdn.adobe.com>>%HOSTS%
ECHO 0.0.0.0 cc-cdn.adobe.com.edgekey.net>>%HOSTS%
ECHO 0.0.0.0 cclibraries-defaults-cdn.adobe.com>>%HOSTS%
ECHO 0.0.0.0 cclibraries-defaults-cdn.adobe.com.edgekey.net>>%HOSTS%
ECHO 0.0.0.0 cd536oo20y.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cmdls.adobe.com>>%HOSTS%
ECHO 0.0.0.0 cn-assets.adobedtm.com.edgekey.net>>%HOSTS%
ECHO 0.0.0.0 cr2fouxnpm.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 crl.verisign.net>>%HOSTS%
ECHO 0.0.0.0 crl.verisign.net.>>%HOSTS%
ECHO 0.0.0.0 crlog-crcn.adobe.com>>%HOSTS%
ECHO 0.0.0.0 crs.cr.adobe.com>>%HOSTS%
ECHO 0.0.0.0 curbpindd3.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 cv218qmzox6.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv24b15c1z0.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv24v41zibm.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv256ds6c99.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv2b0yc07ls.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv2bqhsp36w.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv2fcqvzl1r.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv2l4573ukh.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv2nn9r0j2r.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv2ska86hnt.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv2ys4tjt9x.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv2yt8sqmh0.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 cv2zp87w2eo.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 d101mw99xq.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 d2ke1291mx.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 d6zco8is6l.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 dfnm3epsb7.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 dsj4bsmk6i.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 dx0nvmv4hz.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 dxyeyf6ecy.adobe.io>>%HOSTS%
ECHO 0.0.0.0 dyv9axahup.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 dyzt55url8.adobe.io>>%HOSTS%
ECHO 0.0.0.0 ebvf40engd.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 edgeproxy-irl1.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 eftcpaiu36.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 eq7dbze88m.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 eqo0sr8daw.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ereg.adobe.com>>%HOSTS%
ECHO 0.0.0.0 ereg.adobe.de>>%HOSTS%
ECHO 0.0.0.0 ereg.wip.adobe.com>>%HOSTS%
ECHO 0.0.0.0 ereg.wip1.adobe.com>>%HOSTS%
ECHO 0.0.0.0 ereg.wip2.adobe.com>>%HOSTS%
ECHO 0.0.0.0 ereg.wip3.adobe.com>>%HOSTS%
ECHO 0.0.0.0 ereg.wip4.adobe.com>>%HOSTS%
ECHO 0.0.0.0 esx6aswt5e.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ethos.ethos02-prod-irl1.ethos.adobe.net>>%HOSTS%
ECHO 0.0.0.0 eu927m40hm.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 eyiu19jd5w.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ffs3xik41x.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 fm8m3wxufy.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 fqaq3pq1o9.adobe.io>>%HOSTS%
ECHO 0.0.0.0 g0rhyhkd7l.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 g3y09mbaam.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 g9cli80sqp.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 genuine.adobe.com>>%HOSTS%
ECHO 0.0.0.0 geo2.adobe.com>>%HOSTS%
ECHO 0.0.0.0 gocart-web-prod-ue1-alb-1461435473.us-east-1.elb.amazonaws.com>>%HOSTS%
ECHO 0.0.0.0 guzg78logz.adobe.io>>%HOSTS%
ECHO 0.0.0.0 gw8gfjbs05.adobe.io>>%HOSTS%
ECHO 0.0.0.0 hf6s5jdv95.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 hijfpxclgz.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 hjs70w1pdi.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 hl2rcv.adobe.com>>%HOSTS%
ECHO 0.0.0.0 hl2rcv.adobe.de>>%HOSTS%
ECHO 0.0.0.0 hlrcv.stage.adobe.com>>%HOSTS%
ECHO 0.0.0.0 hmonvr006v.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 hnk7phkxtg.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 hq0mnwz735.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 hwfqhlenbg.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 i2x2ius9o5.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 i7pq6fgbsl.adobe.io>>%HOSTS%
ECHO 0.0.0.0 ic.adobe.io>>%HOSTS%
ECHO 0.0.0.0 ij0gdyrfka.adobe.io>>%HOSTS%
ECHO 0.0.0.0 ims-na1-prprod.adobelogin.com>>%HOSTS%
ECHO 0.0.0.0 iv218qmzox6.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv24b15c1z0.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv24v41zibm.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv256ds6c99.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv2b0yc07ls.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv2bqhsp36w.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv2fcqvzl1r.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv2l4573ukh.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv2nn9r0j2r.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv2ska86hnt.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv2ys4tjt9x.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv2yt8sqmh0.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 iv2zp87w2eo.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 ivbnpthtl2.adobe.io>>%HOSTS%
ECHO 0.0.0.0 izke0wrq9n.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 j134yk6hv5.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 j14y4uzge7.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 j5vsm79i8a.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 jaircqa037.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 jatil41mhk.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 jc95y2v12r.adobe.io>>%HOSTS%
ECHO 0.0.0.0 je5ufnklzs.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 jfb7fqf90c.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 jir97hss11.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 jmx50quqz0.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 jsspeczo2f.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 jsxfc5yij1.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 jwonv590qs.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 jye4987hyr.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 k.sni.global.fastly.net>>%HOSTS%
ECHO 0.0.0.0 k9cyzt2wha.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 kgj0gsg3cf.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 kjhzwuhcel.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 klw4np5a1x.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 kvi8uopy6f.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 kvn19sesfx.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 kwi5n2ruax.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 l558s6jwzy.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 lcs-cops.adobe.io>>%HOSTS%
ECHO 0.0.0.0 lcs-robs.adobe.io>>%HOSTS%
ECHO 0.0.0.0 ll8xjr580v.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 llnh72p5m3.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 lm.licenses.adobe.com>>%HOSTS%
ECHO 0.0.0.0 lmlicenses.wip4.adobe.com>>%HOSTS%
ECHO 0.0.0.0 lnwbupw1s7.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 lre1kgz2u4.adobe.io>>%HOSTS%
ECHO 0.0.0.0 ltjlscpozx.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 lv5yrjxh6i.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 lz2x4rks1u.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 m59b4msyph.adobe.io>>%HOSTS%
ECHO 0.0.0.0 m59cps6x3n.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 m95pt874uw.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 mge8tcrsbr.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 mid2473ggd.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 mpsige2va9.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 n0yaid7q47.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 n17cast4au.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 n746qg9j4i.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 n78vmdxqwc.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 na1r.services.adobe.com>>%HOSTS%
ECHO 0.0.0.0 na2m-pr.licenses.adobe.com>>%HOSTS%
ECHO 0.0.0.0 na2m-stg2.licenses.adobe.com>>%HOSTS%
ECHO 0.0.0.0 na4r.services.adobe.com>>%HOSTS%
ECHO 0.0.0.0 nh8wam2qd9.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 nhc73ypmli.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 nhs5jfxg10.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 no95ceu36c.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ocsp.spo1.verisign.com>>%HOSTS%
ECHO 0.0.0.0 oee5i55vyo.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 oh41yzugiz.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ok9sn4bf8f.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ood.opsource.net>>%HOSTS%
ECHO 0.0.0.0 oxiz2n3i4v.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 p0bjuoe16a.adobe.io>>%HOSTS%
ECHO 0.0.0.0 p13n.adobe.io>>%HOSTS%
ECHO 0.0.0.0 p3lj3o9h1s.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 p3m760solq.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 p50zgina3e.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 p7uxzbht8h.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pc6sk9bygv.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 pdb7v5ul5q.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ph0f2h2csf.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pljm140ld1.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 pojvrj7ho5.adobe.io>>%HOSTS%
ECHO 0.0.0.0 ppn4fq68w7.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 practivate.adobe>>%HOSTS%
ECHO 0.0.0.0 practivate.adobe.>>%HOSTS%
ECHO 0.0.0.0 practivate.adobe.com>>%HOSTS%
ECHO 0.0.0.0 practivate.adobe.de>>%HOSTS%
ECHO 0.0.0.0 practivate.adobe.ipp>>%HOSTS%
ECHO 0.0.0.0 practivate.adobe.newoa>>%HOSTS%
ECHO 0.0.0.0 practivate.adobe.ntp>>%HOSTS%
ECHO 0.0.0.0 prod-rel-ffc-ccm.oobesaas.adobe.com>>%HOSTS%
ECHO 0.0.0.0 prod.adobegenuine.com>>%HOSTS%
ECHO 0.0.0.0 pv218qmzox6.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv24b15c1z0.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv24v41zibm.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv256ds6c99.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv2b0yc07ls.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv2bqhsp36w.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv2fcqvzl1r.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv2l4573ukh.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv2nn9r0j2r.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv2ska86hnt.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv2ys4tjt9x.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv2yt8sqmh0.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 pv2zp87w2eo.prod.cloud.adobe.io>>%HOSTS%
ECHO 0.0.0.0 px8vklwioh.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 q9hjwppxeq.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 qmyqpp3xs3.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 qttaz1hur3.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 qxc5z5sqkv.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 r1lqxul5sr.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 r3zj0yju1q.adobe.io>>%HOSTS%
ECHO 0.0.0.0 r5hacgq5w6.adobe.io>>%HOSTS%
ECHO 0.0.0.0 r9r6oomgms.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 rb0u8l34kr.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 riiohpqnpf.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 rj669kv2lc.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 rlo1n6mv52.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 rm3xrk61n1.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 rmnia8d0tr.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 s-2.adobe.com>>%HOSTS%
ECHO 0.0.0.0 s-3.adobe.com>>%HOSTS%
ECHO 0.0.0.0 s7odt342lo.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 sbzo5r4687.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 services.prod.ims.adobejanus.com>>%HOSTS%
ECHO 0.0.0.0 sfmzkcuf2f.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 skg7pqn0al.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ssl-delivery.adobe.com.edgekey.net>>%HOSTS%
ECHO 0.0.0.0 sstats.adobe.com>>%HOSTS%
ECHO 0.0.0.0 stls.adobe.com-cn.edgesuite.net>>%HOSTS%
ECHO 0.0.0.0 stls.adobe.com-cn.edgesuite.net.globalredir.akadns.net>>%HOSTS%
ECHO 0.0.0.0 t9phy8ywkd.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 tcxqcguhww.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 tf3an24xls.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 tprqy2lgua.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 tss-geotrust-crl.thawte.com>>%HOSTS%
ECHO 0.0.0.0 tyradj47rp.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 u31z50xvp9.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 uds.licenses.adobe.com>>%HOSTS%
ECHO 0.0.0.0 uf0onoepoe.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ujqx8lhpz4.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 ura7zj55r9.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 uroc9kxpcb.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 use-stls.adobe.com.edgesuite.net>>%HOSTS%
ECHO 0.0.0.0 v5nweiv7nf.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 vajcbj9qgq.adobe.io>>%HOSTS%
ECHO 0.0.0.0 vcorzsld2a.adobe.io>>%HOSTS%
ECHO 0.0.0.0 vfsjlgw02v.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 vicsj37lhf.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 vp7ih9xoxg.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 vqiktmz3k1.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 vqrc5mq1tm.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 vr1i32txj7.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 vr25z2lfqx.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 vrz9w7o7yv.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 vvzbv1ba9r.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 wcxqmuxd4z.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 wip.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wip1.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wip2.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wip3.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wip4.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wjoxlf5x2z.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 workflow-ui-prod.licensingstack.com>>%HOSTS%
ECHO 0.0.0.0 wtooadkup9.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip100.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip101.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip102.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip103.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip104.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip105.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip106.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip107.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip108.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip109.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip110.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip111.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip112.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip113.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip114.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip115.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip116.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip117.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip118.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip119.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip120.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip121.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip122.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip123.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip124.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip125.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip30.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip31.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip32.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip33.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip34.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip35.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip36.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip37.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip38.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip39.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip40.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip41.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip42.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip43.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip44.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip45.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip46.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip47.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip48.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip49.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip50.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip51.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip52.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip53.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip54.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip55.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip56.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip57.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip58.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip59.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip60.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip60.adobe.de>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip61.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip62.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip63.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip64.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip65.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip66.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip67.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip68.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip69.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip70.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip71.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip72.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip73.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip74.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip75.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip76.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip77.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip78.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip79.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip80.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip81.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip82.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip83.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip84.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip85.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip86.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip87.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip88.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip89.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip90.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip91.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip92.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip93.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip94.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip95.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip96.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip97.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip98.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wwis-dubc1-vip99.adobe.com>>%HOSTS%
ECHO 0.0.0.0 www.adobeereg.com>>%HOSTS%
ECHO 0.0.0.0 www.wip.adobe.com>>%HOSTS%
ECHO 0.0.0.0 www.wip1.adobe.com>>%HOSTS%
ECHO 0.0.0.0 www.wip2.adobe.com>>%HOSTS%
ECHO 0.0.0.0 www.wip3.adobe.com>>%HOSTS%
ECHO 0.0.0.0 www.wip4.adobe.com>>%HOSTS%
ECHO 0.0.0.0 wz8kjkd9gc.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 x5cupsunjc.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 x880ulw3h0.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 x8kb03c0jr.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 xbd20b9wqa.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 xesnl0ss94.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 xm8abqacqz.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 xqh2khegrf.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 y2r8jzsv4p.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 yb6j6g0r1n.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 yj8yx3y8zo.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 yri0bsu0ak.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 yshuhythub.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 yuzuoqo0il.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 z2yohmd1jm.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 zekdqanici.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 zfzx6hae4g.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 zmg3v61bbr.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 zooyvml70k.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 zr60t8ia88.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 zrao5tdh1t.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 zrbzvc9mel.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 zu8yy3jkaz.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 zz8r2o83on.adobestats.io>>%HOSTS%
ECHO 0.0.0.0 telecommand.telemetry.microsoft.com.nsat­c.net>>%HOSTS%
ECHO 0.0.0.0 wes.df.telemetry.microsoft.comnet>>%HOSTS%
ECHO 0.0.0.0 apac1.notify.windows.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 i-sn3p-cor001.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 location-inference-westus.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 v10.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 v20.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 vortex-win-sandbox.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 a1621.g.akamai.net>>%HOSTS%
ECHO 0.0.0.0 a1856.g2.akamai.net>>%HOSTS%
ECHO 0.0.0.0 a1961.g.akamai.net>>%HOSTS%
ECHO 0.0.0.0 a248.e.akamai.net>>%HOSTS%
ECHO 0.0.0.0 e2835.dspb.akamaiedge.net>>%HOSTS%
ECHO 0.0.0.0 e7341.g.akamaiedge.net>>%HOSTS%
ECHO 0.0.0.0 e7502.ce.akamaiedge.net>>%HOSTS%
ECHO 0.0.0.0 hostedocsp.globalsign.com>>%HOSTS%
ECHO 0.0.0.0 ipv6.msftncsi.com>>%HOSTS%
ECHO 0.0.0.0 onesettings-db5.metron.live.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 0001-metrics1-data-hicloud-com.geac.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 0001-metrics1-drcn-dt-dbankcloud-cn.geac.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 0002-metrics1-drcn-dt-dbankcloud-cn.geac.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 acfeedbackws.icloud.com>>%HOSTS%
ECHO 0.0.0.0 adhs.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 adx-dra.op.dbankcloud.com>>%HOSTS%
ECHO 0.0.0.0 adx-dra-op-dbankcloud-com-dra.appacc.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 adx-dra-op-dbankcloud-com-dra.edge.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 adx-dra-op-dbankcloud-com-dra.region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 adx-dra.op.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 adx-dra-op-hicloud-com-dra.appacc.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 adx-dra-op-hicloud-com-dra.edge.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 adx-drcn.op.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 adx-dre.op.dbankcloud.com>>%HOSTS%
ECHO 0.0.0.0 adx-dre.op.dbankcloud.com.edgekey.net>>%HOSTS%
ECHO 0.0.0.0 adx-dre.op.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 adx-drru.op.dbankcloud.com>>%HOSTS%
ECHO 0.0.0.0 apac.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 apac.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 api-adservices.apple.com>>%HOSTS%
ECHO 0.0.0.0 aria.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 asimov.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 assets.activity.windows.com>>%HOSTS%
ECHO 0.0.0.0 auc-visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 au.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 au-mobile.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 au-v10c.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 au-v10.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 au-v20.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 au.vortex-win.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 books-analytics-events.apple.com>>%HOSTS%
ECHO 0.0.0.0 brc-visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 browser.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 browser.events.data.msn.cn>>%HOSTS%
ECHO 0.0.0.0 browser.events.data.msn.com>>%HOSTS%
ECHO 0.0.0.0 browser.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 cac-visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 ca.iadsdk.apple.com>>%HOSTS%
ECHO 0.0.0.0 cds1143.lon.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds320.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds333.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds334.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds335.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds339.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 cds344.lcy.llnw.net>>%HOSTS%
ECHO 0.0.0.0 ce2617d2a3a1a6b03e6b908e5fde808f.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 cf.iadsdk.apple.com>>%HOSTS%
ECHO 0.0.0.0 config.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 datacollector-dra.dt.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 datacollector-dra.dt.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 datacollector-drcn.dt.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 datacollector-drcn.dt.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 datacollector-dre.dt.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 datacollector-dre.dt.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 datacollector-drru.dt.dbankcloud.ru>>%HOSTS%
ECHO 0.0.0.0 datacollector-drru.dt.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 data.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 dec-visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 de-v20.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 de.vortex-win.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 dnkeeper.dbankcloud.com>>%HOSTS%
ECHO 0.0.0.0 dnkeeper.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 dnkeeper.platform.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 ecs.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 emea.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 emea.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 eu.aria.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 eu.blobcollector.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 euc-excel-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 euc-onenote-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 euc-powerpoint-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 euc-visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 euc-word-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 eu.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 eu-ic3.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 eu-mobile.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 eu-office.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 eu.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 eurffc-word-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 eurppc-excel-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 eurppc-powerpoint-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 eurppc-word-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 eu-teams.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 eu-v10c.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 eu-v10.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 eu-v20.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 eu-watsonc.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 events.data.msn.cn>>%HOSTS%
ECHO 0.0.0.0 events.data.msn.com>>%HOSTS%
ECHO 0.0.0.0 events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 events-dra-op-dbankcloud-cn-dra.appacc.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dra-op-dbankcloud-cn-dra.appacc-region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dra-op-dbankcloud-cn-dra.edge.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dra-op-dbankcloud-cn-dra.region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dra-op-dbankcloud-com-dra.appacc.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dra-op-dbankcloud-com-dra.edge.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dra-op-dbankcloud-com-dra.region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dra.op.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 events-dra-op-hicloud-com-dra.appacc.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dra-op-hicloud-com-dra.appacc-region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dra-op-hicloud-com-dra.edge.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dre.op.dbankcloud.com>>%HOSTS%
ECHO 0.0.0.0 events-dre-op-dbankcloud-com-dre.appacc.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dre-op-dbankcloud-com-dre.appacc-region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-dre.op.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 events-dre-op-hicloud-com-dre.appacc.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 events-op-hicloud-com-drcn.appacc.dbankedge.net>>%HOSTS%
ECHO 0.0.0.0 events-op-hicloud-com-drcn.appacc-region.dbankedge.net>>%HOSTS%
ECHO 0.0.0.0 events-sandbox.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 events-sandbox.data.msn.com>>%HOSTS%
ECHO 0.0.0.0 excelonline.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 excel-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 exo.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 exo.nelsdf.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 feedbackws.fe.apple-dns.cn>>%HOSTS%
ECHO 0.0.0.0 feedbackws.icloud.com>>%HOSTS%
ECHO 0.0.0.0 feedbackws.icloud.com.cn>>%HOSTS%
ECHO 0.0.0.0 ffc-word-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 frc-visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 functional.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 global.aria.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 global.asimov.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 graph-next.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 grs.dbankcloud.asia>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-asia-dra.appacc.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-asia-dra.appacc-region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 grs.dbankcloud.com>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-com-dra.appacc.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-com-dra.appacc-region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-com-dra.edge.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-com-dra.region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-com-drcn.wec.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-com-dre.appacc.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-com-dre.appacc-region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-com-dre.edge.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs-dbankcloud-com-dre.region.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 grs.dbankcloud.eu>>%HOSTS%
ECHO 0.0.0.0 grs.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 grs.platform.dbankcloud.ru>>%HOSTS%
ECHO 0.0.0.0 gwx.windows.com>>%HOSTS%
ECHO 0.0.0.0 hisearch-dra.dt.dbankcloud.com>>%HOSTS%
ECHO 0.0.0.0 hubblecontent.osi.office.net>>%HOSTS%
ECHO 0.0.0.0 iadsdk.apple.com>>%HOSTS%
ECHO 0.0.0.0 ic3.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 identity.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 inc-visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 jp.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 jp-mobile.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 jp-v10c.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 jp-v10.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 jp-v20.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 l4.tb.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 l5.pf.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 legacywatson.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 logbak.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 logservice1.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 logservice-dra.platform.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 logservice-dre.platform.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 logservice-dre.platform.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 logservice-drru.dt.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 logservice.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 logtransform.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 m365cdn.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 measure.office.com>>%HOSTS%
ECHO 0.0.0.0 measure.office.net>>%HOSTS%
ECHO 0.0.0.0 metrics1.data.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 metrics1.data.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 metrics1-data-hicloud-com.ge.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 metrics1-data-hicloud-com.gere.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 metrics1-drcn.dt.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 metrics1-drcn-dt-dbankcloud-cn.ge.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 metrics1-drcn-dt-dbankcloud-cn.gere.dbankedge.cn>>%HOSTS%
ECHO 0.0.0.0 metrics2.data.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 metrics3.data.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 metrics5.data.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 metrics5.dt.dbankcloud.ru>>%HOSTS%
ECHO 0.0.0.0 metrics6.dt.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 metrics.apple.com>>%HOSTS%
ECHO 0.0.0.0 metrics.data.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 metrics-dra.dt.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 metrics-dra.dt.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 metrics-drcn.dt.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 metrics-dre.data.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 metrics-dre.dt.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 metrics.dt.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 metrics.dt.hicloud.com>>%HOSTS%
ECHO 0.0.0.0 metrics.icloud.com>>%HOSTS%
ECHO 0.0.0.0 metrics.mzstatic.com>>%HOSTS%
ECHO 0.0.0.0 mobile.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 mobile.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 mobile.events-sandbox.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 nelsdf.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 nexusrules.live.com>>%HOSTS%
ECHO 0.0.0.0 noam.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 noam.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 noc-visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 notes-analytics-events.apple.com>>%HOSTS%
ECHO 0.0.0.0 o365diagtelemetry.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 office-c.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 office.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 office-events-data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 office-g.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 officehub.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 office.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 onenoteonline.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 openlocation-drcn.platform.dbankcloud.com>>%HOSTS%
ECHO 0.0.0.0 pf.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 pf.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 pf.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 pgteu1-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgteu1-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgteu1-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgteu2-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgteu2-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgteu2-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgteu3-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgteu3-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgteu3-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgteu4-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgteu4-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus1-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus1-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus1-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus2-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus2-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus2-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus3-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus3-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus3-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus4-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus4-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus4-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus5-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus5-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus5-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus6-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus6-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 pgtus6-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 phonesubmissions.apple.com>>%HOSTS%
ECHO 0.0.0.0 pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 powerpointonline.nelsdf.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 powerpoint-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 ppc-excel-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 ppc-onenote-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 ppc-powerpoint-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 ppc-word-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 ppe.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 sdwan.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 securemetrics.apple.com>>%HOSTS%
ECHO 0.0.0.0 securemvt.apple.com>>%HOSTS%
ECHO 0.0.0.0 self.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 self-events-data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 server1.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 server2.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 server3.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 server4.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 server5.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 server6.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 server7.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 server8.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 server.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 server.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 sgtus1-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 sgtus1-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 sgtus1-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 spo.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 statsfe2.update.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 stocks-analytics-events.apple.com>>%HOSTS%
ECHO 0.0.0.0 supportmetrics.apple.com>>%HOSTS%
ECHO 0.0.0.0 tb.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 tb.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 tb.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 teams.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 teams-events-data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 teams.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 tfl.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 tgtus1-excel-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 tgtus1-powerpoint-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 tgtus1-word-telemetry-vip.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 tr.iadsdk.apple.com>>%HOSTS%
ECHO 0.0.0.0 ubacollect-drcn.cloud.dbankcloud.cn>>%HOSTS%
ECHO 0.0.0.0 ukc-onenote-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 ukc-visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 uk.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 uk-mobile.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 uk-v20.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 uk.vortex-win.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 upload2.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 upload.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 us4-v20.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 us5-v20.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 us.aria.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 usc-onenote-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 usc-visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 us.events.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 us-mobile.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 us.pipe.aria.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 us-teams.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 us-v10c.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 us-v10.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 us-v20.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 v10c.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 visioonline.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 visio-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 wan.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 watson.alpha.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 watsonc.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 watson.df.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 watson.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 watson.officeint.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 weather-analytics-events.apple.com>>%HOSTS%
ECHO 0.0.0.0 win-global-asimov-leafs-events-data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 wordonline.nel.measure.office.net>>%HOSTS%
ECHO 0.0.0.0 word-telemetry.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 xp.apple.com>>%HOSTS%
ECHO 0.0.0.0 4.perf.msedge.net>>%HOSTS%
ECHO 0.0.0.0 42c56e166af1267c6fa147324f8f0f7d.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 54ee634a8aaada55244129d9e0b8b2e8.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 7338afbd46dd110c9c0a2ffd81509db1.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 7a34fffea8b6276e76b053164cf6abad.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 920cbdaa1ed63646acf0241ed4da5340.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 a-9999.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-ring.a-9999.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 a-ring.msedge.net>>%HOSTS%
ECHO 0.0.0.0 aad.cs.dds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 acdc-direct.office.com>>%HOSTS%
ECHO 0.0.0.0 ads2.msn.com>>%HOSTS%
ECHO 0.0.0.0 ads2.msn.com.c.footprint.net>>%HOSTS%
ECHO 0.0.0.0 adserver.bing.com>>%HOSTS%
ECHO 0.0.0.0 afd-a-acdc-direct.office.com>>%HOSTS%
ECHO 0.0.0.0 afd-k-acdc-direct.office.com>>%HOSTS%
ECHO 0.0.0.0 api.dds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 api.promotions.skype.com>>%HOSTS%
ECHO 0.0.0.0 applicationinsights.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 arc.msn.com>>%HOSTS%
ECHO 0.0.0.0 arc1.msn.com>>%HOSTS%
ECHO 0.0.0.0 ase.rt.prod.applicationinsights.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 asia.smartscreen-prod.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 asimov-win.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 asimov.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 asimov.vortex.data.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 asimovprod.azurewebsites.net>>%HOSTS%
ECHO 0.0.0.0 asse.rt.prod.applicationinsights.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 atm-fp-direct.office.com>>%HOSTS%
ECHO 0.0.0.0 augloop.office.com>>%HOSTS%
ECHO 0.0.0.0 augmentation.osi.office.net>>%HOSTS%
ECHO 0.0.0.0 auh-efz.office.com>>%HOSTS%
ECHO 0.0.0.0 az12170.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az25854.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az412542.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az412617.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az413505.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az416426.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az598575.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az690879.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az693360.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az700035.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az708531.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az725175.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az735311.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az745087.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az745193.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 az745681.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 bat-bing-com.a-0001.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 bat.bing-int.com>>%HOSTS%
ECHO 0.0.0.0 bat.bing.com>>%HOSTS%
ECHO 0.0.0.0 big.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 bn1wns2011508.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020010626.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020011855.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn3sch020022331.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121022.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101121318.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn4sch101123006.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bo.promotions.skype.com>>%HOSTS%
ECHO 0.0.0.0 brazil.smartscreen-prod.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 c.bing.com>>%HOSTS%
ECHO 0.0.0.0 c.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 checkappexec.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 choice.live.com>>%HOSTS%
ECHO 0.0.0.0 client-office365-tas.msedge.net>>%HOSTS%
ECHO 0.0.0.0 clientlog.portal.office.com>>%HOSTS%
ECHO 0.0.0.0 clouddc2-dev.sentinel.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clouddc2-dev.syslog.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clouddc2-dev.syslogagent.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clouddc2-dev.syslogclient.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clouddc2-dev.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clouddc2.sentinel.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clouddc2.syslog.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clouddc2.syslogagent.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clouddc2.syslogclient.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 clouddc2.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 config.edge.skype.com>>%HOSTS%
ECHO 0.0.0.0 cs.dds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 dc.applicationinsights.azure.com>>%HOSTS%
ECHO 0.0.0.0 dc.applicationinsights.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 dc.services.visualstudio.com>>%HOSTS%
ECHO 0.0.0.0 dc.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 dds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 dev.applicationinsights.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 dev.ppe.applicationinsights.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 devicegraph.dds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ecs.office.com>>%HOSTS%
ECHO 0.0.0.0 eu.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 eun.rt.prod.applicationinsights.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 europe.smartscreen-prod.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 euw.rt.prod.applicationinsights.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 exo-ring.msedge.net>>%HOSTS%
ECHO 0.0.0.0 f03f61f372c16ca98465ef16fd4246a0.fp.measure.office.com>>%HOSTS%
ECHO 0.0.0.0 fd.dds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 footprintpredict.com>>%HOSTS%
ECHO 0.0.0.0 for-efz.office.com>>%HOSTS%
ECHO 0.0.0.0 fp-vp.azureedge.net>>%HOSTS%
ECHO 0.0.0.0 fp.msedge.net>>%HOSTS%
ECHO 0.0.0.0 fpc.msedge.net>>%HOSTS%
ECHO 0.0.0.0 g.msn.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 glbdns.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 i-bn3p-cor090.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 i-sn3p-cor002.api.p001.1drv.com>>%HOSTS%
ECHO 0.0.0.0 i.s1.social.ms.akadns.net>>%HOSTS%
ECHO 0.0.0.0 ipv6.login.live.com>>%HOSTS%
ECHO 0.0.0.0 ipv6.login.msa.akadns6.net>>%HOSTS%
ECHO 0.0.0.0 iriscoremetadataprod.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 k-ring.msedge.net>>%HOSTS%
ECHO 0.0.0.0 kmwatsonc.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 legacy-redirection-neurope-prod-hp.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 lhr-efz.office.com>>%HOSTS%
ECHO 0.0.0.0 listazureresources.encryption.applicationinsights.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 livetileedge.dsx.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 mel-efz.office.com>>%HOSTS%
ECHO 0.0.0.0 metrics.skype.com>>%HOSTS%
ECHO 0.0.0.0 microsoft-hohm.com>>%HOSTS%
ECHO 0.0.0.0 msa.s2s.watson.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 msa.watson.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 msnads.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 msnvidweb.vo.msecnd.net>>%HOSTS%
ECHO 0.0.0.0 nav.smartscreen.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 nw-kmwatson.events.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 odinvzc.azureedge.net>>%HOSTS%
ECHO 0.0.0.0 onedrive-collection.device.mobileengagement.windows.net>>%HOSTS%
ECHO 0.0.0.0 optanon.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 outlook-exo.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 outlook.ha.office.com>>%HOSTS%
ECHO 0.0.0.0 ow1.res.office365.com>>%HOSTS%
ECHO 0.0.0.0 ow1.res.office365.com.edgekey.net>>%HOSTS%
ECHO 0.0.0.0 ppe.applicationinsights.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 prod.fe.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 prod.nexusrules.live.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 promotions.skype.com>>%HOSTS%
ECHO 0.0.0.0 quickpulse-prod-use.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 r.bat.bing.com>>%HOSTS%
ECHO 0.0.0.0 redir.metaservices.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 redir.metaservices.microsoft.com.edgesuite.net>>%HOSTS%
ECHO 0.0.0.0 redirection.prod.cms.msn.com>>%HOSTS%
ECHO 0.0.0.0 redirection.prod.cms.msn.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 responses.df.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ris.api.iris.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 rt.applicationinsights.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 siweb.microsoft.akadns.net>>%HOSTS%
ECHO 0.0.0.0 sjc-efz.office.com>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcolcus01.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcolcus03.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcolcus11.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcolcus13.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcoleus00.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcoleus02.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcoleus04.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcoljpw03.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcoluks05.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcolweu04.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 skypedataprdcolwus03.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 smartscreen-prod.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 smartscreen-sn3p.smartscreen.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 spo-ring.msedge.net>>%HOSTS%
ECHO 0.0.0.0 spynet2.microsoft.akadns.net>>%HOSTS%
ECHO 0.0.0.0 spynetalt.microsoft.akadns.net>>%HOSTS%
ECHO 0.0.0.0 star-r-bat-bing-com.a-0001.a-msedge.net>>%HOSTS%
ECHO 0.0.0.0 statsfe1.ws.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 support.msn.microsoft.akadns.net>>%HOSTS%
ECHO 0.0.0.0 telecommand.telemetry.microsoft.com.nsat-c.net>>%HOSTS%
ECHO 0.0.0.0 telecommend.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 templatelogging.office.com>>%HOSTS%
ECHO 0.0.0.0 tsfe-prod-bn2.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 tsfe.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 uk.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 umwatsonc.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 unitedkingdom.smartscreen-prod.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 unitedstates.smartscreen-prod.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 us.vortex.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 us.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 use.rt.prod.applicationinsights.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 ussc.rt.prod.applicationinsights.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 view.wac.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 vortex-sandbox.data.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 vortex.data.msn.com>>%HOSTS%
ECHO 0.0.0.0 vortex.sandbox.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 vortexingester.dds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 waconafd.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 waconatm.officeapps.live.com>>%HOSTS%
ECHO 0.0.0.0 watson2.alpha.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 watson7.alpha.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 wd-prod-ss-as.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 wd-prod-ss-br.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 wd-prod-ss-eu.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 wd-prod-ss-uk.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 wd-prod-ss-us.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 wd-prod-ss.trafficmanager.net>>%HOSTS%
ECHO 0.0.0.0 web.vortex-win.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 web.vortex.data.microsoft.com.akadns.net>>%HOSTS%
ECHO 0.0.0.0 web.vortex.data.msn.com>>%HOSTS%
ECHO 0.0.0.0 wer.alpha.telemetry.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 weweb.vortex.data.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 windowssearch.com>>%HOSTS%
ECHO 0.0.0.0 www.applicationinsights.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 www.bingads.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 www.go.microsoft.akadns.net>>%HOSTS%
ECHO 0.0.0.0 x.urs.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 zto.dds.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 0.r.msn.com>>%HOSTS%
ECHO 0.0.0.0 act-3-blu.mesh.com>>%HOSTS%
ECHO 0.0.0.0 activesync.glbdns2.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 ads.eu.msn.com>>%HOSTS%
ECHO 0.0.0.0 ads.msn.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 adsmockarc.azurewebsites.net>>%HOSTS%
ECHO 0.0.0.0 adsyndication.msn.com>>%HOSTS%
ECHO 0.0.0.0 aidps.msn.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 analytics.live.com>>%HOSTS%
ECHO 0.0.0.0 analytics.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 analytics.msn.com>>%HOSTS%
ECHO 0.0.0.0 analytics.msnbc.msn.com>>%HOSTS%
ECHO 0.0.0.0 analytics.r.msn.com>>%HOSTS%
ECHO 0.0.0.0 appexmapsappupdate.blob.core.windows.net>>%HOSTS%
ECHO 0.0.0.0 arc2.msn.com>>%HOSTS%
ECHO 0.0.0.0 arc3.msn.com>>%HOSTS%
ECHO 0.0.0.0 arc9.msn.com>>%HOSTS%
ECHO 0.0.0.0 atlas.c10r.facebook.com>>%HOSTS%
ECHO 0.0.0.0 bl3302.storage.skyprod.akadns.net>>%HOSTS%
ECHO 0.0.0.0 blu.mobileads.msn.com>>%HOSTS%
ECHO 0.0.0.0 bn1-2cd.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn1cd.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bn2wns1b.wns.windows.com>>%HOSTS%
ECHO 0.0.0.0 bs.eyeblaster.akadns.net>>%HOSTS%
ECHO 0.0.0.0 c.atdmt.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 c.msn.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 c.ninemsn.com.au>>%HOSTS%
ECHO 0.0.0.0 c.no.msn.com>>%HOSTS%
ECHO 0.0.0.0 cmsresources.windowsphone.com>>%HOSTS%
ECHO 0.0.0.0 col.mobileads.msn.com>>%HOSTS%
ECHO 0.0.0.0 content.windows.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 digg.analytics.live.com>>%HOSTS%
ECHO 0.0.0.0 displaycatalog.md.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 download-ssl.msgamestudios.com>>%HOSTS%
ECHO 0.0.0.0 ff4a487e56259f4bd5831e9e30470e83.azr.msnetworkanalytics.testanalytics.net>>%HOSTS%
ECHO 0.0.0.0 flex.msn.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 global.msads.net.c.footprint.net>>%HOSTS%
ECHO 0.0.0.0 js.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 licensing.md.mp.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 logging.windows.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 m.anycast.adnxs.com>>%HOSTS%
ECHO 0.0.0.0 mediadiscovery.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 msnportal.112.2o7.net>>%HOSTS%
ECHO 0.0.0.0 popup.msn.com>>%HOSTS%
ECHO 0.0.0.0 rad.msn.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 rmads.eu.msn.com>>%HOSTS%
ECHO 0.0.0.0 rpt.rad.msn.com>>%HOSTS%
ECHO 0.0.0.0 sb.scorecardresearch.com>>%HOSTS%
ECHO 0.0.0.0 secure.anycast.adnxs.com>>%HOSTS%
ECHO 0.0.0.0 sgmetrics.cloudapp.net>>%HOSTS%
ECHO 0.0.0.0 shell.windows.com>>%HOSTS%
ECHO 0.0.0.0 sls.update.microsoft.com.nsatc.net>>%HOSTS%
ECHO 0.0.0.0 spynet.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 sqm.microsoft.com>>%HOSTS%
ECHO 0.0.0.0 query.prod.cms.rt.microsoft.com/cms/api/am/binary/RE2JgkA>>%HOSTS%
ECHO 0.0.0.0 static-2mdn-net.l.google.com>>%HOSTS%
ECHO 0.0.0.0 udc.msn.com>>%HOSTS%
ECHO 0.0.0.0 w3.b.cap-mii.net>>%HOSTS%
ECHO 0.0.0.0 www.modern.ie>>%HOSTS%
ECHO 0.0.0.0 p1-play.edge4k.com>>%HOSTS%
ECHO 0.0.0.0 t1.daumcdn.net>>%HOSTS%
ECHO 0.0.0.0 play.kakao.com>>%HOSTS%
ECHO 0.0.0.0 telemetry.gfe.nvidia.com>>%HOSTS%
ECHO 0.0.0.0 gfe.nvidia.com>>%HOSTS%
ECHO 0.0.0.0 gfwsl.geforce.com>>%HOSTS%
ECHO 0.0.0.0 services.gfe.nvidia.com>>%HOSTS%
ECHO 0.0.0.0 accounts.nvgs.nvidia.com>>%HOSTS%
ECHO 0.0.0.0 events.gfe.nvidia.com>>%HOSTS%
ECHO 0.0.0.0 img.nvidiagrid.net>>%HOSTS%
ECHO 0.0.0.0 images.nvidiagrid.net>>%HOSTS%
ECHO 0.0.0.0 images.nvidia.com>>%HOSTS%
ECHO 0.0.0.0 ls.dtrace.nvidia.com>>%HOSTS%
ECHO 0.0.0.0 ota.nvidia.com>>%HOSTS%
ECHO 0.0.0.0 rds-assets.nvidia.com>>%HOSTS%
ECHO 0.0.0.0 assets.nvidiagrid.net>>%HOSTS%
ECHO 0.0.0.0 nvidia.tt.omtrdc.net>>%HOSTS%
ECHO 0.0.0.0 api.commune.ly>>%HOSTS%
ECHO 0.0.0.0 login.nvgs.nvidia.cn>>%HOSTS%
ECHO 0.0.0.0 activate.bitsum.com>>%HOSTS%
ATTRIB +r "%WINDIR%\system32\drivers\etc\hosts"
ECHO ********** Add firewall rules. Block unwanted IP addresses.
netsh advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="telemetry_www.trust.office365.com" dir=out action=block remoteip=64.4.6.100 enable=yes
netsh advfirewall firewall add rule name="telemetry_www.moskisvet.com.c.footprint.net" dir=out action=block remoteip=8.253.37.126 enable=yes
netsh advfirewall firewall add rule name="telemetry_www.moskisvet.com.c.footprint.net" dir=out action=block remoteip=198.78.208.254 enable=yes
netsh advfirewall firewall add rule name="telemetry_www.cisco.com" dir=out action=block remoteip=198.135.3.118 enable=yes
netsh advfirewall firewall add rule name="telemetry_wusonprem.ipv6.microsoft.com.akadns.net" dir=out action=block remoteip=157.56.106.189 enable=yes
netsh advfirewall firewall add rule name="telemetry_wns.windows.com" dir=out action=block remoteip=40.77.229.0-40.77.229.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_wes.df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.93 enable=yes
netsh advfirewall firewall add rule name="telemetry_wdcpeurope.microsoft.akadns.net" dir=out action=block remoteip=137.117.235.16 enable=yes
netsh advfirewall firewall add rule name="telemetry_watson.telemetry.microsoft.com" dir=out action=block remoteip=40.77.228.92 enable=yes
netsh advfirewall firewall add rule name="telemetry_watson.ppe.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.11 enable=yes
netsh advfirewall firewall add rule name="telemetry_watson.microsoft.com.nsatc.net" dir=out action=block remoteip=65.52.108.154 enable=yes
netsh advfirewall firewall add rule name="telemetry_watson.live.com" dir=out action=block remoteip=207.46.223.94 enable=yes
netsh advfirewall firewall add rule name="telemetry_vortex-db5.metron.live.com.nsatc.net" dir=out action=block remoteip=191.232.139.5 enable=yes
netsh advfirewall firewall add rule name="telemetry_vd.vidfuture.com" dir=out action=block remoteip=66.225.197.197 enable=yes
netsh advfirewall firewall add rule name="telemetry_v4ncsi.msedge.net" dir=out action=block remoteip=13.107.4.52 enable=yes
netsh advfirewall firewall add rule name="telemetry_v20-asimov-win.vortex.data.microsoft.com.akadns.net" dir=out action=block remoteip=64.4.54.254 enable=yes
netsh advfirewall firewall add rule name="telemetry_v10-win.vortex.data.microsoft.com.akadns.net" dir=out action=block remoteip=111.221.29.254 enable=yes
netsh advfirewall firewall add rule name="telemetry_us.vortex-win.data.microsoft.com" dir=out action=block remoteip=40.90.136.33 enable=yes
netsh advfirewall firewall add rule name="telemetry_urs.microsoft.com.nsatc.net" dir=out action=block remoteip=157.55.233.125,192.232.139.180 enable=yes
netsh advfirewall firewall add rule name="telemetry_trouter-neu-a.cloudapp.net" dir=out action=block remoteip=13.69.188.18 enable=yes
netsh advfirewall firewall add rule name="telemetry_trouter-easia-a.dc.trouter.io" dir=out action=block remoteip=13.75.106.0 enable=yes
netsh advfirewall firewall add rule name="telemetry_telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.9 enable=yes
netsh advfirewall firewall add rule name="telemetry_telemetry.appex.search.prod.ms.akadns.net" dir=out action=block remoteip=168.61.24.141 enable=yes
netsh advfirewall firewall add rule name="telemetry_telemetry.appex.bing.net" dir=out action=block remoteip=65.52.161.64,168.63.108.233 enable=yes
netsh advfirewall firewall add rule name="telemetry_telecommand.telemetry.microsoft.com" dir=out action=block remoteip=65.55.252.92 enable=yes
netsh advfirewall firewall add rule name="telemetry_tapeytapey.com" dir=out action=block remoteip=2.21.246.26 enable=yes
netsh advfirewall firewall add rule name="telemetry_t.urs.microsoft.com.nsatc.net" dir=out action=block remoteip=64.4.54.167,65.55.44.85 enable=yes
netsh advfirewall firewall add rule name="telemetry_t.urs.microsoft.com" dir=out action=block remoteip=131.253.40.37 enable=yes
netsh advfirewall firewall add rule name="telemetry_survey.watson.microsoft.com" dir=out action=block remoteip=207.68.166.254 enable=yes
netsh advfirewall firewall add rule name="telemetry_statsfe2-df.ws.microsoft.com.nsatc.net" dir=out action=block remoteip=134.170.115.60 enable=yes
netsh advfirewall firewall add rule name="telemetry_statsfe2.ws.microsoft.com.nsatc.net" dir=out action=block remoteip=131.253.14.153 enable=yes
netsh advfirewall firewall add rule name="telemetry_statsfe2.ws.microsoft.com" dir=out action=block remoteip=207.46.114.61 enable=yes
netsh advfirewall firewall add rule name="telemetry_statsfe2.update.microsoft.com.akadns.net" dir=out action=block remoteip=65.52.108.153 enable=yes
netsh advfirewall firewall add rule name="telemetry_stats.update.microsoft.com.nsatc.net" dir=out action=block remoteip=64.4.54.22 enable=yes
netsh advfirewall firewall add rule name="telemetry_static.sl-reverse.com" dir=out action=block remoteip=169.54.179.156 enable=yes
netsh advfirewall firewall add rule name="telemetry_ssw.live.com.nsatc.net" dir=out action=block remoteip=207.46.7.252 enable=yes
netsh advfirewall firewall add rule name="telemetry_ssw.live.com" dir=out action=block remoteip=207.46.101.29 enable=yes
netsh advfirewall firewall add rule name="telemetry_sqm.msn.com" dir=out action=block remoteip=65.55.252.93 enable=yes
netsh advfirewall firewall add rule name="telemetry_sqm.df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.94 enable=yes
netsh advfirewall firewall add rule name="telemetry_sonybank.net" dir=out action=block remoteip=2.21.246.24 enable=yes
netsh advfirewall firewall add rule name="telemetry_settings-win-ppe.data.microsoft.com" dir=out action=block remoteip=40.77.226.248 enable=yes
netsh advfirewall firewall add rule name="telemetry_settings-sandbox.data.microsoft.com" dir=out action=block remoteip=111.221.29.177 enable=yes
netsh advfirewall firewall add rule name="telemetry_settings-sandbox.data.glbdns2.microsoft.com" dir=out action=block remoteip=191.232.140.76 enable=yes
netsh advfirewall firewall add rule name="telemetry_services.wes.df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.92 enable=yes
netsh advfirewall firewall add rule name="telemetry_service.xbox.com" dir=out action=block remoteip=157.55.129.21 enable=yes
netsh advfirewall firewall add rule name="telemetry_secure-ams.adnxs.com" dir=out action=block remoteip=37.252.163.244,37.252.163.106 enable=yes
netsh advfirewall firewall add rule name="telemetry_secure.flashtalking.com" dir=out action=block remoteip=95.101.244.134 enable=yes
netsh advfirewall firewall add rule name="telemetry_schemas.microsoft.akadns.net" dir=out action=block remoteip=65.54.226.187 enable=yes
netsh advfirewall firewall add rule name="telemetry_sact.atdmt.com" dir=out action=block remoteip=94.245.121.177 enable=yes
netsh advfirewall firewall add rule name="telemetry_s0.2mdn.net" dir=out action=block remoteip=172.217.21.166 enable=yes
netsh advfirewall firewall add rule name="telemetry_s.outlook.com" dir=out action=block remoteip=134.170.3.199 enable=yes
netsh advfirewall firewall add rule name="telemetry_rmads.msn.com" dir=out action=block remoteip=157.56.23.91 enable=yes
netsh advfirewall firewall add rule name="telemetry_reports.wes.df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.91 enable=yes
netsh advfirewall firewall add rule name="telemetry_redir.metaservices.microsoft.com" dir=out action=block remoteip=194.44.4.200,194.44.4.208,2.21.246.42,2.21.246.58 enable=yes
netsh advfirewall firewall add rule name="telemetry_realgames.cn" dir=out action=block remoteip=65.55.57.27 enable=yes
netsh advfirewall firewall add rule name="telemetry_pipe.skype.com" dir=out action=block remoteip=40.115.1.44 enable=yes
netsh advfirewall firewall add rule name="telemetry_perthnow.com.au" dir=out action=block remoteip=2.21.246.8 enable=yes
netsh advfirewall firewall add rule name="telemetry_osiprod-weu-snow-000.cloudapp.net" dir=out action=block remoteip=23.97.178.173 enable=yes
netsh advfirewall firewall add rule name="telemetry_oca.watson.data.microsoft.com.akadns.net" dir=out action=block remoteip=64.4.54.153 enable=yes
netsh advfirewall firewall add rule name="telemetry_oca.telemetry.microsoft.com.nsatc.net" dir=out action=block remoteip=65.55.252.63 enable=yes
netsh advfirewall firewall add rule name="telemetry_nt-c.ns.nsatc.net" dir=out action=block remoteip=8.254.119.155 enable=yes
netsh advfirewall firewall add rule name="telemetry_nt-b.ns.nsatc.net" dir=out action=block remoteip=8.254.92.155 enable=yes
netsh advfirewall firewall add rule name="telemetry_ns3.msft.net" dir=out action=block remoteip=192.221.113.53 enable=yes
netsh advfirewall firewall add rule name="telemetry_ns3.a-msedge.net" dir=out action=block remoteip=131.253.21.1 enable=yes
netsh advfirewall firewall add rule name="telemetry_ns2.a-msedge.net" dir=out action=block remoteip=204.79.197.2 enable=yes
netsh advfirewall firewall add rule name="telemetry_ns1.gslb.com" dir=out action=block remoteip=8.19.31.10 enable=yes
netsh advfirewall firewall add rule name="telemetry_ns1.a-msedge.net" dir=out action=block remoteip=204.79.197.1 enable=yes
netsh advfirewall firewall add rule name="telemetry_nl-1.ns.nsatc.net" dir=out action=block remoteip=4.23.39.155 enable=yes
netsh advfirewall firewall add rule name="telemetry_nexus.officeapps.live.com" dir=out action=block remoteip=40.76.8.142,23.101.14.229,207.46.153.155 enable=yes
netsh advfirewall firewall add rule name="telemetry_next-services.windows.akadns.net" dir=out action=block remoteip=134.170.30.202 enable=yes
netsh advfirewall firewall add rule name="telemetry_new_wns.windows.com" dir=out action=block remoteip=131.253.21.0-131.253.47.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_msnbot-65-55-108-23.search.msn.com" dir=out action=block remoteip=65.55.108.23 enable=yes
netsh advfirewall firewall add rule name="telemetry_msnbot-64-4-54-18.search.msn.com" dir=out action=block remoteip=64.4.54.18 enable=yes
netsh advfirewall firewall add rule name="telemetry_msnbot-207-46-194-46.search.msn.com" dir=out action=block remoteip=207.46.194.46 enable=yes
netsh advfirewall firewall add rule name="telemetry_msnbot-207-46-194-33.search.msn.com" dir=out action=block remoteip=207.46.194.33 enable=yes
netsh advfirewall firewall add rule name="telemetry_msnbot-207-46-194-29.search.msn.com" dir=out action=block remoteip=207.46.194.29 enable=yes
netsh advfirewall firewall add rule name="telemetry_msnbot-207-46-194-25.search.msn.com" dir=out action=block remoteip=207.46.194.25 enable=yes
netsh advfirewall firewall add rule name="telemetry_msnbot-207-46-194-14.search.msn.com" dir=out action=block remoteip=207.46.194.14 enable=yes
netsh advfirewall firewall add rule name="telemetry_msedge.net" dir=out action=block remoteip=204.79.19.197 enable=yes
netsh advfirewall firewall add rule name="telemetry_ms1-ib.adnxs.com" dir=out action=block remoteip=37.252.163.88 enable=yes
netsh advfirewall firewall add rule name="telemetry_modern.watson.data.microsoft.com.akadns.net" dir=out action=block remoteip=65.55.252.43,65.52.108.29,65.55.252.202 enable=yes
netsh advfirewall firewall add rule name="telemetry_mm.bing.net" dir=out action=block remoteip=204.79.197.200 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft22.com" dir=out action=block remoteip=52.178.178.16 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft21.com" dir=out action=block remoteip=65.55.64.54 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft20.com" dir=out action=block remoteip=40.80.145.27 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft17.com" dir=out action=block remoteip=40.80.145.78 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft16.com" dir=out action=block remoteip=23.99.116.116 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft15.com" dir=out action=block remoteip=77.67.29.176 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft14.com" dir=out action=block remoteip=65.55.223.0-65.55.223.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft13.com" dir=out action=block remoteip=65.39.117.230 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft12.com" dir=out action=block remoteip=64.4.23.0-64.4.23.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft11.com" dir=out action=block remoteip=23.223.20.82 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft10.com" dir=out action=block remoteip=213.199.179.0-213.199.179.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft09.com" dir=out action=block remoteip=2.22.61.66 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft08.com" dir=out action=block remoteip=195.138.255.0-195.138.255.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft07.com" dir=out action=block remoteip=157.55.56.0-157.55.56.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft06.com" dir=out action=block remoteip=157.55.52.0-157.55.52.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft05.com" dir=out action=block remoteip=157.55.236.0-157.55.236.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft04.com" dir=out action=block remoteip=157.55.235.0-157.55.235.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft03.com" dir=out action=block remoteip=157.55.130.0-157.55.130.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft02.com" dir=out action=block remoteip=111.221.64.0-111.221.127.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft01.com" dir=out action=block remoteip=11.221.29.253 enable=yes
netsh advfirewall firewall add rule name="telemetry_microsoft.com" dir=out action=block remoteip=104.96.147.3 enable=yes
netsh advfirewall firewall add rule name="telemetry_mediaroomsds.microsoft.com" dir=out action=block remoteip=134.170.185.70 enable=yes
netsh advfirewall firewall add rule name="telemetry_media.blinkbox.com.c.footprint.net" dir=out action=block remoteip=206.33.58.254 enable=yes
netsh advfirewall firewall add rule name="telemetry_m.adnxs.com" dir=out action=block remoteip=37.252.170.141 enable=yes
netsh advfirewall firewall add rule name="telemetry_legacy.watson.data.microsoft.com.akadns.net" dir=out action=block remoteip=65.55.252.71 enable=yes
netsh advfirewall firewall add rule name="telemetry_inside.microsoftmse.com" dir=out action=block remoteip=65.55.39.10 enable=yes
netsh advfirewall firewall add rule name="telemetry_iact.atdmt.com" dir=out action=block remoteip=94.245.121.178 enable=yes
netsh advfirewall firewall add rule name="telemetry_i4.services.social.microsoft.com" dir=out action=block remoteip=104.79.134.225 enable=yes
netsh advfirewall firewall add rule name="telemetry_i1.services.social.microsoft.com" dir=out action=block remoteip=23.74.190.252,104.82.22.249 enable=yes
netsh advfirewall firewall add rule name="telemetry_hp-comm.ca.msn.com" dir=out action=block remoteip=40.127.139.224 enable=yes
netsh advfirewall firewall add rule name="telemetry_helloaddress.com" dir=out action=block remoteip=2.21.246.10 enable=yes
netsh advfirewall firewall add rule name="telemetry_globalns2.appnexus.net" dir=out action=block remoteip=8.19.31.11 enable=yes
netsh advfirewall firewall add rule name="telemetry_geo-prod.dodsp.mp.microsoft.com.nsatc.net" dir=out action=block remoteip=191.232.139.212 enable=yes
netsh advfirewall firewall add rule name="telemetry_geo-prod.do.dsp.mp.microsoft.com" dir=out action=block remoteip=40.77.226.217-40.77.226.224 enable=yes
netsh advfirewall firewall add rule name="telemetry_geo.settings.data.microsoft.com.akadns.net" dir=out action=block remoteip=64.4.0.0-64.4.63.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_float.2655.bm-impbus.prod.ams1.adnexus.net" dir=out action=block remoteip=37.252.163.215 enable=yes
netsh advfirewall firewall add rule name="telemetry_float.2113.bm-impbus.prod.ams1.adnexus.net" dir=out action=block remoteip=37.252.163.3 enable=yes
netsh advfirewall firewall add rule name="telemetry_float.1334.bm-impbus.prod.fra1.adnexus.net" dir=out action=block remoteip=37.252.170.82 enable=yes
netsh advfirewall firewall add rule name="telemetry_float.1332.bm-impbus.prod.fra1.adnexus.net" dir=out action=block remoteip=37.252.170.81 enable=yes
netsh advfirewall firewall add rule name="telemetry_float.1143.bm-impbus.prod.fra1.adnexus.net" dir=out action=block remoteip=37.252.170.1 enable=yes
netsh advfirewall firewall add rule name="telemetry_flex.msn.com" dir=out action=block remoteip=207.46.194.8 enable=yes
netsh advfirewall firewall add rule name="telemetry_fesweb1.ch1d.binginternal.com" dir=out action=block remoteip=131.253.14.76 enable=yes
netsh advfirewall firewall add rule name="telemetry_fe3.delivery.dsp.mp.microsoft.com.nsatc.net" dir=out action=block remoteip=64.4.54.18 enable=yes
netsh advfirewall firewall add rule name="telemetry_fd-rad-msn-com.a-0004.a-msedge.net" dir=out action=block remoteip=204.79.197.206 enable=yes
netsh advfirewall firewall add rule name="telemetry_fashiontamils.com" dir=out action=block remoteip=69.64.34.185 enable=yes
netsh advfirewall firewall add rule name="telemetry_exch-eu.atdmt.com.nsatc.net" dir=out action=block remoteip=94.245.121.179,94.245.121.176 enable=yes
netsh advfirewall firewall add rule name="telemetry_evoke-windowsservices-tas.msedge.net" dir=out action=block remoteip=13.107.5.88 enable=yes
netsh advfirewall firewall add rule name="telemetry_eu.vortex-win.data.microsoft.com" dir=out action=block remoteip=191.232.139.254 enable=yes
netsh advfirewall firewall add rule name="telemetry_es-1.ns.nsatc.net" dir=out action=block remoteip=8.254.34.155 enable=yes
netsh advfirewall firewall add rule name="telemetry_edge-atlas-shv-01-cdg2.facebook.com" dir=out action=block remoteip=179.60.192.10 enable=yes
netsh advfirewall firewall add rule name="telemetry_e8218.ce.akamaiedge.net" dir=out action=block remoteip=23.57.107.27 enable=yes
netsh advfirewall firewall add rule name="telemetry_e6845.ce.akamaiedge.net" dir=out action=block remoteip=23.57.101.163 enable=yes
netsh advfirewall firewall add rule name="telemetry_dub109-afx.ms.a-0009.a-msedge.net" dir=out action=block remoteip=204.79.197.211 enable=yes
netsh advfirewall firewall add rule name="telemetry_dps.msn.com" dir=out action=block remoteip=131.253.14.121 enable=yes
netsh advfirewall firewall add rule name="telemetry_dmd.metaservices.microsoft.com.akadns.net" dir=out action=block remoteip=52.160.91.170 enable=yes
netsh advfirewall firewall add rule name="telemetry_dmd.metaservices.microsoft.com.akadns.net" dir=out action=block remoteip=40.112.210.171 enable=yes
netsh advfirewall firewall add rule name="telemetry_dmd.metaservices.microsoft.com" dir=out action=block remoteip=40.87.63.92,40.80.145.78,40.80.145.38,40.80.145.27,40.112.213.22 enable=yes
netsh advfirewall firewall add rule name="telemetry_diagnostics.support.microsoft.com" dir=out action=block remoteip=134.170.52.151 enable=yes
netsh advfirewall firewall add rule name="telemetry_diagnostics.support.microsoft.akadns.net" dir=out action=block remoteip=157.56.121.89 enable=yes
netsh advfirewall firewall add rule name="telemetry_df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.7 enable=yes
netsh advfirewall firewall add rule name="telemetry_descargas.diximedia.es.c.footprint.net" dir=out action=block remoteip=185.13.160.61 enable=yes
netsh advfirewall firewall add rule name="telemetry_deploy.static.akamaitechnologies.com" dir=out action=block remoteip=23.218.212.69 enable=yes
netsh advfirewall firewall add rule name="telemetry_deploy.akamaitechnologies.com" dir=out action=block remoteip=95.100.38.95 enable=yes
netsh advfirewall firewall add rule name="telemetry_db5.wns.notify.windows.com.akadns.net" dir=out action=block remoteip=40.77.226.246,40.77.226.247 enable=yes
netsh advfirewall firewall add rule name="telemetry_db5.vortex.data.microsoft.com.akadns.net" dir=out action=block remoteip=40.77.226.250 enable=yes
netsh advfirewall firewall add rule name="telemetry_db5.settings.data.microsoft.com.akadns.net" dir=out action=block remoteip=40.77.226.249,191.232.139.253 enable=yes
netsh advfirewall firewall add rule name="telemetry_db5.displaycatalog.md.mp.microsoft.com.akadns.net" dir=out action=block remoteip=40.77.229.125 enable=yes
netsh advfirewall firewall add rule name="telemetry_db3wns2011111.wns.windows.com" dir=out action=block remoteip=157.56.124.87 enable=yes
netsh advfirewall firewall add rule name="telemetry_dart.l.doubleclick.net" dir=out action=block remoteip=173.194.113.219,173.194.113.220,173.194.113.219,216.58.209.166,172.217.20.134 enable=yes
netsh advfirewall firewall add rule name="telemetry_cy2.settings.data.microsoft.com.akadns.net" dir=out action=block remoteip=64.4.54.253,13.78.188.147 enable=yes
netsh advfirewall firewall add rule name="telemetry_cs697.wac.thetacdn.net" dir=out action=block remoteip=192.229.233.249 enable=yes
netsh advfirewall firewall add rule name="telemetry_cs479.wac.edgecastcdn.net" dir=out action=block remoteip=68.232.35.139 enable=yes
netsh advfirewall firewall add rule name="telemetry_corpext.msitadfs.glbdns2.microsoft.com" dir=out action=block remoteip=131.107.113.238 enable=yes
netsh advfirewall firewall add rule name="telemetry_compatexchange.cloudapp.net" dir=out action=block remoteip=23.99.10.11 enable=yes
netsh advfirewall firewall add rule name="telemetry_colonialtoolset.com" dir=out action=block remoteip=208.84.0.53 enable=yes
netsh advfirewall firewall add rule name="telemetry_col130-afx.ms.a-0008.a-msedge.net" dir=out action=block remoteip=204.79.197.210 enable=yes
netsh advfirewall firewall add rule name="telemetry_co4.telecommand.telemetry.microsoft.com.akadns.net" dir=out action=block remoteip=65.55.252.190 enable=yes
netsh advfirewall firewall add rule name="telemetry_cn.msn.fr" dir=out action=block remoteip=23.102.21.4 enable=yes
netsh advfirewall firewall add rule name="telemetry_choice.microsoft.com.nsatc.net" dir=out action=block remoteip=65.55.128.81,157.56.91.77 enable=yes
netsh advfirewall firewall add rule name="telemetry_chinamobileltd.com" dir=out action=block remoteip=211.137.82.38 enable=yes
netsh advfirewall firewall add rule name="telemetry_cdn.energetichabits.com" dir=out action=block remoteip=93.184.220.20 enable=yes
netsh advfirewall firewall add rule name="telemetry_cdn.deezer.com.c.footprint.net" dir=out action=block remoteip=8.254.209.254 enable=yes
netsh advfirewall firewall add rule name="telemetry_cannon-construction.co.uk" dir=out action=block remoteip=93.184.220.29 enable=yes
netsh advfirewall firewall add rule name="telemetry_candycrushsoda.king.com" dir=out action=block remoteip=185.48.81.162 enable=yes
netsh advfirewall firewall add rule name="telemetry_c.nine.com.au" dir=out action=block remoteip=207.46.194.10 enable=yes
netsh advfirewall firewall add rule name="telemetry_c.microsoft.akadns.net" dir=out action=block remoteip=134.170.188.139 enable=yes
netsh advfirewall firewall add rule name="telemetry_bsnl.eyeblaster.akadns.net" dir=out action=block remoteip=82.199.80.141 enable=yes
netsh advfirewall firewall add rule name="telemetry_bots.teams.skype.com" dir=out action=block remoteip=13.107.3.128 enable=yes
netsh advfirewall firewall add rule name="telemetry_bn2.vortex.data.microsoft.com.akadns.net" dir=out action=block remoteip=65.55.44.109 enable=yes
netsh advfirewall firewall add rule name="telemetry_blu173-mail-live-com.a-0006.a-msedge.net" dir=out action=block remoteip=204.79.197.208 enable=yes
netsh advfirewall firewall add rule name="telemetry_beta.t.urs.microsoft.com" dir=out action=block remoteip=157.56.74.250 enable=yes
netsh advfirewall firewall add rule name="telemetry_bay175-mail-live-com.a-0007.a-msedge.net" dir=out action=block remoteip=204.79.197.209 enable=yes
netsh advfirewall firewall add rule name="telemetry_b.ns.nsatc.net" dir=out action=block remoteip=198.78.208.155 enable=yes
netsh advfirewall firewall add rule name="telemetry_auth.nym2.appnexus.net" dir=out action=block remoteip=68.67.155.138 enable=yes
netsh advfirewall firewall add rule name="telemetry_auth.lax1.appnexus.net" dir=out action=block remoteip=68.67.133.169 enable=yes
netsh advfirewall firewall add rule name="telemetry_auth.ams1.appnexus.net" dir=out action=block remoteip=37.252.164.5 enable=yes
netsh advfirewall firewall add rule name="telemetry_assets2.parliament.uk.c.footprint.net" dir=out action=block remoteip=192.221.106.126 enable=yes
netsh advfirewall firewall add rule name="telemetry_assets.dishonline.com.c.footprint.net" dir=out action=block remoteip=207.123.56.252 enable=yes
netsh advfirewall firewall add rule name="telemetry_asimov-sandbox.vortex.data.microsoft.com.akadns.net" dir=out action=block remoteip=64.4.54.32 enable=yes
netsh advfirewall firewall add rule name="telemetry_array204-prod.dodsp.mp.microsoft.com.nsatc.net" dir=out action=block remoteip=65.52.0.0-65.52.255.255 enable=yes
netsh advfirewall firewall add rule name="telemetry_apnic.net" dir=out action=block remoteip=221.232.247.2,222.216.3.213 enable=yes
netsh advfirewall firewall add rule name="telemetry_a-msedge.net" dir=out action=block remoteip=204.79.197.204 enable=yes
netsh advfirewall firewall add rule name="telemetry_ams1-ib.adnxs.com" dir=out action=block remoteip=37.252.163.207,37.252.162.228,37.252.162.216 enable=yes
netsh advfirewall firewall add rule name="telemetry_ampudc.udc0.glbdns2.microsoft.com" dir=out action=block remoteip=137.116.81.24 enable=yes
netsh advfirewall firewall add rule name="telemetry_akadns.info" dir=out action=block remoteip=157.56.96.54 enable=yes
netsh advfirewall firewall add rule name="telemetry_ads.msn.com" dir=out action=block remoteip=157.56.91.82,157.56.23.91,104.82.14.146,207.123.56.252,185.13.160.61,8.254.209.254,65.55.128.80,8.12.207.125 enable=yes
netsh advfirewall firewall add rule name="telemetry_adnxs.com" dir=out action=block remoteip=37.252.170.80,37.252.170.142,37.252.170.140,37.252.169.43 enable=yes
netsh advfirewall firewall add rule name="telemetry_ad.doubleclick.net" dir=out action=block remoteip=172.217.20.230 enable=yes
netsh advfirewall firewall add rule name="telemetry_acyfdr.explicit.bing.net" dir=out action=block remoteip=204.79.197.201 enable=yes
netsh advfirewall firewall add rule name="telemetry_a.msft.net" dir=out action=block remoteip=208.76.45.53 enable=yes
netsh advfirewall firewall add rule name="Block_TCP-69" dir=in action=block protocol=tcp localport=69 enable=yes
netsh advfirewall firewall add rule name="Block_TCP-135" dir=in action=block protocol=tcp localport=135 enable=yes
netsh advfirewall firewall add rule name="Block_TCP-137" dir=in action=block protocol=tcp localport=137 enable=yes
netsh advfirewall firewall add rule name="Block_TCP-138" dir=in action=block protocol=tcp localport=138 enable=yes
netsh advfirewall firewall add rule name="Block_TCP-139" dir=in action=block protocol=tcp localport=139 enable=yes
netsh advfirewall firewall add rule name="Block_TCP-445" dir=in action=block protocol=tcp localport=445 enable=yes
netsh advfirewall firewall add rule name="Block_TCP-1025" dir=in action=block protocol=tcp localport=1025 enable=yes
netsh advfirewall firewall add rule name="Block_TCP-4444" dir=in action=block protocol=tcp localport=4444 enable=yes
netsh advfirewall firewall add rule name="Block_TCP-5000" dir=in action=block protocol=tcp localport=5000 enable=yes
GOTO REG
:RESTART
ECHO ********** Reboot
SHUTDOWN -r -t 00
