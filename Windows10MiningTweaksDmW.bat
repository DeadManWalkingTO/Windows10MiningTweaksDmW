REM ========== Start ==========

REM -----------Requesting administrative privileges---------------
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
REM ---------------------------------------------------------

CLS
@ECHO OFF
COLOR 1F
SET V=3.1.4
TITLE Windows 10 Mining Tweaks (x64) Version %V% by: DeadManWalking
ECHO ###############################################################################
ECHO #                                                                             #
ECHO #  Windows10MiningTweaksDmW Version %V%                                     #
ECHO #                                                                             #
ECHO #  Microsoft Windows 10  --  Build 10240 (x64) or later                       #
ECHO #                                                                             #
ECHO #  AUTHOR: DeadManWalking  (DeadManWalkingTO-GitHub)                          #
ECHO #                                                                             #
ECHO #                                                                             #
ECHO #  Features                                                                   #
ECHO #                                                                             #
ECHO #  1. Registry Tweaks                                                         #
ECHO #  2. Removing Services                                                       #
ECHO #  3. Removing Scheduled Tasks                                                #
ECHO #  4. Removing Windows Default Apps                                           #
ECHO #  5. Disable / Remove OneDrive                                               #
ECHO #  6. Blocking Telemetry Servers                                              #
ECHO #                                                                             #
ECHO ###############################################################################
ECHO.

REM ========== 1. Registry Tweaks ==========

ECHO.
ECHO ###############################################################################
ECHO #  1. Registry Tweaks  --  Start                                              #
ECHO ###############################################################################
ECHO.

:regstart
set /p registry="Apply Registry tweaks? y/n: "
if '%registry%' == 'n' goto regend
if /i "%registry%" neq "y" goto regstart

:reg0start
set /p reg0="Replace Utilman with CMD? y/n: "
if '%reg0%' == 'n' goto reg1start
if /i "%reg0%" neq "y" goto reg0start
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "cmd.exe" /f > NUL 2>&1

:reg1start
set /p reg1="Disable Quick Access as default view in Explorer? y/n: "
if '%reg1%' == 'n' goto reg2start
if /i "%reg1%" neq "y" goto reg1start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "LaunchTo" /t REG_DWORD /d 0 > NUL 2>&1

:reg2start
set /p reg2="Show computer shortcut on desktop? y/n: "
if '%reg2%' == 'n' goto reg3start
if /i "%reg2%" neq "y" goto reg2start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg3start
set /p reg3="Show file extensions? y/n: "
if '%reg3%' == 'n' goto reg4start
if /i "%reg3%" neq "y" goto reg3start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg4start
set /p reg4="Disable lockscreen? y/n: "
if '%reg4%' == 'n' goto reg5start
if /i "%reg4%" neq "y" goto reg4start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg5start
set /p reg5="Enable classic control panel view? y/n: "
if '%reg5%' == 'n' goto reg6start
if /i "%reg5%" neq "y" goto reg5start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg6start
set /p reg6="Hide indication for compressed NTFS files? y/n: "
if '%reg6%' == 'n' goto reg7start
if /i "%reg6%" neq "y" goto reg6start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t RED_DWORD /d 0 /f > NUL 2>&1

:reg7start
set /p reg7="Disable Windows Update sharing? y/n: "
if '%reg7%' == 'n' goto reg8start
if /i "%reg7%" neq "y" goto reg7start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg8start
set /p reg8="Remove Pin to start? y/n: "
if '%reg8%' == 'n' goto reg9start
if /i "%reg8%" neq "y" goto reg8start
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1

:reg9start
set /p reg9="Classic vertical icon spacing? y/n: "
if '%reg9%' == 'n' goto reg10start
if /i "%reg9%" neq "y" goto reg9start
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1150" /f > NUL 2>&1

:reg10start
set /p reg10="Remove versioning tab from properties? y/n: "
if '%reg10%' == 'n' goto reg11start
if /i "%reg10%" neq "y" goto reg10start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v NoPreviousVersionsPage /t REG_DWORD /d 1 /f > NUL 2>&1

:reg11start
set /p reg11="Disable jump lists? y/n: "
if '%reg11%' == 'n' goto reg12start
if /i "%reg11%" neq "y" goto reg11start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg12start
set /p reg12="Remove telemetry and data collection? y/n: "
if '%reg12%' == 'n' goto reg13start
if /i "%reg12%" neq "y" goto reg12start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg13start
set /p reg13="Apply Internet Explorer 11 tweaks? y/n: "
if '%reg13%' == 'n' goto reg14start
if /i "%reg13%" neq "y" goto reg13start
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.com" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.com" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg14start
set /p reg14="Disable Cortana, Bing Search and Searchbar? y/n: "
if '%reg14%' == 'n' goto reg15start
if /i "%reg14%" neq "y" goto reg14start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg15start
set /p reg15="Change Logon screen background with accent color? y/n: "
if '%reg15%' == 'n' goto reg16start
if /i "%reg15%" neq "y" goto reg15start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg16start
set /p reg16="Disable Windows Error Reporting? y/n: "
if '%reg16%' == 'n' goto reg17start
if /i "%reg16%" neq "y" goto reg16start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg17start
set /p reg17="Disable automatic Windows Updates? y/n: "
if '%reg17%' == 'n' goto reg18start
if /i "%reg17%" neq "y" goto reg17start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d 2 /f > NUL 2>&1

:reg18start
set /p reg18="Disable Hibernation? y/n: "
if '%reg18%' == 'n' goto servstart
if /i "%reg18%" neq "y" goto reg18start
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

:regend
ECHO.
ECHO ###############################################################################
ECHO #  1. Registry Tweaks  --  End                                                #
ECHO ###############################################################################
ECHO.

REM ========== 2. Removing Services ==========

ECHO.
ECHO ###############################################################################
ECHO #  2. Removing Services  --  Start                                            #
ECHO ###############################################################################
ECHO.

:servstart
set /p services="Removing Services? y/n: "
if '%services%' == 'n' goto servend
if /i "%services%" neq "n" if /i "%services%" neq "y" goto servstart

:serv01start
set /p serv01="Disable Connected User Experiences and Telemetry (To turn off Telemetry and Data Collection)? y/n: "
if '%serv01%' == 'n' goto serv02start
if /i "%serv01%" neq "y" goto serv01start
sc config DiagTrack start= Disabled > NUL 2>&1

:serv02start
set /p serv02="Disable Diagnostic Policy Service? y/n: "
if '%serv02%' == 'n' goto serv03start
if /i "%serv02%" neq "y" goto serv02start
sc config DPS start= Disabled > NUL 2>&1

:serv03start
set /p serv03="Disable Distributed Link Tracking Client (If your computer is not connected to any network)? y/n: "
if '%serv03%' == 'n' goto serv04start
if /i "%serv03%" neq "y" goto serv03start
sc config TrkWks start= Disabled > NUL 2>&1

:serv04start
set /p serv04="Disable WAP Push Message Routing Service (To turn off Telemetry and Data Collection)? y/n: "
if '%serv04%' == 'n' goto serv05start
if /i "%serv04%" neq "y" goto serv04start
sc config dmwappushservice start= Disabled > NUL 2>&1

:serv05start
set /p serv05="Disable Downloaded Maps Manager (If you don't use Maps app)? y/n: "
if '%serv05%' == 'n' goto serv06start
if /i "%serv05%" neq "y" goto serv05start
sc config MapsBroker start= Disabled > NUL 2>&1

:serv06start
set /p serv06="Disable IP Helper (If you don't use IPv6 connection)? y/n: "
if '%serv06%' == 'n' goto serv07start
if /i "%serv06%" neq "y" goto serv06start
sc config iphlpsvc start= Disabled > NUL 2>&1 

:serv07start
set /p serv07="Disable Program Compatibility Assistant Service? y/n: "
if '%serv07%' == 'n' goto serv08start
if /i "%serv07%" neq "y" goto serv07start
sc config PcaSvc start= Disabled > NUL 2>&1 
	
:serv08start
set /p serv08="Disable Print Spooler (If you don't have a printer)? y/n: "
if '%serv08%' == 'n' goto serv09start
if /i "%serv08%" neq "y" goto serv08start
sc config Spooler start= Disabled > NUL 2>&1 

:serv09start
set /p serv09="Disable Remote Registry (You can set it to DISABLED for Security purposes)? y/n: "
if '%serv09%' == 'n' goto serv10start
if /i "%serv09%" neq "y" goto serv09start
sc config RemoteRegistry start= Disabled > NUL 2>&1 
	
:serv10start
set /p serv10="Disable Secondary Logon? y/n: "
if '%serv10%' == 'n' goto serv11start
if /i "%serv10%" neq "y" goto serv10start
sc config seclogon start= Disabled > NUL 2>&1 	
	
:serv11start
set /p serv11="Disable Security Center? y/n: "
if '%serv11%' == 'n' goto serv12start
if /i "%serv11%" neq "y" goto serv11start
sc config wscsvc start= Disabled > NUL 2>&1 
	
:serv12start
set /p serv12="Disable TCP/IP NetBIOS Helper (If you are not in a workgroup network)? y/n: "
if '%serv12%' == 'n' goto serv13start
if /i "%serv12%" neq "y" goto serv12start
sc config lmhosts start= Disabled > NUL 2>&1
	
:serv13start
set /p serv13="Disable Touch Keyboard and Handwriting Panel Service (If you don't want to use touch keyboard and handwriting features)? y/n: "
if '%serv13%' == 'n' goto serv14start
if /i "%serv13%" neq "y" goto serv13start
sc config TabletInputService start= Disabled > NUL 2>&1
	
:serv14start
set /p serv14="Disable Windows Error Reporting Service? y/n: "
if '%serv14%' == 'n' goto serv15start
if /i "%serv14%" neq "y" goto serv14start
sc config WerSvc start= Disabled > NUL 2>&1
	
:serv15start
set /p serv15="Disable Windows Image Acquisition (WIA) (If you don't have a scanner)? y/n: "
if '%serv15%' == 'n' goto serv16start
if /i "%serv15%" neq "y" goto serv15start
sc config stisvc start= Disabled > NUL 2>&1

:serv16start
set /p serv16="Disable Windows Search? y/n: "
if '%serv16%' == 'n' goto serv17start
if /i "%serv16%" neq "y" goto serv16start
sc config WSearch start= Disabled > NUL 2>&1
del "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /s > NUL 2>&1

:serv17start
set /p serv17="Disable tracking services? y/n: "
if '%serv17%' == 'n' goto serv18start
if /i "%serv17%" neq "y" goto serv17start
sc config diagnosticshub.standardcollector.service start= Disabled > NUL 2>&1
sc config WMPNetworkSvc start= Disabled > NUL 2>&1

:serv18start
set /p serv18="Disable Superfetch? y/n: "
if '%serv18%' == 'n' goto serv19start
if /i "%serv18%" neq "y" goto serv18start
sc config SysMain start= Disabled > NUL 2>&1

:serv19start
set /p serv19="Disable Windows Defender? y/n: "
if '%serv19%' == 'n' goto servend
if /i "%serv19%" neq "y" goto serv19start
sc config WinDefend start= Disabled > NUL 2>&1
sc config WdNisSvc start= Disabled > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > NUL 2>&1
del "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*" /s > NUL 2>&1

:servend
ECHO.
ECHO ###############################################################################
ECHO #  2. Removing Services  --  End                                              #
ECHO ###############################################################################
ECHO.

REM ========== 3. Removing Scheduled Tasks ==========

ECHO.
ECHO ###############################################################################
ECHO #  3. Removing Scheduled Tasks  --  Start                                     #
ECHO ###############################################################################
ECHO.

:schedstart
set /p schedules="Removing scheduled tasks? y/n: "
if '%schedules%' == 'n' goto schedend
if /i "%schedules%" neq "n" if /i "%schedules%" neq "y" goto schedstart

schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > NUL 2>&1

:schedend
ECHO.
ECHO ###############################################################################
ECHO #  3. Removing Scheduled Tasks  --  End                                       #
ECHO ###############################################################################
ECHO.

REM ========== 4. Removing Windows Default Apps ==========

ECHO.
ECHO ###############################################################################
ECHO #  4. Removing Windows Default Apps  --  Start                                #
ECHO ###############################################################################
ECHO.

:winappstart
set /p winapps="Removing Windows default apps? y/n: "
if '%winapps%' == 'n' goto winappend
if /i "%winapps%" neq "n" if /i "%winapps%" neq "y" goto winappstart

powershell "Get-AppxPackage *3d* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *bing* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *zune* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *photo* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *communi* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *solit* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *phone* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *soundrec* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *camera* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *people* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *office* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *xbox* | Remove-AppxPackage" > NUL 2>&1

:winappend
ECHO.
ECHO ###############################################################################
ECHO #  4. Removing Windows Default Apps  --  End                                  #
ECHO ###############################################################################
ECHO.

REM ========== 5. Disable / Remove OneDrive ==========

ECHO.
ECHO ###############################################################################
ECHO #  5. Disable / Remove OneDrive  --  Start                                    #
ECHO ###############################################################################
ECHO.

:odrivestart
set /p onedrive="Disable OneDrive? y/n: "
if '%onedrive%' == 'n' goto odriveend
if /i "%onedrive%" neq "y" goto odrivestart
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > NUL 2>&1

:odriveend
ECHO.
ECHO ###############################################################################
ECHO #  5. Disable / Remove OneDrive  --  End                                      #
ECHO ###############################################################################
ECHO.

REM ========== 6. Blocking Telemetry Servers ==========

ECHO.
ECHO ###############################################################################
ECHO #  6. Blocking Telemetry Servers  --  Start                                   #
ECHO ###############################################################################
ECHO.

:hoststart
set /p hostsblock="Blocking Telemetry Servers? y/n: "
if '%hostsblock%' == 'n' goto hostend
if /i "%hostsblock%" neq "n" if /i "%hostsblock%" neq "y" goto hoststart

copy "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > NUL 2>&1
attrib -r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1
FIND /C /I "vortex.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telecommand.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 oca.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "redir.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 redir.metaservices.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 choice.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 choice.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "reports.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "services.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 services.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.ppe.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.ppe.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.appex.bing.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.urs.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.urs.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net:443" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.appex.bing.net:443>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "settings-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 settings-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
attrib +r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1

:hostend
ECHO.
ECHO ###############################################################################
ECHO #  6. Blocking Telemetry Servers  --  End                                     #
ECHO ###############################################################################
ECHO.

REM ========== Finish ==========

:finish
ECHO.
ECHO ###############################################################################
ECHO #                                                                             #
ECHO #  Windows10MiningTweaksDmW Version %V%                                     #
ECHO #                                                                             #
ECHO #  AUTHOR: DeadManWalking  (DeadManWalkingTO-GitHub)                          #
ECHO #                                                                             #
ECHO ###############################################################################
ECHO #                                                                             #
ECHO #  Finish. Ready for mining!                                                  #
ECHO #                                                                             #
ECHO #  Press any key to exit.                                                     #
ECHO #                                                                             #
ECHO ###############################################################################
PAUSE > NUL

REM ========== EOF ==========
