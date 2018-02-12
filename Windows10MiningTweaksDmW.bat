rem ========== Start ==========

cls
@echo OFF
clolor 1F
set V=3.3.0
title Windows 10 Mining Tweaks (x64) Version %V% by: DeadManWalking
echo ###############################################################################
echo #                                                                             #
echo #  Windows10MiningTweaksDmW Version %V%                                     #
echo #                                                                             #
echo #  Microsoft Windows 10  --  Build 10240 (x64) or later                       #
echo #                                                                             #
echo #  AUTHOR: DeadManWalking  (DeadManWalkingTO-GitHub)                          #
echo #                                                                             #
echo #                                                                             #
echo #  Features                                                                   #
echo #                                                                             #
echo #  1. Registry Tweaks                                                         #
echo #  2. Removing Services                                                       #
echo #  3. Removing Scheduled Tasks                                                #
echo #  4. Removing Windows Default Apps                                           #
echo #  5. Disable / Remove OneDrive                                               #
echo #  6. Blocking Telemetry Servers                                              #
echo #                                                                             #
echo ###############################################################################
echo.

rem ========== Automatically Check & Get Admin Rights ==========

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion

:checkPrivileges
NET FILE 1>nul 2>nul
if '%errorlevel%' == '0' ( goto gotPrivileges ) ELSE ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
echo.
echo ###############################################################################
echo #  Invoking UAC for Privilege Escalation                                      #
echo ###############################################################################

echo Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
echo args = "ELEV " >> "%vbsGetPrivileges%"
echo For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
echo args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
echo Next >> "%vbsGetPrivileges%"
echo UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
exit /B

:gotPrivileges
setlocal & pushd .
CD /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

rem ========== 1. Registry Tweaks ==========

echo.
echo ###############################################################################
echo #  1. Registry Tweaks  --  Start                                              #
echo ###############################################################################
echo.

:regstart
set /p registry="Apply Registry tweaks? y/n: "
if '%registry%' == 'n' goto regend
if /i "%registry%" neq "y" goto regstart

:reg0start
set /p reg0="Replace Utilman with CMD? y/n: "
if '%reg0%' == 'n' goto reg1start
if /i "%reg0%" neq "y" goto reg0start
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "cmd.exe" /f > nul 2>&1

:reg1start
set /p reg1="Disable Quick Access as default view in Explorer? y/n: "
if '%reg1%' == 'n' goto reg2start
if /i "%reg1%" neq "y" goto reg1start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "LaunchTo" /t REG_DWORD /d 0 > nul 2>&1

:reg2start
set /p reg2="Show computer shortcut on desktop? y/n: "
if '%reg2%' == 'n' goto reg3start
if /i "%reg2%" neq "y" goto reg2start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f > nul 2>&1

:reg3start
set /p reg3="Show file extensions? y/n: "
if '%reg3%' == 'n' goto reg4start
if /i "%reg3%" neq "y" goto reg3start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > nul 2>&1

:reg4start
set /p reg4="Disable lockscreen? y/n: "
if '%reg4%' == 'n' goto reg5start
if /i "%reg4%" neq "y" goto reg4start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f > nul 2>&1

:reg5start
set /p reg5="Enable classic control panel view? y/n: "
if '%reg5%' == 'n' goto reg6start
if /i "%reg5%" neq "y" goto reg5start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /t REG_DWORD /d 1 /f > nul 2>&1

:reg6start
set /p reg6="Hide indication for compressed NTFS files? y/n: "
if '%reg6%' == 'n' goto reg7start
if /i "%reg6%" neq "y" goto reg6start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t RED_DWORD /d 0 /f > nul 2>&1

:reg7start
set /p reg7="Disable Windows Update sharing? y/n: "
if '%reg7%' == 'n' goto reg8start
if /i "%reg7%" neq "y" goto reg7start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > nul 2>&1

:reg8start
set /p reg8="Remove Pin to start? y/n: "
if '%reg8%' == 'n' goto reg9start
if /i "%reg8%" neq "y" goto reg8start
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /f > nul 2>&1

:reg9start
set /p reg9="Classic vertical icon spacing? y/n: "
if '%reg9%' == 'n' goto reg10start
if /i "%reg9%" neq "y" goto reg9start
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1150" /f > nul 2>&1

:reg10start
set /p reg10="Remove versioning tab from properties? y/n: "
if '%reg10%' == 'n' goto reg11start
if /i "%reg10%" neq "y" goto reg10start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v NoPreviousVersionsPage /t REG_DWORD /d 1 /f > nul 2>&1

:reg11start
set /p reg11="Disable jump lists? y/n: "
if '%reg11%' == 'n' goto reg12start
if /i "%reg11%" neq "y" goto reg11start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f > nul 2>&1

:reg12start
set /p reg12="Remove telemetry and data collection? y/n: "
if '%reg12%' == 'n' goto reg13start
if /i "%reg12%" neq "y" goto reg12start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f > nul 2>&1

:reg13start
set /p reg13="Apply Internet Explorer 11 tweaks? y/n: "
if '%reg13%' == 'n' goto reg14start
if /i "%reg13%" neq "y" goto reg13start
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.com" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.com" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > nul 2>&1

:reg14start
set /p reg14="Disable Cortana, Bing Search and Searchbar? y/n: "
if '%reg14%' == 'n' goto reg15start
if /i "%reg14%" neq "y" goto reg14start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > nul 2>&1

:reg15start
set /p reg15="Change Logon screen background with accent color? y/n: "
if '%reg15%' == 'n' goto reg16start
if /i "%reg15%" neq "y" goto reg15start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f > nul 2>&1

:reg16start
set /p reg16="Disable Windows Error Reporting? y/n: "
if '%reg16%' == 'n' goto reg17start
if /i "%reg16%" neq "y" goto reg16start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > nul 2>&1

:reg17start
set /p reg17="Disable automatic Windows Updates? y/n: "
if '%reg17%' == 'n' goto reg18start
if /i "%reg17%" neq "y" goto reg17start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d 2 /f > nul 2>&1

:reg18start
set /p reg18="Disable Hibernation? y/n: "
if '%reg18%' == 'n' goto servstart
if /i "%reg18%" neq "y" goto reg18start
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f > nul 2>&1

:regend
echo.
echo ###############################################################################
echo #  1. Registry Tweaks  --  End                                                #
echo ###############################################################################
echo.

rem ========== 2. Removing Services ==========

echo.
echo ###############################################################################
echo #  2. Removing Services  --  Start                                            #
echo ###############################################################################
echo.

:servstart
set /p services="Removing Services? y/n: "
if '%services%' == 'n' goto servend
if /i "%services%" neq "n" if /i "%services%" neq "y" goto servstart

:serv01start
set /p serv01="Disable Connected User Experiences and Telemetry (To turn off Telemetry and Data Collection)? y/n: "
if '%serv01%' == 'n' goto serv02start
if /i "%serv01%" neq "y" goto serv01start
sc config DiagTrack start= Disabled > nul 2>&1

:serv02start
set /p serv02="Disable Diagnostic Policy Service? y/n: "
if '%serv02%' == 'n' goto serv03start
if /i "%serv02%" neq "y" goto serv02start
sc config DPS start= Disabled > nul 2>&1

:serv03start
set /p serv03="Disable Distributed Link Tracking Client (If your computer is not connected to any network)? y/n: "
if '%serv03%' == 'n' goto serv04start
if /i "%serv03%" neq "y" goto serv03start
sc config TrkWks start= Disabled > nul 2>&1

:serv04start
set /p serv04="Disable WAP Push Message Routing Service (To turn off Telemetry and Data Collection)? y/n: "
if '%serv04%' == 'n' goto serv05start
if /i "%serv04%" neq "y" goto serv04start
sc config dmwappushservice start= Disabled > nul 2>&1

:serv05start
set /p serv05="Disable Downloaded Maps Manager (If you don't use Maps app)? y/n: "
if '%serv05%' == 'n' goto serv06start
if /i "%serv05%" neq "y" goto serv05start
sc config MapsBroker start= Disabled > nul 2>&1

:serv06start
set /p serv06="Disable IP Helper (If you don't use IPv6 connection)? y/n: "
if '%serv06%' == 'n' goto serv07start
if /i "%serv06%" neq "y" goto serv06start
sc config iphlpsvc start= Disabled > nul 2>&1 

:serv07start
set /p serv07="Disable Program Compatibility Assistant Service? y/n: "
if '%serv07%' == 'n' goto serv08start
if /i "%serv07%" neq "y" goto serv07start
sc config PcaSvc start= Disabled > nul 2>&1 
	
:serv08start
set /p serv08="Disable Print Spooler (If you don't have a printer)? y/n: "
if '%serv08%' == 'n' goto serv09start
if /i "%serv08%" neq "y" goto serv08start
sc config Spooler start= Disabled > nul 2>&1 

:serv09start
set /p serv09="Disable Remote Registry (You can set it to DISABLED for Security purposes)? y/n: "
if '%serv09%' == 'n' goto serv10start
if /i "%serv09%" neq "y" goto serv09start
sc config RemoteRegistry start= Disabled > nul 2>&1 
	
:serv10start
set /p serv10="Disable Secondary Logon? y/n: "
if '%serv10%' == 'n' goto serv11start
if /i "%serv10%" neq "y" goto serv10start
sc config seclogon start= Disabled > nul 2>&1 	
	
:serv11start
set /p serv11="Disable Security Center? y/n: "
if '%serv11%' == 'n' goto serv12start
if /i "%serv11%" neq "y" goto serv11start
sc config wscsvc start= Disabled > nul 2>&1 
	
:serv12start
set /p serv12="Disable TCP/IP NetBIOS Helper (If you are not in a workgroup network)? y/n: "
if '%serv12%' == 'n' goto serv13start
if /i "%serv12%" neq "y" goto serv12start
sc config lmhosts start= Disabled > nul 2>&1
	
:serv13start
set /p serv13="Disable Touch Keyboard and Handwriting Panel Service (If you don't want to use touch keyboard and handwriting features)? y/n: "
if '%serv13%' == 'n' goto serv14start
if /i "%serv13%" neq "y" goto serv13start
sc config TabletInputService start= Disabled > nul 2>&1
	
:serv14start
set /p serv14="Disable Windows Error Reporting Service? y/n: "
if '%serv14%' == 'n' goto serv15start
if /i "%serv14%" neq "y" goto serv14start
sc config WerSvc start= Disabled > nul 2>&1
	
:serv15start
set /p serv15="Disable Windows Image Acquisition (WIA) (If you don't have a scanner)? y/n: "
if '%serv15%' == 'n' goto serv16start
if /i "%serv15%" neq "y" goto serv15start
sc config stisvc start= Disabled > nul 2>&1

:serv16start
set /p serv16="Disable Windows Search? y/n: "
if '%serv16%' == 'n' goto serv17start
if /i "%serv16%" neq "y" goto serv16start
sc config WSearch start= Disabled > nul 2>&1
del "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /s > nul 2>&1

:serv17start
set /p serv17="Disable tracking services? y/n: "
if '%serv17%' == 'n' goto serv18start
if /i "%serv17%" neq "y" goto serv17start
sc config diagnosticshub.standardcollector.service start= Disabled > nul 2>&1
sc config WMPNetworkSvc start= Disabled > nul 2>&1

:serv18start
set /p serv18="Disable Superfetch? y/n: "
if '%serv18%' == 'n' goto serv19start
if /i "%serv18%" neq "y" goto serv18start
sc config SysMain start= Disabled > nul 2>&1

:serv19start
set /p serv19="Disable Windows Defender? y/n: "
if '%serv19%' == 'n' goto serv20start
if /i "%serv19%" neq "y" goto serv19start
sc config WinDefend start= Disabled > nul 2>&1
sc config WdNisSvc start= Disabled > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > nul 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > nul 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > nul 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > nul 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > nul 2>&1
DEL "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*" /s > nul 2>&1

:serv20start
set /p serv20="Xbox Services (5)? y/n: "
if '%serv20%' == 'n' goto serv21start
if /i "%serv20%" neq "y" goto serv20start
rem Xbox Accessory Management Service
sc config XboxGipSvc start= Disabled > nul 2>&1
rem Xbox Game Monitoring
sc config xbgm start= Disabled > nul 2>&1
rem Xbox Live Auth Manager
sc config XblAuthManager start= Disabled > nul 2>&1
rem Xbox Live Game Save
sc config XblGameSave start= Disabled > nul 2>&1
rem Xbox Live Networking Service
sc config XboxNetApiSvc start= Disabled > nul 2>&1

:serv21start
set /p serv21="AllJoyn Router Service? y/n: "
if '%serv21%' == 'n' goto serv22start
if /i "%serv21%" neq "y" goto serv21start
rem  This service is used for routing the AllJoyn messages for AllJoyn clients.
sc config AJRouter start= Disabled > nul 2>&1

:serv22start
set /p serv22="Bluetooth Services (2)? y/n: "
if '%serv22%' == 'n' goto serv23start
if /i "%serv22%" neq "y" goto serv22start
rem Bluetooth Handsfree Service
sc config BthHFSrv start= Disabled > nul 2>&1
rem Bluetooth Support Service
sc config bthserv start= Disabled > nul 2>&1

:serv23start
set /p serv23="Geolocation Service? y/n: "
if '%serv23%' == 'n' goto serv24start
if /i "%serv23%" neq "y" goto serv23start
sc config lfsvc start= Disabled > nul 2>&1

:serv24start
set /p serv24="Phone Service? y/n: "
if '%serv24%' == 'n' goto serv25start
if /i "%serv24%" neq "y" goto serv24start
sc config PhoneSvc start= Disabled > nul 2>&1

:serv25start
set /p serv25="Windows Biometric Service? y/n: "
if '%serv25%' == 'n' goto serv26start
if /i "%serv25%" neq "y" goto serv25start
sc config WbioSrvc start= Disabled > nul 2>&1

:serv26start
set /p serv26="Windows Mobile Hotspot Service? y/n: "
if '%serv26%' == 'n' goto serv27start
if /i "%serv26%" neq "y" goto serv26start
sc config icssvc start= Disabled > nul 2>&1

:serv27start
set /p serv27="Windows Media Player Network Sharing Service? y/n: "
if '%serv27%' == 'n' goto serv28start
if /i "%serv27%" neq "y" goto serv27start
sc config WMPNetworkSvc start= Disabled > nul 2>&1

:serv28start
set /p serv28="Windows Update Service? y/n: "
if '%serv28%' == 'n' goto serv29start
if /i "%serv28%" neq "y" goto serv28start
sc config wuauserv start= Disabled > nul 2>&1

:serv29start
set /p serv29="Enterprise App Management Service? y/n: "
if '%serv29%' == 'n' goto serv30start
if /i "%serv29%" neq "y" goto serv29start
sc config EntAppSvc start= Disabled > nul 2>&1

:serv30start
set /p serv30="Hyper-V Services (9)? y/n: "
if '%serv30%' == 'n' goto servend
if /i "%serv30%" neq "y" goto serv30start
rem HV Host Service
sc config HvHost start= Disabled > nul 2>&1
rem Hyper-V Data Exchange Service
sc config vmickvpexchange start= Disabled > nul 2>&1
rem Hyper-V Guest Service Interface
sc config vmicguestinterface start= Disabled > nul 2>&1
rem Hyper-V Guest Shutdown Service
sc config vmicshutdown start= Disabled > nul 2>&1
rem Hyper-V Heartbeat Service
sc config vmicheartbeat start= Disabled > nul 2>&1
rem Hyper-V PowerShell Direct Service
sc config vmicvmsession start= Disabled > nul 2>&1
rem Hyper-V Remote Desktop Virtualization Service
sc config vmicrdv start= Disabled > nul 2>&1
rem Hyper-V Time Synchronization Service
sc config vmictimesync start= Disabled > nul 2>&1
rem Hyper-V Volume Shadow Copy Requestor
sc config vmicvss start= Disabled > nul 2>&1

:servend
echo.
echo ###############################################################################
echo #  2. Removing Services  --  End                                              #
echo ###############################################################################
echo.

rem ========== 3. Removing Scheduled Tasks ==========

echo.
echo ###############################################################################
echo #  3. Removing Scheduled Tasks  --  Start                                     #
echo ###############################################################################
echo.

:schedstart
set /p schedules="Removing scheduled tasks? y/n: "
if '%schedules%' == 'n' goto schedend
if /i "%schedules%" neq "n" if /i "%schedules%" neq "y" goto schedstart

schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > nul 2>&1

:schedend
echo.
echo ###############################################################################
echo #  3. Removing Scheduled Tasks  --  End                                       #
echo ###############################################################################
echo.

rem ========== 4. Removing Windows Default Apps ==========

echo.
echo ###############################################################################
echo #  4. Removing Windows Default Apps  --  Start                                #
echo ###############################################################################
echo.

:winappstart
set /p winapps="Removing Windows default apps? y/n: "
if '%winapps%' == 'n' goto winappend
if /i "%winapps%" neq "n" if /i "%winapps%" neq "y" goto winappstart

powershell "Get-AppxPackage *3d* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *bing* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *zune* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *photo* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *communi* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *solit* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *phone* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *soundrec* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *camera* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *people* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *office* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *xbox* | Remove-AppxPackage" > nul 2>&1

:winappend
echo.
echo ###############################################################################
echo #  4. Removing Windows Default Apps  --  End                                  #
echo ###############################################################################
echo.

rem ========== 5. Disable / Remove OneDrive ==========

echo.
echo ###############################################################################
echo #  5. Disable / Remove OneDrive  --  Start                                    #
echo ###############################################################################
echo.

:odrivestart
set /p onedrive="Disable OneDrive? y/n: "
if '%onedrive%' == 'n' goto odriveend
if /i "%onedrive%" neq "y" goto odrivestart
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > nul 2>&1

:odriveend
echo.
echo ###############################################################################
echo #  5. Disable / Remove OneDrive  --  End                                      #
echo ###############################################################################
echo.

rem ========== 6. Blocking Telemetry Servers ==========

echo.
echo ###############################################################################
echo #  6. Blocking Telemetry Servers  --  Start                                   #
echo ###############################################################################
echo.

:hoststart
set /p hostsblock="Blocking Telemetry Servers? y/n: "
if '%hostsblock%' == 'n' goto hostend
if /i "%hostsblock%" neq "n" if /i "%hostsblock%" neq "y" goto hoststart

copy "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > nul 2>&1
attrib -r "%WINDIR%\system32\drivers\etc\hosts" > nul 2>&1
find /C /I "vortex.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telecommand.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telecommand.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telecommand.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "oca.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 oca.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "oca.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sqm.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sqm.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sqm.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "redir.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 redir.metaservices.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "choice.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 choice.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "choice.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 choice.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "reports.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "services.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 services.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sqm.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sqm.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.ppe.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.ppe.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.appex.bing.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.appex.bing.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.urs.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.urs.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.appex.bing.net:443" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.appex.bing.net:443>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "settings-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 settings-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
attrib +r "%WINDIR%\system32\drivers\etc\hosts" > nul 2>&1

:hostend
echo.
echo ###############################################################################
echo #  6. Blocking Telemetry Servers  --  End                                     #
echo ###############################################################################
echo.

rem ========== Finish ==========

:finish
echo.
echo ###############################################################################
echo #                                                                             #
echo #  Windows10MiningTweaksDmW Version %V%                                     #
echo #                                                                             #
echo #  AUTHOR: DeadManWalking  (DeadManWalkingTO-GitHub)                          #
echo #                                                                             #
echo ###############################################################################
echo #                                                                             #
echo #  Finish. Ready for mining!                                                  #
echo #                                                                             #
echo #  Press any key to exit.                                                     #
echo #                                                                             #
echo ###############################################################################
PAUSE > nul

rem ========== EOF ==========
