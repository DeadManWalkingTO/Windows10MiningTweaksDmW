REM ========== Start ==========

CLS
@ECHO OFF
COLOR 1F
SET V=3.2.9
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

REM ========== Automatically Check & Get Admin Rights ==========

:init
SETLOCAL DisableDelayedExpansion
SET "batchPath=%~0"
FOR %%k IN (%0) DO SET batchName=%%~nk
SET "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
SETLOCAL EnableDelayedExpansion

:checkPrivileges
NET FILE 1>NUL 2>NUL
IF '%errorlevel%' == '0' ( GOTO gotPrivileges ) ELSE ( GOTO getPrivileges )

:getPrivileges
IF '%1'=='ELEV' (ECHO ELEV & SHIFT /1 & GOTO gotPrivileges)
ECHO.
ECHO ###############################################################################
ECHO #  Invoking UAC for Privilege Escalation                                      #
ECHO ###############################################################################

ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
ECHO args = "ELEV " >> "%vbsGetPrivileges%"
ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
ECHO Next >> "%vbsGetPrivileges%"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
EXIT /B

:gotPrivileges
SETLOCAL & PUSHD .
CD /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>NUL 2>NUL  &  SHIFT /1)

REM ========== 1. Registry Tweaks ==========

ECHO.
ECHO ###############################################################################
ECHO #  1. Registry Tweaks  --  Start                                              #
ECHO ###############################################################################
ECHO.

:regstart
SET /p registry="Apply Registry tweaks? y/n: "
IF '%registry%' == 'n' GOTO regend
IF /i "%registry%" neq "y" GOTO regstart

:reg0start
SET /p reg0="Replace Utilman with CMD? y/n: "
IF '%reg0%' == 'n' GOTO reg1start
IF /i "%reg0%" neq "y" GOTO reg0start
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "cmd.exe" /f > NUL 2>&1

:reg1start
SET /p reg1="Disable Quick Access as default view in Explorer? y/n: "
IF '%reg1%' == 'n' GOTO reg2start
IF /i "%reg1%" neq "y" GOTO reg1start
REG add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "LaunchTo" /t REG_DWORD /d 0 > NUL 2>&1

:reg2start
SET /p reg2="Show computer shortcut on desktop? y/n: "
IF '%reg2%' == 'n' GOTO reg3start
IF /i "%reg2%" neq "y" GOTO reg2start
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg3start
SET /p reg3="Show file extensions? y/n: "
IF '%reg3%' == 'n' GOTO reg4start
IF /i "%reg3%" neq "y" GOTO reg3start
REG add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg4start
SET /p reg4="Disable lockscreen? y/n: "
IF '%reg4%' == 'n' GOTO reg5start
IF /i "%reg4%" neq "y" GOTO reg4start
REG add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg5start
SET /p reg5="Enable classic control panel view? y/n: "
IF '%reg5%' == 'n' GOTO reg6start
IF /i "%reg5%" neq "y" GOTO reg5start
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg6start
SET /p reg6="Hide indication for compressed NTFS files? y/n: "
IF '%reg6%' == 'n' GOTO reg7start
IF /i "%reg6%" neq "y" GOTO reg6start
REG add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t RED_DWORD /d 0 /f > NUL 2>&1

:reg7start
SET /p reg7="Disable Windows Update sharing? y/n: "
IF '%reg7%' == 'n' GOTO reg8start
IF /i "%reg7%" neq "y" GOTO reg7start
REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg8start
SET /p reg8="Remove Pin to start? y/n: "
IF '%reg8%' == 'n' GOTO reg9start
IF /i "%reg8%" neq "y" GOTO reg8start
REG delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
REG delete "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
REG delete "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1

:reg9start
SET /p reg9="Classic vertical icon spacing? y/n: "
IF '%reg9%' == 'n' GOTO reg10start
IF /i "%reg9%" neq "y" GOTO reg9start
REG add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1150" /f > NUL 2>&1

:reg10start
SET /p reg10="Remove versioning tab from properties? y/n: "
IF '%reg10%' == 'n' GOTO reg11start
IF /i "%reg10%" neq "y" GOTO reg10start
REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v NoPreviousVersionsPage /t REG_DWORD /d 1 /f > NUL 2>&1

:reg11start
SET /p reg11="Disable jump lists? y/n: "
IF '%reg11%' == 'n' GOTO reg12start
IF /i "%reg11%" neq "y" GOTO reg11start
REG add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg12start
SET /p reg12="Remove telemetry and data collection? y/n: "
IF '%reg12%' == 'n' GOTO reg13start
IF /i "%reg12%" neq "y" GOTO reg12start
REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg13start
SET /p reg13="Apply Internet Explorer 11 tweaks? y/n: "
IF '%reg13%' == 'n' GOTO reg14start
IF /i "%reg13%" neq "y" GOTO reg13start
REG add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.com" /f > NUL 2>&1
REG add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.com" /f > NUL 2>&1
REG add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
REG add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg14start
SET /p reg14="Disable Cortana, Bing Search and Searchbar? y/n: "
IF '%reg14%' == 'n' GOTO reg15start
IF /i "%reg14%" neq "y" GOTO reg14start
REG add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > NUL 2>&1
REG add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg15start
SET /p reg15="Change Logon screen background with accent color? y/n: "
IF '%reg15%' == 'n' GOTO reg16start
IF /i "%reg15%" neq "y" GOTO reg15start
REG add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg16start
SET /p reg16="Disable Windows Error Reporting? y/n: "
IF '%reg16%' == 'n' GOTO reg17start
IF /i "%reg16%" neq "y" GOTO reg16start
REG add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg17start
SET /p reg17="Disable automatic Windows Updates? y/n: "
IF '%reg17%' == 'n' GOTO reg18start
IF /i "%reg17%" neq "y" GOTO reg17start
REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d 2 /f > NUL 2>&1

:reg18start
SET /p reg18="Disable Hibernation? y/n: "
IF '%reg18%' == 'n' GOTO servstart
IF /i "%reg18%" neq "y" GOTO reg18start
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

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
SET /p services="Removing Services? y/n: "
IF '%services%' == 'n' GOTO servend
IF /i "%services%" neq "n" IF /i "%services%" neq "y" GOTO servstart

:serv01start
SET /p serv01="Disable Connected User Experiences and Telemetry (To turn off Telemetry and Data Collection)? y/n: "
IF '%serv01%' == 'n' GOTO serv02start
IF /i "%serv01%" neq "y" GOTO serv01start
SC config DiagTrack START= Disabled > NUL 2>&1

:serv02start
SET /p serv02="Disable Diagnostic Policy Service? y/n: "
IF '%serv02%' == 'n' GOTO serv03start
IF /i "%serv02%" neq "y" GOTO serv02start
SC config DPS START= Disabled > NUL 2>&1

:serv03start
SET /p serv03="Disable Distributed Link Tracking Client (If your computer is not connected to any network)? y/n: "
IF '%serv03%' == 'n' GOTO serv04start
IF /i "%serv03%" neq "y" GOTO serv03start
SC config TrkWks START= Disabled > NUL 2>&1

:serv04start
SET /p serv04="Disable WAP Push Message Routing Service (To turn off Telemetry and Data Collection)? y/n: "
IF '%serv04%' == 'n' GOTO serv05start
IF /i "%serv04%" neq "y" GOTO serv04start
SC config dmwappushservice START= Disabled > NUL 2>&1

:serv05start
SET /p serv05="Disable Downloaded Maps Manager (If you don't use Maps app)? y/n: "
IF '%serv05%' == 'n' GOTO serv06start
IF /i "%serv05%" neq "y" GOTO serv05start
SC config MapsBroker START= Disabled > NUL 2>&1

:serv06start
SET /p serv06="Disable IP Helper (If you don't use IPv6 connection)? y/n: "
IF '%serv06%' == 'n' GOTO serv07start
IF /i "%serv06%" neq "y" GOTO serv06start
SC config iphlpsvc START= Disabled > NUL 2>&1 

:serv07start
SET /p serv07="Disable Program Compatibility Assistant Service? y/n: "
IF '%serv07%' == 'n' GOTO serv08start
IF /i "%serv07%" neq "y" GOTO serv07start
SC config PcaSvc START= Disabled > NUL 2>&1 
	
:serv08start
SET /p serv08="Disable Print Spooler (If you don't have a printer)? y/n: "
IF '%serv08%' == 'n' GOTO serv09start
IF /i "%serv08%" neq "y" GOTO serv08start
SC config Spooler START= Disabled > NUL 2>&1 

:serv09start
SET /p serv09="Disable Remote Registry (You can set it to DISABLED for Security purposes)? y/n: "
IF '%serv09%' == 'n' GOTO serv10start
IF /i "%serv09%" neq "y" GOTO serv09start
SC config RemoteRegistry START= Disabled > NUL 2>&1 
	
:serv10start
SET /p serv10="Disable Secondary Logon? y/n: "
IF '%serv10%' == 'n' GOTO serv11start
IF /i "%serv10%" neq "y" GOTO serv10start
SC config seclogon START= Disabled > NUL 2>&1 	
	
:serv11start
SET /p serv11="Disable Security Center? y/n: "
IF '%serv11%' == 'n' GOTO serv12start
IF /i "%serv11%" neq "y" GOTO serv11start
SC config wscsvc START= Disabled > NUL 2>&1 
	
:serv12start
SET /p serv12="Disable TCP/IP NetBIOS Helper (If you are not in a workgroup network)? y/n: "
IF '%serv12%' == 'n' GOTO serv13start
IF /i "%serv12%" neq "y" GOTO serv12start
SC config lmhosts START= Disabled > NUL 2>&1
	
:serv13start
SET /p serv13="Disable Touch Keyboard and Handwriting Panel Service (If you don't want to use touch keyboard and handwriting features)? y/n: "
IF '%serv13%' == 'n' GOTO serv14start
IF /i "%serv13%" neq "y" GOTO serv13start
SC config TabletInputService START= Disabled > NUL 2>&1
	
:serv14start
SET /p serv14="Disable Windows Error Reporting Service? y/n: "
IF '%serv14%' == 'n' GOTO serv15start
IF /i "%serv14%" neq "y" GOTO serv14start
SC config WerSvc START= Disabled > NUL 2>&1
	
:serv15start
SET /p serv15="Disable Windows Image Acquisition (WIA) (If you don't have a scanner)? y/n: "
IF '%serv15%' == 'n' GOTO serv16start
IF /i "%serv15%" neq "y" GOTO serv15start
SC config stisvc START= Disabled > NUL 2>&1

:serv16start
SET /p serv16="Disable Windows Search? y/n: "
IF '%serv16%' == 'n' GOTO serv17start
IF /i "%serv16%" neq "y" GOTO serv16start
SC config WSearch START= Disabled > NUL 2>&1
del "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /s > NUL 2>&1

:serv17start
SET /p serv17="Disable tracking services? y/n: "
IF '%serv17%' == 'n' GOTO serv18start
IF /i "%serv17%" neq "y" GOTO serv17start
SC config diagnosticshub.standardcollector.service START= Disabled > NUL 2>&1
SC config WMPNetworkSvc START= Disabled > NUL 2>&1

:serv18start
SET /p serv18="Disable Superfetch? y/n: "
IF '%serv18%' == 'n' GOTO serv19start
IF /i "%serv18%" neq "y" GOTO serv18start
SC config SysMain START= Disabled > NUL 2>&1

:serv19start
SET /p serv19="Disable Windows Defender? y/n: "
IF '%serv19%' == 'n' GOTO serv20start
IF /i "%serv19%" neq "y" GOTO serv19start
SC config WinDefend START= Disabled > NUL 2>&1
SC config WdNisSvc START= Disabled > NUL 2>&1
REG add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > NUL 2>&1
DEL "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*" /s > NUL 2>&1

:serv20start
SET /p serv20="Xbox Services (5)? y/n: "
IF '%serv20%' == 'n' GOTO serv21start
IF /i "%serv20%" neq "y" GOTO serv20start
REM Xbox Accessory Management Service
SC config XboxGipSvc START= Disabled > NUL 2>&1
REM Xbox Game Monitoring
SC config xbgm START= Disabled > NUL 2>&1
REM Xbox Live Auth Manager
SC config XblAuthManager START= Disabled > NUL 2>&1
REM Xbox Live Game Save
SC config XblGameSave START= Disabled > NUL 2>&1
REM Xbox Live Networking Service
SC config XboxNetApiSvc START= Disabled > NUL 2>&1

:serv21start
SET /p serv21="AllJoyn Router Service? y/n: "
IF '%serv21%' == 'n' GOTO serv22start
IF /i "%serv21%" neq "y" GOTO serv21start
REM  This service is used for routing the AllJoyn messages for AllJoyn clients.
SC config AJRouter START= Disabled > NUL 2>&1

:serv22start
SET /p serv22="Bluetooth Services (2)? y/n: "
IF '%serv22%' == 'n' GOTO serv23start
IF /i "%serv22%" neq "y" GOTO serv22start
REM Bluetooth Handsfree Service
SC config BthHFSrv START= Disabled > NUL 2>&1
REM Bluetooth Support Service
SC config bthserv START= Disabled > NUL 2>&1

:serv23start
SET /p serv23="Geolocation Service? y/n: "
IF '%serv23%' == 'n' GOTO serv24start
IF /i "%serv23%" neq "y" GOTO serv23start
SC config lfsvc START= Disabled > NUL 2>&1

:serv24start
SET /p serv24="Phone Service? y/n: "
IF '%serv24%' == 'n' GOTO serv25start
IF /i "%serv24%" neq "y" GOTO serv24start
SC config PhoneSvc START= Disabled > NUL 2>&1

:serv25start
SET /p serv25="Windows Biometric Service? y/n: "
IF '%serv25%' == 'n' GOTO serv26start
IF /i "%serv25%" neq "y" GOTO serv25start
SC config WbioSrvc START= Disabled > NUL 2>&1

:serv26start
SET /p serv26="Windows Mobile Hotspot Service? y/n: "
IF '%serv26%' == 'n' GOTO serv27start
IF /i "%serv26%" neq "y" GOTO serv26start
SC config icssvc START= Disabled > NUL 2>&1

:serv27start
SET /p serv27="Windows Media Player Network Sharing Service? y/n: "
IF '%serv27%' == 'n' GOTO serv28start
IF /i "%serv27%" neq "y" GOTO serv27start
SC config WMPNetworkSvc START= Disabled > NUL 2>&1

:serv28start
SET /p serv28="Windows Update Service? y/n: "
IF '%serv28%' == 'n' GOTO serv29start
IF /i "%serv28%" neq "y" GOTO serv28start
SC config wuauserv START= Disabled > NUL 2>&1

:serv29start
SET /p serv29="Enterprise App Management Service? y/n: "
IF '%serv29%' == 'n' GOTO serv30start
IF /i "%serv29%" neq "y" GOTO serv29start
SC config EntAppSvc START= Disabled > NUL 2>&1

:serv30start
SET /p serv30="Hyper-V Services (9)? y/n: "
IF '%serv30%' == 'n' GOTO servend
IF /i "%serv30%" neq "y" GOTO serv30start
REM HV Host Service
SC config HvHost START= Disabled > NUL 2>&1
REM Hyper-V Data Exchange Service
SC config vmickvpexchange START= Disabled > NUL 2>&1
REM Hyper-V Guest Service Interface
SC config vmicguestinterface START= Disabled > NUL 2>&1
REM Hyper-V Guest Shutdown Service
SC config vmicshutdown START= Disabled > NUL 2>&1
REM Hyper-V Heartbeat Service
SC config vmicheartbeat START= Disabled > NUL 2>&1
REM Hyper-V PowerShell Direct Service
SC config vmicvmsession START= Disabled > NUL 2>&1
REM Hyper-V Remote Desktop Virtualization Service
SC config vmicrdv START= Disabled > NUL 2>&1
REM Hyper-V Time Synchronization Service
SC config vmictimesync START= Disabled > NUL 2>&1
REM Hyper-V Volume Shadow Copy Requestor
SC config vmicvss START= Disabled > NUL 2>&1

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
SET /p schedules="Removing scheduled tasks? y/n: "
IF '%schedules%' == 'n' GOTO schedend
IF /i "%schedules%" neq "n" IF /i "%schedules%" neq "y" GOTO schedstart

SCHTASKS /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > NUL 2>&1
SCHTASKS /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > NUL 2>&1

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
SET /p winapps="Removing Windows default apps? y/n: "
IF '%winapps%' == 'n' GOTO winappend
IF /i "%winapps%" neq "n" IF /i "%winapps%" neq "y" GOTO winappstart

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
SET /p onedrive="Disable OneDrive? y/n: "
IF '%onedrive%' == 'n' GOTO odriveend
IF /i "%onedrive%" neq "y" GOTO odrivestart
REG add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > NUL 2>&1

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
SET /p hostsblock="Blocking Telemetry Servers? y/n: "
IF '%hostsblock%' == 'n' GOTO hostend
IF /i "%hostsblock%" neq "n" IF /i "%hostsblock%" neq "y" GOTO hoststart

COPY "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > NUL 2>&1
ATTRIB -r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1
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
ATTRIB +r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1

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
