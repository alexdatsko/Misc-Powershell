@echo off
:::::::::::::::::::::::::::::::::::::  Please set the name below to the correct server hostname
set servername=server
:::::::::::::::::::::::::::::::::::::
cls
echo.
echo Security Audit - Workstation Script - 01/05/24
echo Alex Datsko (alexd@mmeconsulting.com)
echo.
echo.
echo (This script will attempt to delete itself after if run locally from C:\Temp. If running from a local PC, please delete the script when it is completed!!)
c:
cd \
echo STARTING LOCAL ADMIN PASSWORD ROLL
echo.
net user Administrator DenyNervousBurning22 /add /y /expires:never  
net user Administrator DenyNervousBurning22 /y /expires:never /active:yes
net user MME BelgiumTurnerPayroll22 /add /y /expires:never /fullname:"MME Consulting, Inc." /comment:"MME's Alternate Admin Login"
net user MME BelgiumTurnerPayroll22 /y /expires:never /active:yes /fullname:"MME Consulting, Inc." /comment:"MME's Alternate Admin Login"
net localgroup administrators MME /add
echo.
pause
cls
echo.
echo                       B                         
echo ------------------------------------------------
echo ------------------- Users: ---------------------
echo ------------------------------------------------
net user
echo Guest User account:
net user guest |findstr /i active
echo.
echo.
pause
echo                       C                         
echo ------------------------------------------------
echo ------------------- Shares: --------------------
echo ------------------------------------------------
net share
echo. 
echo.
pause
echo                       D                         
echo ------------------------------------------------
echo --------------- Rogue Stuff: -------------------
echo ------------------------------------------------
appwiz.cpl
echo. 
echo.
pause
echo                       E                         
echo ------------------------------------------------
echo --------------- Mapped Drives: -----------------
echo ------------------------------------------------
net use
::echo PLEASE RUN 'net use' from a NON-ADMIN command prompt!
echo.
echo.
pause
echo                       F                          
echo ------------------------------------------------
echo ------------ Windows version: ------------------
echo ------------------------------------------------
winver
wmic os get Caption,Version,BuildNumber,OSArchitecture
echo.
echo.
pause
echo                       G                         
echo ------------------------------------------------
echo ------------ Windows updates: ------------------
echo ------------------------------------------------
if exist "%windir%\system32\wuapp.exe" (
  start "%windir%\system32\wuapp.exe"
) else (
  start ms-settings:windowsupdate
)
::  start wuauclt.exe /detectnow
::  wuauclt.exe /detectnow /updatenow
echo.
echo.
pause
echo                       H                         
echo ------------------------------------------------
echo -------------- Dell Command Update -------------
echo ------------------------------------------------
echo.
echo BIOS shows the serial number is:
echo.
wmic bios get serialnumber
echo.
echo Please check for Dell Command update manually if this is a Dell workstation.
echo.
mkdir \\%servername%\data\secaud >nul
mkdir c:\temp >nul
echo Creating GPresult c:\temp\%computername%.html .. This will fail in non-domain environments obviously.
gpresult /f /h c:\temp\%computername%.html
echo Copying to \\%servername%\data\secaud .. This will fail in non-domain environments obviously.
xcopy c:\temp\%computername%.html \\%servername%\data\secaud
echo.
echo.
pause
echo                       I                         
echo ------------------------------------------------
echo ---------------- Antivirus: --------------------
echo ------------------------------------------------
powershell -exec bypass -c 'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct'
::if exist "%ProgramFiles%\Windows Defender\MSASCui.exe" (
::  start "%ProgramFiles%\Windows Defender\MSASCui.exe"
::) else (
::  msg %username% "Check Antivirus manually!!!!"
::)
msg %username% "Check Antivirus manually!!!!"
echo.
echo.
pause
echo                       J                         
echo ------------------------------------------------
echo ---------------- Firewall: ---------------------
echo ------------------------------------------------
start firewall.cpl
echo.
echo.
pause
echo                       K                         
echo ------------------------------------------------
echo ------- Scheduled Tasks / Startup Items: -------
echo ------------------------------------------------
start taskschd.msc
start msconfig
pause
echo                       L                         
echo ------------------------------------------------
echo -------------- Bitlocker Enabled: --------------
echo ------------------------------------------------
manage-bde -status c: | findstr /i conversion
IF %ERRORLEVEL% NEQ 0 (
  echo No Bitlocker found!!!!!!! (Or, this needs to be run as administrator)
)
pause
echo                       M                       
echo ------------------------------------------------
echo ---------------- UAC Enabled: ------------------
echo ------------------------------------------------
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" | find  "0x0" >NUL
if "%ERRORLEVEL%"=="0"  ECHO UAC disabled
if "%ERRORLEVEL%"=="1"  ECHO UAC enabled
echo.
IF EXIST "c:\temp\_WORKSTATION.BAT" (
  echo Deleting script... c:\temp\_WORKSTATION.BAT
  del c:\temp\_WORKSTATION.BAT /f /q
) ELSE (
    echo.
    echo Script looks like it wasn't run from C:\Temp, skipping deletion. PLEASE DELETE FROM THE SERVER MANUALLY ONCE YOU ARE DONE!
    echo.
)
echo.
echo DONE!
echo.
echo.
pause