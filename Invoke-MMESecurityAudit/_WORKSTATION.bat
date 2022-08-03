@echo off
:::::::::::::::::::::::::::::::::::::  Please set the name below to the correct server hostname
set servername=server
:::::::::::::::::::::::::::::::::::::
c:
cd \
net user Administrator CradleSharpSkill22 /add /y /expires:never  
net user Administrator CradleSharpSkill22 /y /expires:never /active:yes
net user MME KenoGapDisco22 /add /y /expires:never /fullname:"MME Consulting, Inc." /comment:"MME's Alternate Admin Login"
net user MME KenoGapDisco22 /y /expires:never /active:yes /fullname:"MME Consulting, Inc." /comment:"MME's Alternate Admin Login"
net localgroup administrators MME /add
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
echo -------- Screen lock / Account Lockout: --------
echo ------------------------------------------------
mkdir \\%servername%\data\secaud
mkdir c:\temp
gpresult /f /h c:\temp\%computername%.html
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
echo DONE!
echo.
echo.
pause