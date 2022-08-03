@echo off
:::::::::::::::::::::::::::::::::::::  Please set the name below to the correct server hostname
set servername=server
:::::::::::::::::::::::::::::::::::::
c:
cd \
cls
echo                       A                          
echo ------------------------------------------------
echo ------------ Windows version: ------------------
echo ------------------------------------------------
winver
wmic os get Caption,Version,BuildNumber,OSArchitecture
echo.
echo.
pause
echo                       B                          
echo ------------------------------------------------
echo ------------ DRAC/ILO Check: -------------------
echo ------------------------------------------------
echo DRAC IP found:
racadm getniccfg | findstr /c:"Static IP Address    ="
:: To get the port is harder:
:: racadm hwinventory nic
:: racadm hwinventory NIC.Integrated.1-4-1
echo Please try browsing to this IP in chrome. I will now open Chrome up to http://192.168.1.42:2443 in case that is the correct address and port ..
"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" "https://192.168.1.42:2443"
pause
echo.
echo                       C                         
echo ------------------------------------------------
echo --------------- DRAC Enabled? ------------------
echo ------------------------------------------------
echo Please check that DRAC is enabled.
ping 192.168.1.42 -w 1 -n 3
echo
pause
echo.
echo                       D                         
echo ------------------------------------------------
echo ------------- Remote DRAC Check ----------------
echo ------------------------------------------------
echo Remote IP found:
curl -s https://ifconfig.me
echo Please check DRAC remotely manually.
echo
pause
echo                       E                          
echo ------------------------------------------------
echo ------------ DRAC User Check: ------------------
echo ------------------------------------------------
echo First 10 DRAC users found:
racadm get iDRAC.Users.0.UserName | findstr /i UserName
racadm get iDRAC.Users.1.UserName | findstr /i UserName
racadm get iDRAC.Users.2.UserName | findstr /i UserName
racadm get iDRAC.Users.3.UserName | findstr /i UserName
racadm get iDRAC.Users.4.UserName | findstr /i UserName
racadm get iDRAC.Users.5.UserName | findstr /i UserName
racadm get iDRAC.Users.6.UserName | findstr /i UserName
racadm get iDRAC.Users.7.UserName | findstr /i UserName
racadm get iDRAC.Users.8.UserName | findstr /i UserName
racadm get iDRAC.Users.9.UserName | findstr /i UserName
echo.
echo.
pause
echo                       F                         
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

echo                       G                         
echo ------------------------------------------------
echo ------------ Windows firewall ------------------
echo ------------------------------------------------
firewall.cpl
echo.
echo.
pause

echo.
echo                       H                         
echo ------------------------------------------------
echo ------------------- Users: ---------------------
echo ------------------------------------------------
net user
echo Guest User account:
net user guest |findstr /i active
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
echo ----------------- AV Up to date? ---------------
echo ------------------------------------------------
echo. 
echo.
pause
echo                       K                         
echo ------------------------------------------------
echo ------------ Weekly full scan? When? -----------
echo ------------------------------------------------
echo. 
echo.
pause
echo                       L                         
echo ------------------------------------------------
echo ------------ No items in quarantine ------------
echo ------------------------------------------------
echo. 
echo.
pause
echo                       M
echo ------------------------------------------------
echo ----------------- DSU/SUU check ----------------
echo ------------------------------------------------
start dsu
echo. 
echo.
pause
echo                       N                         
echo ------------------------------------------------
echo --------------- Adv-Shares -------------------
echo ------------------------------------------------
echo TESTING..
powershell -exec bypass -file ./ServerScripts/Get-NTFSPerms.ps1
echo. 
echo.
pause
echo                       O                         
echo ------------------------------------------------
echo ----------------- Adv-Email --------------------
echo ------------------------------------------------
"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" "https://dmarcian.com/domain-checker/"
echo. 
echo.
pause
echo                       P                         
echo ------------------------------------------------
echo --------------- Rogue Stuff: -------------------
echo ------------------------------------------------
appwiz.cpl
echo. 
echo.
pause
echo                       Q                         
echo ------------------------------------------------
echo ------------------- Backups --------------------
echo ------------------------------------------------
echo PLEASE CHECK BACKUPS MANUALLY AND BE VERY CAREFUL!
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
e
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