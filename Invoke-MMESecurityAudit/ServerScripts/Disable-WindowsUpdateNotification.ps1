$windir=[System.Environment]::ExpandEnvironmentVariables("%WINDIR%")+"\System32"
set-location $windir
takeown /f musnotification.exe
cmd /c "icacls musnotification.exe /deny Everyone:(X)"
takeown /f musnotificationux.exe
cmd /c "icacls musnotificationux.exe /deny Everyone:(X)"
