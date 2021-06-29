$windir=[System.Environment]::ExpandEnvironmentVariables("%WINDIR%")+"\System32"
set-location $windir
icacls musnotification.exe /remove:d Everyone
icacls musnotification.exe /grant Everyone:F
icacls musnotification.exe /setowner "NT SERVICE\TrustedInstaller"
icacls musnotification.exe /remove:g Everyone
icacls musnotificationux.exe /remove:d Everyone
icacls musnotificationux.exe /grant Everyone:F
icacls musnotificationux.exe /setowner "NT SERVICE\TrustedInstaller"
icacls musnotificationux.exe /remove:g Everyone
