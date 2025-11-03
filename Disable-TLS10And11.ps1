$info = "
##################################################################
# Disable-TLS10And11.ps1
# Alex Datsko @ .
# This script will completely Disable TLS 1.0 and 1.1 from being used on a server.
# v0.1 - 10/28/24 - Initial
"

$datetime = Get-Date -Format "yyyy-MM-dd hh_mm_ss"
$logfile = "c:\Temp\Disable-TLS10And11.txt"
$debug = 0

$info
"------------------- $datetime"  | tee -append $logfile
if (!(Test-Path "C:\Temp")) {
  New-Item -ItemType Directory -Path "C:\Temp" -ErrorAction Continue
}

Write-Host "[.] Current TLS 1.0, 1.1 and 1.2 settings:"  | tee -append $logfile
Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"  | ft  | tee -append $logfile
Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"  | ft  | tee -append $logfile
Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"  | ft  | tee -append $logfile

try {
  Write-Host "[.] Disable TLS 1.0 to Disabled : creating key" | tee -append $logfile
  New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null
  Write-Host "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\Enabled=0" | tee -append $logfile
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0 -PropertyType "DWORD" -Force | Out-Null
  Write-Host "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\DisabledByDefault=1" | tee -append $logfile
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWORD" -Force | Out-Null
} catch {
  Write-Host "ERROR: $_" | tee -append $logfile
}
try {
  Write-Host "[.]  Disable TLS 1.1 to Disabled : creating key" | tee -append $logfile
  Write-Host "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\Enabled=0" | tee -append $logfile
  New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0 -PropertyType "DWORD" -Force | Out-Null
  Write-Host "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\DisabledByDefault=1" | tee -append $logfile
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWORD" -Force | Out-Null
} catch {
  Write-Host "ERROR: $_" | tee -append $logfile
}
try {
  Write-Host "[.] Enable TLS 1.2 to Enabled : creating key" | tee -append $logfile
  New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null
  Write-Host "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\Enabled=1" | tee -append $logfile
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -PropertyType "DWORD" -Force | Out-Null
  Write-Host "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\DisabledByDefault=0" | tee -append $logfile
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -PropertyType "DWORD" -Force | Out-Null
} catch {
  Write-Host "ERROR: $_" | tee -append $logfile
}

Write-Host "[.] New TLS 1.0, 1.1 and 1.2 settings:"
Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"  | ft
Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"  | ft
Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"  | ft

Write-Host "[+] TLS 1.0 and 1.1 are disabled, and TLS 1.2 is enabled. Please restart the server to apply changes." | tee -append $logfile
Write-Host "[!] Done!" 
