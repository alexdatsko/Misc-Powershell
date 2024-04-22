Write-Host "`n[!] Wazuh Agent reinstaller script v0.1"
Write-Host "[.] Stopping service 'WazuhSvc' and waiting 3 seconds.."
Get-Service "WazuhSvc" | Stop-Service
Start-Sleep 3
$SoftwareRemoval = (Get-WmiObject Win32_Product) | Where-Object { $_.Name -like "*wazuh*" }
if ($SoftwareRemoval) {
  Write-Host "[.] Removing Wazuh Agent by Win32_Product.Uninstall().."
  $SoftwareRemoval.Uninstall()
} else {
  Write-Host "[.] Removing Wazuh Agent by (HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\).UninstallString .."
  $registrySoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
   if ($registrySoftware.UninstallString) {
   Start-Process -FilePath $software.UninstallString -Wait
  }
}
Write-Host "[.] Sleep for 30 seconds for full removal.."
Start-Sleep 30  
Write-Host "[.] Removing all files from: c:\program files (x86)\ossec-agent\"
Remove-Item "c:\program files (x86)\ossec-agent\*" -Recurse -Force 
Write-Host "[.] Downloading Wazuh agent from https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi "
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile ${env:temp}\wazuh-agent; 
Write-Host "[.] Installing Wazuh agent from $env:temp .. "
msiexec.exe /i ${env:temp}\wazuh-agent /q WAZUH_MANAGER='45.26.118.188' WAZUH_AGENT_GROUP='MME-Windows-Workstations' WAZUH_REGISTRATION_SERVER='45.26.118.188'  WAZUH_AGENT_NAME="$env:computername"
Write-Host "[.] Sleep for 5 seconds before starting service.."
Start-Sleep 5
Write-Host "[.] Starting service WazuhSvc .."
Get-Service "WazuhSvc" | Start-Service
Write-Host "[.] Checking service status.."
Get-Service "WazuhSvc" 
Write-Host "[!] Done!"
