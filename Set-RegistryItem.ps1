if (!(Test-Path "C:\Temp")) { New-Item -ItemType Directory "C:\Temp" } 
$CurrentSetting = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" -Name DependOnService).DependOnService
$CurrentSetting | Out-File "C:\Temp\Lanmanworkstation.log" # Save current setting to log file in c:\Temp
if ($CurrentSetting) {
  $CurrentSettings = $CurrentSetting.split("`n")
  if ($CurrentSettings[0] -eq 'Bowser' -and $CurrentSettings[1] -eq 'MRxSmb20' -and $CurrentSettings[2] -eq 'NSI') {
    Write-Host "[!] Good values found already for Lanmanworksation\DependOnService! Exiting"
    exit
  } else {
    Write-Host "[!] Setting good values for DependOnService.."
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation' -Name DependOnService -Value "Bowser`nMRxSmb20`nNSI" -Type String
  }
} else {
  Write-Host "[!] Creating new key for DependOnService.."
  New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation' -Name DependOnService -Value "Bowser`nMRxSmb20`nNSI" -PropertyType String
}
Write-Host "[!] Done."

