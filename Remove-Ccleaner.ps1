# Removes CCleaner. Can be added as a startup script and run via GPO

Function Remove-InstalledSoftwarebyUninstallReg {
  param ($SoftwareName)
  Write-Host "[.] Searching Uninstaller registry for $SoftwareName.."
  if (Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
      Where-Object DisplayName -eq $SoftwareName -OutVariable Results) {
    if (!(Test-Path "$($Results.InstallLocation)\uninst.exe")) {
      Write-Host "[!] Error - uninstall file doesn't exist: $($Results.InstallLocation)\uninst.exe"
      exit
    } else {
      Write-Host "[.] Removing $(($Results).DisplayName) .. running $($Results.InstallLocation)\uninst.exe"
      & "$($Results.InstallLocation)\uninst.exe" /S
    }   
  } else {
    Write-Host "[!] CCleaner not found, exiting!"
  }
}


#Remove-InstalledSoftwarebyUninstallReg "Ccleaner"
# This is not working at Computer start.

$Action = New-ScheduledTaskAction -Execute "C:\Program Files\Ccleaner\uninst.exe" -Argument "/S"
$Trigger = New-ScheduledTaskTrigger -AtStartup -Delay (New-TimeSpan -Minutes 1)
$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Description "Uninstall Ccleaner at Startup"
Register-ScheduledTask -TaskName "Uninstall Ccleaner" -InputObject $Task -User "NT AUTHORITY\SYSTEM" -RunLevel Highest

