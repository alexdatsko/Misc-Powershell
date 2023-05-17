# Removes CCleaner. Can be added as a Login script and run via GPO
# WORKS BY USER LOGIN SCRIPT ONLY!

$Logfile = "c:\temp\CCleanerUninst.log"
if (!(Test-Path "C:\Temp")) { New-Item -ItemType Directory "c:\Temp" }
Function Remove-InstalledSoftwarebyUninstallReg {
  param ($SoftwareName)
  Write-Host "[.] Searching Uninstaller registry for $SoftwareName.." | Out-File $Logfile -Append
  if (Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
      Where-Object DisplayName -eq $SoftwareName -OutVariable Results) {
    if (!(Test-Path "$($Results.InstallLocation)\uninst.exe")) {
      Write-Host "[!] Error - uninstall file doesn't exist: $($Results.InstallLocation)\uninst.exe" | Out-File $Logfile -Append
      exit
    } else {
      Write-Host "[.] Removing $(($Results).DisplayName) .. running $($Results.InstallLocation)\uninst.exe" | Out-File $Logfile -Append
      & "$($Results.InstallLocation)\uninst.exe" /S
    }   
  } else {
    Write-Host "[!] $SoftwareName not found, exiting!"
  }
}


Remove-InstalledSoftwarebyUninstallReg "Ccleaner"
