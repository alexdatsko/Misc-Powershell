param (
  [string []]$Ignored
)

$info = 
"##############################################################
# Remove-AllPrinterDrivers.ps1
# Alex Datsko alexd@mmeconsulting.com
#   This script will clear the print spooler, remove all printer drivers from the registry, and restart print spooler
#   For those times when a driver installed from a now non-existent server seems to get stuck and cause issues w/ the OS.
#   You can optionally includ an ignore list of a printer/printers NOT to remove (they must be listed exactly as shown in the registry):
# 
#   
# Usage:
#   ./Remove-AllPrinterDrivers.ps1 -Ignore @(""HP Laserjet M351"",""Brother Laser X89"")"
# v0.1 - 10/31/2024"

$info

$Verbose = $false

$Ignoredv3 = @("Remote Desktop Easy Print","Microsoft Shared Fax Driver","Microsoft enhanced Point and Print compatibility driver","LogMeIn Printer Driver")
$Ignoredv4 = @("Microsoft Print To PDF","Microsoft Print To PDF","Send to Microsoft OneNote 16 Driver")
$IgnoredPP = @("winprint","LogMeIn Print Processor")
$IgnoredMonitors = @("Appmon","Local Port","LogMeIn Printer Port Monitor","Microsoft Shared Fax Monitor","Standard TCP/IP Port","USB Monitor","WSD Port")
$IgnoredPrinters = @("Fax","Microsoft Print to PDF","Microsoft XPS Document Writer","OneNote (Desktop)")
$IgnoredPrinterPorts = @("(Default)","Fax","Microsoft Print to PDF","Microsoft XPS Document Writer","OneNote (Desktop)")

$RegistryPaths = @{
  "DriversV3"          = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3"
  "DriversV4"          = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-4"
  "PrintProcessors"    = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Print Processors"
  "Monitors"           = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"
  "Printers"           = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers"
}

function Remove-SubkeysNotInIgnoreList {
  param (
      [string]$RegistryPath,
      [array]$IgnoreList,
      [array]$Ignored
  )

  # Check if the registry path exists
  if (Test-Path $RegistryPath) {
    Write-Output "[.] Checking tree: $RegistryPath .."
    $Subkeys = Get-ChildItem -Path $RegistryPath
      if ($Verbose) { Write-Output "Subkeys: $subkeys" }
      foreach ($Subkey in $Subkeys) {
          if ($IgnoreList -notcontains $Subkey.PSChildName -and $Ignored -notcontains $Subkey.PSChildName) {
              Remove-Item -Path "$RegistryPath\$($Subkey.PSChildName)" -Recurse -Force
              Write-Output "[-] Deleted: $RegistryPath\$($Subkey.PSChildName)"
          } else {
              Write-Output "[.] Ignored: $RegistryPath\$($Subkey.PSChildName)"
          }
      }
  } else {
      Write-Output "Path not found: $RegistryPath"
  }
}

Write-Output "[.] Backing up the registry.."
#reg save "HKLM\SYSTEM\CurrentControlSet\Control\Print" c:\temp\print
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Print" c:\temp\print.reg    # Save a text file with all of the printer registry backed up
Write-Output "[.] Clearing print spooler.."
Get-Service spooler | Stop-Service
$out = (cmd.exe /c 'del c:\windows\system32\drivers\spool\printers\*.* /s /f /q')
Get-Service spooler | Start-Service
Write-Output "[.] Removing ALL printer driver entries from registry.."
# Run the function for each registry path
Remove-SubkeysNotInIgnoreList -RegistryPath $RegistryPaths["DriversV3"] -IgnoreList $Ignoredv3 -Ignored $Ignored
Remove-SubkeysNotInIgnoreList -RegistryPath $RegistryPaths["DriversV4"] -IgnoreList $Ignoredv4 -Ignored $Ignored
Remove-SubkeysNotInIgnoreList -RegistryPath $RegistryPaths["PrintProcessors"] -IgnoreList $IgnoredPP -Ignored $Ignored
Remove-SubkeysNotInIgnoreList -RegistryPath $RegistryPaths["Monitors"] -IgnoreList $IgnoredMonitors -Ignored $Ignored
Remove-SubkeysNotInIgnoreList -RegistryPath $RegistryPaths["Printers"] -IgnoreList $IgnoredPrinters -Ignored $Ignored
Write-Output "[.] Restarting print spooler.."
Get-Service spooler | Restart-Service
Write-Output "[!] Done!"
