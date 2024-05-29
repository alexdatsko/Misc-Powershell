[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Help = $false,                         # this flag will show help and exit
  [switch] $ShowOnly = $false,                     # this flag will allow ShowOnly 
  [switch] $RemoveDevice = $true,                  # this flag will remove the pnp device located in $DeviceString
  [switch] $WithReboot = $false,                   # this flag will reboot the computer automatically after the fixes
  [string] $DeviceString = "Xerox DocuMate",        # Change this to the closest partial for the device you want to search for in devmgmt
  [string] $LogFile = "C:\Temp\Fix-UpperLowerFilters.txt"    # Where the output will be logged to
)

$rundate = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
$msg = '
#################################
# Fix-UpperLowerFilters.ps1
# Alex Datsko @ MME Consulting 05-28-2024
#
# Fix for USB devices that have the following error message in Device Manager: 
#   "Windows cannot start this hardware device because its configuration information (in the registry) is incomplete or damaged (Code 19)"
# Removes reg keys for "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\$($ClassID)\" UpperFilters and LowerFilters
'
$helpmsg = '
# params (
#  [switch] $ShowOnly = $false,                     # this flag will allow ShowOnly 
#  [switch] $RemoveDevice = $true,                  # this flag will remove the pnp device located in $DeviceString
#  [switch] $WithReboot = $false,                   # this flag will reboot the computer automatically after the fixes
#  [string] $DeviceString = "Xerox DocuMate",        # Change this to the closest partial for the device you want to search for in devmgmt
#  [string] $LogFile = "C:\Temp\Fix-UpperLowerFilters.txt"    # Where the output will be logged to
#)
'

function Get-PNPDevice {
  param (
    $querystring
  )
  $computer = "."
  $namespace = "root\CIMV2"
  $query = "SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%$($querystring)%'"

  $wmi = Get-WmiObject -Namespace $namespace -Query $query -ComputerName $computer

  foreach ($item in $wmi) {
    Write-Output "$($item.ClassGuid) - $($item.Caption) - $($item.Name)"
  }
}

function Get-PNPDeviceGuid {
  param (
    $querystring
  )
  $computer = "."
  $namespace = "root\CIMV2"
  $query = "SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%$($querystring)%'"

  $wmi = Get-WmiObject -Namespace $namespace -Query $query -ComputerName $computer

  foreach ($item in $wmi) {
    Write-Output "$($item.ClassGuid)"
  }
}

Write-Host $msg
Write-Host "-------------------------------------------------`n$($rundate)" | tee $LogFile -Append
if ($Help -eq $true) { $helpmsg ; exit }

$ClassGuid = Get-PNPDeviceGuid -querystring $DeviceString
if ($ClassGuid) {
  Write-Host "[.] Class GUID found: $ClassGuid" | tee $LogFile -Append
  $RegKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$($ClassGuid)"
  Write-Host "[.] Checking registry key: $RegKey" | tee $LogFile -Append
  $LowerFilters = ((Get-ItemProperty -Path "$($RegKey)" -ErrorAction SilentlyContinue).LowerFilters)
  $UpperFilters = ((Get-ItemProperty -Path "$($RegKey)" -ErrorAction SilentlyContinue).UpperFilters)
  try {
    Write-Host "LowerFilters contains: $LowerFilters" | tee $LogFile -Append
    Write-Host "UpperFilters contains: $UpperFilters" | tee $LogFile -Append
  } catch {
    Write-Host "[!] An error occurred READING the registry key(s):" | tee $LogFile -Append
    Write-Host $_
  }
} else {
  Write-Host "[.] Class GUID not found for $DeviceString!! Exiting" | tee $LogFile -Append
  Get-PNPDeviceGuid -querystring $DeviceString  | tee $LogFile -Append
}

if ($ShowOnly -eq $true) {
  Write-Host "[!] Exiting, -ShowOnly found." | tee $LogFile -Append
  exit
}

if ($RemoveDevice -eq $true)  {
  if ($ClassGuid) {
    & "pnputil" /remove-device /class "$ClassGuid"
  } else {
    Write-Host "[!] No Class GUID found, skipping Device Removal.." | tee $LogFile -Append
  }
}

# Remove reg keys
if ($LowerFilters -ne "" -and $LowerFilters -ne $null) {
  try {
    Remove-ItemProperty -Path $RegKey -Name "LowerFilters" -Force -ErrorAction SilentlyContinue | tee $LogFile -Append
    Write-Host "$($RegKey)\LowerFilters key removed" | tee $LogFile -Append
  } catch {
    Write-Host "[!] An error occurred DELETING the registry key(s):" | tee $LogFile -Append
    Write-Host $_ | tee $LogFile -Append
  }
}
if ($UpperFilters -ne "" -and $UpperFilters -ne $null) {
  try {
    Remove-ItemProperty -Path $RegKey -Name "UpperFilters" -Force -ErrorAction SilentlyContinue | tee $LogFile -Append
    Write-Host "$($RegKey)\UpperFilters key removed" | tee $LogFile -Append
  } catch {
    Write-Host "[!] An error occurred DELETING the registry key(s):" | tee $LogFile -Append
    Write-Host $_ | tee $LogFile -Append
  }
}
if ($WithReboot -eq $true) {
  shutdown /r /f 
}

Write-Host "[+] Done.  A reboot is required."
