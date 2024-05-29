
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

function Get-PNPDevice {
  param (
    $querystring
  )
  $computer = "."
  $namespace = "root\CIMV2"
  $query = "SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%$($querystring)%'"

  $wmi = Get-WmiObject -Namespace $namespace -Query $query -ComputerName $computer

  foreach ($item in $wmi) {
    Write-Output "$($item.ClassGuid) $($item.Name)"
  }
}

Get-PNPDevice
