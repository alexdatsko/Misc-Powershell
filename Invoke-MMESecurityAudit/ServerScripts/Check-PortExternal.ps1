function Check-PortExternal {

  Param(
    [parameter(Mandatory=$true)]
    [String]
    $Port,
    [String]
    $IP
  )
  if ($IP.length -gt 6) {  # shortest length of a numerical dotted decimal length is 7 - i.e '1.1.1.1'
    $ExternalIP = $IP 
  } else {
    $ExternalIP = (Invoke-WebRequest ifconfig.me/ip).Content
  }
  Write-Host "Checking $ExternalIP port $port .." -ForegroundColor Gray
  $postParams = @{port=$Port;ip=$ExternalIP}
  $Response = (Invoke-WebRequest -Uri https://canyouseeme.org/ -Method POST -Body $postParams).Content 
  foreach ($Line in $Response) {
    if ($Line -like "*I could <b>not*") {
      Write-Host "DRAC on IP $ExternalIP port $Port NOT open!!" -ForegroundColor Red
      return $false
    } 
    if ($Line -like "*<b>Success:*") { 
      Write-Host "DRAC on IP $ExternalIP port $Port is open" -ForegroundColor Green
      return $true
    }
  }
  if ($Response -like "*Unable to*") { 
    $Response
  }
}
