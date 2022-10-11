$DC_ServiceList = @("NSI","RpcSs","TcpIp","Dhcp","Eventlog","DNS","NTDS")
$MachineType = ''

Write-Output "`n`n[o] --- NLA FIX ---"

Write-Output "[.] Checking Machine type.."
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if ($osInfo.ProductType -eq 1) { $MachineType = 'Workstation' }
if ($osInfo.ProductType -eq 3) { $MachineType = 'MemberServer' }

if ($MachineType -eq '') {
    Write-Output "[.] Checking Services.."
    $DC=$false
    foreach ($service in $DC_ServiceList) {
      if (!(Get-Service "$service" -ErrorAction SilentlyContinue)) {
        Write-Output "$service doesn't exist! Not a DC"
        $DC=$false
        break
      } else {
        $DC=$true
      }
    }
    if ($DC) { 
      $MachineType = 'DC' 
    }
}

Write-Output "[!] Machine Type found: $MachineType`n"
Write-Output "[.] Setting dependencies for NLA Service:"
if ($MachineType -eq 'Workstation' -or $MachineType -eq 'MemberServer') {
  Write-Output "[!] Workstation/Member Server: Setting NLA Service to depend on the DNS client service"
  sc.exe config nlasvc depend=TcpIp/DNScache
} 
if ($MachineType -eq 'DC') {
  Write-Output "[!] DC: Setting NLA Service to depend on NSI/RpcSs/TcpIp/Dhcp/Eventlog/DNS/NTDS"
  sc.exe config nlasvc depend=NSI/RpcSs/TcpIp/Dhcp/Eventlog/DNS/NTDS
}

Write-Output "[.] Restarting NLA Service:"
#net.exe stop nlasvc /y
#net.exe start nlasvc
$nlasvc = Get-Service nlasvc 
$nlasvc | Stop-Service -Force -NoWait -ErrorAction SilentlyContinue  # This may cause an error and not start
Start-Sleep 3
if ((Get-Service nlasvc).Status -eq 'Stopped') {
  $nlasvc | Start-Service
} else {
  Write-Output "[!] Error! couldn't stop/start NLA service, may need a reboot."
}

Write-Output "[o] Done!" 
