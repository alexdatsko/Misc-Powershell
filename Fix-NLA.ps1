$DC_ServiceList = @("NSI","RpcSs","TcpIp","Dhcp","Eventlog","DNS","NTDS")
$MachineType = ''
Write-Output "`n`n[o] --- NLA FIX --- `nv0.3 - Set Firewallprofile after`n"
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
  Write-Output "[!] Workstation/Member Server: Setting NLA Service to depend on the TCP/IP and DNS client service"
  sc.exe config nlasvc depend=TcpIp/DNScache
} 
if ($MachineType -eq 'DC') {
  Write-Output "[!] DC: Setting NLA Service to depend on NSI/RpcSs/TcpIp/DHCP/Eventlog/DNS/NTDS"
  sc.exe config nlasvc depend=NSI/RpcSs/TcpIp/DHCP/Eventlog/DNS/NTDS
}
Write-Output "[.] Restarting NLA Service:"
#net.exe stop nlasvc /y
#net.exe start nlasvc
$nlasvc = Get-Service nlasvc 
$nlasvc | Stop-Service -Force -NoWait -ErrorAction SilentlyContinue  # This may cause an error and not stop..
Start-Sleep 3
if ((Get-Service nlasvc).Status -eq 'Stopped') {
  $nlasvc | Start-Service
} else {
  Write-Output "[!] Error! couldn't stop/start NLA service, will try to kill the process here and make sure its restarted.."
  $nlasvc = sc.exe queryex nlasvc
  foreach ($line in $nlasvc) { if ($line -like "*PID*") { $nlapid = $line } }
  Write-Output "[.] Found NLA service $($nlapid), killing:"
  $nlapid2 = ($nlapid.split(":")[1].trim())
  taskkill /f /pid $($nlapid2)
  $nlapidOld = $nlapid2
  Start-Service Nlasvc -Verbose
  Write-Output "[.] Waiting 5 seconds for service to restart.."
  Start-Sleep 5
  Write-Output "[.] Checking for new PID.."
  $nlasvc = sc.exe queryex nlasvc
  foreach ($line in $nlasvc) { if ($line -like "*PID*") { $nlapid = $line } }
  $nlapid2 = ($nlapid.split(":")[1].trim())
  if ($nlapid2 -ne $nlapidOld) {
    Write-Output "[.] Success! NLA service PID=$($nlapid2), Old PID=$($nlapidOld)"
  } else {
    Write-Output "[!] FAILED. PID=$($nlapid2), Old PID=$($nlapidOld)"
    Write-Output "[!] Cannot fix, either you are not running as admin, or server needs a reboot possibly."
  }
}
if ($MachineType -eq 'DC') {
  Start-Sleep 1
  $NetProfile = (Get-NetConnectionProfile).NetworkCategory
  Write-Output "[.] Setting Firewall profile to DomainAuthenticated, currently $($NetProfile):"
  Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory DomainAuthenticated
  Start-Sleep 1
  $NetProfile = (Get-NetConnectionProfile).NetworkCategory
  if ($NetProfile -notlike '*Domain*') {
    Write-Output "[!] Error setting Firewall profile:  SetNetConnectionProfile -NetworkCategory DomainAuthenticated, returned: $($NetProfile)"
    Write-Output "[!] Exiting with errors!"
    exit
  } else {
    Write-Output "[!] Set profile to: $($NetProfile)"
  }
} else {
  Start-Sleep 1
  $NetProfile = (Get-NetConnectionProfile).NetworkCategory
  Write-Output "[.] Setting Firewall profile to Private, currently $($NetProfile):"
  Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
  Start-Sleep 1
  $NetProfile = (Get-NetConnectionProfile).NetworkCategory
  if ($NetProfile -ne 'Private') {
    Write-Output "[!] Error setting Firewall profile:  SetNetConnectionProfile -NetworkCategory Private, returned: $($NetProfile)"
    Write-Output "[!] Exiting with errors!"
    exit
  } else {
    Write-Output "[!] Set profile to: $($NetProfile)"
  }
}
Write-Output "[o] Done!" 
