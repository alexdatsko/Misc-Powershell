
  Write-Output "`n[!] This script will restart the di.Engagement.Tunnel service."
  $diEngagementTunnel = (sc.exe queryex 'di.Engagement.Tunnel')
  #write-host $diEngagementTunnel
  foreach ($line in $diEngagementTunnel) { if ($line -like "*PID*") { $dipid = $line } }
  Write-Host "[.] Found DI Engagement Tunnel service $($dipid), killing:"
  $dipid2 = ($dipid.split(":")[1].trim())
  taskkill /f /pid $($dipid2)
  $dipidOld = $dipid2
  Start-Service "di.Engagement.Tunnel" -Verbose
  Write-Host "[.] Waiting 5 seconds for service to restart.."
  Start-Sleep 5
  Write-Host "[.] Checking for new PID.."
  $diEngagementTunnel = sc.exe queryex 'di.Engagement.Tunnel'
  foreach ($line in $nlasvc) { if ($line -like "*PID*") { $dipid = $line } }
  $dipid2 = ($dipid.split(":")[1].trim())
  if ($dipid2 -ne $dipidOld) {
    Write-Host "[.] Success! NLA service PID=$($dipid2), Old PID=$($dipidOld)"
  } else {
    Write-Host "[!] FAILED. PID=$($dipid2), Old PID=$($dipidOld)"
    Write-Host "[!] Cannot fix, either you are not running as admin, or server needs a reboot possibly."
  }