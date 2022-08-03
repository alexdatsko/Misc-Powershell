$i = 5     # try for 5 minutes
do {
  Get-Service | Select-Object -Property Name,Status,StartType | Where-Object {$_.Status -eq "Stopped" -and ($_.StartType -eq "Automatic")} | Start-Service
  start-sleep 60
  $i-=1  
} while ($i>0)