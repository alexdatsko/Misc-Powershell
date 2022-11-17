<<<<<<< HEAD
﻿$i = 5     # try for 5 minutes
do {
  Get-Service | Select-Object -Property Name,Status,StartType | Where-Object {$_.Status -eq "Stopped" -and ($_.StartType -eq "Automatic")} | Start-Service
  start-sleep 60
  $i-=1  
} while ($i>0)
=======
﻿# Try to start all automatic services once per minute, for X minutes after boot

$MinutesToRetry = 15               # How long will we keep looking at services to make sure they are all still started?

$i = 0
do {
  $Events = get-eventlog application -comp localhost -after (get-date).addminutes(-1))
  $Events | foreach-object {
    if ($_.Message -contains "System.TypeInitializationException: The type initializer for 'DolphinTaskService.JobEngine' threw an exception.") {
      [System.Windows.MessageBox]::Show('Dolphin Job Scheduler service is hung, and has been restarted')
      Get-Service -Name DolphinTaskService | Restart-Service
      sleep 5
    }
  }
  Get-Service | Select-Object -Property Name,Status,StartType | Where-Object {$_.Status -eq "Stopped" -and $_.StartType -eq "Automatic"} | Start-Service
  sleep 55
} while ($i -le $MinutesToRetry)

$StillStopped = Get-Service | Select-Object -Property Name,Status,StartType | Where-Object {$_.Status -eq "Stopped" -and $_.StartType -eq "Automatic"}
if ($StillStopped -ne "") {
  # Create Event for service stopped
} 
>>>>>>> 789b4d5dde1cb51e650d191400987b7331e1195e
