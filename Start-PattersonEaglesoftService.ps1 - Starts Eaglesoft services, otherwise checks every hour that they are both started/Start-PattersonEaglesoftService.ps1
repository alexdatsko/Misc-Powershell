function Sleep-Seconds {
  param(
    $start_sleep,      # Total time to sleep
    $sleep_iteration   # Time to sleep between each notification
  )

    Write-Output ( "Sleeping {0} seconds ... " -f ($start_sleep) )
    if ($sleep_iteration -lt 1) { $sleep_iteration = 1 }   # Must be at least 1 second...
    for ($i=1 ; $i -le ([int]$start_sleep/$sleep_iteration) ; $i++) {
        Start-Sleep -Seconds $sleep_iteration
        Write-Progress -CurrentOperation ("Sleep {0}s" -f ($start_sleep)) ( " {0}s ..." -f ($i*$sleep_iteration) )
    }
    Write-Progress -CurrentOperation ("Sleep {0}s" -f ($start_sleep)) -Completed "Done."

}

function Check-Process {
  param(
    $ProcessRun,
    $ProcessArgs,
    $ProcessName
  )
    Write-Output "[.] Checking $ProcessName service:" 

    if (Get-Process -ProcessName $ProcessName)  { 
      Write-Output "[o] $ProcessName is running" 
    } else { 
      Write-Output "[x] $ProcessName is not running. Starting now.." 
      . $ProcessRun -start
      Write-Output "[.] Waiting 15 seconds.." 
      Sleep-Seconds 15
    }

    Write-Output ""
    if (Get-Process -ProcessName $ProcessName)  { 
      Write-Output "[O] $ProcessName is running" 
    } else { 
      Write-Output "[X] $ProcessName is not running. Could not start!!!" 
    } 

}
Check-Process -ProcessRun "C:\Eaglesoft\Shared Files\PattersonServerStatus.exe" -ProcessArgs "-start" -ProcessName "PattersonServerStatus"
Check-Process -ProcessRun "C:\EagleSoft\Shared Files\techaid.exe" -ProcessArgs "startmsngr" -ProcessName "ESMsgServer"
