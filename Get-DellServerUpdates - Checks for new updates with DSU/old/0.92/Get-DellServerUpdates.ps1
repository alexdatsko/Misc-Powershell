#####################################
#
# Get-DellServerUpdates.ps1 - v0.92
#
# 5/1/2020 Alex Datsko 
#
# Parses Dell Server Update logs for new updates and creates Windows events which are fed to our RMM notification system
# Works with DSU verions 1.5.3, 1.7.0, 1.8.0
#

$date = Get-Date -Format "yyyy-MM-dd"

if (![System.Diagnostics.EventLog]::Exists('MME')) {
    New-EventLog -LogName "MME" -Source "Dell Server Updates" 
}

$DSUPath = "C:\Dell\DELL EMC System Update\"
if (!(test-path($DSUPATH+"dsu.exe"))) {   
  $DSUPath = "C:\Program Files\Dell\DELL EMC System Update\"  # I don't believe this will ever be Program Files (x86)..
  if (!(test-path($DSUPATH+"dsu.exe"))) {     # Check for new install path as of DSU 1.8.0
    $msg = "Could not DSU.exe in either path: C:\Dell\DELL EMC System Update\ or C:\Program Files\Dell\DELL EMC System Update\ .. Exiting"
    Write-Host $msg
    Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 502  -EntryType Error -Message $msg
    exit
  } else {  # working with 1.8.0
    $DSUExe = $DSUPath+"DSU.exe"
    $UpdateLog = $env:ProgramData+"\Dell\DELL EMC System Update\Log.txt"
  }
} else { # working with 1.7.0 or <
  $UpdateLog = $DSUPath+"dell_dup\Log.txt"
  $DSUExe = $DSUPath+"DSU.exe"
}

if (Test-Path($UpdateLog)) {
    Move-Item -Path $UpdateLog -Destination "$UpdateLog.$date.txt"  # start with a fresh log
}

if (Test-Path($DSUExe)) {
    Write-host "Beginning Dell Server update sweep.."
    Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 10500  -EntryType Information -Message "Dell DSU utility - update check began.."
  
    Write-host "Starting DSU.exe.."
    Start-Process -FilePath $DSUExe -WindowStyle Hidden
    #-ErrorAction SilentlyContinue 
    
    Start-Sleep -s 3
    Write-host "Checking process.."
    get-Process DSU     # check that process started.  To-Do - error out if it is not started
    
    Write-host "Sleeping for 5 minutes.."
    Start-Sleep -s 300               # This can take quite a while on some servers to populate a new log file.  Using 5 minutes for now.
    
    Write-host "Stopping process.."
    Stop-Process -Name DSU -Force -ErrorAction SilentlyContinue

    $UpdatesAvailable=""
    $Urgent=0
    if (Test-Path($UpdateLog)) {     # we want to not show updates that are unnecessary or already up to date
        write-host "Parsing update log file.."
        $UpdateList = gc $UpdateLog | ? { !$_.Contains("[-]") -and !$_.Contains("ame as : ") -and !$_.Contains("owngrade to :")  `
            -and !$_.Contains("Catalog.gz") -and !$_.Contains("Date Time") -and !$_.Contains("#DSU Version:")  `
            -and !$_.Contains("#System IP:") -and !$_.Contains("#Date:")  -and !$_.Contains("#ID :") `
            -and !$_.Contains("unable to ") -and !$_.Contains("partial failure") -and !$_.Contains("...") `
            -and $_.trim() -ne "" } | fl | out-string
        $Updates = $UpdateList.split("`n")
        foreach ($Update in $Updates) {
          $UpdatesAvailable+=$Update.split('|')[3]+"`r`n"
          if ($Update | ? { $_.Contains("Urgent")} ) { 
            $Urgent=1
          }
        }
        write-host "---------------UpdatesAvailable: `r`n" $UpdatesAvailable
    }  else {
        Write-host "Error: Log file $UpdateLog not found!"
        Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 501  -EntryType Error -Message "DSU log file not found : $UpdateLog"
        exit
    } 
    
    if ($UpdatesAvailable.trim() -ne "") {           # Make sure we have any updates at all..
        write-host "Updates available."
        if ($Urgent) {    # Parse for urgent
            write-host "Urgent updates available, logging."
            Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 1501  -EntryType Warning -Message "Dell DSU found [Urgent] updates available: `r`n$UpdatesAvailable"
        } else {
            write-host "Recommended updates available, logging."
            Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 10501  -EntryType Information -Message "Dell DSU found [Recommended] updates available: `r`n$UpdatesAvailable"
        }
    } else {
      write-host "No updates available, logging."
      Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 10502  -EntryType Information -Message "Dell DSU found no updates available."
    }
    
} else {
    Write-host "Dell DSU update utility not found! Closing"
    Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 500  -EntryType Error -Message "Dell DSU update utility not found at $DSUExe ..Closing"
    exit
}

Write-host "Done!"
