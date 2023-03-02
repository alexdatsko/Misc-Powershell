$date = Get-Date -Format "yyyy-MM-dd_HH_mm"
$fileToCheck = "C:\Backups (DO NOT DELETE)\Dolphin SQL\ForsterDolphinFull"

$logFile = "c:\Temp\SQLFull-HandleCheck-$($date).log"

function Check-Handles {
  param ($fileToCheck)

  $output = & "C:\Sysinternals\handle64.exe" "$($fileToCheck
) -accepteula"
  foreach ($line in $output) {

    if ($line -match "pid:\s+(\d+)\s+type") {

      $pid = $matches[1]

      $process = Get-Process -Id $pid

      Write-Output "$date - Processes locking file $($fileToCheck): `nProcess ID: $($pid) - Name: $($process.ProcessName)"

    }
  }
}


Check-Handles $fileToCheck | Tee -Append $logFile
