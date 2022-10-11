###############################
# Watch-FolderHandles.ps1
# This will watch a folder for newly created files in a folder (every 3 second)
# and tell us the process/PID creating them

$watchPath = 'C:\users\reception1\Appdata\Local\Temp'
#$watchPath = 'c:\temp\watch'
$Found = $false

while (!($Found)) { 
  $output = ((c:\temp\handle64.exe -accepteula -nobanner $watchPath) | select-string "E2C")
  if ($output) { 
    $Found = $true
    $Output
  }
  #Start-Sleep 3   # Disabling the sleep timer as the output from handle64.exe takes a while already...
}
