[cmdletbinding()]  # For verbose, debug etc
param (
  $FromPath = "C:\Windows\Twain_32 - TSSCAN.dll",    # File to copy from
  $ToPath = "C:\Windows\Twain_32.dll",               # File to copy to (or folder name, file is more specific..)
  $LogFile = "c:\Temp\Copy-FileToFolder.log"
)

$info = ''###################################################################################################################################
# Copy-FileToFolder.ps1 
#   If the file hash has changed, this script will copy a single file from $FromPath to $ToPath
#   MOST LIKELY WILL NEED TO BE RUN WITH ADMINISTRATOR PERMISSIONS!
#   Will try $trytimes tries, every $tryseconds seconds, in case file is locked, will report an error after giving up.
#   (Created to replace c:\windows\Twain_32.dll with the TSScan one, due to something replacing the file nearly weekly..)
#   Alex Datsko @ MME Consulting Inc 
#   Version histroy: v0.1 - 8/27/24
#                    v0.2 - 9/5/24''

$info

$trytimes = 36          # This will try 36 times, which for 5m intervals, is 3 hours.
$tryseconds = 300       # Amount of time to sleep between tries, defaults to 300 = 5 minutes.

$DateTime = Get-Date -Format "yyyy-MM-dd"
"`n$DateTime ------------------------------" | tee -append $LogFile

function Find-ProcessUsingDLL {
  param($DLLFullPath,
        $Kill = $false)
  
  $returnPids = @()
  foreach ($p in Get-Process -IncludeUserName) {
    foreach ($m in $p.modules) {
      if ($m.FileName -like $DLLFullPath) {
        $returnPids += $p.id
        if ($Kill) {
          Write-Output "Found: $($p.UserName) using $($m.FileName) in $($p.Path) PID: $($p.id) - In 'Kill' mode. Terminating!"
          Stop-Process -Id $p.id -Force
        } else {
          Write-Output "Found: $($p.UserName) using $($m.FileName) in $($p.Path) PID: $($p.id) - Not in 'Kill' mode. Use -Kill to kill the process."
        }
      }
    }
  }
  if ($returnPids) {
   # return $returnPids # Probably unnecessary..
  }
}

function Copy-FileToLocation {
  param($FromPath, $ToPath, $LogFile)
  Write-Output "[.] Copying : $FromPath to $ToPath"
  $done = 0
  while (!$done) {
    if (Test-Path "$FromPath" -ErrorAction Continue) {
      Write-Output "[+] Copying $FromPath to $ToPath" | tee -append $LogFile
      try {
        Copy-Item -Path "$FromPath" -Destination "$ToPath" -Force -Recurse -ErrorAction Continue | tee -append $Logfile
      } catch {
        $exmsg = "[-] An error occurred during the copy operation: $_"
        Write-Output $exmsg | Tee -Append $LogFile
        Write-Output "[.] Scanning for PIDs that are using $ToPath ...`n"
        Find-ProcessUsingDLL $ToPath # -Kill
      }
      if ($ex -eq $null) { 
        Write-Output "[+] Completed!" | tee -append $LogFile 
        $done = 1
        exit
      } else { 
        Write-Output "[-] ERROR. Not copied. Trying again in $tryseconds" | tee -append $LogFile 
        Start-Sleep $tryseconds
      }
    } else {
      Write-Output "[-] $FromPath not found, or Access Denied reading folder.." | tee -append $LogFile
    }
    $tries += 1
    if ($trytimes -gt $tries) {
      Write-Error "[-] Failed to copy $trytimes times, with $tryseconds delay.  Aborting..." | tee -append $LogFile
      $done = 1
      exit
    }
  }
}

$ToPathhash = $(Get-FileHash "$ToPath").Hash 
$FromPathhash = $(Get-FileHash "$FromPath").Hash
if ($ToPathhash -ne $FromPathhash) {
  Write-Output "[-] Orig file $FromPath hash: $FromPathhash does not match $ToPath hash: $ToPathhash" | tee -append $LogFile
  Copy-FileToLocation $FromPath $ToPath $LogFile
} else {
  Write-Output "[+] Hashes match: no actions taken."
  Write-Verbose "    Orig file $FromPath SHA256 hash: $FromPathhash == $ToPath SHA256 hash: $ToPathhash" | tee -append $LogFile
}