param (
  $filepath = "\\dc-server\Installation Software\TSScan\twain32.dll for server for ScanX\Twain_32.dll",        # File to copy from
  $folderpath = "C:\Windows\temp\Twain_32.dll"                                                                 # File to copy to (or folder name, file is more specific..)
)

$info = ''###################################################################################################################################
# Copy-FileToFolder.ps1 
#   Script to Copy a single file to $folderpath, for example to overwrite a DLL file in c:\Windows.  Must be run with Administrator perms!
#   Will try $trytimes tries, every $tryseconds seconds, in case file is locked, will report an error after giving up.
#   (Created to replace c:\windows\Twain_32.dll with the TSScan one, due to automated SFC scans "fixing" the file weekly)
#   Alex Datsko @ MME Consulting Inc 8-27-24''

$info

$LogFile = "c:\Temp\Copy-FileToFolder.log"

$trytimes = 36          # This will try 36 times, which for 5m intervals, is 3 hours.
$tryseconds = 300       # Amount of time to sleep between tries, defaults to 300 = 5 minutes.

$DateTime = Get-Date -Format "yyyy-MM-dd"
"`n$DateTime ------------------------------" | tee -append $LogFile

Write-Output "[.] Copying : $filepath to $folderpath"
$done = 0
while (!$done) {
  if (Test-Path "$filepath" -ErrorAction Continue) {
    Write-Output "[+] Copying $filepath to $folderpath" | tee -append $LogFile
    $ex = $null
    try {
      Copy-Item -Path "$filepath" -Destination "$folderpath" -Force -Recurse -ErrorAction Continue | tee -append $Logfile
    } catch {
      while ($e.InnerException) {
        $e = $e.InnerException
        $exmsg += "`n" + $e.Message
      }
      Write-Output "[-] An error occurred during the copy operation: " | Tee -Append $LogFile
      $exmsg | Tee -Append $LogFile
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
    Write-Output "[-] $filepath not found, or Access Denied reading folder.." | tee -append $LogFile
  }
  $tries += 1
  if ($trytimes -gt $tries) {
    Write-Error "[-] Failed to copy $trytimes times, with $tryseconds delay.  Aborting..." | tee -append $LogFile
    $done = 1
    exit
  }
}