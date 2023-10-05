###################################################################################################################################
# Delete-TempFiles.ps1 
#   Script to clean up user profile temp folders, i.e "C:\Users\Reception1\AppData\Local\Temp\*.*" in all user profiles
#   Meant to be run from a scheduled task daily 6am etc.
#   Alex Datsko @ MME Consulting Inc 10-11-22 updated 10/5/23

$LogFile = "c:\Temp\Delete-TempFiles.log"

$DateTime = Get-Date -Format "yyyy-MM-dd"
"`n$DateTime ------------------------------" | tee -append $LogFile
$Users = (GCI C:\Users -Directory).BaseName
foreach ($User in $Users) {
  Write-Output "[.] Processing user $User .." | tee -append $LogFile
  if (Test-Path "C:\Users\$($User)\AppData\Local\Temp" -ErrorAction Continue) {
    Write-Output "[.] Removing $User AppData\Local\Temp folder.. suppressing any errors for files in use..." | tee -append $LogFile
    Remove-Item "C:\Users\$($User)\AppData\Local\Temp\*.*" -Force -Recurse -ErrorAction SilentlyContinue | tee -append $Logfile
  } else {
    "No user profile for $($User)\Appdata\Local\Temp folder found for $User or Access Denied.." | tee -append $LogFile
  }
}