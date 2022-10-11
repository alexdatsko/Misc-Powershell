###################################################################################################################################
# Delete-TempFiles.ps1 
#   Script to clean up user profile temp folders, i.e "C:\Users\Reception1\AppData\Local\Temp\*.*" in all user profiles
#   Meant to be run from a scheduled task daily 6am etc.
#   Alex Datsko @ MME Consulting Inc 10-11-22

$DateTime = Get-Date -Format "yyyy-MM-dd"
"$DateTime ------------------------------" | tee -append c:\Scripts\Delete-TempFiles.log
$Users = GCI C:\Users -Directory
foreach ($User in $Users) {
  Write-Output "[.] Processing user $User .."
  #$results = dir "C:\Users\$($User)\AppData\Local\Temp\E2*" 
  #$results | tee -append c:\Scripts\Delete-TempFiles.log
  cmd.exe /c "del ""C:\Users\$($User)\AppData\Local\Temp\*.*"" /s /f /q" | tee -append c:\Scripts\Delete-TempFiles.log
  gci "C:\Users\$($User)\AppData\Local\Temp" -Directory | where { !($_ -like '.') -and !($_ -like '..') } | remove-item -recurse -force
}