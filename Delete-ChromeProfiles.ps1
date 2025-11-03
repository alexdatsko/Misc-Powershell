###################################################################################################################################
# Delete-TempFiles.ps1 
#   Script to clean up user profile temp folders, i.e "C:\Users\Reception1\AppData\Local\Temp\*.*" in all user profiles
#   Meant to be run from a scheduled task daily 6am etc.
#   Alex Datsko @  10-11-22 updated 10/5/23

$LogFile = "c:\Temp\Delete-TempFiles.log"

# C:\Users\USERNAME\AppData\Local\Google\Chrome\User Data\Profile X\Service Worker\CacheStorage

$DateTime = Get-Date -Format "yyyy-MM-dd"
"`n$DateTime ------------------------------" | tee -append $LogFile
$Users = (GCI C:\Users -Directory).BaseName
foreach ($User in $Users) {
  "[.] Processing user $User .." | tee -append $LogFile
  if (Test-Path "C:\Users\$($User)\AppData\Local\Google" -ErrorAction Continue) {
    $ChromeUserData = "C:\Users\$($User)\AppData\Local\Google\Chrome\User Data\Profile*"
    $Folders = (gci $ChromeUserData -ErrorAction SilentlyContinue).FullName
    if ($Folders) {
      Foreach ($Folder in $Folders) {
        "[+] Checking $($Folder)\Service Worker\CacheStorage\ .." | tee -append $LogFile
        if (Test-Path "$($Folder)\Service Worker\CacheStorage") {
          "[.] Listing contents of $($Folder)\Service Worker\CacheStorage\*.*" | tee -append $LogFile
          $FilesToDelete = (GCI "$($Folder)\Service Worker\CacheStorage\" -File -Recurse -ErrorAction SilentlyContinue).FullName 
          #$FilesToDelete | tee -append $LogFile
          "[-] Removing files $($Folder)\Service Worker\CacheStorage\*.*" | tee -append $LogFile
          foreach ($FileToDelete in $FilesToDelete) {
            Remove-Item $FileToDelete -Force -ErrorAction Continue | tee -append $LogFile
          }
          Remove-Item "$($Folder)\Service Worker\CacheStorage\*" -Recurse -Force -ErrorAction SilentlyContinue | tee -append $LogFile  # Remove folders also
        } else {
          "[ ] No profile data found for $User in $Folder" | tee -append $LogFile
        }
      }
    } else {
      "[ ] No chrome user data folder found for $User" | tee -append $LogFile
    }
  } else {
    "[ ] No chrome folder found for $User or Access Denied.." | tee -append $LogFile
  }
}
"[!] Done!"