param (
  $folderpath = "8x8-Work",            # Folder to copy to in \AppData\Local
  $temppath = "C:\Temp\8x8-Work"      # Folder to copy from
)
$info = '''###################################################################################################################################
# Copy-FolderToAllUsers.ps1 
#   Script to Copy a folder and all files recursively, in $folderpath, to all users AppData C:\Users\<username>\AppData\Local
#   Alex Datsko @  8-27-24'''

$info


$BadUsers = @("ΩWGUA.Bin","!WGUA.Bin","Public","Default User","Default","All Users")

$LogFile = "c:\Temp\Copy-FolderToAllUsers.log"

$DateTime = Get-Date -Format "yyyy-MM-dd"
"`n$DateTime ------------------------------" | tee -append $LogFile

function Get-YesNo {
  param ([string] $text)
  while (0 -eq 0) {
    $yesno = Read-Host  "`n[?] $text [y/N] "
    if ($yesno.ToUpper()[0] -eq 'Y') { return $true } 
    if ($yesno.ToUpper()[0] -eq 'N' -or $yesno -eq '') { return $false } 
  } 
}

$Users = (GCI C:\Users -Directory).BaseName | where { $BadUsers -notcontains $_ }

Write-Host "[.] Copying : $temppath to C:\Users\[username]\AppData\Local\$folderpath"

Write-Host "[.] Users we will copy the folder to:  $Users"
if (Get-YesNo "Would you like to continue?") {
  foreach ($User in $Users) {
    Write-Output "[.] Processing user $User .." | tee -append $LogFile
    if (Test-Path "C:\Users\$($User)\AppData\Local" -ErrorAction Continue) {
      Write-Output "[+] Copying $temppath to C:\Users\$($User)\AppData\Local\$($folderpath) folder.." | tee -append $LogFile
      Copy-Item -Path "$folderpath" -Destination "C:\Users\$($User)\AppData\Local\" -Force -Recurse -ErrorAction Continue | tee -append $Logfile
      Write-Output "[+] Completed $($User)" | tee -append $LogFile
    } else {
      "[-] No C:\Users\$($User)\Appdata\Local folder found for $User or Access Denied.." | tee -append $LogFile
    }
  }
}
