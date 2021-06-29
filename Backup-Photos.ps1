# This script exists to copy files from ServerVM d:\Practice Documents\Clinic Camera\ to an external backup drive G: (labeled 'Images Backup 2021')

# This can be used by to copy files from a folder, then delete files past X days
# Alex Datsko @ MME Consulting (alexd@mmeconsulting.com) 916-550-5514

# Folder to move files from
$Folder = "\\server\d$\Practice Documents\Clinic Camera"

# Log file to write to
$logfile = "D:\Event Log Files\Robocopy logs\deleted_photos.log"

# Log file to write for Robocopy
$robocopylog = $logfile+".robocopy.log"

# How many days of files we should delete from $Folder
$days_to_delete = -365

clear
Write-Host "Robocop log file: " $robocopylog
Write-Host "Deletion log file: " $logfile

Write-Host "Robocopying all files from Clinic Camera folder to G:\"
robocopy.exe $Folder "G:\" /E /R:0 /W:0 /XO /NP /XF Thumbs.db /Log+:$robocopylog /TEE /PURGE /COPYALL

Write-Host "Deleting all files older than $days_to_delete in $Folder ..."
Get-ChildItem $Folder -Recurse -Force -ea 0 |
? {!$_.PsIsContainer -and $_.LastWriteTime -lt (Get-Date).AddDays($days_to_delete)} |
ForEach-Object {
   #$_ | del -Force
   $_.FullName | Out-File $logfile -Append
}

Write-Host "Removing all empty folder and subfolders in $Folder ..."
Get-ChildItem $Folder -Recurse -Force -ea 0 |
? {$_.PsIsContainer -eq $True} |
? {$_.getfiles().count -eq 0} |
ForEach-Object {
    #$_ | del -Force
    $_.FullName | Out-File $logfile -Append
}

Write-Host "Done!"
