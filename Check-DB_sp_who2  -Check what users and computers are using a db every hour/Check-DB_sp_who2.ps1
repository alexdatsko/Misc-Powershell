##########################################
#
# Check-DB_sp_who2 - Alex Datsko 05-10-2021
#
# Find out who all is using a database. 
# 
# Script is meant to be run hourly or so via Task Scheduler and report to the folder below.
#

function Delete-OldestFiles
{
  param(
    [string]$FileLocation,
    [string]$FileExtension,
    [int]$DaysOlderThan
  )
    write-host "Checking for $FileExtension in $FileLocation older than $DaysOlderThan days old..."
    $date = (Get-Date).ToString('yyyy-MM-dd')
    $limit = (Get-Date).AddDays(-$DaysOlderThan)                            # Delete files older than 30 days
   
    if ($FileLocation -notmatch '\\$') {  # Add trailing backslash if it is not there
      $FileLocation += '\'
    }

    $LogLocation = "D:\Backups (Do Not Delete)\Reports\"        # Needs trailing backslash.. This assumes the C:\Backups (DO NOT DELETE) folder already exists..
    $LogFilename = $LogLocation+"DeletedLogFiles-"+$date+".txt"

    if (!(Test-Path -path $LogLocation)) {  # if folder doesn't exist
      try {
        New-Item -ItemType "directory" -Path $LogLocation
        write-host "CREATED: $LogLocation"
      } catch {
        write-host "ERROR: Could not create log folder $LogLocation"
        exit
      }
    }

    "$date - Removing folders/files in $FileLocation : " | Out-file -FilePath "$LogFilename" -append
    $FileList = (gci -path $FileLocation -filter $FileExtension | Where-Object { $_.LastWriteTime -lt $limit })
    #OR we could use the file created date   :        | Where-Object { $_.CreationTime -lt $limit } 
    $FileList | Foreach-Object {
      write-host "Removing $_.FullName "
      $_.FullName | Out-file -FilePath "$LogFilename" -append
      takeown /f $_.FullName /a /r /d y 
      Remove-Item $_.FullName -Force -Recurse -ErrorAction SilentlyContinue
    }

    if (!($FileList.count -gt 0)) {
      write-host "No Files found to delete!"
      "No Files found to delete!" | Out-file -FilePath "$LogFilename" -append
    }

# Delete any empty directories left behind after deleting the old files.
}


 

$date = get-date -Format "yyyy-MM-dd"
$datetime = get-date -Format "yyyy-MM-dd hhmm"
$path = "D:\Backups (Do Not Delete)\Reports"
$filename = "$path\Check-DB_sp_who2 $date.txt" 
$msg = "$datetime - Writing to $filename ..."
Write-Host $msg
$msg | out-file $filename -append
osql -w 600 -E -n -Q "sp_who2" | out-file $filename -append
$msg = "-------------------------------------------------------------------------------------------------------`r`n"
$msg | out-file $filename -append

Delete-OldestFiles -FileLocation "D:\Backups (Do Not Delete)\Reports" -FileExtension "Check-DB_sp_who2.*" -DaysOlderThan 365
