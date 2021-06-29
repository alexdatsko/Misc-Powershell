
###########################################################################
#
# Delete-OldestFiles.ps1
#
# Written 1/31/2020 by Alex Datsko (alex@mmeconsulting.com) - Modified 4/28/21
#
# This script is meant to run as a scheduled task will remove any files of a certain extension in a folder 30 days or older, and log what it deleted to a report file
#
# Script should go in Backups (DO NOT DELETE) folder, but uses absolute paths, so does not need a working directory in a scheduled task
#
#

function Delete-OldestFiles
{
  param(
    [string]$FileLocation,
    [string]$FileExtension,
    [int]$DaysOlderThan
  )

    $date = (Get-Date).ToString('yyyy-MM-dd')
    $limit = (Get-Date).AddDays(-$DaysOlderThan)                            # Delete files older than 30 days
   
    if ($FileLocation -notmatch '\\$') {  # Add trailing backslash if it is not there
      $FileLocation += '\'
    }

    $LogLocation = "D:\Backups (Do Not Delete)\Reports\"        # Needs trailing backslash.. This assumes the C:\Backups (DO NOT DELETE) folder already exists..
    $LogFilename = $LogLocation+"DeleteLathemPayclockFiles-"+$date+".txt"

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


Delete-OldestFiles -FileLocation "C:\Program Files\Lathem Time Corporation\PayClock\Backup\" -FileExtension "*.*" -DaysOlderThan 30

    
