$Today = get-Date -format "MM-dd-yy hh:mm"

# Location specific Variables

$DBName = "DolphinPlatform"             # DB to back up 
$BackupLocation = "D:\Backups (Do Not Delete)\DolphinSQL\"  # Folder to back up to, including trailing \

$TestDBname = "DolphinPlatformTest"     # DB to restore to
$TestDBFile = ""        # Location of new MDF File.  Leave blank
$TestDBLogFile = ""     # Location of new LDF file.  Leave blank
$TestDBPath = ""        # Path to the MDF/LDF test files.  Leave blank to use the existing DB paths

$LogLoc = "D:\Backups (Do Not Delete)\Reports\SQLVerify\"      # With trailing backslash
$LogFile = "__DBbackup_"+(get-Date -format "hh:mm MMddyy")+".log"            # Log filename
$res_Full = ""  # Initialize variable for holding full Restore report.
$Debug = 0

clear
$ScriptName = $MyInvocation.MyCommand.Name
write-host "$ScriptName .. Running at " $Today
write-host "`r`n`r`nProcedure: Starting full database backup of $DBName, test restore to $TestDBname, and verify all data/tables"

if (!(test-path($LogLoc))) {
    Write-host "$LogLoc does not exist.  Creating Report folders.."
    try {
      # Create folders for reports, if they do not exist.
      new-item -path "D:\Backups (Do Not Delete)\Reports" -itemtype Folder
      new-item -path "D:\Backups (Do Not Delete)\Reports\SQLVerify" -itemtype Folder
      new-item -path "D:\Backups (Do Not Delete)\Reports\SQLVerify\Archive" -itemtype Folder
    } catch { 
    # Don't worry about this for now..
    }
}

Write-host "Getting table list from $DBName.."
$cmd = "USE "+$DBname+"; SELECT name FROM SYS.Tables;"
$TableList  = sqlcmd -E -Q $cmd
$TableList = $TableList | select -Skip 3   # Remove first 3 lines (headers etc)
$TableList = $TableList[0..($TableList.count - 2)]  # Remove last 2 lines (blank and dashes)
Write-host "$($Tablelist.count) tables found."
if ($debug) { Write-host "Table list: "; $TableList }

Write-host "Getting Master files list.."
$MasterFiles = sqlcmd -E -Q "SELECT Physical_Name FROM sys.master_files;"
$MasterFiles = $MasterFiles | Select-String -pattern $DBName -SimpleMatch 
$MasterDBFile = $MasterFiles | select-string -pattern ($DBName+".mdf") -SimpleMatch 
$MasterDBFile = ($MasterDBFile -join "").trim()
$MasterDBLogFile = $MasterFiles | select-string -pattern ($DBName+".ldf") -SimpleMatch 
$MasterDBLogFile = ($MasterDBLogFile -join "").trim()
$MasterDBPath = $MasterDBFile | out-string
$MasterDBPath = $MasterDBPath.Substring(0, $MasterDBPath.lastIndexOf('\')+1)

if ($TestDBPath -eq "") { $TestDBPath = $MasterDBPath }  # If TestDBPath is blank, use the same path as above.

#Set the Test DB master DB and Log file locations
$TestDBFile=$TestDBPath+$TestDBName+".mdf"
$TestDBLogFile=$TestDBPath+$TestDBName+"_Log.ldf"

if (($MasterDBFile -eq "") -or ($MasterDBLogFile -eq "")) {
  write-host "Could not find Master files: Could not locate an .MDF or .LDF matching the $DBName !"
  write-host "Command : SELECT Physical_Name FROM sys.master_files;"
  write-host "Returned : `r`n"+$MasterFiles
  exit;
}
if ($debug) { 
    write-host "Master DB Path : '$MasterDBPath'"
    write-host "Master DB file : '$MasterDBFile'"
    write-host "Master DB Log file : '$MasterDBLogFile'"
    write-host "`r`n"
    write-host "Test DB Path : '$TestDBPath'"
    write-host "Test DB file : '$TestDBFile'"
    write-host "Test DB Log file : '$TestDBLogFile'"
}

if ($debug) { 
    Write-Host "Table List found in $DBName : "
    $TableList 
}

#####################################

Write-host "`r`n`r`n`r`n"
write-host "Taking full backup."
$cmd = "BACKUP DATABASE "+$DBName+"
  TO DISK='"+$BackupLocation+$TestDBName+".bak' 
  WITH INIT, DESCRIPTION='"+$DBName+" Test Restore';"
$res_backup = sqlcmd -E -Q $cmd
$res_Full += "FULL BACKUP OF $DBName :`r`n"+$res_backup+ "`r`n==================`r`n"

write-host "`r`nCreating Test DB $TestDBName :"
$cmd = "CREATE DATABASE "+$TestDBName+";"
$res_create= sqlcmd -E -Q $cmd
$res_create
$res_Full += "CREATE TEST DB $TestDBName :`r`n"+$res_create+ "`r`n==================`r`n"

#write-host "`r`nRestoring DB [FileListOnly] $DBname to $TestDBName :"
#$cmd = "RESTORE FILELISTONLY FROM DISK='"+$BackupLocation+$TestDBName+".bak'"
#$res_restore_filelist = sqlcmd -E -Q $cmd
#$res_restore_filelist
#$res_Full += "RESTORE_FILELIST:`r`n"+$res_restore_filelist+ "`r`n==================`r`n"

write-host "`r`n`r`nRestoring DB $DBname to $TestDBName :"
$cmd = "RESTORE DATABASE "+$TestDBName+" FROM DISK='"+$BackupLocation+$TestDBName+".bak' 
WITH REPLACE, RECOVERY,
MOVE 'Ortho_Data' TO '$TestDBFile', 
MOVE 'Ortho_Log' TO '$TestDBLogFile';"
$res_restore = sqlcmd -E -Q $cmd
$res_restore
$res_Full += "RESTORE:`r`n"+$res_restore+ "`r`n==================`r`n"

write-host "`r`nChecking DB - DBCC CHECKDB ($TestDBname) WITH ALL_ERRORMSGS"   # ,NO_INFOMSGS" 
$cmd = "dbcc checkdb ('$TestDBname') WITH ALL_ERRORMSGS"   # ,NO_INFOMSGS" 
$res_checkdb = sqlcmd -E -Q $cmd
$res_checkdb
$res_Full += "CHECKDB:`r`n"+$res_checkdb+"`r`n==================`r`n"

write-host "`r`nChecking DB - Checking Catalog($TestDBname).."
$cmd = "dbcc checkcatalog ('$TestDBname')" 
$res_checkcatalog = sqlcmd -E -Q $cmd
$res_checkcatalog
$res_Full += "CHECKCATALOG:`r`n"+$res_checkcatalog+ "`r`n==================`r`n"

write-host "`r`nChecking DB - Checking Allocation.."
$cmd = "dbcc checkalloc ('$TestDBname') WITH ALL_ERRORMSGS,NO_INFOMSGS" 
$res_checkalloc = sqlcmd -E -Q $cmd
$res_checkalloc 
$res_Full += "CHECKALLOC:`r`n"+$res_checkalloc+ "`r`n==================`r`n"

write-host "`r`nChecking DB - Checking FileGroup.."
$cmd = "dbcc checkfilegroup" 
$res_checkfilegroup = sqlcmd -E -Q $cmd
$res_checkfilegroup
$res_Full += "CHECKFILEGROUP:`r`n"+$res_checkfilegroup+ "`r`n==================`r`n"

Write-host "`r`n`r`n[TABLE CHECKS] Checking $($TableList.count) tables:"
if ($TableList.count > 100) {
  Write-Host "[TABLE CHECKS] WARNING: >100 tables detected, this could take a while .."
}

foreach ($TableName in $TableList) {

    write-host "`r`nChecking DB - Checking Constraints($TableName).."
    $cmd = "USE DolphinPlatform; dbcc checkconstraints ($TableName) WITH ALL_CONSTRAINTS" 
    $res_checkconstraints = sqlcmd -E -Q $cmd
    $res_checkconstraints
    $res_Full += "CHECKCONSTRAINTS:`r`n"+$res_checkconstraints+"`r`n==================`r`n"

    write-host "`r`nChecking DB - Checking Ident($TableName).."
    $cmd = "USE DolphinPlatform; dbcc checkident ($TableName)" 
    $res_checkident = sqlcmd -E -Q $cmd
    $res_checkident
    $res_Full += "CHECKIDENT:`r`n"+$res_checkident+ "`r`n==================`r`n"

    write-host "`r`nChecking DB - Checking Table($TableName).."
    $cmd = "USE DolphinPlatform; dbcc checktable ($TableName)" 
    $res_checktable = sqlcmd -E -Q $cmd
    $res_checktable
    $res_Full += "CHECKTABLE:`r`n"+$res_checktable+ "`r`n==================`r`n"

} 

Write-Host "`r`n`r`nDone with all verifications."
 
write-host "`r`nCleaning up.. DROP DATABASE DolphinPlatformTest;"
sqlcmd -E -b -Q "DROP DATABASE $TestDBName;"

write-host "`r`nRemoving Test files $TestDBFile & $TestDBLogFile .."
$MSSQL_file=$TestDBPath+"DolphinPlatformTest.mdf_MSSQL" # temp file also needs to go
try {
remove-item -path $TestDBFile -force
remove-item -path $TestDBLogFile -force
remove-item -path $MSSQL_file -force
} catch { }
write-host "`r`nDone w/ Cleanup + testing.`r`n=========================================================`r`n"

$LogFullPath = $LogLoc+$LogFile 
Write-host "Writing to Report file: $LogFullPath"
$res_Full | out-file -FilePath $LogFullPath

Write-host "`r`nDisplaying Report: "
$res_Full

write-host "`r`nComplete!"
