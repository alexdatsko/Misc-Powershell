# Location of PSMA 2.0 Scripts
$ScriptDriveLetter = "D" # This is usually C or D, it is the Drive letter holds the Backups DND folder
$ScriptPath = ":\Backups (Do Not Delete)\Scripts\"  
$ScriptFullPath = $ScriptDriveLetter+$ScriptPath
# Location of PSMA 2.0 Reports
$ReportDriveLetter = $ScriptDriveLetter
$ReportPath = ":\Backups (Do Not Delete)\Reports\"
$ReportFullPath = $ReportDriveLetter+$ReportPath
# Location of PSMA 2.0 Framework
$FrameworkPath = $scriptdriveletter+$scriptpath+"_framework.psm1"
# Scheduled Task folder Location
$SchTaskFolder = $ScriptDriveLetter+":\Backups (Do Not Delete)\Scripts\ScheduledTasks\" 
$SchTaskUser = ""    # i.e: EITHER "DOMAIN\User" OR ".\User"

# Backup related scripts
$PortableDriveLetter = "E" # The Portable Drive Letter
$AcronisDailyTIBPath = ""
$AcronisDailyCheckThreshold = 3 # If AcronisDailyTIBPath has not been updated in the last x days, an alert will be generated
$DriveSwapFile = $ReportFullPath+"DriveSwap.csv" # This file holds the Label on the Portable backup drive from last night.
$DriveReportFile = $ReportFullPath+"DriveReport.csv"
$DriveReportArchivePath = "C:\Users\smithj\Archive Drive Report\"

# MS SQL Related
$LDFPath = "" # This is the path of the LDF file
$LDFThreshold = 5GB # This is threshold that will determine if the LDF bloating or not. In GB
$NoonDBFilePath = "" # Path of static noon backup.
$SingleEveningDBFilePath =  "" #P ath of static single or evening backup.
$StaticDBCheckThreshold = 3 # Any more than 3 days since the last DB backup, and an alert will be generated

# These variables are related to Get-FolderSize.ps1
$FolderSizeThresholdGb = 1  # Set minimum reported folder size to 1gb
$FolderSizeMaxDays = 3

# DFS backlog variables
$DFSthreshold = 25

# Event log variables
$LogName = "MME"         # This should be consistent between scripts
$LogSource = "Updater"   # set locally per script
$EventLogMaxSize = 2GB   # maximum size of the MME event log
$RetentionDays = 365     # retain the log records for at least 1 year.
$DaysToCheck = 1         # number of days to search event log for (default to 1 for daily checks)

# Misc
$CDriveLetter = "C" # The C Drive letter
$DDriveLetter = "D" # The D Drive letter

# debug mode: Turn on lots of informational messages by setting to 1
$Debug = 1

# Create the MME event log if it does not exist.
New-EventLog -LogName "MME" -Source "PSMA 2.0" -ErrorAction SilentlyContinue
Start-Sleep -seconds 5 #wait 5s in case the script is being created, noticed I was having some trouble here.
Limit-EventLog -LogName "MME" -RetentionDays $RetentionDays -OverflowAction OverwriteOlder -MaximumSize $EventLogMaxSize   # set the limitation parameters	

# Import the PSMA 2.0 Framework
try { 
  import-module $FrameworkPath -Verbose
  write-host "Framework loaded."
} catch { 
  write-host "Could not load module $FrameworkPath !!!"
  write-eventlog -Logname "MME" -Source "Updater" -EventID 100 -Entrytype Error -Message "Could not load module $FrameworkPath !!!"
  exit
}

######## Basic testing ##########


# Check that the Script Drive letter and path above are good before going any further with the script
if (Test-Path($ScriptFullPath) -type Container) {
  if ($debug) { write-message "$ScriptFullPath folder found." success }
} else {
 try {
   New-Item -Path $ScriptFullPath -ItemType directory
  } catch {
    write-message "Could not create folder $ScriptFullPath !!!" error
    write-eventlog -Logname "MME" -Source "PSMA 2.0" -EventID 100 -Entrytype Error -Message "Could not create folder $ScriptFullPath !!!"
  }
}
