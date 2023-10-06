# Start-DolphinScheduledJobService.ps1 - Starts the Dolphin Ocean Service each day at 12am
#   Restarts Dolphin Scheduled Job service, then checks if it is running every 5 minutes, and starts it again if it has crashed.
#   Import the XML file here to a scheduled task to start at 5am each day and run every 5 minutes
# Alex Datsko @ MME Consulting Inc.
# v0.03 - Updated 10/6/23

$BackupsDrive="D:"
$BackupsFolder="Backups (DO NOT DELETE)"
$ReportFolder = "$BackupsDrive\$BackupsFolder\Reports\DolphinScheduledJob"
$Date = Get-Date -Format "yyyy-MM-dd"   # Get todays date
$Time = Get-Date -Format "hh:mm:ss"     # Get time
$ReportFile = "$($ReportFolder)\DolphinScheduledJob-$($date).txt"   # Create todays log filename

if (!(Test-Path "$BackupsDrive\$BackupsFolder\Reports")) {
  New-Item -ItemType Directory "$BackupsDrive\$BackupsFolder\Reports"
  New-Item -ItemType Directory "$BackupsDrive\$BackupsFolder\Reports\DolphinScheduledJob"
} else {
  if (!(Test-Path "$BackupsDrive\$BackupsFolder\Reports\DolphinScheduledJob")) {
    New-Item -ItemType Directory "$BackupsDrive\$BackupsFolder\Reports\DolphinScheduledJob"
  }
}

$SchedJobService = (Get-Service DolphinTaskService)
$status = $($SchedJobService.Status)
if (!(Test-Path $ReportFile)) {  # If file doesn't exist, create it..
  "" | Out-File $ReportFile
  # Restart once a day at midnight
  $SchedJobService | Restart-Service
  Write-Output "$date $time Restarted service .." | Out-File $ReportFile -Append
  Start-Sleep 15
}
Write-Output "$date $time Grabbing Dolphin service info: $($status)"
Write-Output "$date $time $($SchedJobService.DisplayName) - Service = $($status)" | Out-File $ReportFile -Append
if ($SchedJobService.Status -ne "Running") {
  Write-Output "$date $time Starting Dolphin Scheduled Job service.."
  $SchedJobService | Start-Service
  Write-Output "$date $time Started!" | Out-File $ReportFile -Append
}

# Get the files older than 365 days and remove them
$limitDate = (Get-Date).AddDays(-365) 
Get-ChildItem -Path $ReportFolder -File | Where-Object { $_.LastWriteTime -lt $limitDate } | Remove-Item -Force

