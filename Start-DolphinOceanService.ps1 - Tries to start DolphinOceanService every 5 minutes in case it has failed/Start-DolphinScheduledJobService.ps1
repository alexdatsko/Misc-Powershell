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
Write-Output "$date $time - Service = $($status)" | Out-File $ReportFile -Append
if ($SchedJobService.Status -ne "Running") {
  Write-Output "$date $time Starting Dolphin Scheduled Job service.."
  $SchedJobService | Start-Service
  Write-Output "$date $time Started!" | Out-File $ReportFile -Append
}

