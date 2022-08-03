$BackupsDrive="D:"
$BackupsFolder="Backups (DO NOT DELETE)"
$ReportFolder = "$BackupsDrive\$BackupsFolder\Reports\DolphinOcean"
$Date = Get-Date -Format "yyyy-MM-dd"   # Get todays date
$Time = Get-Date -Format "hh:mm:ss"     # Get time
$ReportFile = "$($ReportFolder)\DolphinOcean-$($date).txt"   # Create todays log filename


if (!(Test-Path "$BackupsDrive\$BackupsFolder\Reports")) {
  New-Item -ItemType Directory "$BackupsDrive\$BackupsFolder\Reports"
  New-Item -ItemType Directory "$BackupsDrive\$BackupsFolder\Reports\DolphinOcean"
} else {
  if (!(Test-Path "$BackupsDrive\$BackupsFolder\Reports\DolphinOcean")) {
    New-Item -ItemType Directory "$BackupsDrive\$BackupsFolder\Reports\DolphinOcean"
  }
}

$OceanService = (Get-Service DolphinOceanService)
$status = $($OceanService.Status)
if (!(Test-Path $ReportFile)) {  # If file doesn't exist, create it..
  "" | Out-File $ReportFile
  # Restart once a day at midnight
  $SchedJobService | Restart-Service
  Write-Output "$date $time Restarted service .." | Out-File $ReportFile -Append
  Start-Sleep 15
}
Write-Output "$date $time Grabbing Dolphin service info: $($status)"
Write-Output "$date $time - Service = $($status)" | Out-File $ReportFile -Append
if ($OceanService.Status -ne "Running") {
  Write-Output "$date $time Starting Dolphin Ocean service.."
  $OceanService | Start-Service
  Write-Output "$date $time Started!" | Out-File $ReportFile -Append
}
