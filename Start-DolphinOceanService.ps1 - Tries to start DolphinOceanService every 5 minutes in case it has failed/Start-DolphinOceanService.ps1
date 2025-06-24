#############################################################################################################################
# Ninja-StartDolphinOceanService.ps1 - Starts the Dolphin Ocean Service each day at 12am
#   Restarts Dolphin Ocean service, then checks if it is running every 5 minutes, and starts it again if it has crashed.
#   Import the XML file here to a scheduled task to start at 5am each day and run every 5 minutes
# Alex Datsko @ MME Consulting Inc.
# v0.03 - Updated 10/6/23
# v0.04 - Updated 6/6/25 - For Ninja

$ReportFolder = "C:\PSMA\Reports\DolphinOcean"
$Date = Get-Date -Format "yyyy-MM-dd"   # Get todays date
$Time = Get-Date -Format "hh:mm:ss"     # Get time
$ReportFile = "$($ReportFolder)\DolphinServiceRestart.txt"   # Create todays log filename


if (!(Test-Path "$ReportFolder")) {
  New-Item -ItemType Directory "$ReportFolder" -Force
  New-Item -ItemType Directory "$ReportFolder" -Force
}

$OceanService = (Get-Service DolphinOceanService)
$status = $($OceanService.Status)
if (!(Test-Path $ReportFile)) {  # If file doesn't exist, create it..
  "" | Out-File $ReportFile
}
# Restart once a day at midnight
"----------------------------`n$date $time Restarted service .." | Out-File $ReportFile -Append
$OceanService | Restart-Service | Out-File $ReportFile -Append
Start-Sleep 15

Write-Output "$date $time  Dolphin Ocean- Status: $status `nGrabbing Dolphin service info: $($status)"
Write-Output "$date $time  $($OceanService.DisplayName) - Service = $($status)" | Out-File $ReportFile -Append
if ($OceanService.Status -ne "Running") {
  Write-Output "$date $time Starting Dolphin Ocean service.."
  $OceanService | Start-Service
  Write-Output "$date $time Started!" | Out-File $ReportFile -Append
}

$SchedJobService = (Get-Service DolphinTaskService)
$status = $($SchedJobService.Status)

# Restart once a day at midnight
$SchedJobService | Restart-Service
Write-Output "$date $time Dolphin Scheduled Job Service - Status: $status `nRestarted service .." | Out-File $ReportFile -Append
Start-Sleep 15

Write-Output "$date $time Grabbing Dolphin service info: $($status)"
Write-Output "$date $time $($SchedJobService.DisplayName) - Service = $($status)" | Out-File $ReportFile -Append
if ($SchedJobService.Status -ne "Running") {
  Write-Output "$date $time Starting Dolphin Scheduled Job service.."
  $SchedJobService | Start-Service
  Write-Output "$date $time Started!" | Out-File $ReportFile -Append
}
