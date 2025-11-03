#####################################
#
# Check-PerfMonJobs.ps1
# Alex Datsko - 
#
# Checks for PerfMon jobs still running.  Also checks the size of the C:\PerfLogs folder sum usage for a threshold
#
# v0.1 - 7/23/2020 - initial
# v0.2 - 8/21/2025 - Updated and added to Ninja

$PerfLogsFolder = "C:\PerfLogs"      # where the perflogs are kept.  Also checks for D:\PerfLogs
$ThresholdInfo = 2                   # threshold in GB to throw a info event
$ThresholdWarning = 20               # threshold in GB to throw a warning event
$ThresholdError = 30                 # threshold in GB to throw an error event

$date = Get-Date -Format "yyyy-MM-dd"

if (![System.Diagnostics.EventLog]::Exists('MME')) {
    New-EventLog -LogName "MME" -Source "PerfMon Jobs" 
}

if (test-path('D:\PerfLogs')) {  
  $PerfLogsFolder = "D:\PerfLogs"
}

$FolderSize = Get-ChildItem $PerfLogsFolder -recurse | Measure-Object -property length -sum
$PerfLogsDiskUsage = [math]::truncate($FolderSize.Sum / 1024 / 1024 / 1024)   # bytes to gigs

if ($PerfLogsDiskUsage -gt $ThresholdWarning) {
  if ($PerfLogsDiskUsage -gt $ThresholdError) { # create error
    $msg = "PerfMon Jobs: (!!!) $PerfLogsFolder usage is over $ThresholdError gb (!!!) Please check that these jobs still need to be running, or that appropriate size constraints are applied."
    Write-Host $msg
    Write-EventLog -LogName "MME" -Source "PerfMon Jobs" -EventId 800  -EntryType Error -Message $msg    
  } else { # create warning
    $msg = "PerfMon Jobs: $PerfLogsFolder usage is over $ThresholdWarning gb"
    Write-Host $msg
    Write-EventLog -LogName "MME" -Source "PerfMon Jobs" -EventId 1800  -EntryType Warning -Message $msg
  }
} else {
  if ($PerfLogsDiskUsage -gt $ThresholdInfo) {
    $msg = "PerfMon Jobs: $PerfLogsFolder is using $PerfLogsDiskUsage gb, no warning/error triggered."
    Write-Host $msg
    Write-EventLog -LogName "MME" -Source "PerfMon Jobs" -EventId 18000  -EntryType Information -Message $msg
  }
}
