$Date = Get-Date -Format "yyyy-MM-dd"
$Time = Get-Date -Format "HH:mm"
$Reportfile = "D:\Backups (Do Not Delete)\Reports\MemoryUsage\MemoryUsage-$($date).txt"
$Processes = (Get-Process | Sort-Object -Descending WS | Select -First 10)
"------------------------------`n$($Date) $($Time)" | Out-File $ReportFile -Append 
$Processes | Out-File $ReportFile -Append 
