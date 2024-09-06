$logFilePath = "C:\temp\event4663-TWAIN_32.txt"
$startTime = (Get-Date).AddHours(-1)
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=$startTime}

foreach ($event in $events) {
  $message = $event.Message
  if ($message -like '*Object Name:		C:\Windows\twain_32.dll*') {
    foreach ($line in $message) {
        if ($line -match '.*Account Name:\s*(\S+).*') { $user = $line.split('Account Name:')[1].trim() }
        if ($line -match '.*Process Name:\s*(\S+).*') { $ProcessName = $line.split('Process Name:')[1].trim() }
        if ($line -match '.*Process ID:\s*(\S+).*') { $processId = $line.split('Process ID:')[1].trim() }
        $logEntry = "Time: $($event.TimeCreated) | User: $user | Process Name: $processName | Process ID: $processId"
        Add-Content -Path $logFilePath -Value $logEntry
        Write-Output $logEntry
    }
  }
}
