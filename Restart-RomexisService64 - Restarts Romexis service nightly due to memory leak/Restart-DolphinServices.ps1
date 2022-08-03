$date = Get-Date -Format "yyyy-MM-dd"
$time = Get-Date -Format "hh:mm"
$path = "D:\Backups (Do Not Delete)\Reports"

# Tries to stop then after 5 seconds, start the Dolphin Ocean and Dolphin Task Scheduler services.
# Tries to start again after another 15 seconds
# Checks the status of the service after another 5 seconds and logs to a report

if (!(Test-Path $path)) {
  New-Item -ItemType Directory -Path $path
} 

$out1 = "----------------------`r`n"
$out1 += "$date - $time `r`n"
$out1 | Out-File $path\RestartDolphinSvcs-$date.txt -Append

$out2 = net stop DolphinOceanService  
start-sleep 5
$out2 += net start DolphinOceanService
start-sleep 15
$out2 += net start DolphinOceanService
start-sleep 5
$out2 += Get-Service DolphinOceanService | Out-String
$out2 | Out-File $path\RestartDolphinSvcs-$date.txt -Append

$out3 = net stop DolphinTaskService
start-sleep 5
$out3 += net start DolphinTaskService
start-sleep 15
$out3 += net start DolphinTaskService
start-sleep 5
$out3 += Get-Service DolphinTaskService | Out-String
$out3 | Out-File $path\RestartDolphinSvcs-$date.txt -Append

