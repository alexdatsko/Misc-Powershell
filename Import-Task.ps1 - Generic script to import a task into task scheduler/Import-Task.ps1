# THIS IS UNTESTED!!!!!
$scriptpath=@{"C:\Backups (Do Not Delete)",
              "D:\Backups (Do Not Delete)",
              "E:\Backups (Do Not Delete)",
              "C:\Backups Do Not Delete",
              "D:\Backups Do Not Delete",
              "E:\Backups Do Not Delete",
              "C:\Backups (DoNotDelete)",
              "D:\Backups (DoNotDelete)",
              "E:\Backups (DoNotDelete)",
              "C:\Backups DoNotDelete",
              "D:\Backups DoNotDelete",
              "E:\Backups DoNotDelete",
              "C:\Backups",
              "D:\Backups",
              "E:\Backups"}


schtasks /delete /tn ExampleTask /F 
$argument = "-Command '$scriptpath\TestScript.ps1'"
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument $argument
$trigger = New-ScheduledTaskTrigger -AtStartup
#$principal = New-ScheduledTaskPrincipal -UserId "admin" -LogonType S4U -RunLevel Highest
#Register-ScheduledTask "ExampleTask" -Action $action -Trigger $trigger -Principal $principal   #nope, lets just run as system
Register-ScheduledTask "ExampleTask" -Action $action -Trigger $trigger -Force -user system
$t = Get-ScheduledTask "ExampleTask"
"Logon type is {0}" -f $t.Principal.LogonType


Register-ScheduledTask "ExampleTask" -InputObject $task -Force -user system
