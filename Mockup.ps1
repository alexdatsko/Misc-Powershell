$date = get-date
$wshell = New-Object -ComObject Wscript.Shell

$TempCDriveSizeRemainCheck = (get-volume -DriveLetter "C").SizeRemaining
$TempCDriveSizeRemin = $TempCDriveSizeRemainCheck / 1GB
$TempCDriveSizeReminReport = [math]::Round($TempCDriveSizeRemin,2)

$wshell.Popup(
"Server Name: MME Mock Server
$date

The Database Backups are current.
There have been 5 Drive swap alerts since the last PSMA
The C drive has $TempCDriveSizeReminReport of Free Space.
The D drive has 310GB of Free Space.
The Shadow copies for the D drive is 03/10 - 03/29 28GB
The Event log has been cleared."
,0,"PSMA Report Mockup")