#Collection
$date = get-date
$Practicename = '' #Dr's name or practice name

#uptime
$os = Get-WmiObject win32_operatingsystem
$uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))

#database check
#see Static DB Check script
# (gci $pathofDatabasebackup).Creationtime = $date
#$TempDBStatus = current/not current


#drivespace
$TempCDriveSizeRemainCheck = (get-volume -DriveLetter "C").SizeRemaining
$TempCDriveSizeRemin = $TempCDriveSizeRemainCheck / 1GB
$TempCDriveSizeReminReport = [math]::Round($TempCDriveSizeRemin,2)
$TempCDriveTotalSizeCheck = (Get-Partition -DriveLetter $CDriveLetter | Get-Disk).Size
$TempCDriveTotalSize = $TempCDriveTotalSizeCheck / 1GB
$TempCDriveTotalSizereport = [math]::Round($TempCDriveTotalSize,2)


$TempDDriveSizeRemainCheck = (get-volume -DriveLetter $DDriveLetter).SizeRemaining 
$TempDDriveSizeRemin = $TempDDriveSizeRemainCheck / 1GB 
$TempDDriveSizeReminReport = [math]::Round($TempDDriveSizeRemin,2) 
$TempDDriveTotalSizeCheck = (Get-Partition -DriveLetter $DDriveLetter | Get-Disk).Size 
$TempDDriveTotalSize = $TempDDriveTotalSizeCheck / 1GB 
$TempDDriveTotalSizereport = [math]::Round($TempDDriveTotalSize,2) 

#shadowcopies
#see additional 

#Popup
$wshell = New-Object -ComObject Wscript.Shell
$wshell.Popup(
"$PracticeName $hostname
$date
$uptime

The Database backup is $TempDBstatus

The C drive has free $TempCDriveSizeReminReport/$TempCDriveTotalSizereport
The D drive has free $TempDDriveSizeReminReport/$TempDDriveTotalSizereport
The Shadow copies for the D drive is 03/10 - 03/29 28GB
"
,0,"PSMA Popup Report")