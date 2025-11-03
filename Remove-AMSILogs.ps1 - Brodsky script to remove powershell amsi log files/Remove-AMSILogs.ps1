#####################################################################################
# Remove-AMSILogs.ps1
# Created 2/19/24 - Alex Datsko @  - alexd@mmeconsulting.com
# This will delete the temporary files in a folder daily at 5am.  
# This was created to fix an issue with Powershell creating AAMSI log files in %temp%\{16E3BD7B-52E2-4640-854A-0803826A1D57} that keep cropping up and making Powershell slow.

$Date = Get-Date -Format "MM-dd-yyyy"
$TempFolder = "$env:UserProfile\Appdata\Local\Temp"
$LogFolder = "D:\Backups (DO NOT DELETE)\Reports\TempFiles"
$LogFile = "$($LogFolder)\$($date).log"

if (!(Test-Path $LogFolder)) {
  New-Item -ItemType Directory $LogFolder -Force
}

Write-Host "[.] Finding all temp files in $TempFolder" | tee -Append $LogFile
$AllTempFiles = Get-ChildItem -Path $TempFolder -Recurse -ErrorAction SilentlyContinue
$AllTempFiles | Out-File -Append $LogFile
Write-Host "[.] Removing all temp files from $TempFolder" | tee -Append $LogFile
$AllTempFiles | remove-item -Force -Recurse -ErrorAction SilentlyContinue | tee -Append $LogFile
# Not working?
cmd.exe /c 'del %temp% /s /f /q'
Write-Host "[!] Done!" | tee -Append $LogFile
