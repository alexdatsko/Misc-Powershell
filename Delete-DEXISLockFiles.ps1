$Logfile = "D:\Data\Dexis\DEXISLockFiles.log"

$Date = Get-Date -Format "yyyy-MM-dd HH:mm"
Write-Host "`n[.] Checking for DEXIS Lock files..."
$Lockfiles = gci -path '\\server\data\dexis\data' -file *.lck -recurse 

if ($Lockfiles) {
  Write-Host "[.] Lock files found:"
  Write-Host $Lockfiles

  Write-Host "[.] Writing Log to $Logfile..."
  "--------- $Date ---------" | Out-file $LogFile -Append
  $Lockfiles | Out-file $Logfile -Append

  Write-Host "[.] Removing DEXIS Lock files..."
  $Lockfiles | remove-item -verbose
}
Write-Host "[!] Done!"