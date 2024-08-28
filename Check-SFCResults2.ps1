$logPath = "C:\temp\sfcScan.log"
$sfcLogPath = "C:\PSMA\SFC.txt"

if (-not (Get-EventLog -LogName Application -Source "SFC Scan Results")) {
    New-EventLog -LogName Application -Source "SFC Scan Results" -ErrorAction SilentlyContinue
}

try {

    if (Test-Path $logPath) {
      Remove-Item "$($logPath).old" -Force -ErrorAction SilentlyContinue  # delete .old file if it exists
      Rename-Item $logPath -NewName "$($logPath).old" -Force  # rename last log to .old
    }

    $prev = [console]::OutputEncoding
    [console]::OutputEncoding = [Text.Encoding]::Unicode

  # Invoke sfc.exe, whose output is now correctly interpreted and
  # apply the CRCRLF workaround.

    (& sfc /scannow) -join "`r`n" -replace "`r`n`r`n", "`r`n" | Tee-Object -Variable content | Out-File "C:\Temp\sfcScan.log"
    [console]::OutputEncoding = $prev

    $content = Get-Content $logPath

    if ($content -like "*Windows Resource Protection did not find any integrity violations.*") {
        $message = "SFC scan: No integrity violations found."
        Write-EventLog -LogName Application -Source "SFC Scan Results" -EntryType Information -EventID 424 -Message $message
        Add-Content -Path $sfcLogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
    } 
    elseif ($content -like "*Windows Resource Protection found corrupt files but was unable to fix some*") {
        $message = "SFC scan: Issues found, unable to fix. View C:\Temp\scfscan.log for details."
        Write-EventLog -LogName Application -Source "SFC Scan Results" -EntryType Error -EventID 425 -Message $message
        Add-Content -Path $sfcLogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
    } 
    elseif ($content -like "*Another servicing or repair operation is currently running*") {
        $message = "SFC scan: Unable to run scan, another servicing or repair operation is currently running."
        Write-EventLog -LogName Application -Source "SFC Scan Results" -EntryType Error -EventID 425 -Message $message
        Add-Content -Path $sfcLogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
    } 
    elseif ($content -like "*Windows Resource Protection found corrupt files and successfully repaired them*") {
        $message = "SFC scan: Successfully repaired corrupted files."
        Write-EventLog -LogName Application -Source "SFC Scan Results" -EntryType Information -EventID 426 -Message $message
        Add-Content -Path $sfcLogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
    } 
    elseif ($content -like "*Windows Resource Protection could not start the repair service*") {
        $message = "SFC scan: Could not start the repair service."
        Write-EventLog -LogName Application -Source "SFC Scan Results" -EntryType Error -EventID 425 -Message $message
        Add-Content -Path $sfcLogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
    } else {
        $message = "SFC scan: Unknown, view log for details $logpath."
        Write-EventLog -LogName Application -Source "SFC Scan Results" -EntryType Error -EventID 425 -Message $message
        Add-Content -Path $sfcLogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
    }
} catch {
    $message = "SFC scan: Error occurred: $($_.Exception.Message)"
    Write-EventLog -LogName Application -Source "SFC Scan Results" -EntryType Error -EventID 425 -Message $message
    Add-Content -Path $sfcLogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
}
