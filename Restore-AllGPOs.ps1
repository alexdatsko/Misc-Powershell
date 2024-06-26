﻿$GPOPath = "c:\Temp\BackupGPO"  # This doesn't really matter, we will try to extract current zip backup to $pwd\BackupGPO

Function Extract-GPOBackup {
  param ($BackupFile)
  if ($true) {  # modified to work in Restore-AllGPOs.ps1
    Write-Host "[.] Found newest backup file $($BackupFile), extracting ..."
    Expand-Archive -Path $BackupFile -DestinationPath $pwd -Force # -Verbose
    if ((gci . | where {$_.Name -like 'BackupGPO'}).count -eq 0) {
      Write-Host "[!] Error extracting $BackupFile : BackupGPO folder not found in $pwd  " 
      exit
    } 
  }
}

Function Test-GPOBackup {
  # Check for Backup Files
  $BackupFiles = Get-ChildItem -Path "$($pwd)" -Filter *.zip | where { $_.Name -like "backup*.zip" }
  if ($BackupFiles.Count -gt 1) {
    $BackupFile = $BackupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1  # Select newest backup*.zip
    return $BackupFile
  } else { 
    if ($BackupFiles.Count -eq 1) {
      $BackupFile = $BackupFiles 
      return $BackupFile
    } else { # 0 backup files found
      return $null
    }
  }
}

if (!(Test-Path $GPOPath)) {
  while ((gci $pwd | where { $_.Name -like 'BASE - CC - Bitlocker*' }).count -eq 0) {  # This is a GPO name that MUST be in the GPO backup!!
    $BackupLoc = Test-GPOBackup
    if (($BackupLoc) -ne $null) {
      Extract-GPOBackup $BackupLoc
      $GPOPath = "$pwd\BackupGPO"
      Set-Location $GPOPath
    } else {
      Write-Host "[!] Failed! $GPOPath and Backup file not found.."
      Exit 
    }
  }
}

$GPOFolders = (gci $GPOPath -Directory).Name
ForEach ($GPOFolder in $GPOFolders) {
  if ($GPOFolder -like "*__*") {
    $GPOName = ("$($GPOFolder.Split('{')[0])").Split('__')[0]
    $GPOBackupId = ("{$($GPOFolder.Split('{')[-1])").ToUpper()
    Rename-Item "$($GPOPath)\$($GPOFolder)" "$($GPOPath)\$($GPOBackupId)" -Force
    $GPO = Import-GPO -Path "$GPOPath" -BackupId "$GPOBackupId" -TargetName "$GPOName" -CreateIfNeeded
    Write-Host "[.] Added $($GPO.DisplayName)"
  }
}
Write-Host "[!] Done."