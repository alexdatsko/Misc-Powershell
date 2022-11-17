Write-Output "`r`n`r`n################################"
Write-Output "#"
Write-Output "# Get-BitlockerKeys.ps1"
Write-Output "#"
Write-Output "#   Alex Datsko - 2022-05-09"
Write-Output "#   Retrieves bitlocker keys for the system and saves them to a server share"
Write-Output "#`r`n"

$SharePath = "\\server\data\Alex Datsko"
$LocalPath = "C:\Temp\"
$Date = Get-Date -Format "yyyy-MM-dd hh:mm"
$LocalTxtFile = "$($LocalPath)$($env:computername)-Bitlocker.txt"

Write-Output "Variables:"
Write-Output "`tSharePath : $SharePath"
Write-Output "`t$LocalPath : LocalPath"
Write-Output "`tLocalTxtFile : $LocalTxtFile`r`n"

Write-Output "`r`n[.] Checking that $SharePath exists .."
if (!(Test-Path $SharePath)) {
  Write-Error "[!] Couldn't find $SharePath !! Exiting" 
  Exit
} else {
  Write-Output "[.] Checking for $SharePath write access.."
  try {
    if (Test-Path "$($SharePath)\$($env:computername)-Bitlocker.txt") {
      Write-Output "[.] Found a file already.. Trying to remove $($SharePath)\$($env:computername)-Bitlocker.txt .."
      Remove-Item -Path "$($SharePath)\$($env:computername)-Bitlocker.txt" -Force
    }
  } catch {
    Write-Output "`r`n[!] $SharePath has no write access to remove $($env:computername)-Bitlocker.txt !!`r`n"
  }
  try {
    New-Item -ItemType File -Path "$($SharePath)\$($env:computername)-Bitlocker.txt" | Out-Null
  } catch {
    Write-Output "`r`n[!] $SharePath has no write access!!`r`n"
    Exit
  }
}

Write-Output "[.] Checking for C:\Temp .."
if (!(Test-Path $LocalPath)) {   # Create C:\Temp if it doesn't exist
  try {
    New-Item -ItemType Directory -Path "C:\Temp"
    Write-Output "[!] Created C:\Temp"
  } catch {
    Write-Error "[!] Couldn't create C:\Temp !! Exiting" 
    Exit
  }
}

Write-Output "[.] Writing to $LocalTxtFile .."
"Bitlocker Recovery Keys - $($env:computername)`r`n---------------------------------------------" | Out-File $LocalTxtFile  
# ^^^^ Overwrites file if it exists! ^^^^^
if (Test-Path "C:\") {
  Write-Output "[.] Writing C: Bitlocker keys to $LocalTxtFile .."
  "`n----- C:\ - $Date" | Out-File -FilePath $LocalTxtFile -Append
  (Get-BitLockerVolume -MountPoint C).KeyProtector | Out-File -FilePath $LocalTxtFile -Append
}
if (Test-Path "D:\") {
  Write-Output "[.] Writing D: Bitlocker keys to $LocalTxtFile .."
  "`n----- E:\ - $Date" | Out-File -FilePath $LocalTxtFile -Append
  (Get-BitLockerVolume -MountPoint D).KeyProtector | Out-File -FilePath $LocalTxtFile -Append
}
if (Test-Path "E:\") {
  Write-Output "[.] Writing E: Bitlocker keys to $LocalTxtFile .."
  "`n----- E:\ - $Date" | Out-File -FilePath $LocalTxtFile -Append
  (Get-BitLockerVolume -MountPoint E).KeyProtector | Out-File -FilePath $LocalTxtFile -Append
}
if (Test-Path "F:\") {
  Write-Output "[.] Writing F: Bitlocker keys to $LocalTxtFile .."
  "`n----- F:\ - $Date" | Out-File -FilePath $LocalTxtFile -Append
  (Get-BitLockerVolume -MountPoint E).KeyProtector | Out-File -FilePath $LocalTxtFile -Append
}

if (!(Test-Path $LocalTxtFile)) {
  Write-Output "[.] Done, moving $LocalTxtFile to $SharePath"
  Move-Item -Path $LocalTxtFile -Destination $SharePath
} else {  # Overwrite if it exists..
  Write-Output "[.] Done, copying $LocalTxtFile to $SharePath"
  Copy-Item -Path $LocalTxtFile -Destination $SharePath -Force
  Write-Output "[.] Removing $LocalTxtFile to clean up."
  Remove-Item -Path $LocalTxtFile -Force
}
Write-Output "[.] Done!`r`n"