#############################################
# Backup-AllGPOs.ps1
# Backs up all AD GPOs and Policy Store, to be restored on a new server
# Alex Datsko @ MME Consulting Inc
# v0.03 - 04-24-2023

$pwd = (pwd)
$GPOPath = "$($pwd)\BackupGPO"
$datetime = Get-Date -Format 'DyyyyMMddTHHmmss'
$ErrorFound = $false

Write-Output "[!] Exporting all GPOs to to $GPOPath .."
if (!(Test-Path $GPOPath)) { New-Item -Type Directory $GPOPath | Out-Null }
$GPOs = Get-GPO -All | Where-Object { (!($_.DisplayName -like 'Default*')) -and (!($_.DisplayName -like 'Watchguard*')) -and (!($_.DisplayName -like 'Black Talon*')) }

$GPOs | ForEach-Object { # Display and check the GPOs that will be backed up
  Write-Verbose "Examining: ($_).DisplayName" 
  # Check that there are no issues with naming conventions:
  if ($_.Displayname -like '*&*' -or $_.Displayname -like '*"*' -or $_.Displayname -like '*/*') {
    Write-Host "[!] ERROR: $($_.DisplayName) has invalid characters,  these cannot be used in a policy name safely: "" & /"
    $ErrorFound = $true
  }
}
if ($ErrorFound -eq $true) { Write-Host "[!] Exiting, please fix the issues and re-run the script." ; exit }

$GPOs | ForEach-Object {
  $Id = (Backup-GPO -Guid $_.Id -Path $GPOPath).Id | Select-Object -ExpandProperty Guid
  $_ | Add-Member -NotePropertyName "BackupId" -NotePropertyValue $Id
}
$GPOs | ForEach-Object {
  Get-GPOReport -Guid $_.Id -ReportType Html -Path "$($GPOPath)\{$($_.BackupId)}\$($_.DisplayName.replace('/',' '))).html"
  Rename-Item "$($GPOPath)\{$($_.BackupId)}" "$($GPOPath)\$($_.DisplayName)__{$($_.BackupId)}" -Force
  $bkupfile = "$($GPOPath)\$($_.DisplayName)__{$($_.BackupId)}\bkupinfo.xml" 
  Set-ItemProperty -Path $bkupfile -Name Attributes -Value Normal
}
$GPOs | Export-CSV -Path "$($GPOPath)\GPOList.csv"
Set-ItemProperty -Path "$($GPOPath)\manifest.xml" -Name Attributes -Value Normal

# Grab policies from policy store, central or not
$ADDomain = (Get-ADDomain).DNSRoot
$CPolicyStore = "\\$($ADdomain)\SYSVOL\$($ADDomain)\policies\PolicyDefinitions"
if (Test-Path -Path $CPolicyStore) {
  $PolicyStore=$CPolicyStore
  Write-Output "[!] Central Policy store found at $PolicyStore"
} else {
  $PolicyStore = "C:\Windows\PolicyDefinitions"
  Write-Output "[!] Using standard policy store, $PolicyStore"
}
# Backup all policy store items
Write-Output "[!] Compressing PolicyStore backup file, as $($GPOPath)\PolicyStore-B$($datetime).zip .."
Compress-Archive -Path $PolicyStore -DestinationPath "$($GPOPath)\PolicyStore-B$($datetime).zip" -Force # -Verbose
Write-Output "[.] Done."

Write-Output "[!] Compressing full backup file, as $($GPOPath)\BackupGPO-B$($datetime).zip .."
Compress-Archive -Path $GPOPath  -DestinationPath .\BackupGPO-B$($datetime).zip -Force # -Verbose
#Get-ChildItem "$($GPOPath)\BackupGPOs-B$($datetime).zip" 
Write-Output "[+] Complete!"