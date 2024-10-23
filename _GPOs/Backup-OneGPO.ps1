##################################################
# Backup-OneGPO.ps1
#   This script will back up a single gpo by name, part of the name MUST match. 
#   It may also back up more than one, if matching.
#   These should be able to be restored with Restore-AllGPOs.ps1 or Create-MasteredGPOs.ps1 or Create-SecurityGPOs.ps1.
# Alex Datsko alexd@mmeconsulting.com
# v0.2 - recreated for WPAD GPO issue

# CHANGE THIS TO MATCH THE GPO NAME OR PARTIAL!
$GPOName = "Watchguard - SSO Client"

$datetime = Get-Date -Format "yyyy-MM-dd_hhmm"
$GPOPath = "C:\Temp\BackupGPOs"
New-Item $GPOPath -ItemType Directory -Erroraction SilentlyContinue
Set-Location $GPOPath

$GPOs = Get-GPO -All | Where-Object { ($_.DisplayName -like "*$($GPOName)*") }

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

Write-Output "[+] Compressing full backup file, as $($GPOPath)\BackupGPO-$($GPOName)-B$($datetime).zip .."
Compress-Archive -Path $GPOPath  -DestinationPath .\BackupGPO-$($GPOName)-B$($datetime).zip -Force # -Verbose
Write-Output "[+] Complete!"
pause