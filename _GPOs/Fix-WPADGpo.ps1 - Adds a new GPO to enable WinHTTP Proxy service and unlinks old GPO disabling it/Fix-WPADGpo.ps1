#######################################################################
# Fix-WPADGpo.ps1
# Alex Datsko alexd@mmeconsulting.com
#   This will fix the WPAD GPO issue by unlinking the SEC - CC - WPAD - Disable GPO (or any GPO with 'WPAD' in the name, to be safe)
#   It will then import and link the GPO "SEC - CC - WPAD - Enable" from a backup zip file. The zip file must be present in the same
#   location where the script was run.
# v0.1 - initial


$logfile = "C:\Temp\Fix-WPAD.txt"  # Where the script log is written
$GPOPath = "$(pwd)\BackupGPO"      # We will try to extract current zip backup to $(pwd)\BackupGPO and read the GPOs in from there.

Import-Module ActiveDirectory # This will catch errors quickly on non-DCs

Function Check-GPOExists {
  param ([string]$gpoName)

  if (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue) {
    Write-Verbose "The GPO '$gpoName' exists."
    return $true
  } else {
    Write-Verbose "The GPO '$gpoName' does not exist."
    return $false
  }
}

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

Extract-GPOBackup "$(pwd)\BackupGPO-WPAD.zip"

# Find and remove the WPAD - Enabled GPO, guessing that anything with 'WPAD' in the name should be unlinked!
$DomainString = $ADDomain = (Get-ADDomain).DNSRoot
$ADDomainDN = "$((Get-ADDomain).DistinguishedName)"
$GPOs = Get-GPO -All | Where {$_.DisplayName -like "*WPAD - Disable*" -or $_.DisplayName -like "*WPAD-Disable*" -or $_.DisplayName -like "*WPAD- Disable*"}  # Handle any combo of spaces, although it should only be first or last..
Foreach ($GPO in $GPOs) { 
  Remove-GPLink -Guid $($GPO.Id) -Target $ADDomainDN
  Write-Output "[.] Unlinked: $($GPO.DisplayName)"  | tee $logfile -append
}

# Add the new GPO to reverse the setting for the WinHTTP Proxy service, import and link the GPO to the root of the domain by DN.
$GPOFolders = (gci $GPOPath -Directory).Name
ForEach ($GPOFolder in $GPOFolders) {
  if ($GPOFolder -like "*__*") {
    $GPOName = ("$($GPOFolder.Split('{')[0])").Split('__')[0]
    $GPOBackupId = ("{$($GPOFolder.Split('{')[-1])").ToUpper()
    Rename-Item "$($GPOPath)\$($GPOFolder)" "$($GPOPath)\$($GPOBackupId)" -Force
    $GPO = Import-GPO -Path "$GPOPath" -BackupId "$GPOBackupId" -TargetName "$GPOName" -CreateIfNeeded
    Write-Output "[.] Added: $($GPO.DisplayName)"  | tee $logfile -append
    $GPO | New-GPLink -Target $ADDomainDN -LinkEnabled Yes
    Write-Output "[.] Linked: $($GPO.DisplayName) to $DomainString ($($ADDomainDN))"  | tee $logfile -append
  }
}
    
Write-Output "[!] Done." | tee $logfile -append