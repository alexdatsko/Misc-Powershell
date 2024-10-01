#############################################
# Backup-AllGPOs.ps1
# Backs up all AD GPOs and Policy Store, to be restored on a new server
# Alex Datsko @ MME Consulting Inc
# v0.05 - 09-30-2024

$pwd = (pwd)
$GPOPath = "$($pwd)\BackupGPO"
$datetime = Get-Date -Format 'DyyyyMMddTHHmmss'
$ErrorFound = $false

function Export-WmiFiltersToCSV {
    param (
        [string]$GPOPath = "$($pwd)\BackupGPO",
        [string]$CsvPath = "$($GPOPath)\WmiFilters.csv",
        [string]$DomainDistinguishedName = (Get-ADDomain).DistinguishedName
    )

    $Properties = @('msWMI-ID', 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2', 'msWMI-Author', 'Created', 'Modified')

    $WmiFilters = Get-ADObject `
        -Filter { ObjectClass -eq "msWMI-Som" } `
        -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,$DomainDistinguishedName" `
        -SearchScope OneLevel `
        -Properties $Properties

    $Results = @()

    foreach ($WmiFilter in $WmiFilters) {
        $Response = [PSCustomObject]@{
            Id          = $WmiFilter.'msWMI-ID'.Trim('{}')
            Name        = $WmiFilter.'msWMI-Name'
            Description = $WmiFilter.'msWMI-Parm1'
            Query       = $WmiFilter.'msWMI-Parm2'
            Author      = $WmiFilter.'msWMI-Author'
            Created     = $WmiFilter.Created
            Modified    = $WmiFilter.Modified
        }
        $Results += $Response
    }

    $Results | Export-Csv -Path $CsvPath -NoTypeInformation
    Write-Host "[+] WMI Filters exported to $CsvPath"
}

Write-Output "[.] Exporting all GPOs to to $GPOPath .."
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
  Write-Output "[+] Central Policy store found at $PolicyStore"
} else {
  $PolicyStore = "C:\Windows\PolicyDefinitions"
  Write-Output "[+] Using standard policy store, $PolicyStore"
}
# Remove old policy store backup zip files so we don't include old stuff
$OldFiles = GCI "$($GPOPath)\PolicyStore-B*.*"
Write-Host "Removing old Policy Store Backup files using mask: ""$($GPOPath)\PolicyStore-B*.*"""
if ($OldFiles) {
  foreach ($oldfile in $OldFiles) {
    Remove-Item $oldfile -Force
  }
}
# Backup all policy store items
Write-Output "[+] Compressing PolicyStore backup file, as $($GPOPath)\PolicyStore-B$($datetime).zip .."
Compress-Archive -Path $PolicyStore -DestinationPath "$($GPOPath)\PolicyStore-B$($datetime).zip" -Force # -Verbose

# Backup all WMI Filters
Write-Output "[+] Creating WMI Filter backup file, as $($GPOPath)\WMIFilters.csv .."
Export-WMIFiltersToCSV

Write-Output "[+] Compressing full backup file, as $($GPOPath)\BackupGPO-B$($datetime).zip .."
Compress-Archive -Path $GPOPath  -DestinationPath .\BackupGPO-B$($datetime).zip -Force # -Verbose
#Get-ChildItem "$($GPOPath)\BackupGPOs-B$($datetime).zip" 
Write-Output "[+] Complete!"
pause