[CmdletBinding()]
param ()


$banner="
########################################################################
# Fix-DFSRConflictAndDeleted.ps1
# v0.1 Alex Datsko 01-20-23
# This script will determine if the ConflictAndDeleted folder is using more space than it should and remove the data as necessary
#
"

$Banner
<#
$RFs = Get-DfsReplicationGroup

function byteArrayToString {
param ($byteArray)
    if ($byteArray.Count -gt 0){
        return ($byteArray -ne 0 | foreach {[char]$_}) -join""
    }
    return "N/A"
}

foreach ($RF in $RFs) {
  Write-Output "$($RF.Identifier) - $($RF.GroupName)"
}
#>

$RFs = @()
Write-Output "[.] Guids found:"
$output = (cmd.exe /c 'WMIC.EXE /namespace:\\root\microsoftdfs path dfsrreplicatedfolderconfig get replicatedfolderguid,replicatedfoldername')
$lines = ($output.split("`n")).split("`r")
foreach ($line in $lines) {
  $RF = [PSCustomObject]@{
    Name     = ''
    GUID     = ''
  }
  if ($line.split(' ')[0] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
    $RF.guid=($line).split(' ')[0].trim()
    $RF.name=$line.substring($RF.guid.length+2,($line.length)-($RF.guid.length+2))
    Write-Output "$($RF.guid) - $($RF.name)"
    $RFs+=$RF
  }
}

$RFs

# Cleanup ConflictAndDeleted for all GUIDs
foreach ($RF in $RFs) {
  Write-Output "[.] Trying to clean up $($RF.Name) - $($RF.Guid) .."
  $cmd = 'WMIC.EXE /namespace:\\root\microsoftdfs path dfsrreplicatedfolderinfo where "replicatedfolderguid='''
  $cmd += $RF.GUID
  $cmd += '''" call cleanupconflictdirectory'
  Write-Verbose "Executing $cmd for $($RF.Name)"
  $output = (cmd.exe /c $cmd)
  if ($output -contains "Method execution successful.") {
    Write-Output "[.] Removal successful for $($RF.guid) - $($RF.Name)"
  }
}

