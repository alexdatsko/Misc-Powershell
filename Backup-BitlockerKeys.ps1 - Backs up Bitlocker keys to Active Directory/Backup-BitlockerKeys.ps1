##########################################################################
# Backup-BitlockerKeys.ps1 - Backs up Bitlocker Keys to Active Directory
# Alex Datsko @ MME Consulting - 2-20-2023
#

# Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId (Get-BitLockerVolume -MountPoint "C:").KeyProtector[1].KeyProtectorId

function Backup-BitlockerKeys {
  $BLVs = (Get-BitLockerVolume).MountPoint
  foreach ($BLV in $BLVs) { 
    if (Get-BitLockerVolume -MountPoint $BLV -ErrorAction SilentlyContinue) {
      try {
        Write-Output "[.] Backing up Bitlocker Keys to AD.."
        Backup-BitLockerKeyProtector -MountPoint $BLV -KeyProtectorId (Get-BitLockerVolume -MountPoint $BLV).KeyProtector[1].KeyProtectorId
      } catch { 
        Write-Output "[!] ERROR: Could not access BitlockerKeyProtector. Is drive $BLV encrypted? "
        Get-BitLockerVolume
      }
    }
  }
}

Backup-BitlockerKeys
