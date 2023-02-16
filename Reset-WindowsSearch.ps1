[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Automated = $false 
)

$banner = "
####################################################################
# Reset-WindowsSearch.ps1
# Alex Datsko @ MME Consulting - 01-27-2022
#
# This will reset the windows search service completely including:
# 1) stopping and killing the service, 
# 2) removing the database from disk, 
# 3) [removing all registry entries, ]  CURRENTLY THIS DOESN'T WORK SO THIS PART OF THE SCRIPT IS BROKEN! NEEDS SYSTEM PRIVS, COULD LAUNCH THRU 'PSEXEC.EXE -s -c reg.exe <..>' 
# 4) setting the registry key HKLM:\Software\Microsoft\Windows Search\SetupCompletedSuccessfully 0
# 5) and restarting the service.
#
# NOTE: You will need Psexec.exe to reside in the same directory as this script.
#
# Caution: It will take a while to rebuild the indexing database after this, so file and Outlook searches may be impacted for some time!
#
# The next step, if this does not work, is to run the powershell command: 
#   Remove-WindowsFeature -Name Search-Service
# Then after reboot, re-add it with:
#   Add-WindowsFeature -Name Search-Service

"

$RegKeysToRemove = @("HKLM:\Software\Microsoft\Windows Search\Applications\windows",
   "HKLM:\Software\Microsoft\Windows Search\CatalogNames\windows",
   "HKLM:\Software\Microsoft\Windows Search\Databases\windows",
   "HKLM:\Software\Microsoft\Windows Search\Gather\windows",
   "HKLM:\Software\Microsoft\Windows Search\Gathering manager\Applications\windows",
   "HKLM:\Software\Microsoft\Windows Search\UsnNotifier\windows")

# \SOFTWARE\Microsoft\Windows Search\CatalogNames\Windows - Take ownership as system
# \Software\Microsoft\Windows Search\Gather\windows - Take ownership as system
# \Software\Microsoft\Windows Search\Gathering manager\Applications\windows - Take ownership as system
# \Software\Microsoft\Windows Search\UsnNotifier\windows - Take ownership as system

# NOTE : These profiles may need to be deleted:  ??
# \Software\Microsoft\Windows Search\UsnNotifier\S-1-5-21-*    https://i.imgur.com/PoKjX8R.png
 

Function Set-RegACLOwnerPerms {
  param ([string]$regKeyParam)

  $regKeySub = $regKeyParam.replace("HKLM:\","")

  # Take ownership: 
  $regkey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]"LocalMachine",[Microsoft.Win32.RegistryView]::Registry64)
  $key = $regkey.OpenSubKey($regKeySub, $true)
  $acl = $key.GetAccessControl()
  $acl.SetOwner([System.Security.Principal.NTAccount]"$env:username")
  $key.SetAccessControl($acl)

  # Grant full perms:
  $rule = New-Object System.Security.AccessControl.RegistryAccessRule("$env:username","FullControl","Allow")
  $acl.SetAccessRule($rule)
  $key.SetAccessControl($acl)
}

Write-Verbose "Starting in Verbose mode."
$banner
$SearchSvc = Get-Service wsearch 
if ($SearchSvc) {
  Write-Output "[.] Stopping Windows Search Service.."
  $SearchSvc | Stop-Service
  Write-Output "[.] Sleeping for 4 seconds.."
  Start-Sleep 4
} else {
  Write-Output "[!] Windows Search Service not running."
}
Write-Output "[.] Checking for WSearch process.."
$SearchSvcPID = (sc.exe queryex "WSearch" | findstr /i PID).split(':')[1].trim()
If ([int]$SearchSvcPID -gt 0) {
  Write-Output "[.] Killing WSearch process  PID: $SearchSvcPid"
  Taskkill.exe /f /pid $SearchSvcPid
} else {
  Write-Output "[!] WSearch process not running."
}
if (Test-Path "$($ENV:SystemDrive)\ProgramData\Microsoft\Search\Data") {
  Write-Output "[.] Removing $($ENV:SystemDrive)\ProgramData\Microsoft\Search\Data folder .."
  Remove-Item "$($ENV:SystemDrive)\ProgramData\Microsoft\Search\Data" -Force -Recurse
} else {
  Write-Output "[!] $($ENV:SystemDrive)\ProgramData\Microsoft\Search\Data folder does not exist!"
}

<#
Write-Output "[.] Removing Windows Search Registry items with PsExec .."
foreach ($Value in $RegKeysToRemove) {
  #Set-RegACLOwnerPerms $value
  #Remove-Item -Path $value -Force -Recurse
  if ($Value) {
    $Path = $Value.replace("HKLM:\","HKLM\")
  }

  Write-Output "[.] Running: ./psexec.exe -accepteula -u  reg.exe delete ""$($Path)"" /f "
  $Output = (. ./psexec.exe -accepteula -s reg.exe delete ""$($Path)"" /f )
  foreach ($line in $Output) {
    if ($line -like "*error code*") {
      $errorcode = ([int]($out -split('error code'))[1].trim().split('.')[0])
      if ($errorcode -gt 0) {
        # Error returned from reg.exe
        Write-Output "`n[!] Error returned: $out"
      } else {
        Write-Output "[+] Success!"
      }
    }
  }
}
#>

Write-Output "[.] Setting HKLM:\Software\Microsoft\Windows Search\SetupCompletedSuccessfully = REG_DWORD (0)"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Search"  -Name "SetupCompletedSuccessfully" -Value 0 -Type DWord
Write-Output "[.] Starting Windows Search Service.."
Get-Service wsearch | Start-Service
Write-Output "[+] Done!"
