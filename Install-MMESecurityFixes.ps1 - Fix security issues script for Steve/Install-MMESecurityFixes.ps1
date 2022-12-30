[CmdletBinding()]
param ()

$banner="
<#
 # Install-MMESecurityFixes.ps1
 # Alex Datsko alexd@mmeconsulting.com v0.03 12-20-22
 #
 # Check for security settings and fix where possible. Script must be run with Administrative privileges.
 # Checks for (and fixes):

-	Spectre 4 / Meltdown
-	SMB signing [Workstation/Server both added- 12-20-22]
-	Null Sessions
-	Autoplay (2 items)
-	Cached credentials 

 # Usage:
 #   ./Install-SecurityFixes.ps1 [-CheckOnly] [-Verbose]
 #>
"
$oldpwd=pwd

function Check-Reg {
  param (
    $RegKey,
    $RegName,
    $RegType,
    $RegValue,
    $SettingName
  )
  $checkvar = "1" # Default to disabled
  if ($RegKey -like "HKEY_LOCAL_MACHINE*") {
    $RegKey=$RegKey.replace("HKEY_LOCAL_MACHINE","HKLM:")
    Write-Verbose "[.] Replacing HKEY_LOCAL_MACHINE with HKLM: Result- $RegKey"
  }
  $ErrorActionPreference="SilentlyContinue"  # Workaround for this terminating error of not being able to find nonexisting reg values with Get-ItemProperty / Get-ItemPropertyValue
  if (Get-ItemProperty -Path $RegKey -ErrorAction SilentlyContinue) { # if RegKey exists
    Write-Verbose "$RegKey exists."
    $RegValueVar = Get-ItemProperty -Path $RegKey | Select-Object -ExpandProperty $RegName  # if RegName doesn't exist.. This will not throw an error
    if ($RegValueVar -eq $RegValue) {
      Write-Host "[.] [$($SettingName)] - $($RegName) is Enabled, good." -ForegroundColor Green
      $checkvar = 0
    } else {
      Write-Host "[!] [$($SettingName)] - $($RegName) is DISABLED." -ForegroundColor Red
      $checkvar = 1
    }
    Write-Verbose "$RegKey = $RegValueVar" 
  } else {
    Write-Host "[!] [$($SettingName)] - $($RegName) is DISABLED!  $RegKey doesn't exist!" -ForegroundColor Red
    $checkvar = 1
  }
  $ErrorActionPreference="Continue" # Set back to standard error termination setting
  return $checkvar
}

function Run-Cmd {
  param (
        $cmd
  )
  Write-Verbose "Running [$($cmd)]"
  cmd /c $cmd
}

function Set-RequireSMBSigning {
  Write-Host "[!] Making registry changes for [SMB Signing - Require] for both LanManServer and LanManWorkstation" -ForegroundColor Yellow
  # HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters requiresecuritysignature = 0#
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters"  /v EnableSecuritySignature /t REG_DWORD /d 1 /f'
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters"  /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters"  /v EnableSecuritySignature /t REG_DWORD /d 1 /f'
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters"  /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
}

function Check-RequireSMBSigning {
  $check = @()
  $check += Check-Reg -RegKey "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -RegName "EnableSecuritySignature" -RegValue "1" -SettingName "Enable SMB Signing - LanManWorkstation"
  $check += Check-Reg -RegKey "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -RegName "RequireSecuritySignature" -RegValue "1" -SettingName "Require SMB Signing - LanManWorkstation"
  $check += Check-Reg -RegKey "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -RegName "EnableSecuritySignature" -RegValue "1" -SettingName "Enable SMB Signing - LanManServer"
  $check += Check-Reg -RegKey "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -RegName "RequireSecuritySignature" -RegValue "1" -SettingName "Require SMB Signing - LanManServer"
  if ($check -contains 1) { return $True } else { return $False }
}

function Set-Spectre4Meltdown {
  Write-Host "[!] Making registry changes for [Spectre4/Meltdown]" -ForegroundColor Yellow
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 72 /f'
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f'
  $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online
  if ($hyperv) {
    if (($hyperv).State = "Enabled") {  # HyperV feature found and enabled
      Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f'
    }
  }
}

function Check-Spectre4Meltdown {
  $check = @()
<# QID 91462 
QID Detection Logic (Authenticated):  
Operating Systems: Windows Server 2008 R2, Windows 7, Windows 8.1, Windows10, Windows Server 2012, Windows Server 2012 R2, Windows Server 2016,Windows Server 2019 
This QID checks for the presence of following Registry key Value and if these registries are missing or values are wrong then this QID is flagged: 
Reg Key - HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management, Value - FeatureSettingsOverride, REG DWORD - "8264" or "72" or "8" 
Reg Key - HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management, Value - FeatureSettingsOverrideMask, REG DWORD - "3"
#>
  $check += Check-Reg -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -RegName "FeatureSettingsOverride" -RegValue "72" -SettingName "Spectre4/Meltdown"
  $check += Check-Reg -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -RegName "FeatureSettingsOverrideMask" -RegValue "3" -SettingName "Spectre4/Meltdown"
  $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online
  if ($hyperv) {
    if (($hyperv).State = "Enabled") {  # HyperV feature found and enabled
      $check += Check-Reg -RegKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -RegName "MinVmVersionForCpuBasedMitigations" -RegType "REG_SZ" -RegValue "1.0"  -SettingName "Spectre4/Meltdown Hyper-V"
    }
  }
  if ($check -contains 1) { return $True } else { return $False }
}

function Set-NullSession {
  Write-Host "[!] Making registry changes for [Null Sessions - Disable]" -ForegroundColor Yellow
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f'
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f'
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f'
}

function Check-NullSession {
  $check = @()
  $check += Check-Reg -RegKey "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -RegName "RestrictAnonymous" -RegValue "1" -SettingName "Null Sessions - Disable"
  $check += Check-Reg -RegKey "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -RegName "RestrictAnonymousSAM" -RegValue "1" -SettingName "Null Sessions - Disable"
  $check += Check-Reg -RegKey "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -RegName "EveryoneIncludesAnonymous" -RegValue "0" -SettingName "Null Sessions - Disable"
  if ($check -contains 1) { return $True } else { return $False }
}

function Set-WindowsExplorerAutoplay {
  Write-Host "[!] Making registry changes for [Autoplay - Disabled (for computer)]" -ForegroundColor Yellow
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"'
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutorun /t REG_DWORD /d 0xFF /f'
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoAutorun /t REG_DWORD /d 0x1 /f'
  Run-Cmd 'reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutorun /t REG_DWORD /d 0xFF /f'
  Run-Cmd 'reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoAutorun /t REG_DWORD /d 0x1 /f'
}

function Check-WindowsExplorerAutoplay {
  $check = @()
  $check += Check-Reg -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -RegName "NoDriveTypeAutoRun" -RegValue "255" -SettingName "Autoplay - Disabled (for computer)"
  $check += Check-Reg -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -RegName "NoAutoRun" -RegValue "1" -SettingName "Autoplay - Disabled (for computer)"
  $check += Check-Reg -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"  -RegName "NoDriveTypeAutoRun" -RegValue "255" -SettingName "Autoplay - Disabled (for user)"
  $check += Check-Reg -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"  -RegName "NoAutoRun" -RegValue "1" -SettingName "Autoplay - Disabled (for user)"
  if ($check -contains 1) { return $True } else { return $False }
}

function Set-CachedCredentialsDisabled {
  Run-Cmd 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f'
}

function Check-CachedCredentialsDisabled {
  $check = @()
  $check += Check-Reg -RegKey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -RegName "CachedLogonsCount" -RegValue "0" -SettingName "Cached Credentials - Disabled"
  if ($check -contains 1) { return $True } else { return $False }
}

function Set-MMESecuritySettings {
  if (Check-RequireSMBSigning) { Set-RequireSMBSigning }
  if (Check-Spectre4Meltdown) { Set-Spectre4Meltdown }
  if (Check-NullSession) { Set-NullSession }
  if (Check-WindowsExplorerAutoplay) { Set-WindowsExplorerAutoplay }
  if (Check-CachedCredentialsDisabled) { Set-CachedCredentialsDisabled }
}

function Check-MMESecuritySettings {
  Check-RequireSMBSigning
  Check-Spectre4Meltdown
  Check-NullSession
  Check-WindowsExplorerAutoplay
  Check-CachedCredentialsDisabled
}

function Initialize-Script {
  Write-Host $banner
  Write-Verbose "[V] Started in Verbose mode."
  if ($oldpwd -like "\\*") { 
    # Pwd contains \\ at the beginning, we are in a share, can't run cmd.exe from here.. set location to Temp folder temporarily
    Set-Location $env:temp
  }
}

Initialize-Script
if ($CheckOnly) { 
  Check-MMESecuritySettings
} else {
  Set-MMESecuritySettings
}
Set-Location $oldpwd
