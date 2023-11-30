[CmdletBinding()]
param (
    [switch]$CheckOnly
)

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

v0.04 (Rev E) - 11-29-2023
- Changed my Run-Cmd 'cmd.exe /c ..' registry fixes to use native powershell instead.
- Added WinVerifyTrust check and fix
- SMB signing [checked for issues, looks clean]


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


####

function Check-WinVerifyTrust {
  $check = @()
  $check += Check-Reg -RegKey "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -RegName "EnableCertPaddingCheck" -RegValue "1" -SettingName "WinVerifyTrust"
  $check += Check-Reg -RegKey "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -RegName "EnableCertPaddingCheck" -RegValue "1" -SettingName "WinVerifyTrust - Wow6432Node"
  if ($check -contains 1) { return $True } else { return $False }
}

function Set-WinVerifyTrust {
  Write-Output "[+] QID 37833 - WinVerifyTrust Signature Validation fix"
  Write-Output "[.] Creating registry items: HKLM:\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck=1 (and more)"
  New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust" -Force | Out-Null
  New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value "1" -PropertyType "String" -Force | Out-Null

  Write-Output "[.] Creating registry item: HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck=1"
  New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust" -Force | Out-Null
  New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value "1" -PropertyType "String" -Force | Out-Null    
  Write-Output "[!] Done!"
}

####

function Set-RequireSMBSigning {
  Write-Host "[!] Making registry changes for [SMB Signing - Require] for both LanManServer and LanManWorkstation" -ForegroundColor Yellow
  Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
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
  Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 72 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force

  $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online
  if ($hyperv.State -eq "Enabled") {
    Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name "MinVmVersionForCpuBasedMitigations" -Value "1.0" -Type String -Force
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
  Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord -Force
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
  New-Item -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Force | Out-Null
  Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoDriveTypeAutorun" -Value 0xFF -Type DWord -Force
  Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoAutorun" -Value 0x1 -Type DWord -Force
  New-Item -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Force | Out-Null
  Set-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoDriveTypeAutorun" -Value 0xFF -Type DWord -Force
  Set-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoAutorun" -Value 0x1 -Type DWord -Force
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
  Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0 -Type String -Force
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
  if (Check-WinVerifyTrust) { Set-WinVerifyTrust }
}

function Check-MMESecuritySettings {
  if (Check-RequireSMBSigning) {  }
  if (Check-Spectre4Meltdown) {  }
  if (Check-NullSession) {  }
  if (Check-WindowsExplorerAutoplay) {  }
  if (Check-CachedCredentialsDisabled) {  }
  if (Check-WinVerifyTrust) { }
}

function Initialize-Script {
  Write-Host $banner
  Write-Verbose "[V] Started in Verbose mode."
}

Initialize-Script
if ($CheckOnly) { 
  Check-MMESecuritySettings
} else {
  Set-MMESecuritySettings
}

Write-Host "[!] Done!"