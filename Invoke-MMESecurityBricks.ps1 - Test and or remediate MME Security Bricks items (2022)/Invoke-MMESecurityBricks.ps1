#############################################################
# Invoke-MMESecurityBricks.ps1
# Alex Datsko
# Last edit: 8/11/22
#

# Configuration items
$AcceptableLocalUserList="MME","Administrator","NoVisitors","DefaultAccount","WDAGUtilityAccount"
$SWCheck="Join.me","Splashtop","Screenconnect","WebEx","GotoAssist","TeamViewer"

# Global variables
$Findings=@()
$Remediation=@()


##############################################################
# Library functions

function Add-ToFindings {
  param([string]$txt)

    Write-Host "$txt" -ForegroundColor Red
    $Findings+=$txt
}

function Add-Remediation {
  param([string]$txt)

    Write-Host "$txt" -ForegroundColor Red
    $Remediation+=$txt
}

###############################################################
# Steve - Security Bricks 1

function Test-WindowsUpdates {
#	• Windows updates
#		○ Windows and Optional Updates
#		○ Workstations on Full automatic Apply
#		○ Servers are done manually (Still download and ask to install)
    
    Write-Output "[.] Testing Windows Updates.."

    $NotificationLevels = @{ 0="0 - Not configured"; 1="1 - Disabled"; 2="2 - Notify before download"; 3="3 - Notify before installation"; 4="4 - Scheduled installation"; 5="5 - Users configure" }
    $ScheduledInstallationDays = @{ 0="0 - Every Day"; 1="1 - Every Sunday"; 2="2 - Every Monday"; 3="3 - Every Tuesday"; 4="4 - Every Wednesday"; 5="5 - Every Thursday"; 6="6 - Every Friday"; 7="7 - EverySaturday" }

    Try {
        $AutoUpdateSettings = (New-Object -ComObject Microsoft.Update.AutoUpdate).Settings
        $Result = New-Object -TypeName PSObject -Property @{
            NotificationLevel = $NotificationLevels[$AutoUpdateSettings.NotificationLevel]
            NoAutoUpdate = $AutoUpdateSettings.NoAutoUpdate
            AUOptions = $AutoUpdateSettings.AUOptions
            UseWUServer = $AutoUpdateSettings.UseWUServer
            ReadOnly = $AutoUpdateSettings.ReadOnly
            Required = $AutoUpdateSettings.Required
            ScheduledInstallDay = $ScheduledInstallationDays[$AutoUpdateSettings.ScheduledInstallDay]
            ScheduledInstallTime = $AutoUpdateSettings.ScheduledInstallTime
            IncludeRecommendedUpdates = $AutoUpdateSettings.IncludeRecommendedUpdates
            NonAdministratorsElevated = $AutoUpdateSettings.NonAdministratorsElevated
            FeaturedUpdatesEnabled = $AutoUpdateSettings.FeaturedUpdatesEnabled
            

        }
        Switch($RegName)
        {
            'AUOptions' { $Value = $NotificationLevels[$Value] }
            'ScheduledInstallDay' { $Value = $ScheduledInstallationDays[$Value] }
        }
        $Result | Add-Member -MemberType NoteProperty -Name $RegName -Value $Value
    } Catch {
        Write-Error "Can't find Windows Auto Update settings using (New-Object -ComObject Microsoft.Update.AutoUpdate).Settings" 
    }

    try {
        $WindowsUpdate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\"
    } Catch {
        Write-Error "Can't find registry subkey: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate. It's likely this machine doesn't use Group Policy for Windows Update settings."
    }

    $WindowsUpdate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\"

    $Result = New-Object -TypeName PSObject -Property @{
        #NotificationLevel = $NotificationLevels[$AutoUpdateSettings.NotificationLevel]
        NoAutoUpdate = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\'  -ErrorAction SilentlyContinue -Name NoAutoUpdate
        AUOptions = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\' -ErrorAction SilentlyContinue -Name AUOptions
        ScheduledInstallDay = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\' -ErrorAction SilentlyContinue -Name ScheduledInstallDay
        ScheduledInstallTime = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\' -ErrorAction SilentlyContinue -Name ScheduledInstallTime
        IncludeRecommendedUpdates = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\' -ErrorAction SilentlyContinue -Name IncludeRecommendedUpdates
        NonAdminsElevated = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\' -ErrorAction SilentlyContinue -Name NonAdministratorsElevated
        FeatUpdate = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\' -ErrorAction SilentlyContinue -Name FeaturedUpdatesEnabled
        UseWUServer = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\' -ErrorAction SilentlyContinue -Name UseWUServer
    }
    Add-ToFindings "$Result"
}

function Test-WindowsFirewall {
#	• Windows Firewall
#		○ On - Private (or Domain) connected (fix NLA)
    
    Write-Output "[.] Testing Windows Firewall.."
    $NetFirewall = (Get-NetFirewallProfile | Select Name,Enabled)
    $NetFirewall
    foreach ($n in $NetFirewall) {
      if ($n.Enabled=$false) { 
        $FirewallOff=$true
        $Profile+=$_.Name+" "
      }
    }
    if ($FirewallOff) { 
      Add-ToFindings "[!] One or more of the Firewall Profiles is set to Off : $Profile"
    }
}

function Fix-WindowsFirewall {
    $NetFirewall = (Get-NetFirewallProfile | Where {$_.Enabled -ne $true})
    foreach ($n in $NetFirewall) {
      $n | Set-NetFirewallProfile -Enabled
      Add-ToRemediation "[!] Enabled Firewall on $($n.Name)- Testing of all apps must occur after!"
    }
}

function Test-GuestAccount {
#	• Guest Account
#		○ Renamed to 'No Visitors'
#		○ Disabled
    $GuestUser = Get-LocalUser -Name "Guest"
    if ($GuestUser.Enabled) {
        Add-ToFindings "[!] Guest user is enabled: "+$GuestUser
    }
}

function Fix-GuestAccount {
#	• Guest Account
#		○ Renamed to 'No Visitors'
#		○ Disabled
    Rename-LocalUser -Name "Guest" -NewName "NoVisitors" | Disable-LocalUser
}

function Test-RogueUserAccts {
#	• Rogue User accounts
#		○ Enumerate and add to list to disable
    if (!($AcceptableLocalUserList)) { 
      $AcceptableLocalUserList="MME","Administrator","NoVisitors","DefaultAccount","WDAGUtilityAccount"
    }
    $Users = Get-LocalUser
    $RogueUsers=@()
    foreach ($user in $Users) {
      if ((-not ($AcceptableLocalUserList -contains ($user.Name))) -and ($user.Enabled) -eq $true) {
        $Rogue = $true
        $RogueUsers+=$user.Name
      }
    }
    if ($Rogue) {
      foreach ($RogueUser in $RogueUsers) {
        Add-ToFindings "[!] Found possible rogue local user enabled: $RogueUser"
      }
    }
}

function Test-BruteForceLockout {
#	• Brute Force lockout
#		○ 5/30/30
    #Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout" -Name "MaxDenials"
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts"
    
}

function Test-RemoteAccessTools {
#	• Remove remote access tools
#		○ Enumerate and add to list to remove
#			§ Join.me
#			§ Splashtop
#			§ Screenconnect
#			§ WebEx
#			§ GotoAssist
#			§ TeamViewer
#               etc
    $RATools=@()
    if (!($SWCheck)) {
        $SWCheck=("Join.me","Splashtop","Screenconnect","WebEx","GotoAssist","TeamViewer")
    }
    $SWCheck | ForEach { 
         $Installed = get-wmiobject -ComputerName $_ -class Win32_Product -ErrorAction SilentlyContinue | ?{ $_.Name -like "*$_*" } | select Name,IdentifyingNumber ; 
        $RATools+=$Installed.Name 
    }
    Foreach ($RATool in $RATools) {
        Add-ToFindings "[!] Remote Access tool found: $RATool"
    }

}

function Test-BitlockerDriveEncryption {
#	• Bitlocker Drive encryption
#		○ Enumerate if it is turned on
#		○ Key stored properly
}

function Test-ChromeSettings {
#	• Chrome settings
#		○ Do not allow storing of passwords
#		○ Don't auto sign in to websites
#		○ No saved passwords in Chrome
#		○ Turn off 'continue running background apps when Chrome is closed'
}

# Sebastian - Security Bricks 2
function Test-PasswordComplexity {
#	• Password complexity
#		○ Set by gpedit (local policies)
#			§ Enforce password history (can’t use the last 3 passwords), max password age (forces changing it), minimum password length, password must meet complexity requirement, disable store passwords. 
}

function Test-PasswordReuse {
#	• Password re-use
#		○ Not sure what could be done via script, maybe test against current role password
}

function Test-PasswordManagement {
#	• Password mgmt
#		○ Nothing really can be done via script but recommend that 1Password is installed if its not

}

function Test-ScreenLocking {
#	• Screen locking
#		○ gpedit.msc > Computer Config> Windows Settings> Security Settings > Account Policies > Account Lockout Policy folder. Interactive logon: Machine inactivity limit (in seconds) 
}

function Test-2FA {
#	• 2Fa
#		○ Nothing can be done by script here, I don't think
}

function Test-SecureRemoteAccess {
#	• External RDP / Inbound Policies on WG
#		○ whatismyip.com/port-scanner
#	• Secure Remote Access
#		○ Not much we can do to scan for this, other than check for common VPN / RDG ports, make sure LMI is installed, etc..
}

function Test-Antivirus {
#	• Antivirus
#		○ LMI Portal > login > AntiVirus > Manage > Choose your office (Computer Groups) > select the PCs or all of them > choose the policy (action
}

function Test-EDR {
#	• EDR
#		○ Can check for EPDR installed?
}

function Test-Wifi {
#	• Wifi
#		○ Wireless network connected to - Guest vs Private, etc
#		○ Wifi scheduler
}

function Test-WifiSegmentation {
#	• Wifi segmentation
#		○ Private vs Guest
}

function Test-AutoplayDisabled {
#	• Autoplay Disabled
#		○ Check reg setting
}

function Test-SMBSigning {
#	• SMB Signing
#		○ Disable
}

function Test-NullSessions {
#	• Null sessions
#		○ Disable - reg settings
#	• Null sessions 2
#		○ HKLM\SYSTEM\CurrentControlSet\Control\Lsa
}

function Test-EncryptedBackups {
#	• Encrypted backups
#		○ Not much we can do here, maybe use an API key with Acronis cloud to check backups via API?
}

#################################################################################################################

function Invoke-SecurityBricksChecks {
  param([string]$Test)

  if ($Test) {
    switch ($Test) {
      "WindowsUpdates" { Test-WindowsUpdates }
    } 
  } else {  ### Main list here ##########
    Test-WindowsUpdates
  }
}

#################################################################################################################

function Invoke-SecurityBricksRemediation {
}

#################################################################################################################
# MAIN
#

Invoke-SecurityBricksChecks
Invoke-SecurityBricksRemediation
