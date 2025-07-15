############################################################################
#
#  Invoke-MMESecurityAudit.ps1
#
#  MME Security Audit Automation Script (draft)
#
#  Alex Datsko (alexd@mmeconsulting.com) 
#
# v0.1 - 2021-06-03 - initial
# v0.5 - 2025-07-15 - updated for mari's list automation
####################################################

# Shared routines
Function Get-OSInfo {
    $OSInfo = Get-ComputerInfo OsName,OsVersion,OsBuildNumber,OsHardwareAbstractionLayer,WindowsVersion
     "OS: $($OSInfo.OsName) build $($OSInfo.OsBuildNumber)" 

    [double]$osver = [string][environment]::OSVersion.Version.major + '.' + [environment]::OSVersion.Version.minor 
    # In the above we cast to a string to build the value and then cast back to a double.
    # This numeric version number can then be tested against a desired minimum version:
    if ($osver -ge 5.0 -and $osver -lt 9.0) {  #Server 2008 / 2008 r2
         "Windows Vista/Server 2008 or greater. Checking for ESU.." 
 
        #### NOT SURE IF THIS WORKS ....
        #//////Purpose of this script is to detect if the Win2008/R2 machine has an Extended Security Update (ESU). It will write to a registry key with a 1(true), or a 0(false) to indicate if the license exists.
 
        $ESUWin2008Year1 = (Get-WmiObject softwarelicensingproduct -filter "ID='553673ed-6ddf-419c-a153-b760283472fd'" | Select LicenseStatus)
        $ESUWin2008Year2 = (Get-WmiObject softwarelicensingproduct -filter "ID='04fa0286-fa74-401e-bbe9-fbfbb158010d'" | Select LicenseStatus)
        $ESUWin2008Year3 = (Get-WmiObject softwarelicensingproduct -filter "ID='16c08c85-0c8b-4009-9b2b-f1f7319e45f9'" | Select LicenseStatus)
        if ($ESUWin2008Year1 -match '@{LicenseStatus=1}') {
             'Win2008/R2 ESU Year 1 found' 
        }
        else {
             'No Win2008/R2 ESU Year 1' 
        }
        if ($ESUWin2008Year2 -match '@{LicenseStatus=1}') {
             'Win2008/R2 ESU Year 2 found' 
        }
        else {
             'No Win2008/R2 ESU Year 2' 
        }
        if ($ESUWin2008Year3 -match '@{LicenseStatus=1}') {
             'Win2008/R2 ESU Year 3 found' 
        }
        else {
             'No Win2008/R2 ESU Year 3' 
        }
        if ($ESUWin2008Year1 -or $ESUWin2008Year2 -or $ESUWin2008Year3) { } else {
           "Windows Vista/Server 2008/R2 - NO ESU found!!"  
        }
    }
    if ($osver -ge 9.0 -and $osver -lt 10.0) {  "Windows 7/Server 2012/R2"  }
    if ($osver -ge 10.0) {  "Windows 10/Server 2016 or greater"  }
}


########################################################### MAIN ##################################################

 "`n# A - Hostname"
hostname

 "`n# B - Users"
net user
net localgroup administrators
 "  Guest User account:"
net user guest |findstr /i active

 "`n# C - Shares"
net share

 "`n# D - Rogue apps/EOL Software"
Get-WmiObject -Class Win32_Product

 "`n# E - Mapped Drives"
net use

 "`n# F - OS Version"
# Get OS end of life status"
Get-OSInfo

 "`n# G - Windows updates"
wmic qfe | findstr /i 2025

 "`n# H - Screen lock etc"
mkdir c:\temp
gpresult /f /h c:\temp\%computername%.html
mkdir \\%servername%\data\secaud\2025
xcopy c:\temp\%computername%.html \\%servername%\data\secaud\2025
echo.

 "`n# I - Antivirus status"
# 1. Defender Status (enabled/disabled)
$defenderStatus = Get-MpComputerStatus | Select-Object -Property AMServiceEnabled, RealTimeProtectionEnabled
"I- Windows Defender Status: $($defenderStatus | Format-List | Out-String | Add-Content $LogFile)"

# 2. SecurityCenter2 registered products (sometimes EDR shows here)
$products = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntivirusProduct" -ErrorAction SilentlyContinue
if ($products) {
    "I - Registered Antivirus Products:"
    $products | Select-Object displayName, pathToSignedProductExe, productState | Format-Table -AutoSize | Out-String
} else {
    "    No registered AV in SecurityCenter2 namespace (could be EDR-only or corrupted registration)"
}

# 3. Installed Products Scan (via Win32_Product, be aware of slow performance)
$win32 = Get-WmiObject -Class Win32_Product
$avMatches = $win32 | Where-Object {
    $_.Name -match 'EDR|Antivirus|EPDR|Webroot|Crowdstrike|SentinelOne|Cortex|Carbon|Norton|McAfee|Bitdefender|Malwarebytes|ESET|TrendMicro|Avira|AVG|Avast'
}

if ($avMatches) {
    "I - Installed AV/EDR Products:"
    $avMatches | Select-Object Name, Version, Vendor | Format-Table -AutoSize | Out-String
} else {
    "    No matching AV/EDR products found in Win32_Product"
}

 "`n# J - Firewall status"
$FirewallProfileDisabled = 0
$FirewallProfiles = (Get-NetFirewallProfile)
$FirewallProfiles | % {
  if ($_.Enabled -eq 1) {
     "J: Windows Firewall $($_.Name) profile is enabled" 
  } else {
     "J: Windows Firewall $($_.Name) profile is disabled!" 
    $FirewallProfileDisabled = 1
  }
}
if ($FirewallProfileDisabled) {
   "J: A Windows Firewall profile is disabled!" 
} else {
   "J: All Windows Firewall profiles are enabled." 
}

 "`n# K - Scheduled tasks"
"`nK: Startup Run Keys"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
"`nK: Startup Run Keys (HKLM)" 
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
"`nK: Scheduled Tasks (Verbose)" 
schtasks /query /fo LIST /v

 "`n# L - Bitlocker"
 Get-BitLockerVolume
#$bitlocker = manage-bde -status C: | findstr /i conversion
#if ($LASTEXITCODE -eq 0) {
#    "`nL: BitLocker Enabled`n$bitlocker"
#} else {
#    "`nL: BitLocker not enabled or admin required."
#}

 "`n# M - UAC Enabled"
$uacVal = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"
if ($uacVal -eq 0) {
    "`nM: UAC is disabled"
} else {
    "`nM: UAC is enabled"
}


# Get DRAC status / DRAC check

# Check if DRAC is working internally

$ipV4 = Test-Connection -ComputerName $env:COMPUTERNAME -Count 1  | Select -ExpandProperty IPV4Address | Select -ExpandProperty IPAddressToString
$ipfirst3 = $ipv4.split(".")[0]+"."+$ipv4.split(".")[1]+"."+$ipv4.split(".")[2]+"."
# ASSUMES a /24 subnet!!!  Also assumes DRAC is .42 !!! (Also, ends in a .)
$DRACIP = $ipfirst3+"42"
 "Testing if $DRACIP is responding to ping.." 
if (!(Test-NetConnection $DRACIP)) {
  $DRACIP = Read-Host "$DRACIP not responding.  What is the internal IP Address of the DRAC? "  
} else {
   "$DRACIP responded to ping." 
}

$Port2443 = (Test-NetConnection $DRACIP -port 2443).TcpTestSucceeded
$Port5902 = (Test-NetConnection $DRACIP -port 5902).TcpTestSucceeded
if ($Port2443) {
   "DRAC $DRACIP Port 2443: $Port2443 .. Open" 
} else {
   "DRAC $DRACIP Port 2443: $Port2443 .. Closed!" 
}
if ($Port5902) {
   "DRAC $DRACIP Port 5902: $Port5902 .. Open" 
} else {
   "DRAC $DRACIP Port 5902: $Port5902 .. Closed!" 
}

# Check if External DRAC port is open
. .\Check-PortExternal.ps1
Check-PortExternal -port 2443
Check-PortExternal -port 5902



# Get local user list
 "Local users list: " 
$LocalUsers = Get-LocalUser | Select Name,Enabled,FullName
$LocalUsers | ft

# Get localgroup administrators list
 "Administrators group list: " 
$LocalAdmins = Get-LocalGroupMember -Name "Administrators" | Select -ExpandProperty Name
$LocalAdmins | ft

# Domain user last login check
. .\Get-ADUserLastLogon.ps1

# Get Antivirus status
#UGH - This seems not to work right on Server 2016
. .\Get-AVStatus.ps1
Get-AVStatus localhost

# Get DSU Firmware update list
. .\Check-DSUUpdate.ps1

# Get File share list
. .\Get-NTFSPerms.ps1

# Email security check
$DmarcDomain = Get-Host "Domain to check on http://www.dmarcian.com/domain-checker ? "
$postParams = @{domain="$($DmarcDomain)"}
Invoke-WebRequest -Uri http://www.dmarcian.com/domain-checker -Method POST -Body $postParams
# Reviewed their page, is uses Vue.js front end which is a lot of javascript
# Not sure how easy it would be to pass the domain name in, might have to use Burp and see what the actual request looks like
# For now, quicker probably to just open the page in chrome and type it manually..
start chrome.exe https://dmarcian.com/domain-checker/

# Remote access check
# Check manually for now... too many to find
start appwiz.cpl
[System.Windows.MessageBox]::Show('Check remote access applications manually!')

# Backups working/current?
# Check manually for now, too many variables
explorer.exe =
[System.Windows.MessageBox]::Show('Check backups manually!')

# Set security policies?
# BETA testing currently.
 "Setting updated security policies ..." 
. .\Set-Secpol.bat

# Print Output
Function Output-SecAudInfo {
     "OUTPUT:`r`n"
     "OS End of Life? `t`t`t:`t$OSEndOfLife"
     "DRAC - Equipped? Enterprise License? `t:`t$DRACEnterpriseLicense"
     "DRAC - Enabled? `t`t`t:`t$DRACEnabled"
     "DRAC - Working remotely?`t:`t$DRACWorkingRemotely"
     "DRAC - User check? `t`t:`t$DRACUsers"
     "OS Up to date? Review+Rec`t:`t$WindowsUpdates"
     "Antivirus - Enabled?  `t:`t$AntivirusEnabled"
     "Local user check / admins group check"
     "Antivirus - Enabled?  Review+Rec`t:`t$AVEnabled"
     "Antivirus - Up to date?`t:`t$AVUpdates"
     "Antivirus - Weekly full scan?  When? `t:`t$AVFullScan"
     "No items in quarantine? `t:`t$AVQuarantine"
     "DSU - Up to date?`t:`t$DSUUpdates"
     "Share permission / security`t:`t$SMBAudit"
     "Email Security`t`t:`t$EmailSecurity"
     "Remove rogue remote tools`t:`t$RogueRemoteAccess"
     "Backups - Working? Current?`t`t:`t$BackupsCurrent"
     "Backups - Encrypted per HIPAA stds?`t:`t$BackupsEncrypted"
     "Backups - Gen3 password?`t`t`t:`t$BackupsGen3"
     "Backups - unencrypted PHI on removable drives?`t:`t$BackupsUnencrypted"
     "Backups - SQL Backup working?`t:`t$BackupsSQL"
     "Domain users - Last Login`t`t`t:`t$ADLastLogin"
}
#Output-SecAudInfo
