############################################################################
#
#  Invoke-MMESecurityAudit.ps1
#
#  MME Security Audit Automation Script (draft)
#
#  Alex Datsko (alexd@mmeconsulting.com) 2021-06-03
#
#
#

####################################################
# Shared routines


# Get OS end of life status
. .\Get-OSInfo.ps1
Get-OSInfo

# Get Status of Firewall profiles
$FirewallProfileDisabled = 0
$FirewallProfiles = (Get-NetFirewallProfile)
$FirewallProfiles | % {
  if ($_.Enabled -eq 1) {
    Write-Host "Windows Firewall $($_.Name) profile is enabled" -Foregroundcolor Gray
  } else {
    Write-Host "Windows Firewall $($_.Name) profile is disabled!" -Foregroundcolor Yellow
    $FirewallProfileDisabled = 1
  }
}
if ($FirewallProfileDisabled) {
  write-Host "A Windows Firewall profile is disabled!" -ForegroundColor Red
} else {
  write-Host "All Windows Firewall profiles are enabled." -ForegroundColor Green
}

# Get Bitlocker status
$BitlockerVols = Get-BitLockerVolume
$BitlockerVols

# Get DRAC status / DRAC check

# Check if DRAC is working internally

$ipV4 = Test-Connection -ComputerName $env:COMPUTERNAME -Count 1  | Select -ExpandProperty IPV4Address | Select -ExpandProperty IPAddressToString
$ipfirst3 = $ipv4.split(".")[0]+"."+$ipv4.split(".")[1]+"."+$ipv4.split(".")[2]+"."
# ASSUMES a /24 subnet!!!  Also assumes DRAC is .42 !!! (Also, ends in a .)
$DRACIP = $ipfirst3+"42"
Write-Host "Testing if $DRACIP is responding to ping.." -ForegroundColor Gray
if (!(Test-NetConnection $DRACIP)) {
  $DRACIP = Read-Host "$DRACIP not responding.  What is the internal IP Address of the DRAC? "  
} else {
  Write-Host "$DRACIP responded to ping." -ForegroundColor Green
}

$Port2443 = (Test-NetConnection $DRACIP -port 2443).TcpTestSucceeded
$Port5902 = (Test-NetConnection $DRACIP -port 5902).TcpTestSucceeded
if ($Port2443) {
  Write-Host "DRAC $DRACIP Port 2443: $Port2443 .. Open" -ForegroundColor Green
} else {
  Write-Host "DRAC $DRACIP Port 2443: $Port2443 .. Closed!" -ForegroundColor Red
}
if ($Port5902) {
  Write-Host "DRAC $DRACIP Port 5902: $Port5902 .. Open" -ForegroundColor Green
} else {
  Write-Host "DRAC $DRACIP Port 5902: $Port5902 .. Closed!" -ForegroundColor Red
}

# Check if External DRAC port is open
. .\Check-PortExternal.ps1
Check-PortExternal -port 2443
Check-PortExternal -port 5902



# Get local user list
Write-Host "Local users list: " -ForegroundColor Gray
$LocalUsers = Get-LocalUser | Select Name,Enabled,FullName
$LocalUsers | ft

# Get localgroup administrators list
Write-Host "Administrators group list: " -ForegroundColor Gray
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
Write-Host "Setting updated security policies ..." -ForegroundColor Green
. .\Set-Secpol.bat

# Print Output
Function Output-SecAudInfo {
    Write-Host "OUTPUT:`r`n"
    Write-Host "OS End of Life? `t`t`t:`t$OSEndOfLife"
    Write-Host "DRAC - Equipped? Enterprise License? `t:`t$DRACEnterpriseLicense"
    Write-Host "DRAC - Enabled? `t`t`t:`t$DRACEnabled"
    Write-Host "DRAC - Working remotely?`t:`t$DRACWorkingRemotely"
    Write-Host "DRAC - User check? `t`t:`t$DRACUsers"
    Write-Host "OS Up to date? Review+Rec`t:`t$WindowsUpdates"
    Write-Host "Antivirus - Enabled?  `t:`t$AntivirusEnabled"
    Write-Host "Local user check / admins group check"
    Write-Host "Antivirus - Enabled?  Review+Rec`t:`t$AVEnabled"
    Write-Host "Antivirus - Up to date?`t:`t$AVUpdates"
    Write-Host "Antivirus - Weekly full scan?  When? `t:`t$AVFullScan"
    Write-Host "No items in quarantine? `t:`t$AVQuarantine"
    Write-Host "DSU - Up to date?`t:`t$DSUUpdates"
    Write-Host "Share permission / security`t:`t$SMBAudit"
    Write-Host "Email Security`t`t:`t$EmailSecurity"
    Write-Host "Remove rogue remote tools`t:`t$RogueRemoteAccess"
    Write-Host "Backups - Working? Current?`t`t:`t$BackupsCurrent"
    Write-Host "Backups - Encrypted per HIPAA stds?`t:`t$BackupsEncrypted"
    Write-Host "Backups - Gen3 password?`t`t`t:`t$BackupsGen3"
    Write-Host "Backups - unencrypted PHI on removable drives?`t:`t$BackupsUnencrypted"
    Write-Host "Backups - SQL Backup working?`t:`t$BackupsSQL"
    Write-Host "Domain users - Last Login`t`t`t:`t$ADLastLogin"
}
#Output-SecAudInfo
