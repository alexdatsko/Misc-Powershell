#Start-Transcript  # Security risk to log these!!!

# Get parameters from commandline

param (
  [Parameter()]
  [string] $ServerPasswordRoll, 
  [Parameter()]
  [string] $UserPasswordRoll, 
  [Parameter()]
  [string] $ServerLocalPasswordRoll, 
  [Parameter()]
  [string] $ServerDomainPasswordRoll, 
  [Parameter()]
  [string] $DracPasswordRoll, 
  [Parameter()]
  [string] $CheckLogsOnly
  )


Write-Output "`r`n`r`n`r`n#######################################################"
Write-Output "#"
Write-Output "#   Invoke-PasswordRoll.ps1"
Write-Output "#   Alex Datsko @ . (alex.datsko@mmeconsulting.com)"
Write-Output "#"
Write-Output "# This script will perform a server local/domain administrator/serviceadmin/mme and/or domain user password and/or DRAC password roll."
Write-Output "# Some tests will be run before and after to see if any authentication or lockout events can be found."
Write-Output "#"
Write-Output "# v0.1 - 09-03-21 - Converted the batch script I use to powershell.  Not complete.."
Write-Output "# v0.2 - 04-28-22 - Got this actually working and usable, added DRAC passwords etc"
Write-Output "# v0.3 - 05-03-22 - Fixed asking for DRAC MME password if not rolling anything else, added some parameters"
Write-Output "# v0.4 - 05-04-22 - Refactored how parameters will work - add param for each password, and determine if we are rolling that subset"
Write-Output "# v0.5 - 05-13-22 - Lots of changes, logging more information, fixing parameters, refactoring, etc"
Write-Output "# v0.6 - 09-02-22 - Fixing parameters, fixed some variable names, control flow, little more on task/service report"
Write-Output "# v0.7 - 02-05-24 - Testing, fixes of DRAC roll, etc"

Write-Output "#`r`n"

### NOT FINISHED WITH USER PASSWORD ROLL - COPY OU PICKER FROM Install-SecurityGPO.ps1


############################## ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

$todaysdate = Get-Date -format "MM/dd/yyyy"
$todaystime = Get-Date -format "hh:mm"


function Read-NoYesTrueFalse {
  param(
    [string] $varText
  )
  if ($varText.Length -lt 1) {
    Write-Error "[!] Username Length omitted - programming error! Exiting"
    Exit
  }
  $notDoneReadYesNo = $true
  $returnVar = $false

  while ($notDoneReadYesNo) {
    $input = Read-Host $varText
    if (($input.ToUpper() -eq "N") -or ($input -eq "")) { 
      $returnVar = $false
      $notDoneReadYesNo = $false
    } else { 
      $returnVar = $true
      $notDoneReadYesNo = $false
    }
  }
  return $returnVar
}


function Read-YesNoTrueFalse {
  param(
    [string] $varText
  )
  if ($varText.Length -lt 1) {
    Write-Error "[!] Username Length omitted - programming error! Exiting"
    Exit
  }
  $notDoneReadYesNo = $true
  $returnVar = $false

  while ($notDoneReadYesNo) {
    $input = Read-Host $varText
    if (($input.ToUpper() -eq "Y") -or ($input -eq "")) { 
      $returnVar = $true
      $notDoneReadYesNo = $false
    } else { 
      $returnVar = $false
      $notDoneReadYesNo = $false
    }
  }
  return $returnVar
}


function Get-Password {
  param(
    [string] $usernameText,
    [int] $usernameLength,
    [string] $defaultpw
  )

  $usernameVar = ""
  if ($usernameLength -lt 1) {
    Write-Error "[!] Username Length omitted - programming error! Exiting"
    Exit
  }
  while ($usernameVar.Length -lt $usernameLength) {
    $usernameVar = Read-Host "  [?] $usernameText password to use? "
    if ($usernameVar.Length -lt $usernameLength) {
      
      if ($usernameVar = "") { 
        #First check if there is a valid default, if CR/LF was used to pick the default
        if ($defaultpw.Length -gt ($usernameLength-1)) {
          return $defaultpw
        } else {
          Write-Host "[X] Default password $defaultpw Too short, needs to be $usernameLength chars!" -ForegroundColor Red
        }
      }
      Write-Host "[X] $usernameLength Password $usernameVar Too short!" -ForegroundColor Red
    }
  }
  return $usernameVar
}

function Get-SecEvents {
  param(
    [string] $SecurityEvent,
    [string] $LogMessage
  )
  $args = @{}
  #$args.Add("StartTime", ((Get-Date).AddHours(-24)))
  $args.Add("StartTime", (Get-Date))
  $args.Add("EndTime", (Get-Date))   # not needed
  $args.Add("LogName", "Security")
  $args.Add("ID", $SecurityEvent)
  Write-Host "[!] Checking for $SecurityEvent $LogMessage .."
  try {
    Get-WinEvent -FilterHashTable $args 
  } catch {
    Write-Host "[!] Either no events exist, or something went wrong! .."
    # Not catching the errors right now, oh well..
  }
}


function CheckTasks { 
    # TODO : Show all Scheduled tasks with Administrator, with MME, etc
    # TODO : ROLL all Scheduled task passwords for each user appropriately!
    Write-Host "[.] Creating preliminary task report.."
    schtasks.exe /query /s localhost  /V /FO CSV | ConvertFrom-Csv | Where { (($_."Run As User" -like "*Administrator") -or ($_."Run As User" -like "*MME*") -or ($_."Run As User" -like "*ServiceAdmin*")) } | select-object TaskName, "Run As User"

    Write-Output "[!] Opening Task scheduler, please correct any Administrator/ServiceAdmin passwords:" 
    taskschd.msc
}

function CheckServices {
    # TODO : Show all services with Administrator, with MME, etc
    #Get-Service | Where { 
    # TODO : ROLL all service passwords for each user appropriately and restart services!
    Write-Host "[.] Creating preliminary service report.."
    Get-WmiObject win32_Service | where {$_.StartName -like '*Administrator' -or `
                                         $_.StartName -like '*MME' -or `
                                         $_.StartName -like '*ServiceAdmin' }  | fl Name,StartName,DisplayName
    Write-Output "[!] Opening Services, please correct any Administrator/ServiceAdmin/MME passwords:" 
    services.msc
}

function Pick-OU {
  param(
     $OUList 
  )

  $done=0
  while (!($done)) {
    try { # Have user pick from a list of OU's
      if (!($OUList)) { 
        Write-Verbose "[x] No OU list supplied, Choosing from all OUs.." 
        $OUList = (Get-ADOrganizationalUnit -filter *)    
      }
    } catch { 
      Write-Error "`r`n(Get-ADOrganizationalUnit -filter *) error listing domains!`r`n"
      Exit
    } 

    Write-Verbose "(List of OUs)" 
    $i = 0
    foreach ($OU in $OUList) {
      Write-Host "$i : [$($OU.Name)] - $($OU.DistinguishedName)"
      $i += 1
    }
    $maxopt = $i
    Write-Host "$maxopt : DO NOT IMPORT THIS GPO"
    $input = Read-Host "Please pick the OU to apply to [$maxopt] "
    $choice = [int]$input
    if ($input -eq "") { $choice = [int]$i }  #If no input, do nothing.
    #Write-Host "Input : $input `r`nChoice : $choice" 
    if (!($choice -eq $maxopt) -and !($choice -eq "")) {  # make sure we have picked something, ignore if its DO NOT IMPORT or somehow blank string
      $DomainOUName = $OUList[$choice].Name
      $DomainString = $OUList[$choice].DistinguishedName
      #Write-Host "You have picked: $DomainOUName - $DomainString"
    } else {
      Write-Host "[!] WILL NOT IMPORT THIS POLICY."
      Return
    }
    
    # Validate choice:
    $choices = @()
    for ($j=0 ; $j -le $maxopt ; $j++) { $choices += [int]$j }  #Ugly.. Further validation that choice is an actual choice..
    #Write-Host "Choice : $choice `r`nChoices : $choices`r`nChoices contains choice : $($choices.Contains($choice))"
    if ($choices.Contains($choice)) {
      Write-Verbose "(Good choice made)" 
      $Done=1
    } else {
      Write-Host "[X] Error in selection." 
      # Instead, have them type the LDAP string??? 
      # Or, just pick from whats there.. duh
      #$IncorrectOU = 0
      #while ($IncorrectOU) {
      #  $DomainString = Read-Host "Please type domain LDAP path to use instead of $($DomainString)?  "
      #  if ([adsi]::Exists("LDAP://$($DomainString)")) { $IncorrectOU = 1 } else { Write-Host "LDAP://$($DomainString) not found!! Try again.." }
      #}
    }
  }   
  Write-Verbose "(Returning $DomainString)" 
  return $DomainString
}

function Check-PasswordRollErrors {
  param (
    [string] $Resp1,
    [string] $Resp2,
    [string] $Resp3
  )
  $ErrorReturn = @()

  if (($resp1 -eq "The command completed successfully.") -and ($resp2 -eq "The command completed successfully.") -and `
      ($resp3 -eq "The command completed successfully.")) {
      return $false
  } else { 
     if ($resp1 -ne "The command completed successfully.") { $ErrorReturn += $resp1 }
     if ($resp2 -ne "The command completed successfully.") { $ErrorReturn += $resp2 } 
     if ($resp3 -ne "The command completed successfully.") { $ErrorReturn += $resp3 }
     return $ErrorReturn
  }
}

Function UserPasswordRoll {
    Write-Host "`r`n------------------- Domain User Password Roll -------------------`r`n" 
    # Clear-Host
    $DomainString=(Get-ADDomain).DistinguishedName
    $UserOUs = Get-ADOrganizationalUnit | where {$_.DisplayName -like "*user*"}
    $OUString = Pick-OU $UserOUs
    
    Write-Debug 'CMD: cmd.exe /c "dsquery user -limit 0 "'+$OUString+'" >users.txt"'
    $resp=cmd.exe /c "dsquery user -limit 0 ""$OUString"" >users.txt" 
    Write-Host "`r`nUsers found: "
    $resp
    start "notepad.exe" "users.txt"
    Write-Output "`r`n[!] Save your changes in notepad.  Delete any users from the list who you do not want their password changed."
    Read-Host "[?] Paused, please press enter."
    Write-Output ""
    Write-Output "[!] After next prompt, the users passwords will be changed to '$($UserPassword)' .. Ctrl-C to exit if you have made any mistakes!! `r`n"
    Read-Host "[?] Paused, please press enter."
    Write-Output "`r`n[.] Changing passwords ...`r`n"
    Write-Debug "CMD: type users.txt | dsmod user -pwd $UserPassword"
    $resp = cmd /c 'type users.txt | dsmod user -pwd $UserPassword'
    $resp 
    # TODO : Validate output, check for errors, etc
    Write-Output "[o] Done!"
    Read-Host "[?] Paused, please press enter."
}

function DracPasswordRoll {
  param (
    [string] $DRACAdmin,
    [string] $MME
  )
    $DRACAdminUser=$null
    $DRACManUser=$null
    $DRACMMEUser=$null
    $resp=(racadm getsysinfo)
    if ($null -eq $resp) {
      Write-Host "[!] Racadm command not found. Is this running on a HVH or Dell server?"
      exit
    }
    Write-Host "`r`n------------------- DRAC Password Roll -------------------`r`n" 
    Write-Host "[.] Rolling DRAC Passwords for either Administrator, DRACMan, or MME users.."
    Write-Verbose "[.] Using password for Administrator/DRACMan (whichever exists) : $($DRACAdmin)"
    Write-Verbose "[.] Using password for MME User (if it exists) : $($MME)"
    for ($i=0; $i -lt 6; $i++) {
      $dracuser=(racadm get iDRAC.Users.$i.UserName | select-string UserName)
      if ($dracuser -like "*Administrator*") {    $DRACAdminUser=$i ; Write-Host "[!] Found DRAC Administrator user, id=$i" }
      if ($dracuser -like "*DRACMan*") {    $DRACManUser=$i ; Write-Host "[!] Found DRAC DRACMan user, id=$i" }
      if ($dracuser -like "*MME*") {   $DRACMMEUser=$i  ; Write-Host "[!] Found DRAC MME user, id=$i" }
    }
    if ($DRACAdminUser) { Write-Host "[!] Running: racadm set iDRAC.Users.$($DRACAdminUser).Password $DRACAdmin" ; racadm set iDRAC.Users.$($DRACAdminUser).Password $DRACAdmin }
    if ($DRACManUser) { Write-Host "[!] Running: racadm set iDRAC.Users.$($DRACManUser).Password $DRACAdmin" ; racadm set iDRAC.Users.$($DRACManUser).Password $DRACAdmin }
    if ($DRACMMEUser) { Write-Host "[!] Running: racadm set iDRAC.Users.$($DRACMMEUser).Password $MME" ; racadm set iDRAC.Users.$($DRACMMEUser).Password $MME }
    Write-Host "[.] DRAC Password roll complete!"
    $DracAdmin=""
    $MME=""
}

function ServerLocalPasswordRoll {
  param (
    [string] $LocalAdministrator,
    [string] $MME
  )

    Write-Host "`r`n------------------- Server Local User Password Roll -------------------`r`n"
    
    Write-Host "[.] Changing local Administrator password to $LocalAdministrator"
    $resp1=cmd /c "net user Administrator $($LocalAdministrator) /y /expires:never"
    Write-Host "[.] Changing local MME password to $MME"
    $resp2=cmd /c "net user MME $($MME) /y  /fullname:", Inc." /comment:""MME''s Alternate Admin Login"" /expires:never"
    Write-Host "[.] Adding MME to Local Administrators group"
    $resp3=cmd /c 'net localgroup Administrators MME /add'
    
    $resp1
    $resp2
    $resp3
    $PwdRollErrors = Check-PasswordRollErrors $resp1 $resp2 $resp3
    if (!($PwdRollErrors)) {
      Write-Host "[!] Password roll successful." -ForegroundColor Green
    } else {
      Write-Host "[!] Password roll had ERRORS." -ForegroundColor Red
      $PwdRollErrors
    }

    Write-Host "[!] Additional configuration steps to standardize:"
    Write-Host "[.] Turn on remote desktop"
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    #Write-Host "[.] Allow RDP through firewall (Legacy)"
    #netsh firewall set service type = remotedesktop mode = enable
    Write-Host "[.] Allow RDP through firewall"
    netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
    #Write-Host "[.] Enable automatic Windows updates"
    #reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f

    # Clear passwords
    $LocalAdministrator=""
    $MME=""
    #Clear-Host
    return $true
}

function ServerDomainPasswordRoll {
  param (
    [string] $Administrator,
    [string] $ServiceAdmin,
    [string] $MME
  )
    Write-Host "`r`n------------------- Server Domain User Password Roll -------------------`r`n" 
    Write-Host "[.] Changing Domain Administrator password to $Administrator"
    $resp1=cmd /c "net user Administrator $($Administrator) /y /domain /expires:never"
    Write-Host "[.] Changing Domain ServiceAdmin password to $ServiceAdmin"
    $resp2=cmd /c "net user ServiceAdmin $($ServiceAdmin) /y /domain /expires:never /comment:""MME''s Service Admin Login"""
    Write-Host "[.] Changing Domain MME password to $MME"
    $resp3=cmd /c "net user MME $($MME) /y /domain /fullname:", Inc." /comment:""MME''s Alternate Admin Login"" /expires:never"
    
    $resp1
    $resp2
    $resp3
    return (Check-PasswordRollErrors $resp1 $resp2 $resp3)
}


function Get-SecEvents {
  param(
    [string] $SecurityEvent,
    [string] $LogMessage
  )
  $args = @{}
  #$args.Add("StartTime", ((Get-Date).AddHours(-24)))
  $args.Add("StartTime", (Get-Date))
  $args.Add("EndTime", (Get-Date))   # not needed
  $args.Add("LogName", "Security")
  $args.Add("ID", $SecurityEvent)
  Write-Host "[!] Checking for $SecurityEvent $LogMessage .."
  try {
    Get-WinEvent -FilterHashTable $args 
  } catch {
    Write-Host "[!] Either no events exist, or something went wrong! .."
    # Not catching the errors right now, oh well..
  }
}

function CheckSecurityLogs {
    write-host "`r`n`r`n`r`n`r`n[o] Checking security logs.."
    Get-SecEvents "4740" "Lockout Events:"
    Get-SecEvents "4776" "Logon failed Events:"
    Get-SecEvents "4771" "Logon failed Events:"
    Get-SecEvents "4768" "Logon failed Events:"
    Get-SecEvents "4625" "Kerberos failed logon Events:"
}

############################## Determine which password rolls we are doing - Domain, Local, Workstation, DRAC?


# This will ignore parameters....
<##>
$ServerPasswordRoll = $false
$UserPasswordRoll = $false
$ServerLocalPasswordRoll = $false
$ServerDomainPasswordRoll = $false
$DracPasswordRoll = $false
$CheckLogsOnly = $false


if ($args.Count -lt 1) {   # ask for passwords if none are given on commandline..
  if (Read-NoYesTrueFalse "[?] Check recent Logs Only? [y/N]") {  
    CheckSecurityLogs
    Exit
  }
  $ServerDomainPasswordRoll = Read-YesNoTrueFalse "[?] Roll Server DOMAIN Admin/ServiceAdmin/MME accounts? [Y/n]"
  $ServerLocalPasswordRoll = Read-YesNoTrueFalse "[?] Roll Server LOCAL Admin/ServiceAdmin/MME accounts? [Y/n]"
  $UserPasswordRoll = Read-YesNoTrueFalse "[?] Roll Workstation/Role/Domain user passwords? [Y/n]"
  $DracPasswordRoll = Read-YesNoTrueFalse "[?] Roll DRAC User passwords? [Y/n]"
} else {
  # Set parameters from commandline
}

Write-Host "`r`n ________________________________________________"
write-Host " | Rolling Server Domain Passwords: $ServerDomainPasswordRoll"
write-Host " | Rolling Server Local Passwords: $ServerLocalPasswordRoll"
write-Host " | Rolling User Passwords: $UserPasswordRoll"
write-Host " | Rolling DRAC Passwords: $DracPasswordRoll"
Write-Host " ````````````````````````````````````````````````````"

Write-Host "[!] Checking status of current SMB Connections and sessions (before)..."
Get-SmbConnection | ft
Get-SmbSession | ft


# Get all of the required passwords once we've verified we are changing them.
if ($ServerDomainPasswordRoll -eq $true) {   
  $Administrator = Get-Password "Domain Administrator" 12
  $ServiceAdmin = Get-Password "Domain ServiceAdmin User" 12
  $MME = Get-Password "Domain MME User" 12
} else {    # If a domain roll is in effect, we are not doing a local roll!
  $ServerDomainPasswordRoll = $false
  Write-Output "[!] Not rolling Domain admin/mme/serviceadmin!"
  
  # Maybe we roll local passwords?
  if ($ServerLocalPasswordRoll -eq $true) {
    $LocalAdministrator = = Get-Password "Local Administrator" 12
    #$LocalServiceAdmin = Read-Host "  [?] Local ServiceAdmin password to use? "   # We don't use this..
    $MME = Get-Password "MME Local User" 12
    # TODO : Validate passwords, reenter if blank/too short!!
  } else { 
    Write-Output "[!] Not rolling Local admin/mme/serviceadmin!"
  }
}
if ($UserPasswordRoll -eq $true) {
  $UserPassword = Get-Password "Role account/workstation user" 12
} else { 
  Write-Output "[!] Not rolling workstation users!"
}
if ($DracPasswordRoll -eq $true) {
  $DRACAdmin = Get-Password "DRAC Administrator" 12 
  Write-Output "[!] (Domain/local MME user will be rolled if the user exists as well!"
  if (($MME).Length -lt 1) { 
    $MME = Get-Password "MME DRAC user (enter for $MME)" 12 $MME
  }
} else { 
  $DracPasswordRoll = $false
  Write-Output "[!] Not rolling DRAC users!"
}

# Perform the password rolls if we are doing them
if ($DracPasswordRoll -eq $true) {
  DracPasswordRoll -DRACAdmin $DRACAdmin -MME $MME
}

if ($ServerDomainPasswordRoll -eq $true) {
  ServerDomainPasswordRoll -Administrator $Administrator -ServiceAdmin $ServiceAdmin -MME $MME
}

if ($ServerLocalPasswordRoll -eq $true) {
  ServerLocalPasswordRoll -Administrator $Administrator -MME $MME
}

if ($UserPasswordRoll -eq $true) {
  UserPasswordRoll
}

Write-Output "`r`n[.] All password rolls complete."

if (($ServerDomainPasswordRoll -eq $true) -or ($ServerLocalPasswordRoll -eq $true)) {
    CheckServices
    CheckTasks


#Write-Host Sleeping for 10 seconds before we check for SMB connections again...
#start-sleep -seconds 10
Write-Host "[o] Checking SMB Connections and Sessions (after).."
Get-SmbConnection | ft
Get-SmbSession | ft

Check-SecurityLogs
}

Write-Host "[!] Done!"
#Stop-Transcript
# SIG # Begin signature block
# MIIFdgYJKoZIhvcNAQcCoIIFZzCCBWMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUvrICwkLV7xxlmBBBaS/rI+gp
# SCqgggMOMIIDCjCCAfKgAwIBAgIQVDcKwidS441PC0MxPmn5ZDANBgkqhkiG9w0B
# AQUFADAdMRswGQYDVQQDDBJMb2NhbCBDb2RlIFNpZ25pbmcwHhcNMjQwMjA2MTU0
# NDQzWhcNMjUwMjA2MTYwNDQzWjAdMRswGQYDVQQDDBJMb2NhbCBDb2RlIFNpZ25p
# bmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7HYEhBl2mlbQW2M3I
# 1F7zmonpakf+yhP3tB9ZdR3M1rPJvezR6NgA5dY12VdttrTcnUX/CDs/C2THzK/v
# R9lBk/DnvzWnDVcSNMnA8s5HUzK6qJS8tgt0JjJXx12PrUB7yJgdFi4e2sGWNLiR
# zZiWuYDvSY0vvtQmlNzhdX2rWZ6Di6Fw/f8fCTqQlrO7WKI7+KlGbJLqKr1/aJmN
# uoWagHqZK9fjNDlXZjKThPklUDs1Fb9Y69q1gc2sqUOCRZDp7dg9QqF0UQAiWuaG
# yAa5kWKeCseOUA4pN2aypTZ8teRgSr3H9CjzN9KAD5Om/yBWkOc4o//uXz6DmHKX
# xSDtAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcD
# AzAdBgNVHQ4EFgQUA9OZgpZhhcSrPb2ICPNBwmk0NswwDQYJKoZIhvcNAQEFBQAD
# ggEBALNnrO3TZZSKSfMbTQAuzpnAuB7T6wImLMjf0klX0JKy3JK38yJTCvBU9KHF
# 5/QR0CnbJMbO2EcV/VeqQjOg81BJi315PT4V6f6iN8bCJ/VCB58vCu8j6mOAgre3
# nNFeYrpd1wdLll1K4Hbrl+jeHXoP+x5nuQ26FwlMYQPzHfSdHAfKPEe+JIGoE7r7
# 5pDJCYlw/0xICms501WBxx10NGCbNZf1v03y99R/yhwiXMxnOJWKRQ3ohB/bGncV
# UGiUQHIFDL4Dm9Bnr8DAYajtrrpQRAXcH7SV0VF7zZ04X2ptuakEMY6ZE2s2xi2S
# HA0riGPO7Vefa+34+tIa7JBL3tQxggHSMIIBzgIBATAxMB0xGzAZBgNVBAMMEkxv
# Y2FsIENvZGUgU2lnbmluZwIQVDcKwidS441PC0MxPmn5ZDAJBgUrDgMCGgUAoHgw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQx
# FgQUVY2USRYTRFYozCTlrgsxzLc+prgwDQYJKoZIhvcNAQEBBQAEggEAoSe9DyTi
# BssqGRDFpyQM74rlAkWYMHL2E7VSh+b2RqjfKqxz0ujCKUcexrNI7uetXR4fkvuq
# OdESFe5W5B/jUrRby855K0/hjbdOGUZm1VOVO4eldtih5OyHr2RBj6ky58rxI8Jo
# FPu9XjaAq2UHp+NwQalDdh5Rqh7ST+Dq7ytQWhGEZ/w+g2Zp8dQtipJpzLo2N2wF
# +de3BzMozfXgVLldNCyBSH8wpw+egIMOBm4vVcTCyPNNm437MEacxgrYbgrOTm6y
# o/Ad5AO2yvxBgDT//Z4donMHQP0eOvTbU2DWhoe6THlNNNGbq/XxeGaCqBvFq91G
# vXfzfiibsS9U+w==
# SIG # End signature block
