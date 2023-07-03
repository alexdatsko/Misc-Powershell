[cmdletbinding()]  # For verbose, debug etc
param(
  $Days=1
)

#Start-Transcript

$note="
############################
# Get-ADFailedLogins.ps1
# Alex Datsko (alex.datsko@mmeconsulting.com) v0.2 7-3-23
# Gets a list of failed login events for daily logs, to be compiled for security audits
#"

$DomainWide = $false   # Set this to true to check ALL DC's in the domain!  Firewall rule must be in place to allow this.
if (Test-Path "D:\") {
  $outputfolder = "d:\data\secaud\Results"
} else {
  $outputfolder = "c:\data\secaud\Results"
}
$eventlist = @(4771,4625,529)  # Event ID's to check for
#$eventlist = @(4770,4771,4776,4625,529)  # Event ID's to check for
$date = Get-Date -format "yyyy-MM-dd"
$year = Get-Date -format "yyyy"
$startTime = (Get-Date).AddDays(-$Days)  # Check 1 days worth of results
$filename = "$($outputfolder)\$($env:computername)-$($year)-ADFailedLogons.csv"  # Yearly compounded CSV
$logfile = "$($outputfolder)\$($env:computername)-$($year)-ADFailedLogons.log"  # Yearly log

$note
Write-Verbose "[!] Running in verbose mode."

<#
Checking for:
4771: Kerberos pre-authentication failed. This event is generated when a Kerberos ticket request (TGT) fails because the number of failed password attempts exceeds the threshold, among other reasons.
4625: An account failed to log on. This event is generated if a logon request fails. This is most commonly a result of a bad username or authentication information.
529: This event signifies a failed logon attempt. It is generated when an unauthorized or incorrect login attempt is made to a computer or network resource. The event provides information about the user account, domain, logon type, and the source of the logon request. Event ID 529 is commonly associated with potential security breaches or brute-force attacks.

(No longer) checking for:
#4770: This event indicates that a user account has been reset. It is logged when a user resets their own password or when an administrator resets the password for a user account. The event record includes details such as the account name, domain, and the user who performed the reset.
#4776: The domain controller attempted to validate the credentials for an account. This event occurs when a network logon attempt fails for a specific user.


Also, this may be required on all DCs for comms:

New-NetFirewallRule -DisplayName "Allow Get-WinEvent RPC" `
    -Direction Inbound `
    -LocalPort 135 `
    -Protocol TCP `
    -Action Allow `
    -Profile Domain

#>

function Write-EventArray {
  param ([xml[]]$xmlitems,
         [string]$eventid)

  if ($xmlitems) {
    if (!(Test-Path $filename)) {
      Write-Host "Writing to new file $filename .. "
      "SEP=," | Out-File $filename 
      "server,datetime,eventid,computer,subjectusername,tarusername,logontype,ip" | Out-File $filename -Append
    } else {
      Write-Host "Writing to existing file $filename .. "
    }
    foreach ($xmlitem in $xmlitems) { 
      $eventid_found = $xmlitem.Event.System.EventID
      $computer = $xmlitem.Event.System.Computer
      $datetime = [DateTime]::Parse($xmlitem.Event.System.TimeCreated.SystemTime).ToLocalTime()
      $subjectusername = ($xmlitem.Event.EventData.Data | where-object {$_.Name -eq "SubjectUserName"}).'#text'
      $tarusername = ($xmlitem.Event.EventData.Data | where-object {$_.Name -eq "TargetUserName"}).'#text'
      $logontype = ($xmlitem.Event.EventData.Data | where-object {$_.Name -eq "LogonType"}).'#text'
      $ip = ($xmlitem.Event.EventData.Data | where-object {$_.Name -eq "IpAddress"}).'#text'     
      Write-Verbose $($xmlitem.Event.EventData.Data | Out-String)
      Write-Verbose "$DC,$datetime,$eventid_found,$computer,$subjectusername,$tarusername,$logontype,$ip"
      """$DC"",""$datetime"",""$eventid_found"",""$computer"",""$subjectusername"",""$tarusername"",""$logontype"",""$ip""" | out-file $filename -Append
      $items+=1
    }
    "$date - $DC - Reported on $items items for $eventid" | Tee -Append $logfile
  } else {
    "$date - $DC - Nothing to report for $eventid !" | Tee -Append $logfile
  }
}

##### MAIN

if (!(Test-Path $outputfolder)) {
  New-Item -ItemType Directory $OutputFolder -Force -ErrorAction SilentlyContinue
}
"$date - Checking Events.." | Tee -Append $logfile

$DCs=@()
if ($true -eq $DomainWide) {
  $DCList = Get-ADDomainController -Filter *
  foreach ($DC in $DCList) {
    if (Test-NetConnection $DC) {
      $DCs += $DC
    } else {
      "$date - Found $DC could not be contacted! Not adding" | Tee -Append $logfile
    }
  }
} else {
  $DCs = @("$env:computername")
}
foreach ($DC in $DCs) {
  foreach ($eventid in $eventlist) {
    $xmlitems = @()
    $items = ""
    Write-Host "[.] Checking $DC for $eventid events.." 
    try {
      $null = ($items = Get-WinEvent -ComputerName $DC -FilterHashtable @{logname="Security"; id=$([int]$eventid); StartTime=$startTime} -ErrorAction SilentlyContinue) | Out-Null  
    } catch {
      Write-Verbose "$($_ | Format-List * -Force)"
      "$date - $DC - Error: $_.Exception.Message" | Tee -Append $logfile
    }
    if ($items) { 
      foreach ($item in $items) {
        $xmlitems += [xml]$item.ToXml()
      }
      Write-EventArray -XMLItems $xmlitems -EventID $eventid -DC $DC.Name
    } else { 
      "$date - $DC - No $eventid items found." | Tee -Append $logfile
    } 
  }
}
Write-Host "[!] Done!"
#Stop-Transcript
