[cmdletbinding()]  # For verbose, debug etc
param()

#Start-Transcript

$note="
############################
# Get-ADFailedLogins.ps1
# Alex Datsko (alex.datsko@mmeconsulting.com)  6-21-23 - updated 7/24/23
# Gets a list of failed login events for daily logs, to be compiled for security audits
#"

$outputfolder = "d:\data\secaud\Results"
$eventlist = @(4740,4771,4625,529)  # Event ID's to check for
#$eventlist = @(4770,4771,4776,4625,529)  # Event ID's to check for
$date = Get-Date -format "yyyy-MM-dd"
$year = Get-Date -format "yyyy"
$startTime = (Get-Date).AddDays(-1)  # Check 1 days worth of results
$filename = "$($outputfolder)\$($year)-ADFailedLogons.csv"  # Yearly compounded CSV
$logfile = "$($outputfolder)\$($year)-ADFailedLogons.log"  # Yearly log

$note
Write-Verbose "[!] Running in verbose mode."

<#
Checking for:
4740: Account lockout
4771: Kerberos pre-authentication failed. This event is generated when a Kerberos ticket request (TGT) fails because the number of failed password attempts exceeds the threshold, among other reasons.
4625: An account failed to log on. This event is generated if a logon request fails. This is most commonly a result of a bad username or authentication information.
529: This event signifies a failed logon attempt. It is generated when an unauthorized or incorrect login attempt is made to a computer or network resource. The event provides information about the user account, domain, logon type, and the source of the logon request. Event ID 529 is commonly associated with potential security breaches or brute-force attacks.

(No longer) checking for:
#4770: This event indicates that a user account has been reset. It is logged when a user resets their own password or when an administrator resets the password for a user account. The event record includes details such as the account name, domain, and the user who performed the reset.
#4776: The domain controller attempted to validate the credentials for an account. This event occurs when a network logon attempt fails for a specific user.
#>

function Write-EventArray {
  param ([xml[]]$xmlitems,
         [string]$eventid)

  if ($xmlitems) {
    if (!(Test-Path $filename)) {
      Write-Host "Writing to new file $filename .. "
      "SEP=," | Out-File $filename 
      "datetime,eventid,computer,subjectusername,tarusername,logontype,ip" | Out-File $filename -Append
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
      Write-Verbose "$datetime,$eventid_found,$computer,$subjectusername,$tarusername,$logontype,$ip"
      """$datetime"",""$eventid_found"",""$computer"",""$subjectusername"",""$tarusername"",""$logontype"",""$ip""" | out-file $filename -Append
      $items+=1
    }
    "$date - Reported on $items items for $eventid" | Tee -Append $logfile
  } else {
    "$date - Nothing to report for $eventid !" | Tee -Append $logfile
  }
}

##### MAIN

if (!(Test-Path $outputfolder)) {
  New-Item -ItemType Directory $OutputFolder -Force -ErrorAction SilentlyContinue
}

$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
  if (Test-NetConnection $DC) {
    foreach ($eventid in $eventlist) {
      $xmlitems = @()
      $items = ""
      Write-Host "[.] Checking for $eventid events.." 
      $null = ($items = Get-WinEvent -ComputerName $DC -FilterHashtable @{logname="Security"; id=$([int]$eventid); StartTime=$startTime} -ErrorAction SilentlyContinue) | Out-Null  
      if ($items) { 
        foreach ($item in $items) {
          $xmlitems += [xml]$item.ToXml()
        }
        Write-EventArray -XMLItems $xmlitems -EventID $eventid 
      } else { 
        Write-Host "[!] No $eventid items found!" 
        "$date - No $eventid items found." | Tee -Append $logfile
      } 
    }
  }
}
Write-Host "[!] Done!"
#Stop-Transcript
