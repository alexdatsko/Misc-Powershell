[CmdletBinding()]
param ()

$banner="
############################################################
# Find-FirewallBlockedEvents.ps1
# v 0.02 - Alex Datsko 2-07-23
# Finds relevant Firewall blocked events and logs to a full (and quick) text file
# This is to be run on the Domain Controller and/or Termserver
#
# NOTE: Running this more than once, will compound the auth_events* files, since it only appends
#"
# Changelog: 
#  v0.02 - added Windows firewall disable event 4950

$DaysToSearch = 1                                           # How many days to go back
$OutputFolder = "C:\Temp"                                   # Folder where output is stored
$FirewallEventsFileQuick = "$($OutputFolder)\$($env:computername)-firewall_events_quick.txt"   # File name of all events found (quick oneline format)
$FirewallEventsFile = "$($OutputFolder)\$($env:computername)-firewall_events.txt"              # File name of all events found (detailed)
$date = Get-Date -format "yyyy-MM-dd"                       # Date variable
$debug=0                                                    # Debug variable (Set to 1 to look at each record found individually)

Write-Output "`n`n"
Write-Output $banner
Write-Output "# Date: $date"
Write-Output "# Hostname: $env:computername"
Write-Output "# File Output (quick): $FirewallEventsFileQuick"
Write-Output "# File Output (full): $FirewallEventsFile"
Write-Output "#`n"

# Determine what logs and event IDs to note
$Events=@()
$IIDs = (4147)
$Lognames = ('Security')
Write-Host "[!] Checking in $Lognames for Events: $IIDs"

# Parse all Event logs
Foreach ($Logname in $LogNames) {
  Write-Host "[.] Checking Logname : $Logname"
  Foreach ($ID in $IIDs) {
    Write-Verbose "[.] Checking for Event ID : $ID"
    $Filter = @{
      Logname = $Logname
      ID = $ID
      StartTime = ((Get-Date).AddDays(-$DaysToSearch))
      EndTime = (Get-Date)
    }
    $Events = Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue
    if($?) {   
      foreach ($event in $Events) {
        $acct = ""
        $newline = ""
        foreach ($line in (($Event.Message).split("`n"))) {
<#
          if ($line -like "*Destination Port*") {
            $newline = $line.replace('Destination Port','').replace(' ','').replace("`t","").replace("`r","").replace("`n","")
            if (($newline[0] -ne '-') -and ($newline.length -gt 1) -and ($newline -ne 'Network-')) {
              $acct += " DestPort: $newline"
            }
          }

          if ($line -like "*Network Address:*") {
            $newline = $line.replace('Network Address:','').replace(' ','').replace("`t","").replace("`r","").replace("`n","")
            if (($newline[0] -ne '-') -and ($newline.length -gt 1) -and ($newline -ne 'Source-') -and ($newline -ne 'Source-')) {
              $acct += " NetworkAddr: $newline"
            }
          }
#>
        }
        $TimeCreated = "$($Event.Timecreated)"
        $msg = "$($Event.ID) - $($TimeCreated) - $acct"
        $msg | tee -Append $FirewallEventsFileQuick
        $event | fl  | Out-File -Append $FirewallEventsFile
        if ($debug) {
          Write-Host "`nEvent:"
          $Event
          Write-Host "`nRAW variables: "
          "Event ID: $($Event.ID)"
          "Time Created: $TimeCreated"
          "Account/other info: $acct"
          Read-Host "[!] Done processing event - hit enter to continue"
        }
      }
    } else {
      Write-Verbose "[!] Error, couldn't run Get-WinEvent, or error searching with filter settings: Logname: $LogName Event: $ID "
    }

  }
}