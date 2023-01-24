[CmdletBinding()]
param ()

$banner="
############################################################
# Find-SecurityEvents.ps1
# v 0.02 - Alex Datsko 1-18-23
# Finds relevant security events and logs to a full (and quick) text file
# This is to be run on the Domain Controller and/or Termserver
#
# NOTE: Running this more than once, will compound the auth_events* files, since it only appends
#"
# Changelog: 
#  v0.02 - added Windows firewall disable event 4950

$DaysToSearch = 1                                           # How many days to go back
$OutputFolder = "C:\Temp"                                   # Folder where output is stored
$AuthEventsFileQuick = "$($OutputFolder)\$($env:computername)-auth_events_quick.txt"   # File name of all events found (quick oneline format)
$AuthEventsFile = "$($OutputFolder)\$($env:computername)-auth_events.txt"              # File name of all events found (detailed)
$date = Get-Date -format "yyyy-MM-dd"                       # Date variable
$debug=0                                                    # Debug variable (Set to 1 to look at each record found individually)

Write-Output "`n`n"
Write-Output $banner
Write-Output "# Date: $date"
Write-Output "# Hostname: $env:computername"
Write-Output "# File Output (quick): $AuthEventsFileQuick"
Write-Output "# File Output (full): $AuthEventsFile"
Write-Output "#`n"

# Determine what logs and event IDs to note
$Events=@()
if (Get-WmiObject -Namespace "root\CIMV2\TerminalServices" -Class "Win32_TerminalServiceSetting" | select -ExpandProperty TerminalServerMode) {
  Write-Host "[.] This computer is a terminal server."
  $IIDs = (21,22,23,24,25,39,40,98,131,140,226,301,1024,1025,1026,1027,1028,1029,1102,1103,1105,1143,1149,1158,1401,1403,4624,4625,4634,4647,4648,4656,4658,4663,4688,4689,4778,4779,5058,5059,5061,5156,5158,9009)
  $Lognames = ('Security','Microsoft-Windows-TerminalServices-RDPClient/Operational','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational','Microsoft-Windows-TerminalServices-RDPClient/Operational','Microsoft-Windows-TerminalServices-Gateway/Operational')
} else {
  if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") { 
    Write-Host "[.] This computer is a domain controller."
    $IIDs = (529,530,531,532,533,534,535,536,537,539,657,4625,4648,4740,4771,4772,4773,12294,4950)
    $Lognames = ('Security')
  } else {
    Write-Host "[!] This computer is not a domain controller or terminal server, output may be limited."
    $IIDs = (529,530,531,532,533,534,535,536,537,539,657,4625,4648,4740,4771,4772,4773,12294,4950)
    $Lognames = ('Security')
  }
} 

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
          if ($line -like "*Account Name:*") {
            $newline = $line.replace('Account Name:','').replace(' ','').replace("`t","").replace("`r","").replace("`n","")
            if (($newline[0] -ne '-') -and ($newline.length -gt 1) -and ($newline -ne 'Network-')) {
              $acct += " AcctName: $newline"
            }
          }
          if ($line -like "*Network Address:*") {
            $newline = $line.replace('Network Address:','').replace(' ','').replace("`t","").replace("`r","").replace("`n","")
            if (($newline[0] -ne '-') -and ($newline.length -gt 1) -and ($newline -ne 'Source-') -and ($newline -ne 'Source-')) {
              $acct += " NetworkAddr: $newline"
            }
          }
          if ($line -like "*Workstation Name:*") {
            $newline = $line.replace('Workstation Name:','').replace(' ','').replace("`t","").replace("`r","").replace("`n","")
            if (($newline[0] -ne '-') -and ($newline.length -gt 1)) {
              $acct += " WSName: $newline"
            }
          }
          if ($line -like "*Process Name:*") {
            $newline = $line.replace('Process Name:','').replace(' ','').replace("`t","").replace("`r","").replace("`n","")
            if (($newline[0] -ne '-') -and ($newline.length -gt 1)) {
              $acct += " Process: $newline"
            }
          }
          if ($line -like "User:*") {
            $newline = $line.replace('User:','').replace(' ','').replace("`t","").replace("`r","").replace("`n","")
            if (($newline[0] -ne '-') -and ($newline.length -gt 1)) {
              $acct += " User: $newline"
            }
          }
        }
        $TimeCreated = "$($Event.Timecreated)"
        $msg = "$($Event.ID) - $($TimeCreated) - $acct"
        $msg | tee -Append $AuthEventsFileQuick
        $event | fl  | Out-File -Append $AuthEventsFile
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