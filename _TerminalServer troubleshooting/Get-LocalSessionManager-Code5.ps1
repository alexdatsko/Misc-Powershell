
##################################################################
# Get-LocalSessionMaanger-Code5.ps1
# Alex Datsko @ .
# This script will look through the event log and corellate Code 5's (session takeover) with Usernames and IPs that are taking the session over
# Updated - 9-14-22 to add DNS lookup of hostnames
# Worked on this a bit further 10/23/23, date range etc

$Days = 14      #  (Days worth of events to view)
$EndDate= Get-Date -Format "MM-dd-yyyy"
$ADate = (Get-Date).AddDays(-$Days)
$StartDate = Get-Date $ADate -Format "MM-dd-yyyy"
$logfile = "C:\Temp\Termserver-code5.txt"

$Events = Get-WinEvent -logname "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where {($_.Id  -eq "40") -or ($_.Id -eq "25")-and ($_.Timecreated -ge $startDate -and $_.Timecreated -lt $endDate)} | Sort-Object TimeCreated -Descending  
Foreach ($Event in $Events) {
  $Result = "" | Select Message,User,TimeCreated
  $Result.TimeCreated = $Event.TimeCreated
  if ($Event.Message -like "*reconnection succeeded:*")  {
    Foreach ($MsgElement in ($Event.Message -split "`n")) {
      $Element = ""
      if ($MsgElement -like "*User: *") {
        $Element = $MsgElement -split "User: "
        $User = $Element[1] -replace "`r", ""
      }
      if ($MsgElement -like "*Session ID: *") {
        $Element = $MsgElement -split "Session ID: "
        $SessionID= $Element[1] -replace "`r", ""
      }
      if ($MsgElement -like "*Source Network Address: *") {
        $Element = $MsgElement -split "Source Network Address: "
        $SourceIP = $Element[1] -replace "`r", ""
      }
    }
    "Found reconnection: $User Session: $SessionID Source IP: $SourceIP"
  }
  
  if ($Event.Message -like "*reason code 5*")  {
    $Element = $MsgElement -split "Session "
    $SessionNo = $Element[1] -split " has" 
    $time = $Event.TimeCreated
    $ComputerName = "<unknown>"
    try { 
      $DNSName = [System.Net.Dns]::GetHostByAddress($SourceIP).Hostname
      if ($DNSName) { $ComputerName = $DNSName }
    } catch {
      $ComputerName = "<unknown>"
    }
    $Result = "$time - Session ID $SessionID - taken over by $User - Source IP: $SourceIP - ComputerName: $ComputerName"
    "[.] Found disconnection via code 5 - $Result"| out-file $logfile -Append
    $User = ""
    $SessionID= ""
    $SourceIP = ""
  }
} 
$null = Read-Host "[Press enter to continue]"
