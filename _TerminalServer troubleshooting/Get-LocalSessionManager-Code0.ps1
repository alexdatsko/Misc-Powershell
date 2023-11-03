
##################################################################
# Get-LocalSessionManager-Code0.ps1
# Alex Datsko @ MME Consulting Inc.
# This script will look through the event log and show all Code 0's (disconnections)
# Fixed up 10/23/23, something was very wrong with this..

$Days = 2      # (Days worth of events to view)
$StartDate = (Get-Date).AddDays(-$Days)
$EndDate = Get-Date

$logfile = "c:\temp\Termserver-Code0.txt"
$debug = 0

$Events = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" |
    Where-Object {
        ($_.Id -eq 40 -or $_.Id -eq 25 -or $_.Id -eq 24) -and
        ($_.TimeCreated -ge $StartDate -and $_.TimeCreated -le $EndDate)
    } |
    Sort-Object TimeCreated -Descending

$eventnum = ($events).Count
Write-Host "$eventnum LocalSessionManager events [24,25,40] found in date range $StartDate - $EndDate"
Write-Host "Results:"
$Results = Foreach ($Event in $Events) {
  $Result = "" | Select Message,User,TimeCreated
  $Result.TimeCreated = $Event.TimeCreated
  if ($Event.Message -like "*has been disconnected:*")  {
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
    if ($debug) { write-host "`n`nDEBUG: Found disconnection: $User `tSession: $SessionID `tSource IP: $SourceIP" }
  }
  if ($Event.Message -like "*reason code 0*")  {
    $SessionNo = "-"
    Foreach ($MsgElement in ($Event.Message -split "`n")) {
      $Element = $MsgElement -split "Session "
      $SessionNo = ($Element[1] -split " has")[0] -replace "`r", ""
      if ($debug) { 
        write-host "  DEBUG: $MsgElement"
        write-host "  DEBUG: Code 0 found for SessionNo '$SessionNo'"
      }
      if ($SessionID -eq $SessionNo) {
        $time = $Event.TimeCreated
        $Result = "$time - Session ID $SessionID - $User - Source IP: $SourceIP"
        "Found disconnection via code 0 - $Result " | tee $logfile -append
        $User = ""
        $SessionID= ""
        $SourceIP = ""
      }
    }
  }
} 
$Results
$null = Read-Host "[Press enter to continue]"
#| Export-Csv C:\temp\RDS.csv -NoType