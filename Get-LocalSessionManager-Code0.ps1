# -After 3/01/2021 -Before 3/11/2021
$AfterDate = "03-01-21"
$BeforeDate = "03-11-21"

$debug=0

$Events = Get-WinEvent -logname "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where {($_.Id  -eq "40") -or ($_.Id -eq "25") -or ($_.Id -eq "24")} 
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
        write-host "Found disconnection via code 0 - $Result "
        $User = ""
        $SessionID= ""
        $SourceIP = ""
      }
    }
  }
} 

#| Export-Csv C:\temp\RDS.csv -NoType