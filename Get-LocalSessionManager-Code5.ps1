# -After 3/10/2011 -Before 3/11/2012

$Events = Get-WinEvent -logname "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where {($_.Id  -eq "40") -or ($_.Id -eq "25")}
$Results = Foreach ($Event in $Events) {
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
#    write-host "Found reconnection: $User Session: $SessionID Source IP: $SourceIP"
  }
  if ($Event.Message -like "*reason code 5*")  {
    $Element = $MsgElement -split "Session "
    $SessionNo = $Element[1] -split " has" 
    $time = $Event.TimeCreated
    $Result = "$time - Session ID $SessionID - taken over by $User - Source IP: $SourceIP"
    write-host "Found disconnection via code 5 - $Result "
    $User = ""
    $SessionID= ""
    $SourceIP = ""
  }
} 

#| Export-Csv C:\temp\RDS.csv -NoType