$info = "
##################################################################
# Get-RDGatewayConnections.ps1
# Alex Datsko @ MME Consulting Inc.
# This script will look through the eventlog, and log recent RD Gateway connections, disconnections and reasons quickly into a file in c:\Temp
# v0.1 - 10/28/24 - Initial
"

$Days = 7      # (Days worth of events to view)
$StartDate = (Get-Date).AddDays(-$Days)
$EndDate = Get-Date

$logfile = "c:\Temp\Termserver-RDGatewayLog-$($Days)_Days.txt"
$CSVFile = "C:\temp\Termserver-RDGateway.csv"
$debug = 0

$info

if (!(Test-Path "C:\Temp")) {
  New-Item -ItemType Directory -Path "C:\Temp" -ErrorAction Continue
}

$Events = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-Gateway/Operational" |
    Where-Object {
        ($_.Id -eq 200 -or ($_.Id -gt 300 -and $_.Id -lt 312)) -and        # 200 or 300-312 will be included
        ($_.TimeCreated -ge $StartDate -and $_.TimeCreated -le $EndDate)
    } |
    Sort-Object TimeCreated -Descending

$eventnum = ($events).Count
"[TOTAL] $eventnum TerminalService-Gateway/Operational events [200, or 300-312] found in date range $StartDate - $EndDate" | tee $Logfile -Append
$Results = Foreach ($Event in $Events) {
  $Result = "" | Select Message,User,TimeCreated,Id
  $Result.TimeCreated = $Event.TimeCreated
  $eid = $Event.Id
  $emsg = $Event.Message 
#  if ($emsg -like "*met connection authorization policy *" -or $emsg -like "*disconnected from*" -or $emsg -like "*has initiated an outbound*" -or $emsg -like "*connected to*" -or $emsg -like "*following error occured: *")  {
  $Element = ""
  if ($emsg -like "*The user *") {
    $Element = ($emsg -split 'e user "')[1]
    $User = (($Element) -split '"')[0]
  }
  if ($emsg -like "*on client computer *") {
    $Element = ($emsg -split 'on client computer "')[1]
    $SourceIP=  (($Element -split '",')[0] -replace '"', '')
  }
  if ($emsg -like "*to resource *") {
    $Element = ($emsg -split 'to resource "')[1]
    $Resource = (($Element -split '"')[0] -replace '"', '')
  }
  if ($emsg -like "*authentication method used was: *") {
    $Element = ($emsg -split 'authentication method used was: "')[1]
    $AuthMethod = (($Element -split '"')[0] -replace '"', '')
  }
  if ($emsg -like "*protocol used: *") {
    $Element = ($emsg -split 'protocol used: "')[1]
    $ConnectionProtocol = (($Element -split '"')[0] -replace '"', '')
  }
  if ($emsg -like "*session duration was *") {
    $Element = ($emsg -split "session duration was ")[1]
    $Duration = ($Element -split ' seconds')[0]
  }
  if ($emsg -like "*the client transferred *") {
    $Element = ($emsg -split "the client transferred ")[1]
    [int]$BytesSent = ($Element -split ' bytes')[0]
    $Element = ($emsg -split "and received ")[1]
    [int]$BytesReceived = ($Element -split ' bytes')[0]
  }
  if ($emsg -like "*following error occured: *") {
    $Element = ($emsg -split 'following error occured: "')[1]
    $ErrorCode = (($Element -split '"')[0] -replace '"','')
  }
  if ($emsg -like "*connect to resource *") {
    $Element = ($emsg -split 'connect to resource "')[1]
    $ErrorCode = (($Element -split '"')[0] -replace '"','')
  }
    
#    if ($debug) { write-host "`n`nDEBUG: Found msg: $User `tSession: $SessionID `tSource IP: $SourceIP" }
#  }
  $time = $Event.TimeCreated
  if ($Event.Message -like "*RD Gateway service has started*")  {   #101
    $Result = "$time [ServiceStarted] $eid - RD Gateway service has started"
  }
  if ($Event.Message -like "*met connection authorization policy*")  {    # 200
    $Result = "$time [CAP Met] $eid User: $User - Source IP: $SourceIP - Resource: $Resource - AuthMethod: $AuthMethod - Protocol: $ConnectionProtocol"
  }
  if ($Event.Message -like "*did not meet connection authorization policy*")  {    # 201
    $Result = "$time [CAP NOT MET (or Couldn't reach resource)] $eid User: $User - Source IP: $SourceIP - ErrorCode: $ErrorCode - AuthMethod: $AuthMethod - Protocol: $ConnectionProtocol"
  }
  if ($Event.Message -like "*connected to resource*")  {   # 302
    $Result = "$time [Conn] $eid User: $User - IP: $SourceIP - Resource: $Resource - Protocol: $ConnectionProtocol"
  }
  if ($Event.Message -like "*disconnected from the following network resource*")  {   #303
    $Result = "$time [Disc] $eid User: $User - Source IP: $SourceIP - Resource: $Resource - Duration - $Duration - BytesSent: $BytesSent - BytesRecvd: $BytesReceived"
  }
  if ($Event.Message -like "*initiated an outbound connection*")  {   #312
    $Result = "$time [Disc] $eid User: $User - Source IP: $SourceIP"
  }
  "$Result " | tee $logfile -append
  $User = ""
  $SessionID= ""
  $SourceIP = ""
  $Resource = ""
  $AuthMethod = "n/a"
  $ConnectionProtocol = ""
  $BytesReceived = ""
  $BytesSent = ""
  $time = ""

} 
if ($Results) {
  Write-Host "[+] Logged, exporting to CSV: $CSVFile"  -ForegroundColor Yellow
  $Results | Export-Csv $CSVFile -NoType
    Write-Host "[+] Results:"  -ForegroundColor Green
  $Results
} else {
  Write-Host "[!] No results!!" -ForegroundColor Red
}
$null = Read-Host "[Press enter to continue]"
