# Invoke-HTTPSSweep.ps1
# Search for port 443 open on .1, .254, wait max of 2 seconds with curl.exe, min length of response: 10 bytes
# Made to look for ATT Modem webgui

$port = 443
foreach ($subnet in $(1..254)) {
  @(1,254) | ForEach-Object { $ip = "192.168.$subnet.$_" ; $result = (curl.exe -sk https://$($ip):$($port) -m 2) ; if ($result.length -gt 10) { Write-Output "`n------- $ip has port $port open : `n$result" } }
}