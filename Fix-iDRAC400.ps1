[cmdletbinding()]  # For verbose, debug etc

$info = "#######################################
# Fix-iDRAC400.ps1
# Alex Datsko -  - alexd@mmeconsulting.com
#   Sets the racadm set idrac.webserver.hostheadercheck 0 command via Redfish, without racadm 
# v0.1 - 01-23-2025 - initial"


$info

$dracip = Read-Host "Enter DRAC IP [192.168.1.42]"
if ($dracip -eq "") {
  $dracip = "192.168.1.42"
}
$dracport = Read-Host "Enter DRAC port [2443]"
if ($dracport -eq "") {
  $dracport = "2443"
}
$username = Read-Host "Enter DRAC username [DRACMan]"
if ($username -eq "") {
  $username = "DRACMan"
}
$password = Read-Host "Enter DRAC password"
$combined = "$($username):$($password)"

Write-Output "`n`n[.] Checking Webserver.1.HostHeaderCheck current settings .."
curl.exe -sk -X GET -u "$combined" "https://$($dracip):$($dracport)/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1?`$select=Attributes/WebServer.1.HostHeaderCheck"

Write-Output "`n`n[.] Setting Webserver.1.HostHeaderCheck to Disabled .."
$data = "{\""Attributes\"":{\""WebServer.1.HostHeaderCheck\"":\""Disabled\""}}"
$cmd = "curl.exe -sk -X PATCH -u ""$combined"" ""https://$($dracip):$($dracport)/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1"" -H ""Content-Type: application/json"" -d ""$data"""
Write-Output "Command being sent: $cmd"
$resp = (cmd.exe /c "$cmd")
if ($resp -like "*request completed successfully*") {
  Write-Output "[+] HostHeaderCheck is now disabled."
} else {
  Write-Output "[-] Something went wrong!  Error: `n`n  $resp `n`n" 
}

Write-Output "`n`n[.] Checking Webserver.1.HostHeaderCheck current settings again just in case.."
curl.exe -sk -X GET -u "$combined" "https://$($dracip):$($dracport)/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1?`$select=Attributes/WebServer.1.HostHeaderCheck"
