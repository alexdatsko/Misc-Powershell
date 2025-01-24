[cmdletbinding()]  # For verbose, debug etc

$info = "#######################################
# Fix-iDRAC400.ps1
# Alex Datsko - MME Consulting Inc - alexd@mmeconsulting.com
#   Sets the racadm set idrac.webserver.hostheadercheck 0 command via Redfish, without racadm 
# v0.1 - 01-23-2025 - initial (NOT CURRENTLY WORKING!)"


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
curl.exe -isk -X GET -u "$combined" "https://$($dracip):$($dracport)/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1?`$select=Attributes/WebServer.1.HostHeaderCheck"

Write-Output "`n`n[.] Setting Webserver.1.HostHeaderCheck to Disabled .."

#Per the article :
# https://github.com/dell/iDRAC-Redfish-Scripting/issues/303
#curl.exe -k -X PATCH -u "$combined" "https://$($dracip):$($dracport)/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1" --insecure -d '{"Attributes":{"WebServer.1.HostHeaderCheck":"Disabled"}}' -i -H "Content-Type: application/json"
# Still not working...
curl.exe -isk -X PATCH -u "$combined" "https://$($dracip):$($dracport)/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1" -H "Content-Type: application/json" -d '{"Attributes":{"WebServer.1.HostHeaderCheck":false}}'

#used to be:
#{"Attributes":{"WebServer.1.HostHeaderCheck":"Enabled"}}

#looks like is now:
#{"@odata.context":"/redfish/v1/$metadata#DellAttributes.DellAttributes","@odata.id":"/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1","@odata.type":"#DellAttributes.v1_0_0.DellAttributes","Attributes":{"WebServer.1.HostHeaderCheck":"Disabled"}}

Write-Output "`n`n[.] Checking Webserver.1.HostHeaderCheck current settings again.."
curl.exe -isk -X GET -u "$combined" "https://$($dracip):$($dracport)/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1?`$select=Attributes/WebServer.1.HostHeaderCheck"
