$info = "
#################################################################################################
# Update-IISSecurityHeaders.ps1
# Alex Datsko - MME Consulting Inc.
#
#   This will update RD Gateway hosts IIS to include several security headers that are found as
#   vulnerabilities on Qualys/PCI scans etc.
#   Eventually we can use this to patch a few different IIS security headers as needed
#   Creates a log file here:  c:\temp\Create-IISSecurityHeaders.log 
#
# v0.1 - 11-14-2024 - initial
# v0.2 - 11-14-2024 - added 2 other fixes
# v0.3 - 12-05-2024 - random save? not sure if this is 100%
"

$dateshort= Get-Date -Format "yyyy-MM-dd HH:mm:ss"
if (!(Test-Path "C:\Temp")) { $null = New-Item -Itemtype directory -Path "C:\Temp" -Force -ErrorAction SilentlyContinue | out-null }

$filechk = "C:\Windows\System32\inetsrv\config\applicationHost.config"
if (!(Test-Path $filechk)) {
  Write-Output "[-] $filechk appears to not exist. Are you sure this is the RD Gateway server? Exiting."
  exit
}


Start-Transcript "C:\Temp\Create-IISSecurityHeaders.log"
$info
$datetime


function Add-IISReferrerPolicyEtc {
  param (
    $inputfile = "C:\Windows\System32\inetsrv\config\applicationHost.config",
    $backup = "C:\Windows\System32\inetsrv\config\applicationHost.config.bak",
    $outputfile = "C:\temp\applicationHost.config"
  )

  Write-Output "`n[!] Starting Add-IISReferrerPolicyAndX-Content-Type-Options- this will add custom headers for Referrer policy and X-Content-TypeOptions"
  Write-Output "[.] Making a backup copy of the config first at $backup ..."
  copy-item -Path $inputfile -Destination $backup -Force
  Write-Output "[.] Making a temporary copy to make changes to at $outputfile .."
  copy-item -Path $inputfile -Destination $outputfile -Force

  $apphost = [xml](Get-Content $outputfile)
  $xml = $apphost

  $newElement = $xml.CreateElement("add")
  $newElement.InnerText = ""
  $newElement.SetAttribute("name", "Referrer-Policy") 
  $newElement.SetAttribute("value", "strict-origin-when-cross-origin") 

  $newElement2 = $xml.CreateElement("add")
  $newElement2.InnerText = ""
  $newElement2.SetAttribute("name", "X-Content-Type-Options") 
  $newElement2.SetAttribute("value", "nosniff") 

  $parentnode = $xml.SelectSingleNode("configuration/system.webServer/httpProtocol/customHeaders")
  $parentNode.AppendChild($newelement)
  $parentNode.AppendChild($newElement2)
  $xml.Save($outputfile)

  #Write-Output " Check outputfile is correct:"
  #notepad $outputfile

  Write-Output "[.] Copying $outputfile back to $inputfile .."
  Copy-item -Path $outputfile -Destination $inputfile -Force

  Write-Output "[.] Restarting IIS, sleeping 6s.."
  iisreset 

  start-sleep 6
  Write-Output "[.] Checking IIS Service.."
  if ((Get-Service -Name W3SVC).Status -eq 'Running') {
    Write-Output "[+] IIS service is running."
  } else {
    Write-Output "[-] IIS service is not running!!!!"
  }

  Write-Output "[+] Done with Add-IISReferrerPolicyEtc" 
}

function Add-HSTSHeaderFix {
  Write-Output "`n[!] Starting Add-HSTSHeaderFix - this will require HSTS to RDGateway's 'Default Web Site'"
  
  Import-Module IISAdministration
  Reset-IISServerManager -Confirm:$false
  Start-IISCommitDelay

  Get-Website # Note name of web site for below
  $sitesCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
  $siteElement = Get-IISConfigCollectionElement -ConfigCollection $sitesCollection -ConfigAttribute @{"name"="Default Web Site"}  # Change name of website as needed
  $hstsElement = Get-IISConfigElement -ConfigElement $siteElement -ChildElementName "hsts"
  Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "enabled" -AttributeValue $true
  Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "max-age" -AttributeValue 31536000
  Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "redirectHttpToHttps" -AttributeValue $true

  Stop-IISCommitDelay
  Remove-Module IISAdministration
  Write-Output "[+] Done with Add-HSTSHeaderFix"
}

function Add-ServerHeaderRemoval {
  Write-OuFtput "`n[!] Starting Add-ServerHeaderRemoval - this will remove 'Server: Microsoft-IIS/10.0' from the server headers"
  Write-Output "[.] Adding regkey: cmd.exe /c 'reg add HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters /v DisableServerHeader /t REG_DWORD /d 2'"
  cmd.exe /c 'reg add HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters /v DisableServerHeader /t REG_DWORD /d 2'
  Start-Sleep 3
  iisreset.exe
  Write-Output "[+] Done with Add-ServerHeaderRemoval"
}

Add-IISReferrerPolicyEtc
Add-HSTSHeaderFix
Add-ServerHeaderRemoval

Write-Output "[.] Stopping transcript."
stop-transcript

Write-Output "[!] Done! Device will need a reboot for the ServerHeader removal fix, you will need to take care of this."