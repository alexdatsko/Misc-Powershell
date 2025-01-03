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
# v0.4 - 01-03-2025 - Fix for IIS 10.0 header on 2022+
# v0.5 - 01-03-2025 - Remove TLS 1.0/1.1
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

  #Get-Website # Note name of web site for below
  # This will always be Default Web Site unless we rename it, unlikely.
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
function Get-OSVersion {
  return [version](Get-CimInstance Win32_OperatingSystem).version
}

function Add-ServerHeaderRemoval {
  $osInfo = Get-CimInstance Win32_OperatingSystem
  if ($osInfo.ProductType -ge 2) {
    Write-Output "`n[!] Starting Add-ServerHeaderRemoval - this will remove 'Server: Microsoft-IIS/10.0' from the server headers"
    if (Get-OSVersion -ge 10.0.20348) {
      # First, back it up!!!      
      $num = 0
      while (Test-Path "C:\Windows\System32\inetsrv\config\applicationHost.config.bak$($num)") {
        $num += 1
      }
      Copy-Item -Path "C:\Windows\System32\inetsrv\config\applicationHost.config" -Destination "C:\Windows\System32\inetsrv\config\applicationHost.config.bak$($num)" -Force
      Import-Module WebAdministration
      #Write-Output "[.] Removing x-aspnet-version header..."  
      # this is not showing up currently, will come back to it.

      Write-Output "[.] Removing 'X-Powered-By: ASP.NET' header..."
      Clear-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']"
      
      Write-Output "[.] Removing 'Server: Microsoft-IIS/10.0' header..."
      Set-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering" -Name "removeServerHeader" -Value "true" -PSPath "MACHINE/WEBROOT/APPHOST"
      iisreset.exe
    } else {
      Write-Output "[.] Adding regkey: cmd.exe /c 'reg add HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters /v DisableServerHeader /t REG_DWORD /d 1'"
      cmd.exe /c 'reg add HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters /v DisableServerHeader /t REG_DWORD /d 1'
      Start-Sleep 3
      iisreset.exe
      # This doesn't work on Server 2022+
      Write-Host "`n[!] NOTE: This will require a reboot after!!`n"
    }
  } else {
    Write-Output "`n[!] Error: not a Windows server!"
  }
  Write-Output "[+] Done with Add-ServerHeaderRemoval"
}

function Check-IISServices {
  $iisServices = @("W3SVC", "WAS", "IISADMIN")
  $statusReport = @()
  Write-Output "[.] Checking Services : $iisServices"
  foreach ($serviceName in $iisServices) {
      $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

      if ($null -eq $service) {
          Write-Output "[!] Service $serviceName not found on this system."
          continue
      }

      if ($service.Status -ne 'Running') {
          Write-Output "[-] Service $serviceName is not running. Attempting to start it..."
          try {
              Start-Service -Name $serviceName -ErrorAction Stop
              Write-Output "Service $serviceName started successfully."
              $status = "Started"
          } catch {
              Write-Output "[-] Failed to start service $serviceName: $_"
              $status = "Failed to Start"
          }
      } else {
          Write-Output "[+] Service $serviceName is running."
          $status = "Running"
      }
      $statusReport += [PSCustomObject]@{
          ServiceName = $serviceName
          Status      = $status
      }
  }
  return $statusReport
}

function Remove-TLS10and11 {
  $datetime = Get-Date -Format "yyyy-MM-dd hh_mm_ss"
  $logfile = "c:\Temp\Disable-TLS10And11.txt"
  $debug = 0

  "------------------- $datetime"  | tee -append $logfile
  if (!(Test-Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp" -ErrorAction Continue
  }

  Write-Output "[.] Current TLS 1.0, 1.1 and 1.2 settings:"  | tee -append $logfile
  Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"  | ft  | tee -append $logfile
  Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"  | ft  | tee -append $logfile
  Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"  | ft  | tee -append $logfile

  try {
    Write-Output "[.] Disable TLS 1.0 to Disabled : creating key" | tee -append $logfile
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null
    Write-Output "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\Enabled=0" | tee -append $logfile
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0 -PropertyType "DWORD" -Force | Out-Null
    Write-Output "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\DisabledByDefault=1" | tee -append $logfile
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWORD" -Force | Out-Null
  } catch {
    Write-Output "ERROR: $_" | tee -append $logfile
  }
  try {
    Write-Output "[.]  Disable TLS 1.1 to Disabled : creating key" | tee -append $logfile
    Write-Output "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\Enabled=0" | tee -append $logfile
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0 -PropertyType "DWORD" -Force | Out-Null
    Write-Output "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\DisabledByDefault=1" | tee -append $logfile
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWORD" -Force | Out-Null
  } catch {
    Write-Output "ERROR: $_" | tee -append $logfile
  }
  try {
    Write-Output "[.] Enable TLS 1.2 to Enabled : creating key" | tee -append $logfile
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null
    Write-Output "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\Enabled=1" | tee -append $logfile
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -PropertyType "DWORD" -Force | Out-Null
    Write-Output "[+]   Setting HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\DisabledByDefault=0" | tee -append $logfile
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -PropertyType "DWORD" -Force | Out-Null
  } catch {
    Write-Output "ERROR: $_" | tee -append $logfile
  }

  Write-Output "[.] New TLS 1.0, 1.1 and 1.2 settings:"
  Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"  | ft
  Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"  | ft
  Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"  | ft

  Write-Output "[+] TLS 1.0 and 1.1 are disabled, and TLS 1.2 is enabled. Please restart the server to apply changes." | tee -append $logfile
  Write-Output "[!] Done!" 

}

Add-IISReferrerPolicyEtc
Add-HSTSHeaderFix
Add-ServerHeaderRemoval
Remove-TLS10and11
$result = Check-IISServices
$result | Format-Table -AutoSize

Write-Output "[.] Stopping transcript."
stop-transcript

Write-Output "[!] Done! (Device may need a reboot for header fix, if noted above.)"