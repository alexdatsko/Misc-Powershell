[cmdletbinding()]  # For verbose, debug etc

############################################################################
#  Invoke-MMESecurityAudit.ps1
#  Alex Datsko (alexd@mmeconsulting.com) 
#
#      MME Security Audit Automation Script (draft)
#
# v0.1 - 2021-06-03 - initial
# v0.5 - 2025-07-15 - updated for mari's list automation
#
############################################################################

param (
    [string]$ServerName = "server",            # Hostname of server where output files can be written, defaults to 'server'
    [string]$ServerPath = "data\secaud"        # Share name/path output files can be written, defaults to 'Data\SecAud'
)

$date = Get-Date -Format "yyyy-MM-dd"

Start-Transcript  "\\$($servername)\$($serverpath)\_$($env:computername)-results-$($date).txt"

if (!(test-path "C:\Temp")) {
    mkdir C:\Temp
}
if (($servername) -and (!(test-path "\\$($servername)\$($serverpath)\2025"))) {
  mkdir "\\$($servername)\$($serverpath)\2025"
}

# Shared routines
Function Get-OSInfo {
    $OSInfo = Get-ComputerInfo OsName,OsVersion,OsBuildNumber,OsHardwareAbstractionLayer,WindowsVersion
     "OS: $($OSInfo.OsName) build $($OSInfo.OsBuildNumber)" 

    [double]$osver = [string][environment]::OSVersion.Version.major + '.' + [environment]::OSVersion.Version.minor 
    # In the above we cast to a string to build the value and then cast back to a double.
    # This numeric version number can then be tested against a desired minimum version:
    if ($osver -ge 5.0 -and $osver -lt 9.0) {  #Server 2008 / 2008 r2
         "Windows Vista/Server 2008 or greater. Checking for ESU.." 
 
        #### NOT SURE IF THIS WORKS ....
        #//////Purpose of this script is to detect if the Win2008/R2 machine has an Extended Security Update (ESU). It will write to a registry key with a 1(true), or a 0(false) to indicate if the license exists.
 
        $ESUWin2008Year1 = (Get-WmiObject softwarelicensingproduct -filter "ID='553673ed-6ddf-419c-a153-b760283472fd'" | Select LicenseStatus)
        $ESUWin2008Year2 = (Get-WmiObject softwarelicensingproduct -filter "ID='04fa0286-fa74-401e-bbe9-fbfbb158010d'" | Select LicenseStatus)
        $ESUWin2008Year3 = (Get-WmiObject softwarelicensingproduct -filter "ID='16c08c85-0c8b-4009-9b2b-f1f7319e45f9'" | Select LicenseStatus)
        if ($ESUWin2008Year1 -match '@{LicenseStatus=1}') {
             'Win2008/R2 ESU Year 1 found' 
        }
        else {
             'No Win2008/R2 ESU Year 1' 
        }
        if ($ESUWin2008Year2 -match '@{LicenseStatus=1}') {
             'Win2008/R2 ESU Year 2 found' 
        }
        else {
             'No Win2008/R2 ESU Year 2' 
        }
        if ($ESUWin2008Year3 -match '@{LicenseStatus=1}') {
             'Win2008/R2 ESU Year 3 found' 
        }
        else {
             'No Win2008/R2 ESU Year 3' 
        }
        if ($ESUWin2008Year1 -or $ESUWin2008Year2 -or $ESUWin2008Year3) { } else {
           "Windows Vista/Server 2008/R2 - NO ESU found!!"  
        }
    }
    if ($osver -ge 9.0 -and $osver -lt 10.0) {  "Windows 7/Server 2012/R2"  }
    if ($osver -ge 10.0) {  "Windows 10/Server 2016 or greater"  }
}


########################################################### MAIN ##################################################

 "`n###################### A - Hostname"
$out = (hostname)
$out

 "`n###################### B - Users"
$out = (net user)
$out += (net localgroup administrators)
$out += "  Guest User account:"
$out += (net user guest |findstr /i active)
$out

 "`n###################### C - Shares"
$out = (net share)
$out

 "`n###################### D - Rogue apps/EOL Software"
$out = ((Get-WmiObject -Class Win32_Product).Name | Sort)
$out

 "`n###################### E - Mapped Drives"
$out = (net use)
$out

 "`n###################### F - OS Version"
$out = (Get-OSInfo)
$out

 "`n###################### G - Windows updates"
$out = (wmic qfe | findstr /i 2025)
$out

 "`n###################### H - Screen lock etc"
gpresult /f /h C:\Temp\$($env:computername).html
$out = (gci "C:\Temp\$($env:computername).html")
$out
copy-item "c:\temp\$($env:computername).html" "\\$($servername)\$($serverpath)\2025\"


"`n###################### I - Antivirus status"
# 1. Defender Status (enabled/disabled)
$defenderStatus = Get-MpComputerStatus | Select-Object -Property AMServiceEnabled, RealTimeProtectionEnabled
"I.1- Windows Defender Status: $($defenderStatus | Format-List | Out-String)"

# 2. SecurityCenter2 registered products (sometimes EDR shows here)
$products = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntivirusProduct" -ErrorAction SilentlyContinue
if ($products) {
    "I.2 - Registered Antivirus Products:"
    $products | Select-Object displayName, pathToSignedProductExe, productState | Format-Table -AutoSize | Out-String
} else {
    "    No registered AV in SecurityCenter2 namespace (could be EDR-only or corrupted registration)"
}

# 3. Installed Products Scan (via Win32_Product, be aware of slow performance)
$win32 = Get-WmiObject -Class Win32_Product
$avMatches = $win32 | Where-Object {
    $_.Name -match 'EDR|Antivirus|EPDR|Webroot|Crowdstrike|SentinelOne|Cortex|Carbon|Norton|McAfee|Bitdefender|Malwarebytes|ESET|TrendMicro|Avira|AVG|Avast'
}

if ($avMatches) {
    "I.3 - Installed AV/EDR Products:"
    $avMatches | Select-Object Name, Version, Vendor | Format-Table -AutoSize | Out-String
} else {
    "    No matching AV/EDR products found in Win32_Product"
}

 "`n###################### J - Firewall status"
$FirewallProfileDisabled = 0
$FirewallProfiles = (Get-NetFirewallProfile)
$FirewallProfiles | % {
  if ($_.Enabled -eq 1) {
     "J: Windows Firewall $($_.Name) profile is enabled" 
  } else {
     "J: Windows Firewall $($_.Name) profile is disabled!" 
    $FirewallProfileDisabled = 1
  }
}
if ($FirewallProfileDisabled) {
   "J: A Windows Firewall profile is disabled!" 
} else {
   "J.All: All Windows Firewall profiles are enabled." 
}

 "`n###################### K - Scheduled Tasks/Startup check"
"`nK: Startup Run Keys"
$out = (reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
"`nK.1: Startup Run Keys (HKLM)"
$out 
$out = (reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run")
"`nK.2: Scheduled Tasks (Verbose)" 
$out = (Get-ScheduledTask | ForEach-Object {
    $taskName = $_.TaskName
    $action = ($_ | Get-ScheduledTaskInfo) | Out-Null
    $definition = (Get-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath).Actions

    foreach ($a in $definition) {
        if ($a.Execute) {
            [PSCustomObject]@{
                TaskName     = $_.TaskPath + $_.TaskName
                CommandLine  = if ($a.Arguments) { "$($a.Execute) $($a.Arguments)" } else { $a.Execute }
            }
        }
    }
} | Format-List)
$out

 "`n###################### L - Bitlocker"
$out = (Get-BitLockerVolume -ErrorAction SilentlyContinue)
if ($out) { $out } else {
    $bitlocker = (manage-bde -status C: | findstr /i conversion)
    if ($LASTEXITCODE -eq 0) {
        "`nL: BitLocker Enabled`n$bitlocker"
    } else {
        "`nL: BitLocker not enabled or admin required."
    }
}

 "`n###################### M - UAC Enabled"
$uacVal = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"
if ($uacVal -eq 0) {
    "`nM: UAC is disabled"
} else {
    "`nM: UAC is enabled"
}


 "`n###################### O - Credential Vault saved items"
$out = (cmdkey /list)
$out

# to do: chrome/ie/etc passwords?

#######################################

Stop-Transcript

"`n[+] Done!"