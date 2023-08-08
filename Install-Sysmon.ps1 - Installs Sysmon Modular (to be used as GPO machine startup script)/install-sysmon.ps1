#######################################################################################
# Install-Sysmon.ps1
# v0.2 8/7/2023 - Alex Datsko
# This script checks if the SysInternals Sysmon logging solution is not installed, and 
# installs and configures it if so.
#
 
$Path = "C:\ProgramData\Sysmon"
$From = "\\mme.local\sysvol\mme.local\Software\Sysmon"

$ConfigFilename = "sysmonconfig.xml"
$ConfigFrom = "$($From)\$($ConfigFilename)"
$ConfigTo = "$($Path)\$($ConfigFilename)"

$Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$LogFile = "C:\ProgramData\Sysmon\_sysmon.log"

Function Start-Sysmon {
  While ((Get-Service "Sysmon" -ErrorAction Silentlycontinue).Status -ne "RUNNING") {   
    "[.] Sysmon service not running. Starting.."  | Tee-Object $Logfile -Append
    Get-service "Sysmon" | start-service -ErrorAction Continue
    Start-Sleep 3
    if ((Get-Service "Sysmon" -ErrorAction Silentlycontinue).Status -ne "RUNNING") {
      "[!] Sysmon service not found, installing!"  | Tee-Object $Logfile -Append
      Install-Sysmon  
    }
  }
}

Function Install-Sysmon {
  "[.] Copying $($From)\sysmon64.exe to $Path .." | Tee-Object $Logfile -Append
  Copy-Item "$($From)\sysmon64.exe" $Path -Force -ErrorAction Continue
  Set-Location "$Path"  # Can't run cmd from a share
  "[.] $Running $($Path)\sysmon64.exe -accepteula -i $ConfigTo .." | Tee-Object $Logfile -Append
  cmd.exe /c """$($Path)\sysmon64.exe"" -accepteula -i $ConfigTo"
  Start-Sleep 5 
  "[.] Starting Sysmon service.." | Tee-Object $Logfile -Append
  Get-service "Sysmon" | start-service
}

####################################### MAIN 

"------------------------------------------`n$Date" | Tee-Object $Logfile -Append
"[.] Checking for SysMon config.." | Tee-Object $Logfile -Append
if (!(test-path "$($ConfigTo)")) {
  New-Item -ItemType Directory $Path -ErrorAction Continue
  Copy-Item $ConfigFrom $ConfigTo -Force -ErrorAction continue
} else {
  "[+] SysMon config found." | Tee-Object $Logfile -Append
}

if ((Get-Service "Sysmon" -ErrorAction Silentlycontinue).Status -ne "RUNNING") {
  Start-Sysmon
}
