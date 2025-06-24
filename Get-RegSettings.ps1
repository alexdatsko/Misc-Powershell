#####################################################
# get-regsettings.ps1
#
# Uses powershell remoting to look up a registry setting on each PC in a domain
# Does NOT skip old broken computer objects!
#

#$comps = "BEL-CHAIR2PC.dental.local"
#$comps = get-adcomputer -filter *  # | select -last 1

# Get only computers that have logged on within the last 90 days
$comps = Get-ADComputer -Filter * -Properties LastLogonDate |
         Where-Object { $_.LastLogonDate -gt (Get-Date).AddDays(-90) }

foreach ($comp in $comps) {
  $prop = (Invoke-Command -computername $($comp.Name) { Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" }); 
  Write-Output "$($comp.Name) : $($Prop.inactivitytimeoutsecs) seconds" 
}