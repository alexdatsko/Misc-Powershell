###############################
# Start-VMs.ps1
# 11-14-22 - Alex Datsko alexd@mmeconsulting.com
# Starts up any virtual machines that are not started at boot.

# NOTE - Please list machines to check in the format:   @("machine1","machine2")    
# Otherwise, comment this line out to check and start ALL VMs.
$VMsToStart = @("server")

$logfile = "D:\Backups (DO NOT DELETE)\Reports\Start-VMs\Start-VMs.txt"

$date = Get-Date -Format "yyyy-MM-dd hh:mm"

"`n--- $($date) ------------------" | tee $LogFile -Append

if ($VMsToStart) {
  "-Only checking $($VMsToStart)" | tee $LogFile -Append
  $VMs = Get-VM -Name $VMsToStart    # If variable is set, use this list of VMs to start
} else {
  $VMs = Get-VM                      # Otherwise, start ALL vms which are unstarted.
}

foreach ($VM in $VMs) {
  "$($VM.Name) - $($VM.State)" | tee $LogFile -Append
  if ($VM.State -ne 'Running') {
    "$($VM.Name) - Starting..." | tee $LogFile -Append
    $Result = Start-VM -Name $VM.Name
    Start-Sleep 15
    if ($VM.State -ne 'Running') {
      "$($VM.Name) - Couldn't start @ $($date) !!!" | tee $LogFile -Append
      "$($VM.Name) - Result : $($Result) !!!" | tee $LogFile -Append
    } else {
      "$($VM.Name) - Started sucessfully." | tee $LogFile -Append
    }
  }
}
