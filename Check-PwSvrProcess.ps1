#######################################################################
# Check-PwSvrProcess.ps1
# Alex Datsko 2023-01-24 alex.datsko@mmeconsulting.com
# Makes sure that PwSvr (PracticeWorks licensing application) is running, starts it if not
# Made to run as a scheduled task every hour, in case after a reboot the licensing service is not started automatically.
#

$datetime = Get-Date -Format "yyyy-MM-dd HH:mm"
$logfile = "c:\Scripts\PwSvr.log"

$Proc = get-process -Name "PwSvr"
if ($Proc) {
  "$datetime - PwSvr.exe Process is Running" | tee $logfile -Append
} else {
  "$datetime - PwSvr.exe Process is Stopped! Restarting.." | tee $logfile -Append
  Start-Process -FilePath "‪C:\Client\PWSvr\PWSvr.exe"
}
