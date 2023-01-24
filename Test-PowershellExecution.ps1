############################################
# Test-PowershellExecution.ps1
#   This script tests for a specific issue we've been running into. 
#   Powershell commands, at certain times will take 30.01 or 90.01 seconds to run, equal to 3 TCP timeouts.
#   This will check the results of Measure-Command { Set-Location C:\Temp }  and if the results takes longer
#   than 30seconds, will send an email to us to investigate further.
#   Script is meant to be ran hourly, it will try to run once per 300 seconds, and if it fails, will try again 
#   next hour, so as to not send too many emails.
# - Possible issue: Script will take 90*4 = 360 seconds to process the 4 lines of powershell to send the email when
#   the problem is occuring.. 

$SecondsToWait = 300 # Wait 5 minutes in between tests
$WaitsPerHour = ((60*60) / $SecondsToWait)   # Run 12 times per hour
# Gmail settings
$username = "AlexDMMETesting" 
$password = "vqmfxplookhxlnmt"  # Needs an app password to run.
$sstr = ConvertTo-SecureString -string $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -argumentlist $username, $sstr
$subject = "Test-PowerShellExecution.ps1 - Lund EMS TS Ortho"

$dateday = Get-Date -format "yyyy-MM-dd"
Start-Transcript "C:\programdata\Test-PowershellExecution-$dateday.log"  # Log here
$x = 0
While ($x -lt ($WaitsPerHour)) {
  $date = Get-Date -Format "yyyy-MM-dd_hh-mm"
  $timetaken = (measure-command { Set-Location c:\temp }).TotalSeconds
  if ($timetaken -gt 30) {  #Write-Output "[!] Powershell command took longer than 30 seconds to run. Sending email."   #
    try { 
      $body = "[!] Powershell command took longer than 30 seconds to run. `nTime Taken: $($timetaken)s `nDate: $date"
      Send-MailMessage -To "alex.datsko@mmeconsulting.com" -From "AlexDMMETesting@gmail.com" -Subject $subject -Body $body -BodyAsHtml -SmtpServer smtp.gmail.com -UseSSL -Credential $cred -Port 587
      Write-Output "[.] Email sent." 
    } catch {
      Write-Output "[!] Email not sent! Error with email provider or network." 
    }
    Exit  # Exit when error is found.
  } else { 
    Write-Output "[.] $date - No issues currently. Time Taken: $($timetaken)s" 
  }
  Start-Sleep ($SecondsToWait)
}
Stop-Transcript

