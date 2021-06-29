$Hostname = "HYPERVHOST"

# Run this once to create exported encrypted pw file:
#$securestringpassword = "SecurePasswordHere"
#$SecureStrText = $securestringpassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
#set-content "ExportedPw.txt" $SecureStrText

if (![System.Diagnostics.EventLog]::Exists('MME')) {
    New-EventLog -LogName "MME" -Source "APC Shutdown" 
}
Write-host "Shutting down $hostname due to power event.."
Write-EventLog -LogName "MME" -Source "APC Shutdown" -EventId  1600 -EntryType Warning -Message "Shutting down $Hostname due to power event.."


$pwdTxt = Get-Content "ExportedPw.txt"
$securePwd = $pwdTxt | ConvertTo-SecureString 
$creds = New-Object System.Management.Automation.PSCredential -ArgumentList "$Hostname\shutdown", $securePwd

# Test w/ Popup:
#[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
#[System.Windows.Forms.MessageBox]::Show('Working')

stop-computer -computer $Hostname -force -credential $creds
