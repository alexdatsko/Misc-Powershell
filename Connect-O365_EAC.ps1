$loginname = Read-Host "What is the admin email to login to?"

Set-ExecutionPolicy RemoteSigned

Write-Host "[.] Installing necessary modules..." 
Install-module AIPService
Install-Module -Name ExchangeOnlineManagement

Write-Host "[.] Importing necessary modules..." 
Import-module AIPService
Import-Module ExchangeOnlineManagement

Write-Host "[.] Connecting to EAC with $loginname ..." 
Connect-ExchangeOnline -UserPrincipalName $loginname

Write-Host "[.] Getting credential to connect to AIP Service..." 
$cred = Get-Credential

Write-Host "[.] Connecting to AIP Service..." 
Connect-AIPService -Credential $cred
Enable-AIPService

#$mailboxname = Read-Host "Mailbox name? I.e First Last > "
#Set-Mailbox -Identity $mailboxname -SingleItemRecoveryEnabled $true
