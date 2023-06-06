Set-ExecutionPolicy RemoteSigned
Install-module AIPService
Import-module AIPService
Install-Module -Name ExchangeOnlineManagement
Import-Module ExchangeOnlineManagement

Connect-ExchangeOnline -UserPrincipalName o365admin@ovationorthodontics.com

$cred = Get-Credential
Connect-AIPService -Credential $cred
Enable-AIPService

$mailboxname = Read-Host "Mailbox name? I.e First Last > "
Set-Mailbox -Identity $mailboxname -SingleItemRecoveryEnabled $true
