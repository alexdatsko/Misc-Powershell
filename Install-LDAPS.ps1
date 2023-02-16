[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Automated = $false   # this allows us to run without supervision and apply all changes (could be dangerous!)
)
#Clear

$header="

###########################################################
# Set up LDAPS (LDAP over SSL) on Windows Server 2016+
# 02-15-2023 - Alex Datsko @ MME Consulting
#
"

$oldPwd = $pwd                               # Grab location script was run from

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Output "`n[!] Not running under Admin context - Re-launching as admin!"
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $Command = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $Command
        Exit
 }
}

$header
Write-Output "[.] 1. Installing the Active Directory Certificate Services (AD CS) role on the Windows Server.."
$AdCsInstalled = Get-WindowsFeature Adcs-Cert-Authority
if (!($AdCsInstalled)) {
  Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
} else {
  Write-Output "[!] Active Directory Certificate Services (AD CS) role is already installed!"
}

Write-Output "[.] 2. Requesting a server certificate from the AD CS. This certificate will be used to secure the LDAP traffic.."
# Note: Replace <ServerFQDN> with the fully qualified domain name of the server, and <Password> with a strong password for the certificate.

$certTemplate = "LDAP"
$ServerFQDN = "$($env:USERDNSDOMAIN)"
Write-Output "[.] Server FQDN found: $ServerFQDN"
$certSubject = "CN=$($ServerFQDN)"
$certPassword = ConvertTo-SecureString -String $(Read-Host "[?] Cert password to use? ") -Force -AsPlainText
$certRequest = New-CertificateRequest -DnsName $certSubject -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(1) -KeySpec KeyExchange
Write-Output "[?] Please enter Credentials to use to authorize Certificate request: " 
$cred = Get-Credential
$certThumbprint = Submit-CertificateRequest -RequestFile $certRequest.FileName -CertTemplate $certTemplate -Credential $Cred -Verbose
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $certThumbprint}
Set-ItemProperty -Path "Cert:\LocalMachine\My\$($cert.Thumbprint)" -Name "PrivateKeyExportable" -Value 1
$certFilePath = Read-Host "[?] Cert File Path to save to? "
Export-PfxCertificate -Cert $cert.PSPath -FilePath "$certFilePath" -Password $certPassword

Write-Output "[.] 3. Creating a registry key to enable LDAPS.."

New-Item -Path "HKLM:\System\CurrentControlSet\Services\LDAP\Parameters" -Name "SecureAuthenticator" -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LDAP\Parameters" -Name "SecureAuthenticator" -Value 1

Write-Output "[.] 4. Importing the server certificate to the Active Directory Certificate Services.."
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certFilePath, $certPassword)
Import-Certificate -CertStoreLocation Cert:\LocalMachine\My -FilePath $certFile -Password $certPassword -Verbose

Write-Output "[.] 5. Restarting the LDAP service for the changes to take effect.."
Restart-Service -Name "LDAP"

Write-Ouput "[+] Done. LDAPS should now be set up and ready to use. You can test it by using an LDAP client, such as LDP or Apache Directory Studio, to connect to the server over port 636 (the default LDAPS port)."

