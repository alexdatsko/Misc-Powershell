[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Automated = $false   # this allows us to run without supervision and apply all changes (could be dangerous!)
)
#Clear

$header="

###########################################################
# Set up LDAPS (LDAP over SSL) on Windows Server 2016+
# 02-15-2023 - Alex Datsko @ 
#
"


# After you make this configuration change, clients that rely on unsigned SASL (Negotiate, Kerberos, NTLM, or Digest) LDAP binds or on LDAP simple binds over
# a non-SSL/TLS connection stop working. To help identify these clients, the directory server of Active Directory Domain Services (AD DS) or Lightweight Directory
# Server (LDS) logs a summary Event ID 2887 one time every 24 hours to indicate how many such binds occurred. 

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

Write-Output "[.] 1. Installing the Active Directory Certificate Services (AD CS) role on the Windows Server.. (This will require a reboot after!)"
$AdCsInstalled = (Get-WindowsFeature Adcs-Cert-Authority).InstallState
if (!($AdCsInstalled -eq 'Installed')) {
  Write-Output '[+] Installing AD CS Role..'
  Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
  Install-WindowsFeature AD-Certificate -IncludeManagementTools
  Write-Output '`n[-] The server will need to be rebooted for this role to be installed properly.'
  Write-Output '`n[-] NOTE: IF running the script remotely, the script will end now, you will need to hit ctrl-c and reboot manually, then run the script again after!'
  $null = Read-Host '[-] Hit enter to reboot, or hit Ctrl-C now to cancel!'
  Restart-Computer -Computername $env:computername -Force
} else {
  Write-Output "[!] Active Directory Certificate Services (AD CS) role is already installed!"
}


Write-Output "[.] 2. Managing the post-installation AD CS role configuration.."

Import-Module -Name ADCSDeployment
Import-Module -Name PKI
$domain = Get-ADDomain
$domain_name = $domain.DNSRoot
$dns_name = $env:computername + '.' + $domain_name;
Install-AdcsCertificationAuthority -CAType "EnterpriseRootCA" -KeyLength 2048 -HashAlgorithmName "SHA256" -ValidityPeriod "Years" -ValidityPeriodUnits 10 -DatabaseDirectory "C:\Windows\system32\CertLog" -LogDirectory "C:\Windows\system32\CertLog" -Force
#Install-AdcsCertificateTemplate -TemplateDisplayName "LDAPS" -SubjectName "CN=*.$($domain)" -DNSName "*.$($domain)" -KeySpec "Signature" -HashAlgorithmName "SHA256" 
# NO alternative found except Add-CATemplate from ADCSDeployment..

Write-Output "[.] 3. Requesting a server certificate from the AD CS. This certificate will be used to secure the LDAP traffic.."


$ServerFQDN = "$($env:USERDNSDOMAIN)"
$certSubject = "CN=$($ServerFQDN)"
$certPassword = ConvertTo-SecureString -String $(Read-Host "[?] Cert password to use? ") -Force -AsPlainText
$certTemplate = "LDAP"  # Replace with the name of the certificate template to use
$certRequest = New-PKICertificateRequest -Subject $certSubject -Template $certTemplate
$cert = Get-Certificate -Template $certTemplate -Sign $certRequest
$certBytes = Export-PKICertificate -Cert $cert -Type PFX -Password $certPassword
$certFile = Read-Host "Cert file path\filename? i.e [C:\Temp\LDAPs.pfx] "  # Replace with the path to the output PFX file
if (!($cerfile)) {
  $cerFile = "C:\Temp\LDAPs.pfx"
}
Set-Content -Path $certFile -Value $certBytes -Encoding Byte

$certFriendlyName = "LDAPs Server Certificate"
$thumbprint = (New-SelfSignedCertificate -DnsName $ServerFQDN -CertStoreLocation Cert:\LocalMachine\My -FriendlyName $certFriendlyName -Type SSLServerAuthentication).Thumbprint
$cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$thumbprint"
$cert.Import($certFile, $certPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)

Write-Output "[.] 4. Creating a registry key to enable LDAPS.."

New-Item -Path "HKLM:\System\CurrentControlSet\Services\LDAP\Parameters" -Name "SecureAuthenticator" -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LDAP\Parameters" -Name "SecureAuthenticator" -Value 1

Write-Output "[.] 5. Importing the server certificate to the Active Directory Certificate Services.."

$certStoreLoc='HKLM:/Software/Microsoft/Cryptography/Services/NTDS/SystemCertificates/My/Certificates';
if (!(Test-Path $certStoreLoc)){
  New-Item $certStoreLoc -Force
}
Copy-Item -Path HKLM:/Software/Microsoft/SystemCertificates/My/Certificates/$thumbprint -Destination $certStoreLoc;


Write-Output "[.] 6. Restarting the NTDS service for the changes to take effect.."
Restart-Service -Name "NTDS" -Force

Write-Ouput "[+] Done. LDAPS should now be set up and ready to use. You can test it by using an LDAP client, such as LDP or Apache Directory Studio, to connect to the server over port 636 (the default LDAPS port)."

