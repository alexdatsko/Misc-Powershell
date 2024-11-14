[cmdletbinding()]  # For verbose, debug etc

$info = "
############################################################
# Install-ADCSRole.ps1
# Alex Datsko - MME Consulting Inc. 
# v0.1 - 11-13-2024 - Initial test
#"

param (
  [string]$CACommonName
)

$datetime = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
$info
$datetime

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
  Write-Output "`n[!] Not running under Admin context - Re-launching as admin!"
  if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
    $Command = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
    Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $Command
    Exit
  }
}

function Check-PreReqs {
  param (
    $Hostname = (hostname),
    $ADDomain = (Get-ADDomain).DNSRoot,
    $ADDomainDN = (Get-ADDomain).DistinguishedName,
    $ADPDC = ((Get-ADDomain).PDCEmulator).ToUpper(),
    $FQDN = ("$($hostname).$($ADDomain)").ToUpper()
  )

  # Prereq check: Joined to a domain, is a domain controller, static IP, fully good on updates, etc.
  if (!($ADDomain)) {
    Write-Output "[.] System does not appear to be joined to a domain."
    exit
  }

  if (!($ADPDC -eq $FQDN)) {
    Write-Output "[.] System does not appear to be the PDC: PDC = $ADPDC, FQDN = $FQDN"
    #exit
  }

  if ((Get-WindowsFeature AD-Certificate).Installed) {
    Write-Output "[-] Error, loooks like AD CS role is already installed! "
    $(Get-WindowsFeature AD-Certificate)
    Write-Event -eventid 1001 "Cert svcs already installed"
    exit
  }

  Write-Output "[+] Pre-requisite checks passed."
}

function Write-Event { 
  param (
    [string]$Log = 'Application',
    [string]$Source = 'MME-Install-ADCSRole',
    [string]$Type = 'Information',
    [int]$EventID = 1000,
    [string]$Msg
  )

  if ($LogToEventLog) {
    if (!( [System.Diagnostics.EventLog]::SourceExists($SourceName) )) {
        New-EventLog -LogName $LogName -Source $SourceName
    }
    Write-EventLog -LogName $Log -Source $Source -EntryType $Type -EventId $eventID -Message $msg
  }
}

function Create-TemplateForLDAPS {
  param (
    [string]$ADDomainDN = (Get-ADDomain).DistinguishedName,
    [string]$FQDN = ("$($hostname).$($ADDomain))").ToUpper()
  )

  Write-Output "[.] Creating template for LDAPS .."
  Import-Module pki

  If (!(Test-Path C:\Temp)) { $null = New-Item -ItemType Directory -Path "C:\Temp" -ErrorAction SilentlyContinue -Force | Out-Null}
  #Export default WebServer tempalte
  ldifde -m -v -d "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$ADDomainDN" -f C:\Temp\web-template.ldf
  
  #Modify-TemplateForLDAPS  ??
  $content = Get-Content "c:\Temp\web-template.ldf"
  $newContent = @"
dn: CN=LDAPS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$ADDomainDN
changetype: add
objectClass: top
objectClass: pKICertificateTemplate
cn: LDAPS
displayName: LDAPS Certificate
distinguishedName: CN=LDAPS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$ADDomainDN
flags: 66179
msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.4924021.4110200.4415496.12410456.14718204.44.1.17
msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.1
msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.2
msPKI-Certificate-Name-Flag: 1
msPKI-Enrollment-Flag: 32
msPKI-Minimal-Key-Size: 2048
msPKI-Private-Key-Flag: 16842752
msPKI-RA-Signature: 0
msPKI-Template-Minor-Revision: 1
msPKI-Template-Schema-Version: 2
pKICriticalExtensions: 2.5.29.15
pKIDefaultCSPs: 1,Microsoft RSA SChannel Cryptographic Provider
pKIDefaultKeySpec: 1
pKIExpirationPeriod: 0x00 0x40 0x39 0x87 0x2E 0xE1 0xFE 0xFF
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.1
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2
pKIKeyUsage: 0x86
pKIMaxIssuingDepth: 0
pKIOverlapPeriod: 0x00 0x80 0xA6 0x0A 0xFF 0xDE 0xFF 0xFF
revision: 100
"@
  
  # Save modified template
  #$newcontent = (((($content -replace "WebServer","LDAPS") -replace "Web Server","LDAPS Certificate") -replace "AIByDl3C/f8=","qfD2agAAAAA=") -replace "10679433.144.1.16","10679433.144.1.1699") # -replace "msPKI-Enrollment-Flag: 0","msPKI-Enrollment-Flag: 64"
  $newcontent | Set-Content "c:\Temp\ldaps.ldf" -Force
  #Reimport 
  ldifde -i -k -f C:\Temp\ldaps.ldf
}

function Request-CertForLDAPS {
  param (
    [string]$CACommonName,
    [string]$Hostname = (hostname),
    [string]$ADDomain = (Get-ADDomain).DNSRoot,
    [string]$ADDomainNBN = (Get-ADDomain).netbiosname,
    [string]$ADDomainDN = (Get-ADDomain).DistinguishedName,
    [string]$ADPDC = ((Get-ADDomain).PDCEmulator).ToUpper(),
    [string]$FQDN = ("$($hostname).$($ADDomain)").ToUpper()
  )
  Write-Output "[.] Creating Certificate for LDAPS .."
  Import-Module pki

  $certRequestPath = "C:\Windows\Certs\LDAPSRequest.inf"
  $CertCSR = "C:\Windows\Certs\ldaps_request.csr"
  $Certificate = "C:\Windows\Certs\ldaps_cert.cer"

  $serverName = "$(Hostname).$($ADDomain)".toUpper()
  $certTemplate = "LDAPS"

  $certRequest = @"
  [Version]
  Signature=`"`$Windows NT`$`"
  
  [NewRequest]
  Subject = `"CN=$($FQDN), O=$($ADDomainNBN), L=Cityname, S=CA, C=USA`"
  KeySpec = 1
  KeyLength = 2048
  Exportable = FALSE
  MachineKeySet = TRUE
  SMIME = FALSE
  PrivateKeyArchive = FALSE
  UserProtected = FALSE
  UseExistingKeySet = FALSE
  ProviderName = `"Microsoft RSA SChannel Cryptographic Provider`"
  ProviderType = 12
  RequestType = PKCS10
  KeyUsage = 0xa0
  
  [EnhancedKeyUsageExtension]
  OID=1.3.6.1.5.5.7.3.1  ; Server Authentication
  
  [RequestAttributes]
  CertificateTemplate = $($certTemplate)
"@
  Set-Content -Path $certRequestPath -Value $certRequest
  
  $null = New-Item -ItemType Directory "C:\Windows\Certs" -Force -ErrorAction SilentlyContinue | Out-Null
  Set-Content -Path $certRequestPath -Value $certRequest

  # Generate the CSR
  certreq -new $certRequestPath $CertCSR

  # Submit the CSR
  certreq -submit -config "SERVER\LDAPS" $CertCSR $Certificate

  return $Certificate
}

function Install-Cert {
  param (
    $Certificate
  )

  # Install the cert
  certreq -accept $Certificate

}


################################ MAIN ########################################

if (!($CACommonName)) {  # Set Default common name to "Server-CA"
  if ($hostname.length -gt 1) {   $CACommonName = "$($hostname)-CA".ToUpper()   }
}

<#
Check-PreReqs

Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools   # No restart needed

$ADCSResult = (Install-ADCSCertificationAuthority -CAType EnterpriseRootCA -CACommonName $CACommonName -KeyLength 2048 -ValidityPeriod Years -ValidityPeriodUnits 99 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -Force)
$ADCSInstalled = $false
if ($ADCSResult.ErrorId -eq 0) { $ADCSInstalled = $true }

Import-Module ADCSAdministration

(Get-Service -Name certsvc | Start-Service)
$certsvc = (Get-Service -Name certsvc).Status 
$certsvcInstalled = $false
if ($certsvc = 'Running') { $certsvcInstalled = $true }

if (!($certsvcinstalled -and $ADCSInstalled)) { Write-Output "[!] Error installing AD CS: `n Cert service not running: status = $certsvc `n or ADCS not Installed: Install-ADCSCertificateAuthority result: $ADCSResult" }

if (!(Get-CATemplate)) {
  Write-Output "[-] Could not get CA Template!  $(Get-CATemplate)"
  exit
}
#>
Create-TemplateForLDAPS

$Certificate = Request-CertForLDAPS -CACommonName $CACommonName

Install-Cert $Certificate


<#  # From old script
$certFriendlyName = "LDAPS Certificate"
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
#>

#Pause and test
$tnc = Test-NetConnection -ComputerName $FQDN -Port 636
if ($tnc) {
  Write-Output "[+] Connected to port 636 for LDAPS, looks good to go!"
} else {
  Write-Output "[-] Error: Could not connect to LDAPS port: 636 - $tnc"
}
$datetime = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Write-Output "[+] Done @ $($datetime)."