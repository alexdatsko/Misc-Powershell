# URL Of certificate host
$certURL = "https:///MME_CodeSigning.cer"
# Set Script name to sign
$script = "script.ps1"

# Creating and exporting self-signed cert on server

$cert = New-SelfSignedCertificate -CertStoreLocation cert:\currentuser\my -Subject "CN=MME Consulting Inc. Code Signing" -KeyAlgorithm RSA -KeyLength 2048 -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -KeyExportPolicy Exportable -KeyUsage DigitalSignature -Type CodeSigningCert

# Export cert to $exportPath

$exportPath = "C:\Temp\MME_CodeSigning.cer" 
Export-Certificate -Cert $cert -FilePath $exportPath -Type CERT

# Import to Trusted root CA Store on this machine

$importPath = "C:\temp\MME_CodeSigning.cer" 
Import-Certificate -FilePath $importPath -CertStoreLocation Cert:\LocalMachine\Root

# Set authenticode signature of script

Write-Host "[.] Signing $script .."
Set-AuthenticodeSignature $script $cert
$AuthenticodeSig = Get-AuthenticodeSignature $script
Write-Host "----------------------------------------`n----------------------------------------`n"
Write-Host "Authenticode Signature to add to EPDR Authorized Software:"
Write-Host "$($AuthenticodeSig.SignerCertificate.Thumbprint)"
Write-Host "----------------------------------------`n----------------------------------------`n"

# Importing cert on remote server

$importPath = "C:\temp\MME_CodeSigning.cer" 
IWR $certURL -OutFile $importPath
Import-Certificate -FilePath $importPath -CertStoreLocation Cert:\LocalMachine\Root -Force

# Test script

./script.ps1