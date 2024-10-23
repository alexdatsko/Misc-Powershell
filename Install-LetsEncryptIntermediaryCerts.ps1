$info = "###################################################
# Install-LetsEncryptIntermediaryCerts.ps1
# Alex Datsko alex.datsko@mmeconsulting.com
#   This script will download the latest 2024 intermediary TLS certificates from
#   LetsEncrypt.org and install them in the computer's Trusted Root CA
#   Certificate store.
# v0.1 - 10/22/2024 - Initial version
# v0.2 - 10/23/2024 - added root certs and check
#"

$info
# Define the directory where the .der files are stored
$certDir = "C:\Temp\TLS"

Write-Output "`n[.] Using directory $CertDir to download and install LetsEncrypt intermediary certificates.  Will create if it does not exist."
New-Item -ItemType Directory -Path $certDir -ErrorAction SilentlyContinue
Set-Location $certDir 

# Fix to use TLS 1.2 for downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Download Root CAs
wget https://letsencrypt.org/certs/isrgrootx1.der -outfile x1.der
wget https://letsencrypt.org/certs/isrg-root-x2.der -outfile x2.der
# These should be included in Windows roots from WU
# To update ALL root certs from Microsoft, download them to 'roots.sst' with this command:
#   certutil -generateSSTFromWU roots.sst  
# Then add these certs to the local computer Trusted Root store with mmc.exe.

# Download subordinate (intermediate) CAs
wget https://letsencrypt.org/certs/2024/e5.der -outfile e5-x1.der
wget https://letsencrypt.org/certs/2024/e5-cross.der -outfile e5-x1.der
wget https://letsencrypt.org/certs/2024/e5.der -outfile e5-x2.der
wget https://letsencrypt.org/certs/2024/e6.der -outfile e6-x2.der
wget https://letsencrypt.org/certs/2024/e6-cross.der -outfile e6-x1.der
wget https://letsencrypt.org/certs/2024/r10.der -outfile r10-x1.der
wget https://letsencrypt.org/certs/2024/r11.der -outfile r11-x1.der

# Download Backup certs (currently no certs are being issued from them, but certs may be issued from them at any time, without warning..)
wget https://letsencrypt.org/certs/2024/e7.der -outfile  e7-x2.der
wget https://letsencrypt.org/certs/2024/e7-cross.der -outfile e7-x1.der
wget https://letsencrypt.org/certs/2024/e8.der -outfile e8-x2.der
wget https://letsencrypt.org/certs/2024/e8-cross.der -outfile e8-x1.der
wget https://letsencrypt.org/certs/2024/e9.der  -outfile e9-x2.der
wget https://letsencrypt.org/certs/2024/e9-cross.der -outfile e9-x1.der
wget https://letsencrypt.org/certs/2024/r12.der -outfile r12-x1.der
wget https://letsencrypt.org/certs/2024/r13.der -outfile r13-x1.der
wget https://letsencrypt.org/certs/2024/r14.der -outfile r14-x1.der

# Loop through each .der file and import it into the Trusted Root Certification Authorities store
$certFiles = Get-ChildItem -Path $certDir -Filter *.der
try {
  foreach ($certFile in $certFiles) {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($certFile.FullName)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($cert)
    $store.Close()
    Write-Host "[+] Imported certificate: $($certFile.FullName)"
  }
} catch { 
  Write-Output "[-] An ERROR occurred importing certificate: $_"
  exit
}

Write-Host "[+] All certificates appeared to be imported.`n"

Write-Host "[.] Checking for certificates in cert:\LocalMachine\Root :"
$certs = gci cert:\LocalMachine\Root | Where { $_.Subject -like "*Let's*" -or $_.Subject -like "*ISRG*" }
if ($certs.count -eq 17) {
  Write-Host "[+] All certificates were imported successfully.`n" -ForegroundColor Green
} else {
  Write-Host "[-] The count did not match 17, something went wrong!`n" -ForegroundColor Red
}
Write-Host "[!] Done!"