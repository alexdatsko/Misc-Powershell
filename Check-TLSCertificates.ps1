param (
  [string]$InputFile = "sites.txt",
  [string]$OutputFile = "sslresp.txt"
)

$info = 
"##############################################################
# Check-TLSCertificates.ps1
# Alex Datsko alexd@mmeconsulting.com
#   This script will check the certificate for each hostname in a filename using -InputFile 
#   Requires: OpenSSL - Download from https://slproweb.com/download/Win64OpenSSL-3_4_0.msi
# Usage:
#   ./Check-TLSCertificates -InputFile sites.txt -OutputFile sslresp.txt
# v0.1 - 10/31/2024"

$info

Remove-Item -Path $OutputFile -ErrorAction SilentlyContinue
Get-Content -Path $InputFile | ForEach-Object {
    $site = $_
    "`n------- $site" | Out-File -FilePath $OutputFile -Append
    $result = & { 
        $ErrorActionPreference = 'Stop'
        try {
            $process = Start-Process "openssl" -ArgumentList "s_client -connect $($site):443" -NoNewWindow -RedirectStandardOutput $OutputFile -Wait -Timeout 5
        } catch {
            "Timeout exceeded for $site"
        }
    }
    $result | Out-File -FilePath $OutputFile -Append
}
