$PowerchuteURIBase = "https://localhost:6547/"

$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

<# Ignore cert- only for trusted servers!!!! #>
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#>

$response = Invoke-WebRequest -Uri $PowerchuteURIBase+"j_security_check;27fce5a4fb7ad280=node02sc3y6hb6aw5bpssj6n2icyr1.node0" -Method Post -Body @{
    j_username='Administrator'
    j_password='Tru%24tn01'
    login='Log+On'
    formtoken='a4e3870d5ad82b90'
    formtokenid='%2Flogon_formtoken'
}

$response.StatusCode
$response

<#
$response.InputFields | Where-Object {
    $_.name -like "* Value*"
} | Select-Object Name, Value

#>