$ports = @(80, 443)
$results = @()

function Test-Port {
    param($ip, $port)

    $scheme = if ($port -eq 443) { "https" } else { "http" }
    $url = "$scheme://$ip"

    try {
        $resp = Invoke-WebRequest -Uri $url -TimeoutSec 4 -UseBasicParsing -Headers @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        return $true
    } catch {
        return $false
    }
}

function Scan-Range {
    param($base1, $base2Start, $base2End)

    for ($i = $base2Start; $i -le $base2End; $i++) {
        Write-Host "Scanning $base1.$i.x..."
        foreach ($lastOctet in @("1", "254")) {
            $ip1 = "$base1.$i.0.$lastOctet"
            $ip2 = "$base1.$i.254.$lastOctet"
            foreach ($ip in @($ip1, $ip2)) {
                foreach ($port in $ports) {
                    if (Test-Port -ip $ip -port $port) {
                        $results += "${ip}:${port} OPEN"
                    }
                }
            }
        }
    }
}

Scan-Range -base1 "192.168" -base2Start 0 -base2End 254
Scan-Range -base1 "172" -base2Start 16 -base2End 31
Scan-Range -base1 "10" -base2Start 0 -base2End 254

$results
