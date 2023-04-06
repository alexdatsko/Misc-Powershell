###################################################################
# Check-IPDNSReverseLookup.ps1
# Checks IP reverse lookup and whois information for a list of IPs
# Alex Datsko @ MME Consulting Inc - 3/6/23
#

[cmdletbinding()]  # For verbose, debug etc

$IPFilename = "C:\temp\ips.txt"
$ips = @()
# Or just paste them here and uncomment:
#$ips = @("127.0.0.1","8.8.8.8","4.2.2.2")

if ($ips.Length -lt 1) {
  if (Test-Path $IPFilename) {
    $ips = Get-Content $IPFileName
    if ($verbose) { 
        Write-Host "IPs loaded from file $($IPFilename): " 
        $ips 
    }
  } else {
    $inputstr = " "
    Write-Host "IP addresses could not be read from $($IPFilename).  Entering manually:"
    while ($inputstr -ne "") {
      $inputstr = read-host "Enter IP address (or enter if you are done) "
      if (([int]($input.split('.')[3]) -gt 0) -and ([int]($inputstr.split('.')[3]) -lt 256)) {
        if ($ips -notcontains $inputstr) {
          $ips += $inputstr
          Write-Host "[+] Added $($inputstr)" -ForegroundColor Green
        } else {
          Write-Host "[!] $($inputstr) already exists!" -ForegroundColor Red
        }
      } else {
        if ($inputstr -ne "") {
          Write-Host "[!] Invalid IP address! Please try again.." -ForegroundColor Red
        }
      }
    }
  }
}

foreach ($ip in $ips) {
    $result = Resolve-DnsName -Type PTR -ErrorAction SilentlyContinue -Name $ip
    if ($result) {
        Write-Host "$($ip): $($result.NameHost)" -NoNewLine
    } else {
        Write-Host "$($ip): No reverse lookup found" -NoNewLine
    }
    $response = Invoke-RestMethod "http://ipwho.is/$ip"
    Write-Host "-- [ipwho.is result]: $(($response).continent) $(($response).region) $(($response).city) $(($response).postal) $(($response).connection)"

    Write-Verbose "Extended results:"
    Write-Verbose "$response"
}