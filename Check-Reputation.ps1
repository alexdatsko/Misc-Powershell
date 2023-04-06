#################################################################################################
# Check-Reputation.ps1
# Alex Datsko 03-28-23
# Read reputational results for an IP Address or URL from 5 online security vendors
#

$IBMusername = "YOUR_XFORCE_USERNAME"
$IBMpassword = "YOUR_XFORCE_PASSWORD"

$AlienVaultapiKey = "YOUR_OTX_API_KEY"

$VTapiKey = "YOUR_VIRUSTOTAL_API_KEY"

$filename = $PSBoundParameters['filename']

# These should not change!
$Pages = @{"$($env:temp)\VirusTotalResults.html",
"$($env:temp)\URLVoidResults.html"
"$($env:temp)\CiscoTalosResults.html",
"$($env:temp)\XForceResults.html",
"$($env:temp)\OTXResults.html",
"$($env:temp)\FortiGuardResults.html"}

Check-Results {
  param ([string]$searchStr)

  # Check for valid URL
  if ($searchStr.ToUpper() -like 'HTTP*') {
    $urlAddress = $searchStr
  } 
  # Check for valid IP
  $ipPattern = "\b(?:\d{1,3}\.){3}\d{1,3}\b"
  if ($searchStr -match $ipPattern) {
    $ipAddress = $searchStr
    $urlAddress = $searchStr   # Can also search a URL that is just an IP
  } else {
    if (!($urlAddress)) { # If not an IPv4 or URL:
      Write-Host "[!] Input must be valid IPv4 or URL starting with 'http'..   `n"
      Return  "( Invalid IP address or URL entered: '$searchStr' )"
    }
  }
  
  # Delete any prior results before continuing:
  foreach ($page in $Pages) {
    if (Test-Path $page) {
      Write-Host "[-] Removing old results: $page"
      Remove-Item -Force $page
    }
  }

  if ($urlAddress)
    # Virustotal 
    $requestUrl = "https://www.virustotal.com/vtapi/v2/url/report?apikey=$apiKey&resource=$urlAddress"
    $response = Invoke-RestMethod -Uri $requestUrl
    $VTResult = $response.positives
    $response | ConvertTo-Html -As Table | Out-File -Encoding UTF8 -FilePath "$($env:temp)\VirusTotalResults.html"

    # URLVoid
    $requestUrl = "https://www.urlvoid.com/scan/$urlAddress"
    $response = Invoke-WebRequest -Uri $requestUrl
    $URLVoidResult = $response.ParsedHtml.getElementsByTagName("font") | Where-Object { $_.innerText -match "Blacklist Status" } | Select-Object -ExpandProperty NextSibling.InnerText
    $requestUrl = "http://www.urlvoid.com/api1000/$urlAddress/"
    $response = Invoke-WebRequest -Uri $requestUrl
    $result = $response.Content | ConvertFrom-Json
    $htmlTable = "<table><tr><th>Scan Date</th><td>$($result.last_scan)</td></tr><tr><th>Domain Age</th><td>$($result.domain_age)</td></tr><tr><th>Domain Rating</th><td>$($result.domain_rating)</td></tr><tr><th>IP Address</th><td>$($result.ip_addr)</td></tr><tr><th>AS Number</th><td>$($result.asn)</td></tr><tr><th>Country</th><td>$($result.country)</td></tr><tr><th>Google Safe Browsing</th><td>$($result.google_safe_browsing)</td></tr><tr><th>Website Antivirus</th><td>$($result.website_antivirus)</td></tr><tr><th>Website Antivirus Result</th><td>$($result.website_antivirus_result)</td></tr><tr><th>Website Blacklist Status</th><td>$($result.website_blacklist_status)</td></tr><tr><th>Website Blacklist Result</th><td>$($result.website_blacklist_result)</td></tr></table>"
    $htmlTable | Out-File -Encoding UTF8 -FilePath "$($env:temp)\URLVoidResults.html"
  }

  if ($IPAddress) {
    # Cisco Talos
    $url = "https://talosintelligence.com/sb_api/query_lookup?query=$ipAddress"
    $response = Invoke-RestMethod -Uri $url
    $TalosResult = $response.Content | ConvertFrom-Json | Select-Object -ExpandProperty query | Select-Object -ExpandProperty verdict
    $requestUrl = "https://talosintelligence.com/sb_api/query_lookup?query=$ipAddress"
    $response = Invoke-WebRequest -Uri $requestUrl
    $result = $response.Content | ConvertFrom-Json    $htmlTable = "<table><tr><th>Query</th><td>$($result.query)</td></tr><tr><th>Verdict</th><td>$($result.verdict)</td></tr><tr><th>First Seen</th><td>$($result.firstseen)</td></tr><tr><th>Last Seen</th><td>$($result.lastseen)</td></tr></table>"
    $htmlTable | Out-File -Encoding UTF8 -FilePath "$($env:temp)\CiscoTalosResults.html"

    # IBM X-Force
    $credential = New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString $password -AsPlainText -Force))
    $url = "https://api.xforce.ibmcloud.com/ipr/$ipAddress"
    $headers = @{
        "Accept" = "application/json"
        "Authorization" = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($username+":"+$password)))"
    }
    $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
    $IBMXforceResult = $response.result[0].score
    $response | ConvertTo-Html -As Table -Property "score", "reasons.reason", "reasons.category" | Out-File -Encoding UTF8 -FilePath "$($env:temp)\XForceResults.html"

    # AienVault Open Threat Exchange
    $url = "https://otx.alienvault.com/api/v1/indicators/IPv4/$ipAddress"
    $headers = @{
        "X-OTX-API-KEY" = $AlienVaultapiKey
    }
    $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
    $AlienVaultResult = $response | ConvertTo-Html -As Table -Property "pulse_count", "reputation", "created", "modified" | Select-String -Pattern "<td>reputation</td><td>(\d+)</td>" | ForEach-Object { $_.Matches.Groups[1].Value }
    $response | ConvertTo-Html -As Table -Property "pulse_count", "reputation", "created", "modified" | Out-File -Encoding UTF8 -FilePath "$($env:temp)\OTXResults.html"

    # FortiGuard
    $requestUrl = "https://fortiguard.com/webfilter?q=$ipAddress"
    $response = Invoke-WebRequest -Uri $requestUrl
    $FortiGuardResult = $response.ParsedHtml.getElementById("queryResult") | Select-Object -ExpandProperty InnerText
    $response.ParsedHtml | ConvertTo-Html -As Table -Property "Site", "FortiGuard Category", "Web Filter Rating", "Threat Level" | Out-File -Encoding UTF8 -FilePath "$($env:temp)\FortiGuardResults.html"
  }

  # Display the results
  if ($urlAddress) {
    Write-Host "VirusTotal reputation score for $ipAddress: $VTResult"
    Write-Host "Cisco Talos reputation score for $ipAddress: $ciscoTalosResult"
  }
  if ($ipAddress) {
    Write-Host "IBM X-Force reputation score for $ipAddress: $IBMXforceResult"
    Write-Host "AlienVault Open Threat Exchange (OTX) reputation score for $ipAddress: $AlienVaultResult"
    Write-Host "URLVoid reputation score for $ipAddress: $URLVoidResult"
    Write-Host "FortiGuard reputation score for $ipAddress: $FortiGuardResult"
  }
}

function Build-Report {
  param ($searchStr)

  if ($searchStr.ToUpper() -like 'HTTP*') {
    $IP = $searchStr.split('://')[1].split('/')[0]  # grab just hostname of URL for report name
  } else {
    $IP = $searchStr   # Have already checked for IP validity above
  }
  # Build full report
  compiledHtmlFile = "$($env:temp)\ThreatResults-$IP.html"
  $stream = New-Object System.IO.StreamWriter($compiledHtmlFile)
  $stream.WriteLine("<html><body>")
  
  foreach ($page in $Pages) {
    if (Test-Path $page) {
      $stream.WriteLine("<h2>$page</h2>")
      $content = Get-Content $page
      $stream.WriteLine($content)
    }
  }
  $stream.WriteLine("</body></html>")
  $stream.close()
  Write-Host "Compiled HTML results file saved to: $compiledHtmlFile"
}

function Show-Results {
  param ($Results)
}

#################################################

if ($filename) {
  Write-Host "Filename parameter found: $filename"
} else {
  $searchStr = Read-Host "[?] What is the IP or URL you would like to check? [Enter when done] "

  $ips = @()
  # Or just paste them here and uncomment:
  #$ips = @("127.0.0.1","8.8.8.8","4.2.2.2")

  if ($ips.Length -lt 1) {
    if (Test-Path $Filename) {
      $ips = Get-Content $FileName
      if ($verbose) { 
          Write-Host "IPs loaded from file $($Filename): " 
          $ips 
      }
    } else {
      $input = " "
      Write-Host "IP addresses could not be read from $($IPFilename).  Entering manually:"
      while ($input -ne "") {
        $input = read-host "Enter IP address (or enter if you are done) "
        if (([int]($input.split('.')[3]) -gt 0) -and ([int]($input.split('.')[3]) -lt 256)) {
          if ($ips -notcontains $input) {
            $ips += $input
            Write-Host "[+] Added $($input)" -ForegroundColor Green
          } else {
            Write-Host "[!] $($input) already exists!" -ForegroundColor Red
          }
        } else {
          if ($input -ne "") {
            Write-Host "[!] Invalid IP address! Please try again.." -ForegroundColor Red
          }
        }
      }
    }
  }
}

foreach ($ip in $ips) {
  Check-Results -searchStr $ip
}

