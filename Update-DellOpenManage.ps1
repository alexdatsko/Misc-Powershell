[cmdletbinding()]  # For verbose, debug etc

function Search-SoftwareVersion {
  param(
    [string]$SoftwareName)

  $SearchString="*$($SoftwareName)*"
  $Results = (get-wmiobject Win32_Product | Where-Object { $_.Name -like $SearchString })
  if ($Results) {
   return ($Results).Version
  } else {
    Write-Host "[!] No WMI entry found for $SearchString .." -ForegroundColor Red
    return $null
  }
}
#Search-SoftwareVersion "OpenManage" 

$OMSA11011Url = "https://dl.dell.com/FOLDER11706730M/1/SysMgmt_11011_x64_patch_A00.msp"   # 11.0.1.1
$OMSA11011Filename = (Split-Path $OMSA11011Url -Leaf)

$OMSA11002Url = "https://dl.dell.com/FOLDER11706695M/1/SysMgmt_11002_x64_patch_A00.msp"
$OMSA11002Filename = (Split-Path $OMSA11002Url -Leaf)

$OMSA10301Url = "https://dl.dell.com/FOLDER11706142M/1/SysMgmt_10301_x64_patch_A00.msp"
$OMSA10301Filename = (Split-Path $OMSA10301Url -Leaf)

$AgentString = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "[.] Checking OMSA Version installed..."
$OMSAVersion = Search-SoftwareVersion "OpenManage" 

# These are failing, can't find the original MSI.. hmm. Not sure if its the way we have installed it on these servers, or what.

if ([Version]$OMSAVersion -le [Version]"11.0.1.0") {
  Write-Host "[+] OMSA Version $OMSAVersion found. Updating to 11.0.1.1"
  Invoke-WebRequest "$OMSA11011Url"  -UserAgent $AgentString -outfile "$($env:temp)\$OMSA11011FileName"
  Start-Process "msiexec.exe" "/update $($env:temp)\$($OMSA11011FileName) /qn /quiet"
} else {
  if ([Version]$OMSAVersion -le [Version]"11.0.0.0") {
    Write-Host "[+] OMSA Version $OMSAVersion found. Updating to 11.0.0.2"
    Invoke-WebRequest "$OMSA11002Url"  -UserAgent $AgentString -outfile "$($env:temp)\$OMSA11002FileName"
    Start-Process "msiexec.exe" "/update $($env:temp)\$($OMSA11002FileName) /qn /quiet" 
  } else {
    if ([Version]$OMSAVersion -le [Version]"10.3.0.0") {
      Write-Host "[+] OMSA Version $OMSAVersion found. Updating to 10.3.0.0"
      Invoke-WebRequest "$OMSA10301Url"  -UserAgent $AgentString -outfile "$($env:temp)\$OMSA10301FileName"
      Start-Process "msiexec.exe" "/update $($env:temp)\$($OMSA10301FileName) /qn /quiet" 
    }
  }
}
