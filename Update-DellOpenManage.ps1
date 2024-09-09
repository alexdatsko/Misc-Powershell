$info = ''###############################################################
# Update-DellOpenManage.ps1
# Updated OMSA 10.0.3.0 to 10.0.3.1, 11.0.0.0 to 11.0.0.2, or 11.0.1.0 to 11.0.1.1 to correct:
# DSA-2024-264: Dell OpenManage Server Administrator (OMSA) Security Update for Local Privilege Escalation via XSL Hijacking Vulnerability  
# Aka CVE-2024-37130 - https://nvd.nist.gov/vuln/detail/CVE-2024-37130
# Alex Datsko MME Consulting 
# v0.1 - 9/6/2024 - orig
# v0.2 - 9/9/2024 - refactor finished, test version after
#''

$info

$Verbose = 0

# Download locations for all OMSA files necessary
$OMSA11011Url = "https://dl.dell.com/FOLDER11706730M/1/SysMgmt_11011_x64_patch_A00.msp"   # 11.0.1.1
$OMSA11011Filename = (Split-Path $OMSA11011Url -Leaf)
$OMSA11010Url = "https://dl.dell.com/FOLDER10653510M/1/OM-SrvAdmin-Dell-Web-WINX64-11.0.1.0-5494_A00.exe"
$OMSA11010Filename = (Split-Path $OMSA11010Url -Leaf)

$OMSA11002Url = "https://dl.dell.com/FOLDER11706695M/1/SysMgmt_11002_x64_patch_A00.msp"
$OMSA11002Filename = (Split-Path $OMSA11002Url -Leaf)
$OMSA11000Url = "https://dl.dell.com/FOLDER10664637M/1/OM-SrvAdmin-Dell-Web-WINX64-11.0.0.0-5488_A00.exe"
$OMSA11000Filename = (Split-Path $OMSA11000Url -Leaf)

$OMSA10301Url = "https://dl.dell.com/FOLDER11706142M/1/SysMgmt_10301_x64_patch_A00.msp"
$OMSA10301Filename = (Split-Path $OMSA10301Url -Leaf)
$OMSA10300Url = "https://dl.dell.com/FOLDER10664805M/1/OM-SrvAdmin-Dell-Web-WINX64-10.3.0.0-5491_A00.exe"
$OMSA10300Filename = (Split-Path $OMSA10300Url -Leaf)

$AgentString = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  # Hack for SSL error downloading files.

function Invoke-WebRequestWait {
  param(
    [string]$Uri, 
    [string]$AgentString, 
    [string]$Location
  )
  $JobName = ((Split-Path $OMSA11011Url) -Split "\\")[3]   # Hack to make it unique, using foldername on Dells site..
  Start-Job -Name $JobName -ScriptBlock {
    Invoke-WebRequest -Uri "$Uri"  -UserAgent "$AgentString" -outfile "$Location"
  }
  Wait-Job -Name $JobName
  Start-Sleep 10  # Wait 10 more seconds for possible defender/antivirus scan etc
  Remove-Job -Name $JobName
}

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

function Update-OMSAVersion {
  param(
    [string]$OMSACurrentVersion,
    [string]$OMSAPatchVersion,
    [string]$OMSAPatchFilename,
    [string]$OMSAPatchURL,
    [string]$OMSAOrigFilename,
    [string]$OMSAOrigURL,
    [string]$OMSAOrigLocation
  )
  $OMSAOrigVersion = ($OMSAOrigFileName -split '-')[5] # Hack to get version from filename
  $PatchTmp = ($OMSAPatchFilename -split '_')[1]
  $OMSAPatchVersion = $PatchTmp.SubString(0,2) + '.' + $PatchTmp.SubString(2,1) + '.' + $PatchTmp.SubString(3,1) + '.' + $PatchTmp.SubString(4,1)  # Even more hacky, but works for all 3

  if ($Verbose) {
    Write-Host "`nDebug info:"
    Write-Host "OMSACurrentVersion $OMSACurrentVersion"
    Write-Host "OMSAOrigVersion $OMSAOrigVersion"
    Write-Host "OMSAPatchVersion $OMSAPatchVersion"

    Write-Host "OMSAOrigFilename $OMSAOrigFilename"
    Write-Host "OMSAOrigURL $OMSAOrigURL"
    Write-Host "OMSAOrigLocation $OMSAOrigLocation"

    Write-Host "OMSAPatchVersion $OMSAPatchVersion"
    Write-Host "OMSAPatchFilename $OMSAPatchFilename"
    Write-Host "OMSAPatchURL $OMSAPatchURL"
  }

  Write-Host "[+] OMSA Version $OMSAVersion found. Updating to "
  Write-Host "[.] First, downloading OMSA $OMSAOrigVersion for the missing .MSI ..." -ForegroundColor Yellow
  Invoke-WebRequestWait -Uri "$OMSAOrigUrl"  -UserAgent $AgentString -outfile "$($env:temp)\$($OMSAOrigFileName)"
  #Start-Process "$($env:temp)\$($OMSAOrigFileName)" -ArgumentList @("-overwrite","-auto C:\OpenManage$($OMSAOrigVersion)") -Wait
  Copy-Item "$($env:temp)\$($OMSAOrigFileName)" "$($env:temp)\$($OMSAOrigFileName).zip"
  Expand-Archive "$($env:temp)\$($OMSAOrigFileName).zip" -DestinationPath "C:\OpenManage$($OMSAOrigVersion)" -Force
  Write-Host "[.] Downloading OMSA $OMSAPatchVersion patch ..."  -ForegroundColor Yellow
  Invoke-WebRequestWait -Uri  "$OMSAPatchUrl"  -UserAgent $AgentString -outfile "$($env:temp)\$($OMSAPatchFileName)"
  Write-Host "[.] Installing OMSA $OMSAPatchVersion patch ..."  -ForegroundColor Yellow
  #Start-Process "msiexec.exe" "/update $($env:temp)\$($OMSA11011FileName) /qn /quiet" # Doesn't work, fails
  $MSILocation = "C:\OpenManage$($OMSAOrigVersion)\windows\SystemsManagementx64\SysMgmtx64.msi"
  $Arguments = "/i ""$($MSILocation)"" PATCH=$($env:temp)\$($OMSAPatchFileName) /qb"
  Write-Host "[.] Installing OMSA $OMSAPatchVersion patch using MSI : $MSILocation`n  and OMSAPatchFilename - $OMSAPatchFileName`n  Calling : Msiexec.exe $arguments"  -ForegroundColor Yellow
  Start-Process "msiexec.exe" -ArgumentList $Arguments -Wait
  
  Write-Host "[.] Finished. Checking for new OMSA Version now..."
  $OMSAVersion = Search-SoftwareVersion "OpenManage" 
  if ($OMSAVersion -eq $OMSAPatchVersion) {
    Write-Host "[!] Success! New OMSA Version : $OMSAVersion" -ForegroundColor Green
  } else {
    Write-Host "[!] Failed! OMSA Version is still : $OMSAVersion" -ForegroundColor Red
  }
}

######################################################################## MAIN 

Write-Host "[.] Checking OMSA Version installed..."
$OMSAVersion = Search-SoftwareVersion "OpenManage" 

# These are failing, can't find the original MSI.. hmm. Not sure if its the way we have installed it on these servers, or what.
if ([Version]$OMSAVersion -le [Version]"11.0.1.0" -and [Version]$OMSAVersion -gt [Version]"11.0.0.0") {
  Update-OMSAVersion -OMSACurrentVersion $OMSAVersion -OMSAPatchVersion "11.0.1.1" -AgentString $AgentString `
                     -OMSAOrigUrl $OMSA11010Url -OMSAOrigFilename $OMSA11010FileName `
                     -OMSAPatchUrl $OMSA11011Url -OMSAPatchFilename $OMSA11011FileName
} else {
  if ([Version]$OMSAVersion -le [Version]"11.0.0.0" -and [Version]$OMSAVersion -gt [Version]"10.3.0.0") {
    Update-OMSAVersion -OMSACurrentVersion $OMSAVersion -OMSAPatchVersion "11.0.0.2" -AgentString $AgentString `
                       -OMSAOrigUrl $OMSA11000Url -OMSAOrigFilename $OMSA11000FileName `
                       -OMSAPatchUrl $OMSA11002Url -OMSAPatchFilename $OMSA11002FileName
  } else {
    if ([Version]$OMSAVersion -eq [Version]"10.3.0.0") {
      Update-OMSAVersion -OMSACurrentVersion $OMSAVersion -OMSAPatchVersion "10.3.0.1" -AgentString $AgentString `
                         -OMSAOrigUrl $OMSA10300Url -OMSAOrigFilename $OMSA10300FileName `
                         -OMSAPatchUrl $OMSA10301Url -OMSAPatchFilename $OMSA10301FileName
    } else {
      Write-Host "[-] Error, this script doesn't apply to $($OMSAVersion), but we can download files you need for the next step." -ForegroundColor Red
      Write-Host "[-] Downloading OpenManage 10.0.3.0" -ForegroundColor Yellow
      Invoke-WebRequestWait -Uri  "$OMSA10300Url"  -UserAgent $AgentString -outfile "$($env:temp)\$($OMSA10300FileName)"
      Start-Process "$($env:temp)\$($OMSA10301FileName)" -ArgumentList " /auto C:\OpenManage10.0.3.0"  -Wait      
      Write-Host "[-] Please update OMSA to at least 10.0.3.0 first, which you can find in: C:\OpenManage10.0.3.0"  -ForegroundColor Yellow
      Write-Host "[.] Downloading OMSA 10.0.3.1 patch to C:\OpenManage10.0.3.0 ..."  -ForegroundColor Yellow
      Invoke-WebRequestWait -Uri  "$OMSA10301Url"  -UserAgent $AgentString -outfile "C:\OpenManage10.0.3.0\$(OMSA10301FileName)"
      Write-Host "[!] Done, please run the install and patch manually from the above path!" -ForegroundColor Yellow
    }
  }
}

Write-Host "[!] Exiting." 