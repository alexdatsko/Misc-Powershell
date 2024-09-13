$info = "###############################################################
# Update-DellOpenManage.ps1
# Updated OMSA 10.0.3.0 to 10.0.3.1, 11.0.0.0 to 11.0.0.2, or 11.0.1.0 to 11.0.1.1 to correct:
# DSA-2024-264: Dell OpenManage Server Administrator (OMSA) Security Update for Local Privilege Escalation via XSL Hijacking Vulnerability  
# Aka CVE-2024-37130 - https://nvd.nist.gov/vuln/detail/CVE-2024-37130
# Alex Datsko MME Consulting 
# v0.1 - 9/6/2024 - orig
# v0.2 - 9/9/2024 - refactor finished, move to `$temp due to possible bad profiles, test version after
# v0.3 - 9/9/2024 - Permission issues on some servers required a take ownership + icalcs of orig OMSA version folder..
#
"

$tmp = "C:\Temp"
$Verbose = 0

Start-Transcript
$date = Get-Date -Format "MM-dd-yyyy"
Write-Host $info
Write-Host $date

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

############################################ FUNCTIONS

function Invoke-WebRequestWait {
  param(
    [string]$Uri, 
    [string]$UserAgent, 
    [string]$outfile
  )
  $JobName = New-Guid
  if ($Verbose) {
    Write-Host "Invoke-WebRequestWait()`nUri: $Uri`nUserAgent: $UserAgent`noutfile: $outfile"
  }
  Start-Job -Name $JobName -ScriptBlock {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "$using:Uri"  -UserAgent "$using:UserAgent" -outfile "$using:outfile"
  } | Receive-Job -Wait -AutoRemoveJob
}

function Expand-ArchiveWait {
  param(
    [string]$Filename, 
    [string]$DestinationPath
  )
  $JobName = New-Guid
  Start-Job -Name $JobName -ScriptBlock {
    Expand-Archive "$using:Filename" -DestinationPath "$using:DestinationPath" -Force
  } | Receive-Job -Wait -AutoRemoveJob
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
    [switch]$NoInstall = $False
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

    Write-Host "OMSAPatchFilename $OMSAPatchFilename"
    Write-Host "OMSAPatchURL $OMSAPatchURL"
  }

  if (!($NoInstall)) {
    Write-Host "`n[+] OMSA Version $OMSAVersion found. Updating to $OMSAPatchVersion" -ForegroundColor Yellow
  } else {
    Write-Host "`n[+] OMSA Version $OMSAVersion found. Downloading $OMSAPatchVersion" -ForegroundColor Yellow
  }
  Write-Host "[.] First, downloading OMSA $OMSAOrigVersion for the missing .MSI ..." -ForegroundColor Yellow
  if ($Verbose) {
    Write-Host "`n[Verbose]:  Invoke-WebRequestWait -Uri ""$OMSAOrigUrl""  -UserAgent ""$AgentString"" -outfile ""$($tmp)\$($OMSAOrigFileName)"""
  }
  Invoke-WebRequestWait -Uri "$OMSAOrigUrl" -UserAgent "$AgentString" -outfile "$($tmp)\$($OMSAOrigFileName)"
  #Start-Process "$($tmp)\$($OMSAOrigFileName)" -ArgumentList @("-overwrite","-auto C:\OpenManage$($OMSAOrigVersion)") -Wait
  Copy-Item "$($tmp)\$($OMSAOrigFileName)" "$($tmp)\$($OMSAOrigFileName).zip"
  Expand-ArchiveWait -Filename "$($tmp)\$($OMSAOrigFileName).zip" -DestinationPath "C:\OpenManage$($OMSAOrigVersion)" -Force
  Write-Host "`n[.] Taking ownership of ""C:\OpenManage$($OMSAOrigVersion)"" for Administrators group w/ Takeown + Icacls..." -ForegroundColor Yellow
  Start-Process "takeown.exe" -ArgumentList "/a /r /d Y /f ""C:\OpenManage$($OMSAOrigVersion)\*.*""" -Wait
  Start-Process "icacls.exe" -ArgumentList """C:\OpenManage$($OMSAOrigVersion)"" /grant Administrators:(F) /t" -Wait
  Write-Host "`n[.] Downloading OMSA $OMSAPatchVersion patch ..."  -ForegroundColor Yellow
  Invoke-WebRequestWait -Uri  "$OMSAPatchUrl"  -UserAgent "$AgentString" -outfile "$($tmp)\$($OMSAPatchFileName)"
  if (!($NoInstall)) {
    Write-Host "`n[.] Installing OMSA $OMSAPatchVersion patch ..."  -ForegroundColor Yellow
    #Start-Process "msiexec.exe" "/update $($tmp)\$($OMSA11011FileName) /qn /quiet" # Doesn't work, fails
    $MSILocation = "C:\OpenManage$($OMSAOrigVersion)\windows\SystemsManagementx64\SysMgmtx64.msi"
    $Arguments = "/i ""$($MSILocation)"" PATCH=$($tmp)\$($OMSAPatchFileName) /qn /quiet"    # /qb can perform a UAC elevation prompt, but /qn cannot, it will just silent fail.
    Write-Host "`n[.] Installing OMSA $OMSAPatchVersion patch using MSI : $MSILocation`n  and OMSAPatchFilename - $OMSAPatchFileName`n  Calling : Msiexec.exe $arguments"  -ForegroundColor Yellow
    Start-Process "msiexec.exe" -ArgumentList $Arguments -Wait
    
    Write-Host "`n[.] Finished. Checking for new OMSA Version now..."
    $OMSAVersion = Search-SoftwareVersion "OpenManage" 
    if ($OMSAVersion -eq $OMSAPatchVersion) {
      Write-Host "`n[!] Success! New OMSA Version : $OMSAVersion" -ForegroundColor Green
    } else {
      Write-Host "`n[!] Failed! OMSA Version is still : $OMSAVersion" -ForegroundColor Red
    }
  }
}

######################################################################## MAIN 

if (!(Test-Path $tmp)) { 
  Write-Host "[.] Creating folder $tmp ..."  
  $null = (New-Item $tmp -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null)
}
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
        Update-OMSAVersion -OMSACurrentVersion $OMSAVersion -OMSAPatchVersion "10.3.0.1" -AgentString $AgentString `
                           -OMSAOrigUrl $OMSA10300Url -OMSAOrigFilename $OMSA10300FileName `
                           -OMSAPatchUrl $OMSA10301Url -OMSAPatchFilename $OMSA10301FileName `
                           -NoInstall
  
      Write-Host "[-] Please update OMSA to at least 10.0.3.0 first, which you can find in: C:\OpenManage10.0.3.0"  -ForegroundColor Yellow
      Write-Host "[.] Downloading OMSA 10.0.3.1 patch to C:\OpenManage10.0.3.0 ..."  -ForegroundColor Yellow
      Invoke-WebRequestWait -Uri  "$OMSA10301Url"  -UserAgent "$AgentString" -outfile "C:\OpenManage10.0.3.0\$($OMSA10301FileName)"
      Write-Host "[!] Done, please run the install and patch manually from the above path!" -ForegroundColor Yellow
    }
  }
}

Write-Host "[!] Exiting." 