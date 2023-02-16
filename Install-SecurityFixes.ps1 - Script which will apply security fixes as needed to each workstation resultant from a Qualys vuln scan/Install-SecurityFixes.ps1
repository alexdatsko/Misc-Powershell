#########################################
# Install-SecurityFixes.ps1
# Alex Datsko - alex.datsko@mmeconsulting.com
#

[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Automated = $false   # this allows us to run without supervision and apply all changes (could be dangerous!)
)
#Clear

$oldPwd = $pwd                               # Grab location script was run from
$ConfigFile = "$oldpwd\_config.ps1"          # Configuration file 
$OSVersion = ([environment]::OSVersion.Version).Major
$QIDsAdded = @()

# Script specific vars:
$Version = "0.31"
$VersionInfo = "v$($Version) - Last modified: 2/15/22"

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Output "`n[!] Not running under Admin context - Re-launching as admin!"
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $Command = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $Command
        Exit
 }
}

# Change title of window
$host.ui.RawUI.WindowTitle = "$($env:COMPUTERNAME) - Install-SecurityFixes.ps1"

if ($ConfigFile -like "*.ps1") {
  try {
    . $($ConfigFile)
  } catch {
    Write-Output "`n`n[!] ERROR: Couldn't import $($ConfigFile) !! Exiting"
    Exit
  }
}

if (!($QIDsIgnored)) {
  Write-Output "`n`n[!] Warning: No QIDs to ignore!"
}

# Try to use TLS 1.2, this fixes many SSL problems with downloading files, before TLS 1.2 is not secure any longer.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


#Start a transscript of what happens while the script is running
if (!(Test-Path $tmp)) { New-Item -ItemType Directory $tmp }
$dateshort= Get-Date -Format "yyyy-MM-dd"
Start-Transcript "$($tmp)\Install-SecurityFixes_$($dateshort).log"

if ($Automated) {
  Write-Host "`n[!] Running in automated mode!`n"   -ForegroundColor Red
}

function Get-YesNo {
  param ([string] $text,
         [string] $results)
  
  $done = 0
  if (!($Automated)) { 
    while ($done -eq 0) {
      $yesno = Read-Host  "[?] $text [n] "
      if ($yesno.ToUpper()[0] -eq 'Y') { return $true } 
      if ($yesno.ToUpper()[0] -eq 'N' -or $yesno -eq '') { return $false } 
      if ($yesno.ToUpper()[0] -eq 'S') { Write-Output $Results }
    }
  } else { 
    Write-Output "[i] Results: "
    Write-Output $Results 
    Write-Output "[+] Applying fix for $text .."
    return $true
  }
}

$hostname = $env:COMPUTERNAME
$datetime = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
$datetimedateonly = Get-Date -Format "yyyy-MM-dd"
$osinstalldate = ([WMI]'').ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).InstallDate) | get-date -Format MM/dd/yyyy
$serialnumber = (wmic bios get serialnumber)
Write-Host "`r`n================================================================" -ForegroundColor DarkCyan
Write-Host "[i] Install-SecurityFixes.ps1" -ForegroundColor Cyan
Write-Host "[i]   $($VersionInfo)" -ForegroundColor Cyan
Write-Host "[i]   Alex Datsko - alex.datsko@mmeconsulting.com" -ForegroundColor Cyan
Write-Host "[i] Date / Time : $datetime" -ForegroundColor Cyan
Write-Host "[i] Computername : $hostname " -ForegroundColor Cyan
Write-Host "[i] SerialNumber : $serialnumber " -ForegroundColor Cyan
Write-Host "[i] OS Install Date : $osinstalldate " -ForegroundColor Cyan
if (([WMI]'').ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).InstallDate) -ge (Get-Date $datetimedateonly).AddDays(0-$IgnoreDaysOld)) {
  if (!(Get-YesNo "$osinstalldate is within $IgnoreDaysOld days, continue?")) {
    Write-Host "[!] Exiting" -ForegroundColor White
    exit
  }
}

# Lets check SERVER first as that is our default..
if (Test-Connection "SERVER" -Count 2 -Delay 1 -Quiet) {
  if (Get-Item "\\SERVER\data\secaud\Install-SecurityFixes.ps1") {
    $ServerName = "SERVER" # if SERVER is on the network, and I can get the script from there,..
  }
} else {  #Can't ping SERVER
  Write-Output "`n[.] Checking $ServerName for connectivity.."
  if ($ServerName) {
    if (!(Test-Connection $ServerName -Count 2 -Delay 1 -Quiet)) {
      $ServerName = Read-Host "[!] Couldn't ping SERVER or $ServerName .. please enter the server name where we can find the .CSV file, or press enter to read it out of the current folder: "
      if (!($ServerName)) { 
        $ServerName = "$($env:computername)"
      }
    }
  }
}

Function Check-NewerVersion { 
  param ([string]$File)

  $FileContents = Get-Content $File 
  foreach ($line in $FileContents) {
    if ($line -like '`$Version = *') {
      $VersionFound = $line.split('=')[1].trim().replace('"','')
      Write-Verbose " New script version: $VersionFound"
      Write-Verbose " New script version Hex: $($VersionFound | Format-Hex)"
      Write-Verbose " Old version: $Version "
      Write-Verbose " Old version hex: $($Version | Format-Hex)"
      if ([version]$VersionFound -gt [version]$Version) {
        return $true
      } else {
        Write-Output "[.] Version found $($VersionFound) is not newer than $($Version)"
      }
      
    }
  }  
  return $false
}

<#
Write-Output "[.] Checking for updated version of script on github.."
$url = "https://raw.githubusercontent.com/alexdatsko/Misc-Powershell/main/Install-SecurityFixes.ps1%20-%20Script%20which%20will%20apply%20security%20fixes%20as%20needed%20to%20each%20workstation%20resultant%20from%20a%20Qualys%20vuln%20scan/Install-SecurityFixes.ps1"
if ((Invoke-WebRequest $url).StatusCode -eq 200) { 
  $client = new-object System.Net.WebClient
  $client.Encoding = [System.Text.Encoding]::ascii
  $client.DownloadFile("$url","$($tmp)\Install-SecurityFixes.ps1")
  $client.Dispose()
  
  if (Check-NewerVersion -File "$($tmp)\Install-SecurityFixes.ps1") {  #Creationtime won't work here
      Write-Output "[+] Found newer version, copying over old script"
      # Copy the new script over this one and run..  Likely this will cause issues .. Lets see..
      Copy-Item "$($tmp)\Install-SecurityFixes.ps1" "\\$($Servername)\data\secaud\Install-SecurityFixes.ps1"
      $(Get-Item "\\$($Servername)\data\secaud\Install-SecurityFixes.ps1").CreationTimeUtc = [DateTime]::UtcNow
      Write-Output "[+] Launching new script.."
      #&"\\$($Servername)\data\secaud\Install-SecurityFixes.ps1"
      . "$($tmp)\Install-SecurityFixes.ps1"  # Run from tmp location for now, looping..
      exit
  }
  Write-Verbose "Continuing script.. Will not get here if we updated."
}
#>

################################################# FUNCTIONS ###############################################

function Remove-Software {
  param ([string]$Products,
         [string]$Results)
  
  Write-Verbose "Results: $Results"
  foreach ($Product in $Products) { # Remove multiple products if passed..
    $Guid = $Product | Select-Object -ExpandProperty IdentifyingNumber
    $Name = $Product | Select-Object -ExpandProperty Name
    if (Get-YesNo "Uninstall $Name - $Guid ") { 
        Write-Output "[.] Removing $Guid (Waiting max of 30 seconds after).."
        $x=0
        cmd /c "msiexec /x $Guid /quiet /qn"
        Write-Host "[.] Checking for removal of $Guid .." -ForegroundColor White -NoNewline
        while ($x -lt 5) {
            Start-sleep 5
            Write-Host "." -ForegroundColor White -NoNewLine
            $x+=1
            $Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like "$Guid"}) 
            if (!($Products)) { 
              $x=5 
              Write-Host "`n[!] $Guid removed successfully!`n" -ForegroundColor Green
            }
        }
        if ($Products) {
            Write-Host "[!] Error removing $($Products.Guid) (or may have taken longer than 30s) !!`n" -ForegroundColor Red
        }
    }
  }
}

function Find-LocalCSVFile {
  param ([string]$Location)    
    #write-Host "Find-LocalCSVFile $Location $OldPwd"
    # FIGURE OUT CSV Filename
    $i = 0
    if (($null -eq $Location) -or ("." -eq $Location)) { $Location = $OldPwd }
    [array]$Filenames = Get-ChildItem "$($Location)\*.csv" | ForEach-Object { $_.Name }
    $Filenames | Foreach-Object {
      Write-Host "[$i] $_" -ForegroundColor Blue
      $i += 1
    }
    if (!($Automated) -and ($i -gt 1)) {   # Don't bother picking if there is just one file..
      Write-Host "[$i] EXIT" -ForegroundColor Blue
      $Selection = Read-Host "Select file to import, [Enter=0] ?"
      if ($Selection -eq $i) { Write-Host "[-] Exiting!" -ForegroundColor Gray ; exit }
      if ($Selection -eq "") { $Selection="0" }
      $Sel = [int]$Selection
    } else { 
      $Sel=0
    }
    if (@($Filenames).length -gt 1) {
      $CSVFilename = "$($Location)\$($Filenames[$Sel])"
    } else {
      if (@($Filenames).length -gt 0) {
        $CSVFilename = "$($Location)\$($Filenames)"  # If there is only 1, we are only grabbing the first letter above.. This will get the whole filename.
      }
    }
    Write-Host "[i] Using file: $CSVFileName" -ForegroundColor Blue
    Return $CSVFileName
}

function Find-ServerCSVFile {
  param ([string]$Location)
  if (!(Test-Path "\\$($Servername)")) {
    Write-Host "[!] Can't access $($serverName), skipping Find-ServerCSVFile!"
    return $null
  }
  if (!($null -eq $Location)) { $Location = "data\secaud" }  # Default to \\$servername\data\secaud if can't read from config..
  if (Test-Path "\\$($ServerName)\$($Location)") {
    $CSVFilename=(Get-ChildItem "\\$($ServerName)\$($Location)" -Filter "*.csv" | Sort-Object LastWriteTime | Select-Object -last 1).FullName
    Write-Host "[i] Found file: $CSVFileName" -ForegroundColor Blue
    return $CSVFilename 
  } else {
    return $null
  }
}

function Start-Browser {
  param ($url)
  #Start-Process "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" -ArgumentList "$($url)"   # No, lets just load the URL in the systems default browser..
  Start-Process "$($url)"
}

Function Add-VulnToQIDList {
  param ( $QIDNum,
          $QIDName,
          $QIDVar)
  if ($QIDsAdded -notcontains $QIDNum) {
    $QIDsListFile = $ConfigFile  # Default to using the ConfigFile.. fix this later!
    if (Get-YesNo "New vulnerability found: [QID$($QIDNum)] - [$($QIDName)] - Add?") {
      Write-Verbose "[v] Adding to variable in $($QIDsListFile): Variable: $($QIDVar)"
      if ($Automated) { Write-Output "[QID$($QIDNum)] - [$($QIDName)] - Adding" }
      $QIDLine = (Select-String  -Path $QIDsListFile -pattern $QIDVar).Line
      Write-Verbose "[v] Found match: $QIDLine"
      $QIDLineNew = "$QIDLine,$QIDNum"    
      Write-Verbose "[v] Replaced with: $QIDLineNew"
      $QIDFileNew=@()
      ForEach ($str in $(Get-Content -path $QIDsListFile)) {
        if ($str -like "*$($QIDLine)*") {
          Write-Verbose "Replaced: `n$str with: `n$QIDLineNew"
          $QIDFileNew += $QIDLineNew
        } else {
          $QIDFileNew += $str
        }
      }
      $QIDFileNew | Set-Content -path $QIDsListFile -Force
      
      $QIDsAdded += $QIDNum
      Write-Verbose "[!] Adding $QIDNum to QIDsAdded. QIDsAdded = $QIDsAdded"
    }
  } else {
    Write-Output "[.] QID $QIDNum already added, skipping"
    Write-Verbose "Found $QIDNum in $QIDsAdded"
  }
}

function Download-NewestAdobeReader {
    # determining the latest version of Reader
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"
    $result = Invoke-RestMethod -Uri "https://rdc.adobe.io/reader/products?lang=mui&site=enterprise&os=Windows%2011&country=US&nativeOs=Windows%2010&api_key=dc-get-adobereader-cdn" `
        -WebSession $session `
        -Headers @{
            "Accept"="*/*"
            "Accept-Encoding"="gzip, deflate, br"
            "Accept-Language"="en-US,en;q=0.9"
            "Origin"="https://get.adobe.com"
            "Referer"="https://get.adobe.com/"
            "Sec-Fetch-Dest"="empty"
            "Sec-Fetch-Mode"="cors"
            "Sec-Fetch-Site"="cross-site"
            "sec-ch-ua"="`" Not A;Brand`";v=`"99`", `"Chromium`";v=`"101`", `"Google Chrome`";v=`"101`""
            "sec-ch-ua-mobile"="?0"
            "sec-ch-ua-platform"="`"Windows`""
            "x-api-key"="dc-get-adobereader-cdn"
    }

    $version = $result.products.reader[0].version
    $version = $version.replace('.','')

    # downloading
    $URI = "https://ardownload2.adobe.com/pub/adobe/acrobat/win/AcrobatDC/$Version/AcroRdrDCx64$($Version)_MUI.exe"
    #$OutFile = Join-Path $tmp "AcroRdrDCx64$($version)_MUI.exe"
    $OutFile = "$($tmp)\readerdc.exe"
    Write-Host "[.] Downloading version $version from $URI to $OutFile"
    Invoke-WebRequest -Uri $URI -OutFile $OutFile -Verbose

    Write-Output "[!] Download complete."
    return $OutFile
}
function Get-ServicePermIssues {
  param ([string]$Results)
  <#  Example:
$str=@'
------------------------------------------------------------	 	 	 	
c:\dolphin\dolphintaskservice.exe	 	 	 	
------------------------------------------------------------	 	 	 	
Users	access-allowed	INHERITED_ACE	append_data execute standard_write_dac standard_read standard_delete standard_write_owner read_extended_attributes read_data synchronize write_data write_extended_attributes write_attributes read_attributes delete_child	
------------------------------------------------------------	 	 	 	
c:\dolphin\dolphinserver.exe	 	 	 	
------------------------------------------------------------	 	 	 	
Users	access-allowed	INHERITED_ACE	append_data execute standard_write_dac standard_read standard_delete standard_write_owner read_extended_attributes read_data synchronize write_data write_extended_attributes write_attributes read_attributes delete_child	
------------------------------------------------------------	 	 	 	
c:\dolphin\dolphinoceanservice.exe	 	 	 	
------------------------------------------------------------	 	 	 	
Users	access-allowed	INHERITED_ACE	append_data execute standard_write_dac standard_read standard_delete standard_write_owner read_extended_attributes read_data synchronize write_data write_extended_attributes write_attributes read_attributes delete_child#
'@
  #>
  $ServicePermIssues = @()
  $maxresults = (([regex]::Matches($Results, "------------------------------------------------------------")).count / 2) # Determine the number of service permission issues
  $ResultsSplit=$Results.split("`n").split("`r")
  foreach ($result in $ResultsSplit) {
    #Write-Verbose "ServicePermIssueResult: $result"
    if ($result -match '\:\\') {     # This SHOULD be safe due to the format accesschk.exe results
      $ServicePermIssues += $result.trim()
    } else {
      #Write-Verbose "Unmatched result: $result"
    }
  }
  #Write-Verbose "Service Permission Issues found: $ServicePermIssues"
  return $ServicePermIssues
}

Function Check-ServiceFilePerms {
param ([string]$FilesToCheck)
  $RelevantList = @("Everyone","BUILTIN\Users","BUILTIN\Authenticated Users","BUILTIN\Domain Users")
  $Output = @() 
  ForEach ($FileToCheck in $FilesToCheck) { 
    $Acl = Get-Acl -Path $FileToCheck   #.FullName   #Not using object from gci
    ForEach ($Access in $Acl.Access) { 
      Write-Verbose "Identity for $($FileToCheck):       $($Access.IdentityReference)"
      #$RelevantList
      if ($RelevantList -contains $Access.IdentityReference) {
        #$Access.FileSystemRights
        if (($Access.FileSystemRights -match "FullControl") -or ($Access.FileSystemRights -like "*Write*")) {
          $Properties = [ordered]@{'Folder Name'=$FileToCheck;'Group/User'=$Access.IdentityReference;'Permissions'=$Access.FileSystemRights;'Inherited'=$Access.IsInherited} 
          $Output += New-Object -TypeName PSObject -Property $Properties 
        }
      }
    }
  }
  Return $Output   # If something is returned, this is not good
}

Function Check-FilePerms {
param ([string]$FilesToCheck)
  #$RelevantList = @("Everyone","Users","Authenticated Users","Domain Users")
  Write-Verbose "Checking file perms for $FilesToCheck .."
  $Output = @() 
  ForEach ($FileToCheck in $FilesToCheck) { 
    $Acl = Get-Acl -Path $FileToCheck   #.FullName   #Not using object from gci
    ForEach ($Access in $Acl.Access) { 
      $Properties = [ordered]@{'Folder Name'=$FileToCheck;'Group/User'=$Access.IdentityReference;'Permissions'=$Access.FileSystemRights;'Inherited'=$Access.IsInherited} 
      $Output += New-Object -TypeName PSObject -Property $Properties 
    }
  }
  Return $Output
} 

function Set-AdminACLsFolder {
param ([string]$RedirectPath)
    $ErrorActionPreference="SilentlyContinue"

    #Using provided path, gather array of user folders to populate usernames
    $list = "$RedirectPath" | get-childitem
    Foreach ($l in $list) {
        #username is name of folder
        $user = $l.name
        # Filepath is folder.FullName
        $path = $l.FullName
        # Force recursive ownership for BUILTIN/Administrators of the folder using builtin Takeown.exe
        TAKEOWN /F $path /A /R /D "Y"
        # Apply full access permissions for both the user and administrators with ICACLS
        ICACLS $path /grant Administrators:F /T 
        #Use AD to check whether user is active/exists and act accordingly
        If (Get-ADUser $user) {
            ICACLS $path /grant "${user}:F" /T 
            # Apply ownership back to user with ICACLS, again, if still exists in AD
            ICACLS $path /setowner "$user" /T
        }
    }
}

function Delete-Folder {
  param ([string]$FolderToDelete,
         [string]$Results)

  if (Test-Path $FolderToDelete -PathType Container) {
    if (Get-YesNo "Found Folder $($FolderToDelete). Try to remove? ") { 
      takeown.exe /a /r /d Y /f $($FolderToDelete)
      Remove-Item $FolderToDelete -Force -Recurse
      # Or, try { and delete with psexec like below function.. Will come back to this if needed.
    } else {
      Write-Output "[!] NOT FIXED. $FolderToDelete can't be removed.  Manual intervention will be required!"
    }
  } else {
    Write-Output "[!] NOT FIXED. $FolderToDelete cannot be found with Test-Path, or might not be a Container type. Manual intervention will be required!"
  }
}

function Delete-File {
  param ([string]$FileToDelete,
         [string]$Results)
  
  if (Test-Path $FileToDelete -PathType Leaf) {
    if (Get-YesNo "Found file $($FileToDelete). Try to remove? ") { 
      Remove-Item $FileToDelete -Force  -ErrorAction SilentlyContinue
      if (Test-Path $FileToDelete -PathType Leaf) { # If it fails:
        Write-Output "[!] Could not remove file with Remove-Item -Force .. Trying Psexec method.."
        if (!(Test-Path -Path "$($oldpwd)\psexec.exe")) {
          Write-Output "[!] Cannot run psexec.exe - not found in $($oldpwd)\psexec.exe by Test-Path ! Fix manually.."
        } else {
          Copy-Item -Path "$($oldpwd)\psexec.exe" -Destination "$($tmp)\psexec.exe" -Force
          
          $exe = "$($tmp)\psexec.exe"
          $params = "-accepteula -s cmd.exe /c 'del /s /f /q ""$($FileToDelete)""'"
          Write-Output "Running: $exe $params"
          $process = Start-Process -FilePath $exe -ArgumentList $params -Wait -Passthru -WindowStyle Hidden
          $process.StandardOutput
          $process.StandardError
          
        }
      }
    } else {
      Write-Output "[!] NOT FIXED. $FileToDelete won't be removed, user chose not to.  Manual intervention will be required!"
    }
  } else {
    Write-Output "[!] NOT FIXED. $FileToDelete cannot be found with Test-Path, or might not be a Leaf type.  Manual intervention will be required!"
  }
}

function Parse-ResultsFolder {  
  param ([string]$Results)
  # Example:
  #   %systemdrive%\Users\Ben-Doctor.CHILDERSORTHO\AppData\Roaming\Zoom\bin\Zoom.exe  Version is  5.9.1.2581#
  # should return:
  # C:\Users\Ben-Doctor.CHILDERSORTHO\AppData\Roaming\Zoom\bin
  $PathResults = ($Results -split('Version is')).trim()
  $PathRaw = Split-Path ($PathResults.replace("%appdata%","$env:appdata").replace("%computername%","$env:computername").replace("%home%","$env:home").replace("%systemroot%","$env:systemroot").replace("%systemdrive%","$env:systemdrive").replace("%programdata%","$env:programdata").replace("%programfiles%","$env:programfiles").replace("%programfiles(x86)%","$env:programfiles(x86)").replace("%programw6432%","$env:programw6432"))
  return $PathRaw
} 

function Parse-ResultsFile {  
  param ([string]$Results)
  # Example:
  #   %systemdrive%\Users\Ben-Doctor.CHILDERSORTHO\AppData\Roaming\Zoom\bin\Zoom.exe  Version is  5.9.1.2581#
  # should return:
  # C:\Users\Ben-Doctor.CHILDERSORTHO\AppData\Roaming\Zoom\bin
  $PathResults = ($Results -split('Version is')).trim()
  $PathRaw = $PathResults.replace("%appdata%","$env:appdata").replace("%computername%","$env:computername").replace("%home%","$env:home").replace("%systemroot%","$env:systemroot").replace("%systemdrive%","$env:systemdrive").replace("%programdata%","$env:programdata").replace("%programfiles%","$env:programfiles").replace("%programfiles(x86)%","$env:programfiles(x86)").replace("%programw6432%","$env:programw6432")
  return $PathRaw
}

############################################# MAIN ###############################################

if (!(Test-Path $($tmp))) {
  try {
    Write-Host "[ ] Creating $($tmp) .." -ForegroundColor Gray
    $null=New-Item $($tmp) -ItemType Directory -ErrorAction SilentlyContinue
  } catch {
    Write-Host "[X] Couldn't create folder $($tmp) !! This is needed for temporary storage." -ForegroundColor Red
    Exit
  }
}

$oldpwd=(Get-Location).Path
if (!(Test-Path $tmp)) {
  New-Item -Type Directory "$tmp" -Force -ErrorAction SilentlyContinue
}
Set-Location "$($tmp)"  # Cmd.exe cannot be run from a server share

$CSVFilename = Find-ServerCSVFile "$($ServerName)\$($CSVLocation)"
if ($null -eq $CSVFilename) {
  $CSVFilename = Find-LocalCSVFile "."
}
# READ CSV
if ($null -eq $CSVFilename) {
  Write-Host "[X] Couldn't find CSV file : $CSVFilename " -ForegroundColor Red
  Exit
} else {
  try {
    $CSVData = Import-CSV $CSVFilename # -Header "Account Name,Vulnerability Report ID,IP,DNS,NetBIOS,QG Host ID,OS,IP Status,QID,Title,Vuln Status,Type,Severity,Port,Protocol,FQDN,SSL,First Detected,Last Detected,Times Detected,Date Last Fixed,CVE ID,Vendor Reference,Threat,Impact,Solution,Exploitability,Associated Malware,Result,PCI Vuln,Category,Associated Tags"
  } catch {
    Write-Host "[X] Couldn't open CSV file : $CSVFilename " -ForegroundColor Red
    Exit
  }
  if (!($CSVData)) {
    Write-Host "[X] Couldn't read CSV data from file : $CSVFilename " -ForegroundColor Red
    Exit
  } else {
    Write-Host "[i] Read CSV data from : $CSVFilename " -ForegroundColor Cyan
  }
}

######## Find if there are any new vulnerabilities not listed ########

$Rows = @()
$CSVData | ForEach-Object {
# Search by title:
  $QID=($_.QID).Replace('.0','') 

  if ($_.Title -like "Apple iCloud for Windows*") {
    if (!($QIDsAppleiCloud -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsAppleiTunes'
    }
  }
  if ($_.Title -like "Apple iTunes for Windows*") {
    if (!($QIDsAppleiTunes -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsAppleiTunes'
    }
  }
  if ($_.Title -like "Chrome*") {
    if (!($QIDsTeamviewer -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsTeamViewer'
    }
  }
  if ($_.Title -like "Firefox*") {
    if (!($QIDsFirefox -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsFirefox'
    }
  }
  if ($_.Title -like "Zoom Client*") {
    if (!($QIDsZoom -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsZoom'
    }
  }
  if ($_.Title -like "TeamViewer*") {
    if (!($QIDsTeamviewer -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsTeamViewer'
    }
  }  
  if ($_.Title -like "Dropbox*") {
    if (!($QIDsDropbox -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsDropbox'
    }
  }
  if ($_.Title -like "Oracle Java*") {            ########
    if (!($QIDsOracleJava -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsOracleJava'
    }
  }
  if ($_.Title -like "Adopt Open JDK*") {             ############
    if (!($QIDsAdoptOpenJDK -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsAdoptOpenJDK'
    }
  }
  if ($_.Title -like "VirtualBox*") {
    if (!($QIDsVirtualBox -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsVirtualBox'
    }
  }
  if ($_.Title -like "Adobe Reader*") {  
    if (!($QIDsAdobeReader -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsAdobeReader'
    }
  }
  if ($_.Title -like "Intel Graphics*") {
    if (!($QIDsIntelGraphicsDriver -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsIntelGraphicsDriver'
    }
  }
  if ($_.Title -like "NVIDIA*") {
    if (!($QIDsNVIDIA -contains $QID)) { 
      Add-VulnToQIDList $QID $_.Title  'QIDsNVIDIA'
    }
  }
  if ($_.Title -like "Dell Client*") {
    if (!($QIDsDellCommandUpdate -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsDellCommandUpdate'
    }
  }
  if ($_.Title -like "Ghostscript*") {
    if (!($QIDsGhostscript -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsGhostScript'
    }
  }

# Search by title:
  if ($_.Results -like "Microsoft vulnerable Microsoft.*") {
    if (!($QIDsUpdateMicrosoftStoreApps -contains $QID)) {
      Add-VulnToQIDList $QID $_.Title  'QIDsUpdateMicrosoftStoreApps'
    }
  }
}
Write-Output "[.] Done checking for new vulns.`n"

############################### Find applicable rows to this machine #################################
# FIND ROWS WITH HOSTNAME = $Hostname
$Rows = @()
$CSVData | ForEach-Object {
  if (($_.NetBIOS.ToUpper()) -eq $Hostname.ToUpper()) {
    $Rows += $_
  }
}

Write-Host "[i] CSV Rows applicable to $Hostname : $($Rows.Count)" -ForegroundColor Cyan
if ($Rows.Count -lt 1) {
  Write-Host "[X] There are no rows applicable to $hostname !! Exiting.." -ForegroundColor Red
  Exit
}
# $Rows

# FIND QIDS FROM THESE ROWS
$QIDs = @()
$QIDsVerbose = @()
$Rows | ForEach-Object {
  $ThisQID=[int]$_.QID.replace(".0","")
  if ($QIDsIgnored -notcontains $ThisQID) {  # FIND QIDS TO IGNORE
    $QIDs += $ThisQID
    $QIDsVerbose += "[QID$($ThisQID) - [$($_.Title)]"
    $Results=($_.Results)
    # ----------------- GRAB OTHER IMPORTANT INFO FROM THIS ROW IF NEEDED! ------------------
    switch ([int]$ThisQID) {
      372294 {
        Write-Verbose "Service permission issues found."
        Write-Verbose "Results: $Results"
        $ServicePermIssues = Get-ServicePermIssues -Results $Results
        Write-Verbose "`nServicePermIssues: "
        foreach ($issue in $ServicePermIssues) { 
          Write-Verbose "Issue: $issue"
        }
      }
    }
  } else {
    $QIDsVerbose += "[Ignored: QID$($ThisQID) - [$($_.Title)]"
  }
}

# DISPLAY QIDs FOUND FOR THIS HOST
Write-Host "[i] QIDs found: $($QIDs.Count) - $QIDs" -ForegroundColor Cyan
ForEach ($Qv in $QIDsVerbose) {  # Show ignored QIDs only if -verbose parameter is supplied
  Write-Verbose $Qv
}

if (!($QIDs)) {
  Write-Host "[X] No QIDs found to fix for $hostname !! Exiting " -ForegroundColor Red
  exit
}
Write-Host "`n"

############################################################################################################################################################################################
# APPLY FIXES FOR QIDs

foreach ($QID in $QIDs) {
    $ThisQID = $QID
    $ThisTitle = (($Rows | Where-Object { $_.QID -eq $ThisQID }) | Select-Object -First 1).Title
    $Results = (($Rows | Where-Object { $_.QID -eq $ThisQID }) | Select-Object -First 1).Results
    switch ([int]$QID)
    {
      376023 { 
        if (Get-YesNo "$_ Remove SupportAssist ? ") {
          $guid = (Get-Package | Where-Object{$_.Name -like "*SupportAssist*"})
          if ($guid) {  ($guid | Select-Object -expand FastPackageReference).replace("}","").replace("{","")  }
          msiexec /x $guid /qn /L*V "$($tmp)\SupportAssist.log" REBOOT=R
          
          # This might require interaction, in which case run this:
          msiexec /x $guid /L*V "$($tmp)\SupportAssist.log"

          # Or:
          # ([wmi]"\\$env:computername\root\cimv2:Win32_Product.$guid").uninstall()   
        }
      }
      105228 { 
        if (Get-YesNo "$_ Disable guest account and rename to NoVisitors ? " -Results $Results) {
            if ($OSVersion -ge 7) {
              Rename-LocalUser -Name "Guest" -NewName "NoVisitors" | Disable-LocalUser
            } else {
              cmd /c 'net user Guest /active:no'
              cmd /c 'wmic useraccount where name="Guest" rename NoVisitors'
            }
        }
      }
      { $QIDsSpectreMeltdown -contains $_ } {
        if (Get-YesNo "$_ Fix spectre4/meltdown ? " -Results $Results) {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 72 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f'
            #cmd /c 'reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" '
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f'
            $QIDsSpectreMeltdown = 1
        } else { $QIDsSpectreMeltdown = 1 }
      }
      110414 {
        if (Get-YesNo "$_ Fix Microsoft Outlook Denial of Service (DoS) Vulnerability Security Update August 2022 ? " -Results $Results) { 
          Invoke-WebRequest "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/outlook-x-none_1763a730d8058df2248775ddd907e32694c80f52.cab" -outfile "$($tmp)\outlook-x-none.cab"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\outlook-x-none.cab $($tmp)"
          cmd /c "msiexec /p $($tmp)\outlook-x-none.msp /qn"
        }
      }
      110413 {
        if (Get-YesNo "$_ Fix Microsoft Office Security Update for August 2022? " -Results $Results) { 
          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/msohevi-x-none_a317be1090606cd424132687bc627baffec45292.cab .."
          Invoke-WebRequest "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/msohevi-x-none_a317be1090606cd424132687bc627baffec45292.cab" -outfile "$($tmp)\msohevi-x-none.msp"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\msohevi-x-none.msp $($tmp)"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\msohevi-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\msohevi-x-none.msp"
          cmd /c "msiexec /p $($tmp)\msohevi-x-none.msp /qn"

          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab .."
          Invoke-WebRequest "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab" -outfile "$($tmp)\excel-x-none.cab"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\excel-x-none.msp $($tmp)"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\excel-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\excel-x-none.msp"
          cmd /c "msiexec /p $($tmp)\excel-x-none.msp /qn"

        }
      }
      110412 {
        if (Get-YesNo "$_ Fix Microsoft Office Security Update for July 2022? " -Results $Results) { 
          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab .."
          Invoke-WebRequest "http://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2022/06/vbe7-x-none_1b914b1d60119d31176614c2414c0e372756076e.cab" -outfile "$($tmp)\vbe7-x-none.cab"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\vbe7-x-none.msp $($tmp)"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\excel-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\vbe7-x-none.msp"
          cmd /c "msiexec /p $($tmp)\vbe7-x-none.msp /qn"
        }
      }
      91738 {
        if (Get-YesNo "$_  - fix ipv4 source routing bug/ipv6 global reassemblylimit? " -Results $Results) { 
            netsh int ipv4 set global sourceroutingbehavior=drop
            Netsh int ipv6 set global reassemblylimit=0
        }
      }
      375589 {  
        if (Get-YesNo "$_ - Delete Dell DbUtil_2_3.sys ? " -Results $Results) {
            cmd /c 'del c:\users\dbutil_2_3*.sys /s /f /q'
        }
      }
      100413 {
        if (Get-YesNo "$_ CVE-2017-8529 - IE Feature_Enable_Print_Info_Disclosure fix ? " -Results $Results) {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" /v iexplore.exe /t REG_DWORD /d 1 /f'
        }
      }
      { 105170,105171 -contains $_ } { 
        if (Get-YesNo "$_ - Windows Explorer Autoplay not Disabled ? " -Results $Results) {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\"  /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f'
            cmd /c 'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\policies\Explorer\"  /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f'
            # QID105170,105171 - disable autoplay
            $path ='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'
            $path2 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\Explorer'
            Set-ItemProperty $path -Name NoDriveTypeAutorun -Type DWord -Value 0xFF
            Set-ItemProperty $path -Name NoAutorun -Type DWord -Value 0x1
            Set-ItemProperty $path2 -Name NoDriveTypeAutorun -Type DWord -Value 0xFF
            Set-ItemProperty $path2 -Name NoAutorun -Type DWord -Value 0x1
        }
      }
      90044 {
        if (Get-YesNo "$_ - Allowed SMB Null session ? " -Results $Results) {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f'
        }
      }
      90007 {
        if (Get-YesNo "$_ - Enabled Cached Logon Credential ? " -Results $Results) {
          cmd /c 'reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount'  
          cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f'
        }
      }
      90043 {
        if (Get-YesNo "$_ - SMB Signing Disabled / Not required (Both LanManWorkstation and LanManServer)) ? " -Results $Results) {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters"  /v EnableSecuritySignature /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters"  /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters"  /v EnableSecuritySignature /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters"  /v RequireSecuritySignature /t REG_DWORD /d 1 /f'

        }
      }
      91805 {
        if (Get-YesNo "$_ - Remove Windows10 UpdateAssistant? " -Results $Results) {
            $Name="UpdateAssistant"
            $Path = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{D5C69738-B486-402E-85AC-2456D98A64E4}"

            #get-wmiobject -class Win32_Product | ?{ $_.Name -like '*Assistant*'} | Format-Table IdentifyingNumber, Name, LocalPackage -AutoSize
            #Write-Host "[ ] Finding GUID for $Name .. Please wait"  -ForegroundColor Gray
            #$GUID = (get-wmiobject -class Win32_Product | ?{ $_.Name -like $Name}).IdentifyingNumber
            $GUID= "{D5C69738-B486-402E-85AC-2456D98A64E4}"

            if ($GUID) {
                Write-Host "[ ] Removing $Name / $GUID .." -ForegroundColor White
                if (msiexec /x $GUID /qn) {
                  Write-Host "[o] Removed!" -ForegroundColor Green
                } else {
                  Write-Host "[x] Couldn't remove!" -ForegroundColor Red
                }
            } else {
              Write-Host "[x] Couldn't find $Name ! Exiting" -ForegroundColor White
            }

            Write-Host "[ ] Checking registry: `r`n  $Path  :" -ForegroundColor Gray
            try {
              $result = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue)
            } catch { 
              Write-Host "Couldn't find Registry entry!! `r`n  $Path" -ForegroundColor Green
            }
            if ($result) {
              Write-Host "[ ] Removing registry: `r`n  $Path  :" -ForegroundColor White
              try {
                Remove-Item -Path $Path\* -Recurse
              } catch {
                Write-Host "Couldn't run Remove-Item -Path $Path\* -Recurse" -ForegroundColor Red
              }
              try {
                Remove-Item -Path $Path -Recurse
              } catch {
                Write-Host "Couldn't run Remove-Item -Path $Path -Recurse"  -ForegroundColor Red
              }
            } else {
              Write-Host "Couldn't find Registry entry!! `r`n  $Path" -ForegroundColor Green
            }
        }
      }
      { $QIDsUpdateMicrosoftStoreApps -contains $_ } {
        if (Get-YesNo "$_ Update all store apps? " -Results $Results) {
          Write-Output "[+] Updating store apps.." 
          $namespaceName = "root\cimv2\mdm\dmmap"
          $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
          $wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
          $result = $wmiObj.UpdateScanMethod()
          Write-Verbose $result
          Write-Output "[+] Trying to update via WinGet .." 
          $result2 = winget upgrade --all --accept-source-agreements --accept-package-agreements --silent
          Write-Verbose $result2
          Write-Output "[!] Done!`n"    
          
        }
      }
      
        ####################################################### Installers #######################################
        # Install newest apps via Ninite

      { $QIDsGhostScript -contains $_ } {
        if (Get-YesNo "$_ Install GhostScript 10.0.0? " -Results $Results) {
          Invoke-WebRequest "https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs1000/gs1000w32.exe" -OutFile "$($tmp)\ghostscript.exe"
          cmd.exe /c "$($tmp)\ghostscript.exe /S"
          #Delete results file, i.e        "C:\Program Files (x86)\GPLGS\gsdll32.dll found#" as lots of times the installer does not clean this up..
          $FileToDelete=$results.split(' found')[0]
          Write-Host "[.] Removing $($FileToDelete) .."
          Remove-Item $FileToDelete -Force
          if (Test-Path $FileToDelete) {
            Write-Output "[x] Could not delete $($FileToDelete), please remove manually!"
          }
        }
      }
      110330 {  
        if (Get-YesNo "$_ - Install Microsoft Office KB4092465? " -Results $Results) {
            Invoke-WebRequest "https://download.microsoft.com/download/3/6/E/36EF356E-85E4-474B-AA62-80389072081C/mso2007-kb4092465-fullfile-x86-glb.exe" -outfile "$($tmp)\kb4092465.exe"
            cmd.exe /c "$($tmp)\kb4092465.exe /quiet /passive /norestart"
        }
      }
      372348 {
        if (Get-YesNo "$_ - Intel Chipset INF util ? " -Results $Results) {
            Invoke-WebRequest "https://downloadmirror.intel.com/30553/eng/setupchipset.exe" -OutFile "$($tmp)\setupchipset.exe"
            # "https://downloadmirror.intel.com/30553/eng/setupchipset.exe"
            cmd /c "$($tmp)\setupchipset.exe -s -accepteula  -norestart -log $($tmp)\intelchipsetinf.log"
            # This doesn't seem to be working, lets just download it and run it for now..
            #cmd /c "$($tmp)\setupchipset.exe -log $($tmp)\intelchipsetinf.log"
            # may be 'Error: this platform is not supported' ..
        }
      }
      372300 {
        if (Get-YesNo "$_ - Intel RST ? " -Results $Results) {
            Invoke-WebRequest "https://downloadmirror.intel.com/655256/SetupRST.exe" -OutFile "$($tmp)\setuprst.exe"
            cmd /c "$($tmp)\setuprst.exe -s -accepteula -norestart -log $($tmp)\intelrstinf.log"
            # OR, extract MSI from this exe and run: 
            # msiexec.exe /q ALLUSERS=2 /m MSIDTJBS /i “RST_x64.msi” REBOOT=ReallySuppress
        }   
      }
      { $QIDsIntelGraphicsDriver  -contains $_ } {
        if (Get-YesNo "$_ Install newest Intel Graphics Driver? " -Results $Results) { 
          Write-Output "[!] THIS WILL NEED TO BE RUN MANUALLY... OPENING BROWSER TO INTEL SUPPORT ASSISTANT PAGE!"
          explorer "https://www.intel.com/content/www/us/en/support/intel-driver-support-assistant.html"
           <#
            #  Intel Graphics driver - https://www.intel.com/content/www/us/en/support/products/80939/graphics.html
            $CPUName = (gwmi win32_processor).Name
            $CPUModel=$CPUName.split('-')[1].split(' ')[0]   # Hope this stays working.. Looks good here.
            $CPUGeneration = $CPUModel[0]
            Write-Output "[.] Found CPU: $CPUName"
            if ($CPUName -like "*i3*") { 
              # Use this to pick the correct driver from the Intel page..
              # Looks like they all point to the same driver so I guess this isn't needed.. Lets still check at least that the computer has an intel i* proc
              wget "https://downloadmirror.intel.com/30196/a08/win64_15.40.5171.exe" -OutFile "$($tmp)\intelgraphics.exe"  
            } else {
              if ($CPUName -like "*i5*") { 
                 wget "https://downloadmirror.intel.com/30196/a08/win64_15.40.5171.exe" -OutFile "$($tmp)\intelgraphics.exe"
                 $rest=$CPUName.split('i5-')[1]
              } else {
                if ($CPUName -like "*i7*") { 
                   wget "https://downloadmirror.intel.com/30196/a08/win64_15.40.5171.exe" -OutFile "$($tmp)\intelgraphics.exe"
                   $rest=$CPUName.split('i7-')[1]
                } else {
                  if ($CPUName -like "*i9*") { 
                    wget "https://downloadmirror.intel.com/30196/a08/win64_15.40.5171.exe" -OutFile "$($tmp)\intelgraphics.exe"
                    $rest=$CPUName.split('i9-')[1]
                  } else {
                    Write-Output "[X] Error: No Intel CPU found!" 
                  }
                }
              }
            }
            cmd /c "$($tmp)\intelgraphics.exe"
            #>
            $QIDsIntelGraphicsDriver = 1 # All done, remove variable to prevent this from running twice
        } else { $QIDsIntelGraphicsDriver=1 }
      }
      
      { $QIDsAppleiCloud -contains $_ } {
        <#
        if (Get-YesNo "$_ Install newest Apple iCloud? ") { 
            Invoke-WebRequest "" -OutFile "$($tmp)\icloud.exe"
            cmd /c "$($tmp)\icloud.exe"
            $QIDsAppleiCloud = 1 # All done, remove variable to prevent this from running twice
        } else { $QIDsAppleiCloud = 1 } # Do not ask again
        #>
        # https://silentinstallhq.com/apple-icloud-install-and-uninstall-powershell/  # THIS SHOULD BE USEFUL.....
        "$_ Can't deploy Apple iCloud via script yet!!! Please install manually! Opening Browser to iCloud page: "
        explorer "https://apps.microsoft.com/store/detail/icloud/9PKTQ5699M62?hl=en-us&gl=us"
      }
      { $QIDsAppleiTunes -contains $_ } {
        if (Get-YesNo "$_ Install newest Apple iTunes? " -Results $Results) { 
            Invoke-WebRequest "https://ninite.com/itunes/ninite.exe" -OutFile "$($tmp)\itunes.exe"
            cmd /c "$($tmp)\itunes.exe"
            $QIDsAppleiTunes = 1 # All done, remove variable to prevent this from running twice
        } else { $QIDsAppleiTunes = 1 } # Do not ask again
      }
      { $QIDsChrome -contains $_ } {
        if (Get-YesNo "$_ Install newest Google Chrome? " -Results $Results) { 
            #  Google Chrome - https://ninite.com/chrome/ninite.exe
            Invoke-WebRequest "https://ninite.com/chrome/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            $QIDsChrome = 1 # All done, remove variable to prevent this from running twice
        } else { $QIDsChrome = 1 }
      }
      { $QIDsFirefox -contains $_ } {
        if (Get-YesNo "$_ Install newest Firefox? " -Results $Results) { 
            #  Firefox - https://ninite.com/firefox/ninite.exe
            Invoke-WebRequest "https://ninite.com/firefox/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            $ResultsFolder = Parse-ResultsFolder $Results
            if ($ResultsFolder -like "**") {
              Delete-Folder $ResultsFolder
            }          
            $QIDsFirefox = 1
        } else { $QIDsFirefox = 1 }
      }
      { $QIDsZoom -contains $_ } {
        if (Get-YesNo "$_ Install newest Zoom Client? " -Results $Results) { 
            #  Zoom client - https://ninite.com/zoom/ninite.exe
            Invoke-WebRequest "https://ninite.com/zoom/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            #If Zoom folder is in another users AppData\Local folder, this will not work
            Delete-Folder (Parse-ResultsFolder $Results)
            $QIDsZoom = 1
        } else { $QIDsZoom = 1 }
      }
      { $QIDsTeamViewer -contains $_ } {
        if (Get-YesNo "$_ Install newest Teamviewer? " -Results $Results) { 
            #  Teamviewer - https://ninite.com/teamviewer15/ninite.exe
            Invoke-WebRequest "https://ninite.com/teamviewer15/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            $QIDsTeamViewer = 1
        } else { $QIDsTeamViewer = 1 }
      }
      { $QIDsDropbox -contains $_ } {
        if (Get-YesNo "$_ Install newest Dropbox? " -Results $Results) { 
            #  Dropbox - https://ninite.com/dropbox/ninite.exe
            Invoke-WebRequest "https://ninite.com/dropbox/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            $QIDsDropbox = 1
        } else { $QIDsDropbox = 1 }
      }
  
        ############################
        # Others: (non-ninite)
  
      { $QIDsOracleJava -contains $_ } {
        if (Get-YesNo "$_ Check Oracle Java for updates? " -Results $Results) { 
            #  Oracle Java 17 - https://download.oracle.com/java/17/latest/jdk-17_windows-x64_bin.msi
            #wget "https://download.oracle.com/java/18/latest/jdk-18_windows-x64_bin.msi" -OutFile "$($tmp)\java17.msi"
            #msiexec /i "$($tmp)\java18.msi" /qn /quiet /norestart
            . "c:\Program Files (x86)\Common Files\Java\Java Update\jucheck.exe"
            $QIDsOracleJava = 1
        } else { $QIDsOracleJava = 1 }
      }
      { $QIDsAdoptOpenJDK -contains $_ } {
        if (Get-YesNo "$_ Install newest Adopt Java JDK? " -Results $Results) { 
            Invoke-WebRequest "https://ninite.com/adoptjavax8/ninite.exe" -OutFile "$($tmp)\ninitejava8x64.exe"
            cmd /c "$($tmp)\ninitejava8x64.exe"
            $QIDsAdoptOpenJDK = 1
        } else { $QIDsAdoptOpenJDK = 1 }
      }
      { $QIDsVirtualBox -contains $_ } {
        if (Get-YesNo "$_ Install newest VirtualBox 6.1.36? " -Results $Results) { 
            Invoke-WebRequest "https://download.virtualbox.org/virtualbox/6.1.36/VirtualBox-6.1.36-152435-Win.exe" -OutFile "$($tmp)\virtualbox.exe"
            cmd /c "$($tmp)\virtualbox.exe"
            $QIDsVirtualBox = 1
        } else { $QIDsVirtualBox = 1 } 
      }
      { $QIDsDellCommandUpdate -contains $_ } {
        if (Get-YesNo "$_ Install newest Dell Command Update? " -Results $Results) { 
            #wget "https://dl.dell.com/FOLDER08334704M/2/Dell-Command-Update-Windows-Universal-Application_601KT_WIN_4.5.0_A00_01.EXE" -OutFile "$($tmp)\dellcommand.exe"
            cmd /c "\\server\data\secaud\Dell-Command-Update-Application_W4HP2_WIN_4.5.0_A00_02.EXE /s"
            $QIDsDellCommandUpdate  = 1
        } else { $QIDsDellCommandUpdate  = 1 }
      }
      { 105734 -eq $_ } {
        if (Get-YesNo "$_ Remove older versions of Adobe Reader ? " -Results $Results) { 
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'Adobe Reader*'})
          if ($Products) {
            Remove-Software $Products -Results $Results
          } else {
            Write-Host "[!] Adobe products not found under 'Adobe Reader*' $Products !!`n" -ForegroundColor Red
          }  
        }
      }
      { $QIDsAdobeReader -contains $_ } {
        if (Get-YesNo "$_ Install newest Adobe Reader DC ? ") {
          Download-NewestAdobeReader
          #cmd /c "$($tmp)\readerdc.exe"
          $Outfile = "$($tmp)\readerdc.exe"
          # silent install
          Start-Process -FilePath $Outfile -ArgumentList "/sAll /rs /rps /msi /norestart /quiet EULA_ACCEPT=YES" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile

          $QIDsAdobeReader = 1
        } else { $QIDsAdobeReader = 1 }
      }
      { $QIDsMicrosoftSilverlight -contains $_ } {
        $Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like '{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00}'})
        if ($Products) {
            Remove-Software $Products -Results $Results
            $QIDsMicrosoftSilverlight = 1
        } else {
          Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
          $QIDsMicrosoftSilverlight = 1
        } 
      }
      { $QIDsSQLServerCompact4 -contains $_ } {
        $Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like '{78909610-D229-459C-A936-25D92283D3FD}'})
        if ($Products) {
            Remove-Software $Products -Results $Results
            $QIDsSQLServerCompact4 = 1
        } else {
          Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
          $QIDsSQLServerCompact4  = 1
        } 
      }
      { $QIDsMicrosoftAccessDBEngine -contains $_ } {
        $Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like '{90120000-00D1-0409-0000-0000000FF1CE}' -or `
                                                           $_.IdentifyingNumber -like '{90140000-00D1-0409-1000-0000000FF1CE}'})
        if ($Products) {
            Remove-Software $Products -Results $Results
            $QIDsMicrosoftAccessDBEngine = 1
        } else {
          Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
          $QIDsMicrosoftAccessDBEngine = 1
        }
      }
      { $QIDsMicrosoftVisualStudioActiveTemplate -contains $_ } {
        $notfound = $true
        if (Get-YesNo "$_ $_ Install Microsoft Visual C++ 2005/8 Service Pack 1 Redistributable Package MFC Security Update? " -Results $Results) { 
          $Installed=get-wmiobject -class Win32_Product | Where-Object{ $_.Name -like '*Microsoft Visual*'} # | Format-Table IdentifyingNumber, Name, LocalPackage -AutoSize
          if ($Installed | Where-Object {$_.IdentifyingNumber -like '{9A25302D-30C0-39D9-BD6F-21E6EC160475}'}) { 
              Write-Host "[!] Found Microsoft Visual C++ 2008 Redistributable - x86 "
              $notfound = $false
              Invoke-WebRequest "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe" -OutFile "$($tmp)\vcredist2008x86.exe"
              cmd /c "$($tmp)\vcredist2008x86.exe /q"
              $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | Where-Object { $_.IdentifyingNumber -like '{837b34e3-7c30-493c-8f6a-2b0f04e2912c}'}) {
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable"
            $notfound = $false
            Invoke-WebRequest "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -OutFile "$($tmp)\vcredist2005.exe"
            cmd /c "$($tmp)\vcredist2005.exe /q"
            $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | Where-Object { $_.IdentifyingNumber -like '{710f4c1c-cc18-4c49-8cbf-51240c89a1a2}'}) {
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable - x86"
            $notfound = $false
            Invoke-WebRequest "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -OutFile "$($tmp)\vcredist2005x86.exe"
            cmd /c "$($tmp)\vcredist2005x86.exe /q"
            $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | Where-Object { $_.IdentifyingNumber -like '{6E8E85E8-CE4B-4FF5-91F7-04999C9FAE6A}'}) { #x64
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable - x64 "
            $notfound = $false
            Invoke-WebRequest "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" -OutFile "$($tmp)\vcredist2005x64.exe"
            cmd /c "$($tmp)\vcredist2005x64.exe /q"
            $QIDsMicrosoftVisualStudioActiveTemplate = 1
          } 

            <# PATCHED versions:
            IdentifyingNumber                      Name                                                           LocalPackage
            -----------------                      ----                                                           ------------
            {ad8a2fa1-06e7-4b0d-927d-6e54b3d31028} Microsoft Visual C++ 2005 Redistributable (x64)                C:\Windows\Installer\4cd95b2e.msi
            {5FCE6D76-F5DC-37AB-B2B8-22AB8CEDB1D4} Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161 c:\Windows\Installer\4cd95b3a.msi
            {9BE518E6-ECC6-35A9-88E4-87755C07200F} Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161 c:\Windows\Installer\4cd95b36.msi
            {710f4c1c-cc18-4c49-8cbf-51240c89a1a2} Microsoft Visual C++ 2005 Redistributable                      C:\Windows\Installer\4cd95b32.msi
            #>
          if ($notfound) {
            Write-Host "[!] Guids not found among: " -ForegroundColor Red
            $Installed
            Write-Host "`n"
            $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }  
        }
      }
      { $QIDsMicrosoftNETCoreV5 -contains $_ } {
            <# Remove one or all of these??
            IdentifyingNumber                      Name                                           LocalPackage
            -----------------                      ----                                           ------------
            {8BA25391-0BE6-443A-8EBF-86A29BAFC479} Microsoft .NET Host FX Resolver - 5.0.17 (x64) C:\Windows\Installer\a3227a.msi
            {5A66E598-37BD-4C8A-A7CB-A71C32ABCD78} Microsoft .NET Runtime - 5.0.17 (x64)          C:\Windows\Installer\a32276.msi
            {E663ED1E-899C-40E8-91D0-8D37B95E3C69} Microsoft .NET Host - 5.0.17 (x64)             C:\Windows\Installer\a3227f.msi


            For now, will remove just the Runtime which I believe is the only vulnerability..  Maybe we remove all 3 though, will find out.
            #>
            $Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like '{5A66E598-37BD-4C8A-A7CB-A71C32ABCD78}'})
            if ($Products) {
                Remove-Software $Products -Results $Results
                $QIDsMicrosoftNETCoreV5 = 1
            } else {
              Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
              $QIDsMicrosoftNETCoreV5 = 1
            }             
      }
      91304 {  # Microsoft Security Update for SQL Server (MS16-136)
        $inst = (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -ErrorAction SilentlyContinue).InstalledInstances
        foreach ($i in $inst)
        {
          $p = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL').$i
          $SQLVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Version
          $SQLEdition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Edition
        }  # Version lists: https://sqlserverbuilds.blogspot.com/
        <#
        SQL Server 2016	13.0.1601.5				
        Support end date: 2021-07-13	+ CU9				
        Ext. end date: 2026-07-14					
        
        SQL Server 2014	12.0.2000.8				
        Support end date: 2019-07-09	+ CU14				
        Ext. end date: 2024-07-09					
        
        Obsolete versions – out of support					
        SQL Server 2012	11.0.2100.60				
        codename Denali	+ CU11				
        Support end date: 2017-07-11					
        Ext. end date: 2022-07-12					
        
        SQL Server 2008 R2	10.50.1600.1				
        SQL Server 10.5					
        codename Kilimanjaro					
        Support end date: 2014-07-08					
        Ext. end date: 2019-07-09					
        
        SQL Server 2008	10.0.1600.22				
        SQL Server 10					
        codename Katmai					
        Support end date: 2014-07-08					
        Ext. end date: 2019-07-09					
#>
        if (Get-YesNo "$_ Install SQL Server $SQLVersion $SQLEdition update? " -Results $Results) { 
          if ("$SQLVersion $SQLEdition" -eq "12.2.5000.0 Express Edition") { # SQL Server 2014 Express
            Invoke-WebRequest "https://www.microsoft.com/en-us/download/confirmation.aspx?id=54190&6B49FDFB-8E5B-4B07-BC31-15695C5A2143=1" -OutFile "$($tmp)\sqlupdate.exe"
            cmd /c "$($tmp)\sqlupdate.exe /q"
          }
          if ("$SQLVersion $SQLEdition" -eq "12.2.5000.0 Standard Edition") { # SQL Server 2014
            Invoke-WebRequest "https://www.microsoft.com/en-us/download/confirmation.aspx?id=57474&6B49FDFB-8E5B-4B07-BC31-15695C5A2143=1" -OutFile "$($tmp)\sqlupdate.exe"
            cmd /c "$($tmp)\sqlupdate.exe /q"
          }
        }
      }
      { $QIDsNVIDIA -contains $_ } {
        if (Get-YesNo "$_ Install newest NVidia drivers ? " -Results $Results) { 
            $NvidiacardFound = $false
            Write-Host "[.] Video Cards found:"
            foreach($gpu in Get-WmiObject Win32_VideoController) {  
              Write-Host $gpu.Description
              if ($gpu.Description -like '*NVidia*') {
                $NvidiacardFound = $true
              }
            }
            if ($NvidiacardFound) {
              Start-Browser "https://www.nvidia.com/download/index.aspx"
              Write-Host "[!] Download and install latest NVidia drivers.. Manual fix!"
            } else {
              Write-Host "[!] No NVIDIA Card found, should be save to remove."
              if (Get-YesNo "$_ Remove NVIDIA PrivEsc exe c:\windows\system32\nvvsvc.exe ? ") { 
                cmd.exe /c "taskkill /f /im nvvsvc.exe"
                cmd.exe /c "del %windir%\System32\nvvsvc.exe"
              }
            }
        } else { $QIDsNVIDIA = 1 }
      }
      { 370468 -contains $_ } {
        $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'Cisco WebEx*'})
        if ($Products) {
            Remove-Software $Products  -Results $Results
        } else {
          Write-Host "[!] Product not found: 'Cisco WebEx*' !!`n" -ForegroundColor Red
        }         
      }
      19472 {
        if (Get-YesNo "$_ Install reg key for Microsoft SQL Server sqldmo.dll ActiveX Buffer Overflow Vulnerability - Zero Day (CVE-2007-4814)? " -Results $Results) { 
          # Set: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{10020200-E260-11CF-AE68-00AA004A34D5}  Compatibility Flags 0x400
          New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility" -Name "{10020200-E260-11CF-AE68-00AA004A34D5}"
          New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{10020200-E260-11CF-AE68-00AA004A34D5}" -Name "Compatibility Flags" -Value 0x400
        }
      }
	
      100269 {
        if (Get-YesNo "$_ Install reg keys for Microsoft Internet Explorer Cumulative Security Update (MS15-124)? " -Results $Results) { 
          New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
          New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Name "iexplore.exe" -Value 1
          New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
          New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Name "iexplore.exe" -Value 1
        } 
      }
      90954 {
        if (Get-YesNo "$_ Install reg key for 2012 Windows Update For Credentials Protection and Management (Microsoft Security Advisory 2871997) (WDigest plaintext remediation)? " -Results $Results) { 
          New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
        }
      }
      91621 {
        if (Get-YesNo "$_ Microsoft Defender Elevation of Privilege Vulnerability April 2020? " -Results $Results) { 
          # This will ask twice due to Delete-File, but I want to offer results first. Could technically add -Results to Delete-File..
          Delete-File "C:\WINDOWS\System32\MpSigStub.exe"
        }
      }
      91649 {
        if (Get-YesNo "$_ Microsoft Defender Elevation of Privilege Vulnerability June 2020? " -Results $Results) { 
          Delete-File "$($env:ProgramFiles)\Windows Defender\MpCmdRun.exe"
        }
      }

      372294 {
        if (Get-YesNo "$_ Fix service permissions issues? " -Results $Results) {
          #Write-Verbose $ServicePermIssues
          foreach ($file in $ServicePermIssues) {
            if (!(Check-ServiceFilePerms $file)) {
              Write-Output "[+] Permissions are good for $file "
            } else { # FIX PERMS.
              
              $objACL = Get-ACL $file
              Write-Output "[.] Checking owner of $file .. $($objacl.Owner)"
              # Check for file owner, to resolve problems setting inheritance (if needed)
              if ($objacl.Owner -notlike "*$($env:USERNAME)") { # also allow [*\]User besides just User
                if (Get-YesNo "Okay to take ownership of $file as $($env:USERNAME) ?") {
                  $objacl.SetOwner([System.Security.Principal.NTAccount] $env:USERNAME)
                } else { 
                  Write-Output "[.] WARNING: Likely the changes will fail, we are not the owner."
                }
              }
              try {
                Set-ACL $file -AclObject $objACL  
              } catch {
                Write-Output "[!] ERROR: Couldn't set owner to $($env:Username) on $($file) .."
              }
              $objACL = Get-ACL $file
              Write-Verbose "[.] Checking inheritance for $file - $(!($objacl.AreAccessRulesProtected)).."
              if (!($objACL.AreAccessRulesProtected)) {  # Inheritance is turned on.. Lets turn it off for this one file.
                # Remove inheritance, resulting ACLs will be limited
                Write-Output "[.] Turning off inheritance for $file"
                $objacl.SetAccessRuleProtection($true,$true)  # 1=protected?, 2=copy inherited ACE? we will modify below
                #$objacl.SetAccessRuleProtection($true,$false)  # 1=protected?, 2=drop inherited rules
                try {
                  Set-ACL $file -AclObject $objACL  
                } catch {
                  Write-Output "[!] ERROR: Couldn't set inheritance on $($file) .."
                }
              }
              Write-Output "[.] Removing Everyone full permissions on $file .."
              $Right = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
              $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None 
              $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly  
              $objType = [System.Security.AccessControl.AccessControlType]::Allow 
              $objUser = New-Object System.Security.Principal.NTAccount("Everyone") 
              $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                  ($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
              $objACL = Get-ACL $file
              $objACL.RemoveAccessRuleAll($objACE) 
              try {
                Set-ACL $file -AclObject $objACL  
              } catch {
                Write-Output "[!] ERROR: Couldn't remove Everyone-full permissions on $file .."
              }
              Write-Output "[.] Removing Users-Write/Modify/Append permissions on $file .."
              # .. Remove write/append/etc from 'Users'. First remove Users rule completely.
              $objUser = New-Object System.Security.Principal.NTAccount("Users") 
              $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                  ($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
              $objACL = Get-ACL $file 
              try {
                $objACL.RemoveAccessRuleAll($objACE) 
              } catch {
                Write-Output "[!] ERROR: Couldn't reset Users permissions on $file .."
              }
              # Then add ReadAndExecute only for Users
              $Right = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
              $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                  ($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
              $objACL.AddAccessRule($objACE) 
              try {
                Set-ACL $file -AclObject $objACL  
              } catch {
                Write-Output "[!] ERROR: Couldn't modify Users to R+X permissions on $file .."
              }
              # Check that issue is actually fixed
              if (!(Check-ServiceFilePerms $file)) {
                Write-Output "[+] Permissions are good for $file "
              } else {
                Write-Output "[!] WARNING: Permissions NOT fixed on $file .. "
                Check-FilePerms "$($file)"
              }
            }
          }
          <# 
          # Old code to check with accesschk.. couldn't get this quite right..
          Write-Output "[.] Downloading accesschk.exe from live.Sysinternals.com to check that this is fixed.."
          wget "https://live.sysinternals.com/accesschk.exe" -outfile "\\dc-server\data\secaud\accesschk.exe"
          $AccesschkEveryone = (start-process "\\dc-server\data\secaud\accesschk.exe" -ArgumentList "-accepteula -uwcqv ""Everyone"" *" -WorkingDirectory $env:temp -NoNewWindow)
          $AccesschkUsers = (start-process "\\dc-server\data\secaud\accesschk.exe" -ArgumentList "-accepteula -uwcqv ""Users"" *" -WorkingDirectory $env:temp -NoNewWindow)
          $AccesschkAuthUsers = (start-process "\\dc-server\data\secaud\accesschk.exe" -ArgumentList "-accepteula -uwcqv ""Authenticated Users"" *" -WorkingDirectory $env:temp -NoNewWindow)
          foreach ($a in $AccesschkUsers) {
            Write-Output "[+] $a"
          }
          #>
        }
      }
      91848 {
        if (Get-YesNo "$_ Install Store Installer app update to 1.16.13405.0 ? " -Results $Results) { 
          # Requires -RunAsAdministrator
          Begin {}
          Process {
            if ([version]'1.16.13405.0' -gt [version](Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue).Version) {
              $zip = (Join-Path -Path $tmp -ChildPath 'Microsoft.DesktopAppInstaller_1.16.13405.0_8wekyb3d8bbwe.zip')
              $zipFolder = "$($zip -replace '\.zip','')"
              if (-not(Test-Path -Path $zip)) {
                $HT = @{
                  Uri = 'https://download.microsoft.com/download/6/6/8/6680c5b1-3fbe-4b70-8189-90ea08609563/Microsoft.DesktopAppInstaller\_1.16.13405.0\_8wekyb3d8bbwe.zip'
                  UseBasicParsing = $true
                  ErrorAction = 'Stop'
                  OutFile = $zip
                }
                try {
                  Invoke-WebRequest @HT
                } catch {
                  Write-Warning -Message "Failed to download zip because $($_.Exception.Message)"
                }
              }
              if (Test-Path -Path $zip) {
                if ((Get-FileHash -Path $zip).Hash -eq 'e79cea914ba04b953cdeab38489b3190fcc88e566a43696aaefc0eddba1af6ab' ) {
                  try {
                    Expand-Archive -Path $zip -DestinationPath (Split-Path $zipFolder -Parent) -Force -ErrorAction Stop
                  } catch {
                    Write-Warning -Message "Failed to unzip because $($_.Exception.Message)"
                  }
                  if ('Valid' -in (Get-ChildItem -Path "$($zipFolder)\*" -Include * -Recurse -Exclude '*.xml' | Get-AuthenticodeSignature | Select-Object -ExpandProperty Status | Sort-Object -Unique)) {
                    $HT = @{
                      Online = $true
                      PackagePath = Join-Path -Path $zipFolder -ChildPath 'Microsoft.DesktopAppInstaller_1.16.13405.0_8wekyb3d8bbwe.msixbundle'
                      SkipLicense = $true
                      ErrorAction = 'Stop'
                    }
                    try {
                      $r = Add-AppxProvisionedPackage @HT
                      if ($r.Online) {
                        Write-Verbose 'Successfully provisionned Microsoft.DesktopAppInstaller' -Verbose
                      }
                    } catch {
                      Write-Warning -Message "Failed to install Appx because $($_.Exception.Message)"
                    }
                  }
                } else {
                  Write-Warning -Message "Downloaded zip file thumbprint (SHA256) doesn't match"
                }
              } else {
                Write-Warning -Message "Zip file $($zip) not found"
              }
            } else {
              Write-Verbose -Message 'Current Microsoft.DesktopAppInstaller appx version is not vulnerable' -Verbose
            }
          }
        }
      }
      Default {
        Write-Host "[X] Skipping QID $_ : " -ForegroundColor Red -NoNewline
        Write-Host "$ThisTitle" -ForegroundColor White
      }
    }
}

Write-Host "[o] Done! Stopping transcript" -ForegroundColor Green
Set-Location $oldpwd
# Disabling the file deletion step for now, EPDR keeps killing the script for being 'suspicious' at this point.
#Write-Host "[.] Deleting all temporary files from $tmp .."
#Remove-Item -Path "$tmp" -Recurse -Force -ErrorAction SilentlyContinue
Stop-Transcript
if (!($Automated)) {
  $null = Read-Host "--- Press enter to exit ---"
}
