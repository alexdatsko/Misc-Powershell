[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Automated = $false,    # this allows us to run without supervision and apply all changes (could be dangerous!)
  [string] $CSVFile,               # Allow user to pick a CSV file on the commandline
  [int[]] $OnlyQIDs,               # Allow user to pick a list of QID(s) to remediate
  [int] $QID,                      # Allow user to pick one QID to remediate
  [switch] $Help                   # Allow -Help to display help for parameters
)

$AllHelp = "########################################################
# Install-SecurityFixes.ps1
# Alex Datsko - alex.datsko@mmeconsulting.com

<#
.SYNOPSIS
    This script installs security fixes for some Qualys scan items, and offers to apply the fixes.
.DESCRIPTION
    This script takes an output of a Qualys scan in a CSV file, determines if the hostname is present in the file, and applies fixes as needed.
.PARAMETER Help
    Displays help information for the script.
.PARAMETER CSVFile
    Specifies the path to the CSV file to use.
.PARAMETER Automated
    Indicates whether the script is running in automated mode. Fixes will be applied automatically.
.PARAMETER QID
    Pick a certain QID to remediate, i.e 105170
.PARAMETER OnlyQIDs
    Pick a smaller list of QIDs to remediate, i.e 1,2,5
.PARAMETER Verbose
    Enables verbose output for detailed information.
#>
"

if ($Help) {
  $parameterNames = $PSBoundParameters.Keys -join ', '
  Write-Verbose "Providing help for $parameterNames .."
  # Lets just print this here for now, because I can't seem to get the appropriate Get-Help commands to work, ugh.

  Write-Host $AllHelp
  exit
}

#Clear

$CheckOptionalUpdates = $true                # Set this to false to ignore Optional Updates registry value
$AlreadySetOptionalUpdates = $false          # This is to make sure we do not keep trying to set the Optional Updates registry value.
$oldPwd = $pwd                               # Grab location script was run from
$UpdateBrowserWait = 60                      # Default to 60 seconds for updating Chrome, Edge or Firefox with -Automated. Can be overwritten in Config, for slower systems.. 
$Update7zipWait = 30                         # How long to wait for the 7-zip Ninite updater to finish and close
$UpdateDellCommandWait = 60                  # How long to wait for Dell Command Update to re-install/update
$ConfigFile = "$oldpwd\_config.ps1"          # Configuration file 
$QIDsListFile = "$oldpwd\QIDLists.ps1"       # QID List file 
$tmp = "$($env:temp)\SecAud"                 # "temp" Temporary folder to save downloaded files to, this will be overwritten when checking config ..
$OSVersion = ([environment]::OSVersion.Version).Major
$SoftwareInstalling=[System.Collections.ArrayList]@()
$QIDsAdded = @()
$QIDSpecific=@()
if ($OnlyQIDs) {
  $QIDSpecific=[System.Collections.Generic.List[int]]$OnlyQIDs
  Write-Verbose "-OnlyQIDs parameter found: $QIDSpecific"
}
if ($QID) {
  $QIDSpecific=[int]$QID
  Write-Verbose "-QID parameter found: $QIDSpecific"
}


# Start a transscript of what happens while the script is running
try {
  Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
}
catch [System.InvalidOperationException]{}

if (!(Test-Path $tmp)) { New-Item -ItemType Directory $tmp }

$dateshort= Get-Date -Format "yyyy-MM-dd"
try {
  Start-Transcript "$($env:temp)\Install-SecurityFixes_$($dateshort).log" -ErrorAction SilentlyContinue
} catch {
  if ($Error[0].Exception.Message -match 'Transcript is already in progress') {
    Write-Warning '[!] Start-Transcript: Already running.'
  } else {
    # re-throw the error if it's not the expected error
    throw $_
  }
}

# ----------- Script specific vars:  ---------------

#### VERSION ###################################################

# No comments after the version number on the next line- Will screw up updates!
$Version = "0.38.27"
# New in this version:   Fixed logic in KB check,  if ([version]$CheckEXEVersion -lt [version]$ResultsVersion) {  instead of LE, also fixed output, correct variable
$VersionInfo = "v$($Version) - Last modified: 4/8/2024"

#### VERSION ###################################################

# Common URL Variables for updates:
$AgentString = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"
$DCUUrl = "https://dl.dell.com/FOLDER10791703M/1/Dell-Command-Update-Application_44TH5_WIN_5.1.0_A00.EXE"
$DCUFilename = ($DCUUrl -split "/")[-1]
$DCUVersion = (($DCUUrl -split "_WIN_")[1] -split "_A0")[0]

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Output "`n[!] Not running under Admin context - Re-launching as admin!"
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $Command = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $Command
        Set-Location $pwd
        Exit
  }
}

# Change title of window
$host.ui.RawUI.WindowTitle = "$($env:COMPUTERNAME) - Install-SecurityFixes.ps1"

# Try to use TLS 1.2, this fixes many SSL problems with downloading files, before TLS 1.2 is not secure any longer.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($Automated) {
  Write-Host "`n[!] Running in automated mode!`n"   -ForegroundColor Red
}

####################################################### FUNCTIONS #######################################################

function Print-YesNoHelp {
  Write-Host "[?] Legend: (Not case sensitive)"
  Write-Host "  Y = Yes"
  Write-Host "  N = No"
  Write-Host "  A = Automated mode, assumes yes to this and every other question"
  Write-Host "  ? = (Print this list)"
  Write-Host "  S = Show Results from CSV"
}

function Get-YesNo {
  param ([string] $text,
         [string] $results)
  
  $done = 0
  if (!($Automated)) { 
    while ($done -eq 0) {
      $yesno = Read-Host  "`n[?] $text [y/N/a/s/?] "
      if ($yesno.ToUpper()[0] -eq 'Y') { return $true } 
      if ($yesno.ToUpper()[0] -eq 'N' -or $yesno -eq '') { return $false } 
      if ($yesno.ToUpper()[0] -eq 'A') { $script:Automated = $true; $global:Automated = $true; Write-Host "[!] Enabling Automated mode! Ctrl-C to exit"; return $true } 
      if ($yesno.ToUpper()[0] -eq '?') { Print-YesNoHelp } 
      if ($yesno.ToUpper()[0] -eq 'S') { 
          Write-Host "[i] Results: " -ForegroundColor Yellow
          foreach ($result in $Results) {
            Write-Host "$($result)" -ForegroundColor Yellow
          }
       }
    }
  } else {  # Automated mode. Show results for -Verbose, then apply fix
    Write-Verbose "[i] AUTOMATED: Results: "
    foreach ($result in $Results) {
      Write-Verbose "$($result)"
    }
    Write-Host "[+] AUTOMATED: Choosing yes for $text .."
    return $true
  }
}

################################################# SCRIPT FUNCTIONS ###############################################

function Set-RegistryEntry {
  param(
      [string]$Path = "HKLM:\Software\MME Consulting Inc\Install-SecurityFixes",
      [string]$Name,
      [int]$Value = 1
  )

  if (-Not(Test-Path -Path $Path)) {
    Write-Verbose "Set-RegistryEntry: !! (Test-Path -Path $Path) - Creating"
    New-Item -Path $Path -Force | Out-Null
  }
  Write-Verbose "Set-RegistryEntry: Creating: Set-ItemProperty -Path $Path -Name $Name -Value $Value"
  Set-ItemProperty -Path $Path -Name $Name -Value $Value
}

function Get-RegistryEntry {
  param(
      [string]$Path = "HKLM:\Software\MME Consulting Inc\Install-SecurityFixes",
      [string]$Name
  )
  $Reg = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue)
  if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {  # If the path exists, check if the property exists
    if (($Reg).PSObject.Properties.Name -contains $Name) {
      Write-Verbose "Get-RegistryEntry: !! The property exists, return its value : $Path / $Name"
      return ($Reg).$Name
    } else {
      Write-Verbose "Get-RegistryEntry: !! (Get-ItemProperty -Path $Path).PSObject.Properties.Name -contains $Name)"
    }
  } else {
    Write-Verbose "Get-RegistryEntry: !! (Test-Path -Path $Path) - Creating"
    if (-Not(Test-Path -Path $Path)) {
      New-Item -Path $Path -Force | Out-Null
    }
  }
  return 0
}

function Read-QIDLists {    # NOT USING!!!!
  # READ IN VALUES FROM QIDsList 
  if ($QIDsListFile -like "*.ps1") {
    if (Test-Path $QIDsListFile) {
      try {
        #. "$($QIDsListFile)"  # This does not import our variables for global use..
        $scriptContent = Get-Content $QIDsListFile -Raw
        $scriptBlock = [scriptblock]::Create($scriptContent)
    
        # Invoke the script block in the global scope
        &$scriptBlock
        foreach ($variableName in $scriptBlock.Variables.Keys) {
            # Define each variable in the global scope
            #$global:$variableName = $scriptBlock.Variables[$variableName]  # Need to do this for all other vars, not ideal.. skipping this for now.
        }
      } catch {
        Write-Output "`n`n[!] ERROR: Couldn't import $($QIDsListFile) !! Exiting"
        Stop-Transcript
        Set-Location $pwd
        Exit
      }
    } else {
      Write-Output "`n`n[!] Warning: Couldn't find $($QIDsListFile) .. Will try to update.."
    }
    # Update will be done separately..
  }
}

function Get-OSVersion {
  return (Get-CimInstance Win32_OperatingSystem).version
}

function Get-NewerScriptVersion {   # Check in ps1 file for VersionStr and report back if its newer than the current value ($VersionToCheck), returns version# if so.
  param ([string]$Filename,
         [string]$VersionStr,
         [string]$VersionToCheck)
  
  $FileContents = Get-Content $Filename
  $TotalLines = $FileContents.Length
  Write-Verbose "[.] Loaded $TotalLines lines from $($Filename) .. Checking for $($VersionStr)"
  foreach ($line in $FileContents) {
    if ($line -like "$VersionStr") {
      if ($line -like '#') {  # Handle comment on same line, i.e: $Version = "1.2.3.0" # Comment ..
        $VersionFound = $line.split('=')[1].split("#")[0].trim().replace('"','')
      } else {
        $VersionFound = $line.split('=')[1].trim().replace('"','')
      }
      Write-Verbose " New script version: $([version]$VersionFound)"
      #if ($OSVersionMaj -ge 10) { Write-Verbose " New script version Hex: $($VersionFound | Format-Hex)" }
      Write-Verbose " Current version: $([version]$VersionToCheck) "
      #if ($OSVersionMaj -ge 10) { Write-Verbose " Current version hex: $($VersionToCheck | Format-Hex)" }
      if ([version]$VersionFound -gt [version]$VersionToCheck) {
        Write-Verbose "[+] Version found $($VersionFound) is newer than $($VersionToCheck)"
        return $VersionFound;
      }
      if ([version]$VersionFound -eq [version]$VersionToCheck) {
        Write-Verbose "[=] Version found is the same: $([version]$VersionFound)"
        return $false;
      }
      if ([version]$VersionFound -lt [version]$VersionToCheck) {
        Write-Verbose "[-] Version found $($VersionFound) is older than $($VersionToCheck)"
        return $false;
      }
    }
  }
  #Write-Output "[.] ERROR: Script version not found in version from Github!?! You must be testing a new version.  Setting Automated=false"
  return $false;
}

function Update-File {  # Not even used currently, but maybe eventually?
  param ([string]$url,
        [string]$FilenameTmp,
        [string]$FilenamePerm, 
        [string]$VersionStr,
        [string]$VersionToCheck)
  if ((Invoke-WebRequest -UserAgent $AgentString -Uri $url).StatusCode -eq 200) { 
    $SplitPath = [System.IO.DirectoryInfo](Split-Path $FilenameTmp -Parent)
    if (!(Test-Path $SplitPath)) {  # This should have been done earlier, but maybe not, lets try to create the $env:temp\Secaud folder
      New-Item -ItemType Directory $SplitPath  
    }
    $client = new-object System.Net.WebClient
    $client.Encoding = [System.Text.Encoding]::ascii
    $client.DownloadFile("$url","$($FilenameTmp)")
    $client.Dispose()
    Write-Verbose "[.] File downloaded, checking version.."
    Write-Verbose "[.] Checking downloaded file $($FilenameTmp) .."
    $NewVersionCheck = (Get-NewerScriptVersion -Filename "$($FilenameTmp)" -VersionStr $($VersionStr) -VersionToCheck $VersionToCheck)
    if ($NewVersionCheck) {  
        If (Get-YesNo "Found newer version $($NewVersionCheck), would you like to copy over this one? ") {
          Copy-Item "$($FilenameTmp)" "$($FilenamePerm)" -Force
        }
        return $true
    } else {
      Write-Verbose "Continuing without updating file $($FilenamePerm)."
    }
  }  
  return $false
}

function Update-ScriptFile {   # Need a copy of this, to re-run main script
  param ([string]$url,
        [string]$FilenameTmp,
        [string]$FilenamePerm, 
        [string]$VersionStr,
        [string]$VersionToCheck)
  
  Write-Verbose "Checking for $($VersionStr) >= $($VersionToCheck) in $($FilenamePerm) .. Downloading $($url)"
  
  if ((Invoke-WebRequest -UserAgent $AgentString -Uri $url).StatusCode -eq 200) { 
    $client = new-object System.Net.WebClient
    $client.Encoding = [System.Text.Encoding]::ascii
    $client.DownloadFile("$url","$($FilenameTmp)")
    $client.Dispose()
    Write-Verbose "[.] File downloaded, checking version.."
    Write-Verbose "[.] Checking downloaded file $($FilenameTmp) .."
    $NewVersionCheck = (Get-NewerScriptVersion -Filename "$($FilenameTmp)" -VersionStr $($VersionStr) -VersionToCheck $VersionToCheck)
    Write-Verbose "var = $NewVersionCheck"
    if ($NewVersionCheck) {  
        if (Get-YesNo "Found newer version $NewVersionCheck, would you like to copy over this one? ") {
          # Copy the new script over this one..
          Copy-Item "$($FilenameTmp)" "$($FilenamePerm)" -Force
          return $true
        }
    } else {
      Write-Verbose "Continuing without updating."
      return $false
    }
    return $false
  }  
}

function Get-Vars {
  $vars = ""
  if ($Automated) { $vars += " -Automated" }
  if ($Verbose) { $vars += " -Verbose" }
  if ($CSVFile) { $vars += " -CSVFile $CSVFile" }
  if ($Help) { $vars += " -Help" }
  Write-Verbose "Get-Vars: Vars = '$Vars'"
  return $vars
}

Function Update-Script {
  # For 0.32 I am assuming $pwd is going to be the correct path
  Write-Host "[.] Checking for updated version of script on github.. Current Version = $($Version)"
  $url = "https://raw.githubusercontent.com/alexdatsko/Misc-Powershell/main/Install-SecurityFixes.ps1%20-%20Script%20which%20will%20apply%20security%20fixes%20as%20needed%20to%20each%20workstation%20resultant%20from%20a%20Qualys%20vuln%20scan/Install-SecurityFixes.ps1"
  if (Update-ScriptFile -URL $url -FilenameTmp "$($tmp)\Install-SecurityFixes.ps1" -FilenamePerm "$($pwd)\Install-SecurityFixes.ps1" -VersionStr '$Version = *' -VersionToCheck $Version) {
    Write-Host "[+] Update found, re-running script .."
    Stop-Transcript
    $Vars = Get-Vars
    Write-Verbose "Re-running script with Vars: '$Vars'"
    . "$($pwd)\Install-SecurityFixes.ps1" $Vars  # Dot source and run from here once, then exit.
    Stop-Transcript
    exit
  } else {
    Write-Host "[-] No update found for $($Version)."
    return $false
  }
}

Function Update-QIDLists {
  # For 0.32 I am assuming $pwd is going to be the correct path
  if (!($QIDsVersion)) { $QIDsVersion = "0.01" }   # If its missing, assume its super old.
  Write-Host "[.] Checking for updated QIDLists file on github.. Current Version = $($QIDsVersion)"  # Had to change to Write-Host, Write-Output is being send back to caller
  $url = "https://raw.githubusercontent.com/alexdatsko/Misc-Powershell/main/Install-SecurityFixes.ps1%20-%20Script%20which%20will%20apply%20security%20fixes%20as%20needed%20to%20each%20workstation%20resultant%20from%20a%20Qualys%20vuln%20scan/QIDLists.ps1"
  if (Update-ScriptFile -URL $url -FilenameTmp "$($tmp)\QIDLists.ps1" -FilenamePerm "$($pwd)\QIDLists.ps1" -VersionStr '$QIDsVersion = *' -VersionToCheck $QIDsVersion) {
    Write-Host "[+] Updates found, reloading QIDLists.ps1 .."
    return $true
    #Read-QIDLists  # Doesn't work in this scope, do it below in global scope
  } else {
    Write-Host "[-] No update found for $($QIDsVersion)."
    return $false
  }
  return $false
}

Function Get-OS {
    # Slower, calls 3 CIMinstances, not sure if needed anywhere
    $cs = Get-WmiObject -Class Win32_ComputerSystem
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $bios = Get-WmiObject -Class Win32_BIOS

    Return [PSCustomObject]@{
        OSName = $os.Caption
        OSVersion = $os.Version
        OSBuild = $os.BuildNumber
        OSArchitecture = $os.OSArchitecture
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
        BIOSVersion = $bios.SMBIOSBIOSVersion
    }
}

Function Get-OSVersionInfo {
    # Returns more than Major.Minor.Build .. for caption basically
    $os = Get-WmiObject -Class Win32_OperatingSystem

    Return [PSCustomObject]@{
        Caption = $os.Caption
        Version = $os.Version
        Build = $os.BuildNumber
        Architecture = $os.OSArchitecture
    }
}

Function Get-OSType {  # 1=Workstation, 2=DC, 3=Server
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $ostype=[int]$os.productType
    Return [int]$ostype
}

Function Install-DellBiosProvider {
  # install the DellBIOSProvider powershell module if set in the config
  if ($InstallDellBIOSProvider) {
    if (Get-RegistryEntry -Name "DellProviderModule" -eq "0") {
      if ([int](Get-OSType) -lt 2) {   # 1=Ws, 2=DC, 3=Server
        if (!(Get-InstalledModule -Name DellBIOSProvider -ErrorAction SilentlyContinue)) {
          Write-Host "[.] Trying to install the NuGet package provider.. [this may take a minute..]" 
          try { $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force } catch { Write-Host "[!] Couldn't install NuGet provider!" ; return $false}
          Write-Host "[.] Trying to install the Dell BIOS provider module.. [this may take a minute..]" 
          try { Install-Module DellBIOSProvider -Force } catch { 
            Write-Host "[!] Couldn't install DellBIOSProvder! "
            $vcredistUrl = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=30679&6B49FDFB-8E5B-4B07-BC31-15695C5A2143=1"
            Write-Host "[.] Trying to install VC 2012 U4 package, but it may require a reboot after. Downloading from: $vcredistUrl"
            try { 
              Invoke-WebRequest -UserAgent $AgentString -Uri $vcredistUrl -outfile "$env:temp\SecAud\vc2012redist_x64.exe" 
            } catch { 
              Write-Host "[!] Failed to download $vcredistUrl !!" -ForegroundColor Red
            }
            if (Test-Path "$env:temp\SecAud\vc2012redist_x64.exe") {
              Write-Host "[.] Trying to install VC 2012 U4 package, but it may require a reboot after."
              try { 
                . "$env:temp\SecAud\vc2012redist_x64.exe" "/q" 
                Write-Host "[+] Looks to have succeeded. The workstation will need a reboot for this to apply properly and the DellBIOSProvider module to work properly." -ForegroundColor Green
              } catch {
                Write-Host "[!] Couldn't install VC 2012 U4 package!" -ForegroundColor Red
                return $false 
              }
              return $false 
            }
          }
          Write-Host "[+] Done!" -ForegroundColor Green
          return $true
        } else {
          Write-Host "[.] DellBIOSProvider already installed." 
          return $true
        }
      } else {
        Write-Verbose "[.] Non-Workstation OS found, ignoring DellBiosProvider module install"
        return $false
      }
    }
  }
}

Function Set-DellBiosProviderDefaults {
  if ((Get-ComputerInfo).OsProductType -eq "WorkStation") { 
    if ($InstallDellBIOSProvider -and $SetWOL) {  # Set WOL settings per model
      if (!(Get-InstalledModule -Name DellBIOSProvider)) {
        Write-Host "[!] No DellBIOSProvder - Can't set WOL"
      } else {
        # For testing, just check and set these 2..
        if (Import-Module DellBIOSProvider) {
          Write-Host "[.] Checking for AcPwrRcvry=On & WakeonLAN=Enabled in DellSMBios:\ .." 
          $AcPwrRcvry=Get-Item -Path DellSMBios:\PowerManagement\AcPwrRcvry
          $WakeonLAN=Get-Item -Path DellSMBios:\PowerManagement\WakeonLAN
          if (!($AcPwrRcvry)) { 
            Write-Host "[.] Setting AcPwrRcvry=On in DellSMBios:\ .."
            try { Set-Item -Path DellSMBios:\PowerManagement\AcPwrRcvry -Value "On" } catch { Write-Host "[.] Couldn't set AcPwrRecvry=On !!" -ForegroundColor Red }
          } else {
            Write-Host "[+] Found AcPwrRcvry=On already"
          }
          if (!($WakeonLAN)) {
            Write-Host "[.] Setting WakeonLAN=Enabled in DellSMBios:\ .."
            try { Set-Item -Path DellSMBios:\PowerManagement\WakeonLAN -Value "Enabled" } catch { Write-Host "[.] Couldn't set WakeonLAN=Enabled !!" -ForegroundColor Red }
          } else {
            Write-Host "[+] Found WakeonLAN=Enabled already"
          }
          Write-Host "[+] Done w/ Dell SMBios settings." -ForegroundColor Green
          Set-RegistryEntry -Name "DellProviderModule" -Value 1 # Set this so we only try it once!
        } else {
          Write-Host "[-] Dell SMBios issue running 'Import-Module DellBiosProvider' - can't set WakeOnLan etc." -ForegroundColor Red
        }
      }
    }
  } else {
    Write-Verbose "[.] Non-Workstation OS found, ignoring DellBiosProvider changes"
  }
}

function Convert-WuaResultCodeToName {
  param( [Parameter(Mandatory=$true)]
    [int] $ResultCode
  )
  $Result = $ResultCode
  switch($ResultCode) {
    2 {
      $Result = "Succeeded"
    }
    3 {
      $Result = "Succeeded With Errors"
    }
    4 {
      $Result = "Failed"
    }
  }
 return $Result
}

function Get-WuaHistory {
  # Get a WUA Session
  $session = (New-Object -ComObject 'Microsoft.Update.Session')
  # Query the latest 1000 History starting with the first recordp
  $history = $session.QueryHistory("",0,50) | ForEach-Object {
    $Result = Convert-WuaResultCodeToName -ResultCode $_.ResultCode
    # Make the properties hidden in com properties visible.
    $_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
    $Product = $_.Categories | Where-Object {$_.Type -eq 'Product'} | Select-Object -First 1 -ExpandProperty Name
    $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
    $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
    $_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru
    Write-Output $_
  }
  #Remove null records and only return the fields we want
  $history |
    Where-Object {![String]::IsNullOrWhiteSpace($_.title)} |
    Select-Object Result, Date, Title, SupportUrl, Product, UpdateId, RevisionNumber
}

function Check-ResultsForFiles {  # 03-29-2024
  param( [Parameter(Mandatory=$true)]
    [string] $Results
  )
  # This returns MULTIPLE Filenames from $Results. 

  # Example:
  #   KB5033920 is not installed  %windir%\Microsoft.NET\Framework64\v2.0.50727\System.dll Version is 2.0.50727.9175 %windir%\Microsoft.NET\Framework\v2.0.50727\System.dll Version is 2.0.50727.9175 %windir%\Microsoft.NET\Framework64\v4.0.30319\System.dll Version is 4.8.9206.0 %windir%\Microsoft.NET\Framework\v4.0.30319\System.dll Version is 4.8.9206.0 KB5034275 or KB5034274 or KB5034276 is not installed#
  #   KB5034122 is not installed  %windir%\system32\ntoskrnl.exe  Version is  10.0.19041.3693#
  #   KB5034184 is not installed  %windir%\system32\win32k.sys  Version is  6.2.9200.24518#
  #   %systemdrive%\Users\Doctor.SMO\AppData\Roaming\Zoom\bin\Zoom.exe  Version is  5.1.28642.705#   (This one is caught below for Zoom, but for example...)
  # 92099:
  #  KB5034184 is not installed  %windir%\system32\win32k.sys  Version is  6.2.9200.24518#
  # 92103:
  #  KB5034184 is not installed  %windir%\system32\win32k.sys  Version is  6.2.9200.24518# (added .sys)
  foreach ($Result in ($Results -split('Version is').trim())) {  # Lets catch multiples like the first example
    if ($Result -like "*.dll*") {
      if ($Result -like "*%windir%*") {
        $CheckFile = $env:windir+(($Result -split "%windir%")[1]).trim()   # THESE WILL NOT WORK WITH SPACES IN THE PATH
      } else {
        if ($Result -like "*%systemdrive%*") {
          $CheckFile = $env:systemdrive+(($Result -split "%systemdrive%")[1]).trim() # ..
        } else {
          Write-Verbose "- Can't split $Result"
        }
      }
    } else {
      if ($Result -like "*.exe*") {
        if ($Result -like "*%windir%*") {
          $CheckFile = $env:windir+(($Result -split "%windir%")[1]).trim()   # THESE WILL NOT WORK WITH SPACES IN THE PATH
        } else {
          if ($Result -like "*%systemdrive%*") {
            $CheckFile = $env:systemdrive+(($Result -split "%systemdrive%")[1]).trim() # ..
          } else {
            Write-Verbose "- Can't split $Result"
          }
        }
      } else {
        if ($Result -like "*.sys*") {
          if ($Result -like "*%windir%*") {
            $CheckFile = $env:windir+(($Result -split "%windir%")[1]).trim()   # THESE WILL NOT WORK WITH SPACES IN THE PATH
          } else {
            if ($Result -like "*%systemdrive%*") {
              $CheckFile = $env:systemdrive+(($Result -split "%systemdrive%")[1]).trim() # ..
            } else {
              Write-Verbose "- Can't split $Result"
            }
          }
        }
      }
    }
    Write-Verbose "CheckFile : $CheckFile"
    $CheckFile = $CheckFile.trim().replace("%ProgramFiles%",(Resolve-Path -Path "$env:ProgramFiles").Path).replace("%ProgramFiles(x86)%",(Resolve-Path -Path "${env:ProgramFiles(x86)}").Path)
    $CheckFile = $CheckFile.replace("%windir%",(Resolve-Path -Path "${env:WinDir}").Path).trim()
    $CheckFiles += $CheckFile
  }
  return $CheckFile
}

function Check-ResultsForFile {  # 03-28-2024
  param( [Parameter(Mandatory=$true)]
    [string] $Results
  )
  # This returns a SINGULAR Filename from the $Results. The first one only..

  # Example:
  #   KB5033920 is not installed  %windir%\Microsoft.NET\Framework64\v2.0.50727\System.dll Version is 2.0.50727.9175 %windir%\Microsoft.NET\Framework\v2.0.50727\System.dll Version is 2.0.50727.9175 %windir%\Microsoft.NET\Framework64\v4.0.30319\System.dll Version is 4.8.9206.0 %windir%\Microsoft.NET\Framework\v4.0.30319\System.dll Version is 4.8.9206.0 KB5034275 or KB5034274 or KB5034276 is not installed#

  # Lets check the results for ' is' and replace the path stuff with actual values, as %vars% are not powershell friendly variables ..
  # There might be more variable expansion I can do, will add it here when needed
  if ($Results -clike "*Version is*") {   # ack, -clike compares case also, -like does NOT, forgot about this.
    if ($Results -clike "*is not installed*") {
      $CheckFile = (($Results -split "is not installed")[0]).trim()
    } else {
      $CheckFile = (($Results -split "Version is")[0]).trim()
    }
  } else {
    if ($Results -clike "*file version is*") {
      $CheckFile = (($Results -split "file version is")[0]).replace("#","").trim()
    }
  }
  Write-Verbose "CheckFile : $CheckFile"
  $CheckFile = $CheckFile.trim().replace("%ProgramFiles%",(Resolve-Path -Path "$env:ProgramFiles").Path).replace("%ProgramFiles(x86)%",(Resolve-Path -Path "${env:ProgramFiles(x86)}").Path)
  $CheckFile = $CheckFile.replace("%windir%",(Resolve-Path -Path "${env:WinDir}").Path).trim()
  return $CheckFile
}

function Check-ResultsForVersion {  # 03-28-2024
  param( [Parameter(Mandatory=$true)]
    [string] $Results
  )
  # This returns a SINGULAR Version from $Results. The first one only!!

  # 92014: 
  #  KB5034122 is not installed  %windir%\system32\ntoskrnl.exe  Version is  10.0.19041.3693#
  # 379369:
  #  C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.dll file version is 23.8.20470.0  C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.dll file version is 23.8.20470.0#
  # 92097: 
  #  KB5034279 or KB5034278 is not installed  %windir%\Microsoft.NET\Framework64\v2.0.50727\System.dll Version is 2.0.50727.8970 %windir%\Microsoft.NET\Framework\v2.0.50727\System.dll Version is 2.0.50727.8970 %windir%\Microsoft.NET\Framework64\v4.0.30319\System.dll Version is 4.8.4654.0 %windir%\Microsoft.NET\Framework\v4.0.30319\System.dll Version is 4.8.4654.0#
  # 100419:
  #  HKLM\Software\Microsoft\Internet Explorer Version = 9.11.9600.21615 KB5034120 is not installed  %windir%\System32\mshtml.dll  Version is  11.0.9600.21615#
  if ($Results -clike "*Version is*") {   # ack, -clike compares case also, -like does NOT, forgot about this.
    $CheckVersion = (($Results -split "Version is ")[1].trim() -split " ")[0].replace("#","").trim()
  } else {
    if ($Results -clike "*file version is*") {
      $CheckVersion = ((($Results -split "file version is")[1]) -split " ")[0].replace("#","").trim()
    } else {
      Write-Verbose "- unable to parse $Results !!"
    }
  }
  Write-Verbose "CheckVersion : $CheckVersion"
  return $CheckVersion
}


################################################# CONFIG FUNCTIONS ###############################################

function Find-ConfigFileLine {  # CONTEXT Search, a match needs to be found but NOT need to be exact line, i.e '$QIDsFlash = 1,2,3,4' returns true if '#$QIDsFlash = 1,2,3,4,9999,12345' is found
  param ([string]$ConfigLine)

  $ConfigContents = (Get-Content -path $ConfigFile)
  ForEach ($str in $ConfigContents) {
    if ($str -like "*$($ConfigLine)*") {
      return $true
    }
  }
  return $false
}

function Set-ConfigFileLine {
  param ([string]$ConfigOldLine,
         [string]$ConfigNewLine)
  if (Get-YesNo "Change [$($ConfigOldLine)] in $($ConfigFile) to [$($ConfigNewLine)] ?") {
    Write-Verbose "Changing line in $($ConfigFile): `n  Old: [$($ConfigOldLine)] `n  New: [$($ConfigNewLine)]"
    $ConfigLine = (Select-String  -Path $ConfigFile -pattern $ConfigOldLine).Line
    Write-Verbose "  Found match: [$($ConfigOldLine)]"  
    Write-Verbose "  Replaced with: [$($ConfigNewLine)]"
    $ConfigContents = (Get-Content -path $ConfigFile)
    $ConfigFileNew=@()
    ForEach ($str in $ConfigContents) {
      if ($str -like "*$($ConfigLine)*") {
        Write-Verbose "Replaced: `n$str with: `n$ConfigNewLine"
        $ConfigFileNew += $ConfigNewLine
      } else {
        $ConfigFileNew += $str
      }
    }
    $ConfigFileNew | Set-Content -path $ConfigFile -Force
  }
}

function Add-ConfigFileLine {
  param ([string]$ConfigNewLine)
  if (Get-YesNo "Add [$($ConfigLine)] to $($ConfigFile) ?") {
    $ConfigContents = Get-Content -Path $ConfigFile
    $ConfigFileNew=@()
    ForEach ($str in $ConfigContents) {
      $ConfigFileNew += $str
    }
    Write-Verbose "Adding line to $($ConfigFile): `nLine: [$($ConfigNewLine)]"
    $ConfigFileNew += $ConfigNewLine
    $ConfigFileNew | Set-Content -path $ConfigFile -Force
  } else { 
    Write-Host "[-] Skipping!"
  }
}

function Remove-ConfigFileLine {  # Wrapper for Change-ConfigFileLine 
  param ([string]$ConfigOldLine)
  Change-ConfigFileLine $ConfigOldLine ""
}

function Is-Array {  
  param($var)
  if ($var -is [array]) {
    return $true
  }
  return $false
}

function Pick-File {    # Show a list of files with a number to the left of each one, pick by number
  param (
    [array]$Filenames
  )
  
  $i=0
  $Filenames | ForEach-Object {
    Write-Host "[$i] $_" -ForegroundColor Gray
    $i += 1
  }

  if (!$Automated -and ($i -gt 1)) {
    Write-Host "[$i] EXIT" -ForegroundColor Blue
    $Selection = Read-Host "Select file to import, [Enter=0] ?"
    if ($Selection -eq $i) { Write-Host "[-] Exiting!" -ForegroundColor Gray; exit }
    if ([string]::IsNullOrEmpty($Selection)) { $Selection = "0" } else {
      $Sel = [int]$Selection
    }
    return "$($Location)\$($Filenames[$Sel])"
  } else {
    $Sel = 0
    if ($Filenames.Length -gt 1) {
      $filename = $Filenames[$Sel]
      Write-Host "[+] Using $Sel - $filename" -ForegroundColor White
      return "$($Location)\$filename"
    } else {
      # if only 1 file, return 1st file.
      Write-Host "[+] Using $Sel - $($Filenames[0])" -ForegroundColor White
      return "$($Location)\$($Filenames[0])"  
    }
  }
  
  if ($i -eq 0) {
    Write-Host "[!] No files found! Error in Pick-File" -ForegroundColor Red
    exit
  }

  Write-Host "[!] Error in Pick-File" -ForegroundColor Red
  exit
}


function Find-LocalCSVFile {
  param ([string]$Location,
         [string]$Oldpwd)
    #write-Host "Find-LocalCSVFile $Location $OldPwd"
    # FIGURE OUT CSV Filename
    Write-Verbose "Checking for CSV in Location: $Location"
    Write-Verbose "OldPwd: $oldPwd"
    if (($null -eq $Location) -or ("." -eq $Location)) { $Location = $OldPwd }
    [array]$Filenames = Get-ChildItem "$($Location)\*.csv" | ForEach-Object { $_.Name }
    if ($Filenames.Length -lt 1) {  # If no files found in $Location, check $OldPwd
      Write-Verbose "Checking for CSV in Location: $OldPwd"
      [array]$Filenames = Get-ChildItem "$($OldPwd)\*Internal*.csv" | ForEach-Object { $_.Name }  # Find only internal scans
    } 
    if (!(Is-Array $Filenames)) {  # If no files found still, error out!
      Write-Host "[!] Error, can't seem to find any CSV files (or none with 'Internal' in the filename).."
      Exit
    }
    Write-Verbose "Filenames:"
    Write-Verbose "$Filenames"
    return (Pick-File $Filenames)    
}

function Find-ServerCSVFile {
  param ([string]$Location)
  Write-Verbose "[Find-ServerCSVFile] Server Name: $Servername"
  Write-Verbose "[Find-ServerCSVFile] Location: $Location"
  if (Test-Connection -ComputerName $servername -Count 2 -Delay 1 -Quiet) {
    Write-Host "[!] Can't access '$($serverName)', skipping Find-ServerCSVFile!"
    return $null
  }
  if (!($null -eq $Location)) { $Location = "data\secaud" }  # Default to \\$servername\data\secaud if can't read from config..
  if (Test-Path "\\$($ServerName)\$($Location)") {
    $CSVFilename=(Get-ChildItem "\\$($ServerName)\$($Location)" -Filter "*.csv" | Sort-Object LastWriteTime | Select-Object -last 1).FullName
    Write-Host "[i] Found most recent CSV file: $CSVFileName" -ForegroundColor Blue
    return $CSVFilename 
  } else {
    Write-Verbose "Can't access \\$($servername)\$($Location) .."
    return $null
  }
}

function Start-Browser {
  param ($url)
  #Start-Process "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" -ArgumentList "$($url)"   
  Start-Process "$($url)"  # Lets just load the URL in the system default browser..
}

Function Add-VulnToQIDList {
  param ( $QIDNum,
          $QIDName,
          $QIDVar,
          $QIDsAdded)
  if ($QIDsAdded -notcontains $QIDNum) {
    #$QIDsListFile = $ConfigFile  # Default to using the ConfigFile.. Probably want to split this out again.. but leave for now
    if (Get-YesNo "New vulnerability found: [QID$($QIDNum)] - [$($QIDName)] - Add?") {
      Write-Verbose "[v] Adding to variable in $($QIDsListFile): Variable: $($QIDVar)"
      if ($Automated) { Write-Output "[QID$($QIDNum)] - [$($QIDName)] - Adding" }
      $QIDLine = (Select-String  -Path $QIDsListFile -pattern $QIDVar).Line
      Write-Verbose "[v] Found match: $QIDLine"
      $QIDLineNew = "$QIDLine,$QIDNum"  | Select-Object -Unique  
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
      # Can't run this here as the scope is local vs global..
      $QIDsAdded += $QIDNum
      Write-Verbose "[!] Adding $QIDNum to QIDsAdded. QIDsAdded = $QIDsAdded"
    }
  } else {
    Write-Output "[.] QID $QIDNum already added, skipping"
    Write-Verbose "Found $QIDNum in $QIDsAdded"
  }
}

################################################# VULN REMED FUNCTIONS ###############################################

function Search-Software {
  param(
    [string]$SoftwareName)

  $SearchString="*$($SoftwareName)*"
  $Results = (get-wmiobject Win32_Product | Where-Object { $_.Name -like $SearchString })
  if ($Results) {
    return $Results
  } else {
    $Results = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like $SearchString }
    if ($Results) {
      return $Results.DisplayName
    } else {
      return $null
    }
  }
}

function Remove-SoftwareByName {
  param (
      [string]$SoftwareName
  )

  # Attempt to uninstall using Win32_Product
  $wmiSoftware = (Get-WmiObject Win32_Product) | Where-Object { $_.Name -like "*$SoftwareName*" }
  if ($wmiSoftware) {
    foreach ($software in $wmiSoftware) {
      if ($software.IdentifyingNumber.length -eq 38) {  # if it looks like it has a real GUID, probably real..
        Write-Host "[-] Uninstalling $($software.Name)..." -ForegroundColor Yellow
        $software.Uninstall()
      }
    }
  } else {
      Write-Host "[.] Software '$SoftwareName' not found using Win32_Product."
      
      # Attempt to uninstall using registry
      $registrySoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                          Where-Object { $_.DisplayName -like "*$SoftwareName*" }
      if ($registrySoftware) {
          foreach ($software in $registrySoftware) {
            if ($software.PSChildName.length -eq 36) {  # if it looks like it has a real GUID, probably real..
              Write-Host "[-] Uninstalling $($software.DisplayName)..." -ForegroundColor Yellow
              if ($software.UninstallString) {
                  Start-Process -FilePath $software.UninstallString -Wait
              }
              else {
                  Write-Host "[.] Uninstall string not found for $($software.DisplayName)."
              }
            }
          }
      }
      else {
          Write-Host "[.] Software '$SoftwareName' not found in registry either."
      }
  }
}


function Remove-Software {
  param ($Products,
         $Results)
  
  foreach ($Product in $Products) { # Remove multiple products if passed.. This only works if found by 
    $Guid = $Product | Select-Object -ExpandProperty IdentifyingNumber
    $Name = $Product | Select-Object -ExpandProperty Name
    if (Get-YesNo "Uninstall $Name - $Guid ") { 
        Write-Host "[.] Removing $Guid (Waiting max of 30 seconds after).. "
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
    } else {
      Write-Host "[.] Not found in WMI, searching Uninstaller registry.."
        if (Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Where-Object DisplayName -eq "" -OutVariable Results) {
            & "$($Results.InstallLocation)\uninst.exe" /S
        }
    }
  }
}

Function Check-Products {
  param ($Products)

  $ProductsArray = @($Products)  # Ensure $Products is treated as an array

  if ($ProductsArray.Count -gt 0) {
    if ($ProductsArray[0].IdentifyingNumber[0] -eq '{') {
      return $true
    }
  }
  return $false
}

function Remove-RegistryItem {
  param ([string]$Path)

  Write-Host "[ ] Checking registry for: `n  $Path  :" -ForegroundColor Gray
  try {
    $result = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue)
  } catch { 
    Write-Host "[!] Couldn't find Registry entry!! `r`n  $Path" -ForegroundColor Green
  }
  if ($result) {
    Write-Host "[.] Removing registry item: `n  $Path  :" -ForegroundColor White
    try { # Remove $Path\*
      Remove-Item -Path $Path\* -Recurse
    } catch {
      Write-Host "[!] Couldn't run Remove-Item -Path $Path\* -Recurse !!" -ForegroundColor Red
    }
    try { # Remove $Path itself
      Remove-Item -Path $Path 
    } catch {
      Write-Host "[!] Couldn't run Remove-Item -Path $Path !!" -ForegroundColor Red
    }
    try { # Check and make sure its removed?
      $result = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue)
    } catch {
      Write-Host "[.] Complete. Registry entry verified removed: `n  $Path" -ForegroundColor Green
    }
    if ($result) {
      Write-Host "[!] Something went wrong. Not successful removing $Path .."  -ForegroundColor Red
    }
  } else {
    Write-Host "[.] Couldn't find Registry entry. Clean." -ForegroundColor Green
  }
}

function Get-NewestAdobeReader {
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
    Invoke-WebRequest -UserAgent $AgentString -Uri $URI -OutFile $OutFile -Verbose

    Write-Output "[!] Download complete."
    return $OutFile
}

function Get-ServicePermIssues {
  param ([string]$Results)

  $ServicePermIssues = @()
  $ResultsSplit = $Results.split("`n").split("`r").split("`t") -split " {2,}"   # There are no more `r or `n newlines now in BTS Qualys reports- as of 3-13-23.  So.. Also split at multiple spaces to catch these, there is likely not one in the middle of an exe filename or path, HOPEFULLY..
  # Shouldn't really matter how many lines there are if we are only looking for C:\ or _:\ separated by 2 or more spaces.. This should work!
  Write-Verbose "ServicePermIssue ResultsSplit (count): $($ResultsSplit.Count)"
  foreach ($result in $ResultsSplit) {
    #Write-Verbose "ServicePermIssueResult: $result"
    if ($result -match '\:\\') {     # This SHOULD be safe for now, due to the format accesschk.exe results
      $ServicePermIssues += $result.trim()
    } else {
      #Write-Verbose "Unmatched result: $result"
    }
  }
  Write-Verbose "Service Permission Issues found: $ServicePermIssues"
  return $ServicePermIssues
}

Function Get-ServiceFilePerms {
param ([string]$FilesToCheck)
  $RelevantList = @("Everyone","BUILTIN\Users","BUILTIN\Authenticated Users","BUILTIN\Domain Users")
  Write-Verbose "Relevant user list: $RelevantList"
  $Output = @() 
  ForEach ($FileToCheck in $FilesToCheck) { 
    $Acl = Get-Acl -Path $FileToCheck   #.FullName   #Not using object from gci
    ForEach ($Access in $Acl.Access) { 
      Write-Verbose "Identity for $($FileToCheck):       $($Access.IdentityReference)"
      if ($RelevantList -contains $Access.IdentityReference) {
        foreach ($CurrentRight in $Access.FileSystemRights) {
          Write-Verbose "FileSystemRights: $CurrentRight"
          if (($CurrentRight -match "FullControl") -or ($CurrentRight -like "*Write*")) {
            $Properties = [ordered]@{'Folder Name'=$FileToCheck;'Group/User'=$Access.IdentityReference;'Permissions'=$CurrentRight;'Inherited'=$Access.IsInherited} 
            $Output += New-Object -TypeName PSObject -Property $Properties 
          }
        }
      }
    }
  }
  Return $Output   # If something is returned, this is not good
}

Function Get-FilePerms {
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

function Remove-Folder {
  param ([string]$FolderToDelete,
         $Results)

  if (Test-Path $FolderToDelete) {
    if (Get-YesNo "Found Folder $($FolderToDelete). Try to remove? ") { 
      $null = (takeown.exe /a /r /d Y /f $($FolderToDelete) > $($tmp)/_takeown.log)
      Remove-Item $FolderToDelete -Force -Recurse
      # Or, try { and delete with psexec like below function.. Will come back to this if needed.
    } else {
      Write-Host "`n[!] NOT FIXED. $FolderToDelete can't be removed.  Manual intervention will be required!"
      return $false
    }
  } else {
    Write-Host "`n[!] $FolderToDelete cannot be found with Test-Path, or might not be a Container type.  (Maybe this has been fixed already?)"
    return $true
  }
  if (Test-Path $FolderToDelete) {
    Write-Host "`n[-] NOT FIXED. $FolderToDelete still found."
    return $false
  } else {
    Write-Host "`n[+] FIXED. $FolderToDelete has been removed." -ForegroundColor Green
    return $true
  }
}

function Remove-File {
  param ($FileToDelete,
         $Results)
  
  if (Test-Path $FileToDelete -PathType Leaf) {
    if (Get-YesNo "Found file $($FileToDelete). Try to remove? ") { 
      Remove-Item $FileToDelete -Force  -ErrorAction SilentlyContinue
      if (Test-Path $FileToDelete -PathType Leaf) { # If it fails:
        Write-Host "[!] Could not remove file with Remove-Item -Force .. Trying Psexec method.."
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
      return $false
    }
  } else {
    Write-Output "[!] $FileToDelete cannot be found with Test-Path, or might not be a Leaf type.  (Maybe this has been fixed already?)"
    return $true
  }
  if (Test-Path $FileToDelete -PathType Leaf) {
    Write-Output "[-] NOT FIXED. $FileToDelete still found." 
  } else {
    Write-Output "[+] FIXED. $FileToDelete has been removed." 
  }
}

function Get-PathRaw {
  param ([string]$ThisPath)
  return Split-Path ($ThisPath.replace("%appdata%","$env:appdata").replace("%computername%","$env:computername").replace("%home%","$env:home").replace("%systemroot%","$env:systemroot").replace("%systemdrive%","$env:systemdrive").replace("%programdata%","$env:programdata").replace("%programfiles%","$env:programfiles").replace("%programfiles(x86)%","$env:programfiles(x86)").replace("%programw6432%","$env:programw6432"))
}

function Get-FileRaw {
  param ([string]$ThisFile)
  return ($ThisFile.replace("%appdata%","$env:appdata").replace("%computername%","$env:computername").replace("%home%","$env:home").replace("%systemroot%","$env:systemroot").replace("%systemdrive%","$env:systemdrive").replace("%programdata%","$env:programdata").replace("%programfiles%","$env:programfiles").replace("%programfiles(x86)%","$env:programfiles(x86)").replace("%programw6432%","$env:programw6432"))
}

function Parse-ResultsFolder {  
  param ($Results)
 
  $Paths = @()
  $x = 0
  Write-Verbose "Results: $Results"
  $count = [regex]::Matches($Results, "Version is").Count
  Write-Verbose "Count of 'Version is': $count"
  if ($count -gt 0) {
    while ($x -le $count) {
      $PathResults = Split-Path ((($Results -split('Version is'))[0]).trim())
      Write-Verbose "PathResults : $PathResults"
      if ($null -ne $PathResults) {
        $PathRaw = Get-PathRaw $PathResults
        Write-Verbose "PathRaw : $PathRaw"
        if ($count -gt 1) {
          if (!($Paths -contains $PathRaw)) {
            $Paths += $PathRaw
          } else {
            Write-Verbose "PathRaw ($PathRaw) matches existing within : $Paths - skipping."
          }
        } else {
          return $PathRaw
        }
      }
      $x += 1
    }
  }  else {
    return $false
  }
  return $Paths  
} 

function Parse-ResultsFile {  
  [CmdletBinding()]
  param ($Results)

  $Paths = @()
  Write-Verbose "Results: $Results"
  $splits = $Results -split 'Version is'
  foreach ($split in $splits) {
    if ($split -match '%.*?\.exe') {
      # Extract file path
      $PathResults = $split -replace '#.*', '' -match '%.*?\.exe'
      $PathFinal = $Matches[0] -replace '%windir%', $env:windir -replace '%systemroot%', $env:systemroot -replace '%systemdrive%', $env:systemdrive
      $Paths += $PathFinal.Trim()
    }
  }
  return $Paths
}

function Parse-ResultsVersion {  
  [CmdletBinding()]
  param ($Results)

  $Versions = @()
  Write-Verbose "Results: $Results"
  $splits = $Results -split 'Version is'
  foreach ($split in $splits) {
    if ($split -match '\d+(\.\d+)+') {
      # Extracting version number
      $VersionResults = $split -match '\d+(\.\d+)+'
      $Versions += [version]$Matches[0]
    }
  }
  return $Versions
}

function Show-FileVersionComparison {
  [CmdletBinding()]
  param ([string]$Name, $Results)

  if ($Results -like "* Version is *") {
    $EXEFiles = Parse-ResultsFile $Results
    $EXEFileVersions = Parse-ResultsVersion $Results

    for ($i = 0; $i -lt $EXEFiles.Length; $i++) {
      $EXEFile = $EXEFiles[$i]
      $EXEFileVersion = $EXEFileVersions[$i]
      Write-Verbose "EXEFile: $EXEFile"
      Write-Verbose "EXEFileVersion: $EXEFileVersion"

      if (Test-Path -Path "$EXEFile") {
        $CurrentEXEFileVersion = "$(((gci $EXEFile -File).VersionInfo.FileVersion).Replace(",","."))"
        $color = "Red"
        $operator = if ($CurrentEXEFileVersion -gt $EXEFileVersion) { ">"; $color="Green" } elseif ($CurrentEXEFileVersion -eq $EXEFileVersion) { "=" } else { "<" }
        Write-Host "[.] $Name - Comparing new version: Filename: $EXEFile" -ForegroundColor Yellow
        Write-Host "    [ Current Version: $CurrentEXEFileVersion ] $operator [ Results Version: $EXEFileVersion ]" -ForegroundColor $color
      } else {
        Write-Host "[-] $EXEFile not found.."
      }
    }
  }
}

function Backup-BitlockerKeys {
  if ($BackupBitlocker) {
    if (Test-Path "C:\Windows\System32\manage-bde.exe") {  # If this exists, bitlocker role is at least installed
      if ((Get-BitlockerVolume -MountPoint 'C:').VolumeStatus -eq "FullyDecrypted") {
        Write-Host "[!] $($BLV) not Bitlocker encrypted!"
        return $false
      } else {
        Write-Host "[!] Found C: Bitlockered."
      }
      $BLVs = (Get-BitLockerVolume).MountPoint
      foreach ($BLV in $BLVs) { 
        if (Get-BitLockerVolume -MountPoint $BLV -ErrorAction SilentlyContinue) {
          try {
            Write-Output "[.] Backing up Bitlocker Keys to AD.."
            Backup-BitLockerKeyProtector -MountPoint $BLV -KeyProtectorId (Get-BitLockerVolume -MountPoint $BLV).KeyProtector[1].KeyProtectorId
            return $true
          } catch { 
            Write-Output "[!] ERROR: Could not access BitlockerKeyProtector. Is drive $BLV encrypted? "
            $BLVol = Get-BitLockerVolume
            $BLVol | select MountPoint,CapacityGB,VolumeStatus
            return $false
          }
        }
      }
    } else {
      Write-Output "[-] Skipping backup of Bitlocker keys."
      return $false
    }
  }
}

function Get-FileVersion {
  param ([string]$FileName)

  try {
    if (Test-Path $Filename) {
      $ThisVersion = (Get-Item $FileName -ErrorAction SilentlyContinue).VersionInfo.ProductVersion  # or FileVersion??
    } else {
      Write-Verbose "! File $Filename not found !"
      return $false
    }
  } catch {
    Write-Verbose "! File $Filename not found, or unknown error checking.. !"
    return $false
  }
  return $ThisVersion
}

function Find-Delimiter {
  param ([string]$CSVFilename)

  $line = Get-Content -Path $CSVFilename | Select-Object -First 1
  return ($line -split "Account Name")[1][0]
} 

function Get-VersionResults {
  param([string]$Results)
  # This checks $Results for the vulnerable Versions found. Can return an array!!!

  # Examples:
  #   single: Vulnerable version of Microsoft 3D Builder detected  Version     '18.0.1931.0'#
  #   single: Microsoft vulnerable Microsoft.Microsoft3DViewer detected  Version     '7.2105.4012.0'#    
  #   multiple: Vulnerable Microsoft Paint 3D detected  Version     '6.2105.4017.0'  Version     '6.2203.1037.0'#
  $vers = @()
  $appname = "??"  # For now, it appname isn't found, it will show that its returning junk when run with -Verbose
  if ($Results -like "*version is*") {   # Fuck you qualys, stay consistent with wording please..
    # %ProgramFiles(x86)%\Google\Chrome\Application\123.0.6312.59\chrome.dll file version is 123.0.6312.59#
    $SplitResults = (($Results) -split "version is").trim()
  } else {
    # assuming its like this instead, outdated UWP app detection:
    # "Vulnerable Microsoft Paint 3D detected  Version     '6.2105.4017.0'  Version     '6.2203.1037.0'#"
    $SplitResults = (($Results) -split "Version").trim()
  }
  #UWP example
  # $Results = "Vulnerable Microsoft Paint 3D detected  Version     '6.2105.4017.0'  Version     '6.2203.1037.0'#"
  # Splits to: 
  #   Vulnerable Microsoft Paint 3D detected                                                                                                  
  #   '6.2105.4017.0'
  #   '6.2203.1037.0'#
  
  #Chrome example
  # $Results = "%ProgramFiles(x86)%\Google\Chrome\Application\123.0.6312.59\chrome.dll file version is 123.0.6312.59#"
  # Splits to: 
  #    %ProgramFiles(x86)%\Google\Chrome\Application\123.0.6312.59\chrome.dll file
  #    123.0.6312.59#  

  Write-Verbose "Get-VersionResults - SplitResults : $splitresults"
  Foreach ($result in $SplitResults) {
    if ($result -like "*detected*" -or $result -like "*file*") { # This one should give us app name
      $appname = ($result).replace("Vulnerable version of","").replace("Microsoft vulnerable","").replace("Vulnerable","").replace("detected","").replace("is","").replace("file","").trim()
      Write-Verbose "Get-VersionResults - Appname found : $appname"
    } else {  # This is an actual version number
      $newvers = $result.replace("'","").replace("#","").trim()
      Write-Verbose "Get-VersionResults - Vers of $appname found: $newvers"
      $vers += $newvers #add to array, this should be short
    }
  }
  Write-Verbose "Get-VersionResults - Returning: $vers"
  return $vers
}

function Remove-SpecificAppXPackage {
  param([string]$Name,
        [string]$Version,
        [string]$Results)

  $i = 0
  $RemovedApp=$false
  Write-Verbose "[Remove-SpecificAppXPackage] : begin"

# Problem 8-4-23: 2 different versions of $Results, and I need the version for each
#   Vulnerable version of Microsoft 3D Builder detected  Version     '18.0.1931.0'#
#   Microsoft vulnerable Microsoft.Microsoft3DViewer detected  Version     '7.2105.4012.0'#
# Answer: split at ' and remove extra chars..

  $VersionResults = Get-VersionResults -Results $Results   # I know, I am doing this twice, once in the main loop, once here. All of this code should be refactored a bit.. I think it should be moved to here.
  Write-Verbose "Results: $Results"
  Write-Verbose "VersionResults: $VersionResults"

  Write-Verbose "Grabbing AppXPackage list with : (Get-AppXPackage ""*$($Name)*"" -AllUsers)"
  $AllResults = (Get-AppXPackage "*$($Name)*" -AllUsers)
  Write-Host "[.] Checking if $Name store app is installed"
  if ($AllResults.Count -gt 0) {
    Write-Host "[.] Yes. $(($AllResults).Count) results. Checking $Name versions.."
    foreach ($result in $AllResults) {
      $AppVersion = [System.Version]($Result).Version
      $AppName = ($Result).PackageFullName
      Write-Verbose "AppName: $AppName"
      Write-Verbose "AppVersion: $AppVersion"
      if ($null -eq $Version -and ($VersionResults).count -lt 1) {
        $Version = $VersionResults
      }
      if ([System.Version]$AppVersion -le [System.Version]$Version) {    # VERSION CHECK
        Write-Host "[!] $($i): Vulnerable version of store app found : $AppName - [$($AppVersion)] <= [$($Version)]"  -ForegroundColor Red
        if (Get-YesNo "$AppName - $AppVersion <= $Version .  Remove? ") {  # Final check, in case there are issues getting $Version or $VersionResults ..
          Write-Host "[.] Removing $AppName :" -ForegroundColor Yellow
          try {
            $null = (Remove-AppxPackage -Package $AppName -ErrorAction SilentlyContinue)            # Remove
          } catch { } # Ignore errors..
          Write-Host "[.] Removing $AppName -AllUsers :" -ForegroundColor Yellow
          try {
            $null = (Remove-AppxPackage -Package $AppName -AllUsers -ErrorAction SilentlyContinue)  # Remove with -AllUsers, this may create an error because a 'user is logged-off'.. but shouldn't matter.
          } catch { } # Ignore errors..
          Write-Host -NoNewLine "[.] Checking for ProvisionedPackage for $AppName : " -ForegroundColor Yellow
          try {
            $null = ($AppxProvisioned = get-appxprovisionedpackage -online | where-object {$_.PackageName -eq $AppName})
            if ($null -ne $AppxProvisioned) {
              Write-Host "Found. `n[.] Removing $((AppxProvisioned).PackageName). `n    RestartNeeded: $(($AppxProvisioned  | remove-appxprovisionedpackage -online).RestartNeeded)" -ForegroundColor Yellow
              $TestProvisionedAppxRemoval = (get-appxprovisionedpackage -online | where-object {$_.PackageName -eq $AppName}) # Quick check again
              if ($null -ne $TestProvisionedAppxRemoval) {
                Write-Host "[+] Remove-AppxProvisionedPackage success!" -ForegroundColor Green
              } else {
                Write-Host "[+] Remove-AppxProvisionedPackage failure. couldn't remove package using:  `n    $AppxProvisioned | Remove-AppXProvisionedPackage -Online" -ForegroundColor Red
              }
            } else {
               Write-Host "Not found." -ForegroundColor Yellow
            }
          } catch { } # Ignore errors..
          $RemovedApp=$AppName
          $i+=1
        } else {
          Write-Host "[!] Skipping."
        }
      } else {
        Write-Host "[!] $($i): Fixed version of $Name found: $AppName - $AppVersion > $Version. Already patched"  -ForegroundColor Green
        $i+=1
      }
    }
  } else {
    Write-Host "[!] No results found from '(Get-AppXPackage *$Name* -AllUsers)' -- Please check Microsoft Store for updates manually! Opening.."
    & explorer "ms-windows-store:"
  }

  if ($RemovedApp) {
    Write-Host "[.] Checking for $RemovedApp after removing.." -ForegroundColor Yellow
    $Rechecks = Get-appxpackage -allusers $RemovedApp
    $RechecksProvisioned = (Get-appxProvisionedPackage -Online | Where-Object { $_.PackageName -like $RemovedApp })
    if (!($Rechecks.Count -gt 0) -and ($null -eq $RechecksProvisioned)) {
      Write-Host "[+] Clean!" -ForegroundColor Green
    } else {
      foreach ($result in $Rechecks) {
        $AppVersion = [System.Version]($Result).Version
        $AppName = ($Result).PackageFullName
        if ([System.Version]$AppVersion -le [System.Version]$Version) {
          Write-Host "[!] Vulnerable version of Appx Package still found : $AppName - $AppVersion <= $Version"  -ForegroundColor Red
          Write-Vebose "result: $result"
          Write-Host "[!] Please either reboot and test again, or fix manually.." -ForegroundColor Red
        }
      }
      foreach ($result in $RechecksProvisioned) {
        $AppVersion = [System.Version]($Result).Version
        $AppName = ($Result).PackageName
        if ([System.Version]$AppVersion -le [System.Version]$Version) {
          Write-Host "[!] Vulnerable version of Provisioned Appx Package still found : $AppName - $AppVersion <= $Version"  -ForegroundColor Red
          Write-Vebose "result: $result"
          Write-Host "[!] Please either reboot and test again, or fix manually.." -ForegroundColor Red
        }
      }
    }
  }
}

Function Update-ViaNinite {
  param(
    [string]$Uri,
    [string]$OutFile,
    [string]$KillProcess,
    [string]$UpdateString
  )
  Write-Host "[.] Updating to newest $UpdateString from Ninite.com .."
  Invoke-WebRequest -UserAgent $AgentString -Uri $Uri -OutFile $OutFile
  Write-Host "[.] Killing all chrome browser windows .."
  taskkill.exe /f /im $(($KillProcess -split "\\")[-1]) # Works without a \ in $KillProcess either.
  Write-Host "[.] Waiting 5 seconds .."
  Start-Sleep 5 # Wait 5 seconds to make sure all processes are killed, could take longer.
  if ($Automated) {
    Write-Host "[.] Running the Ninite updater, this window will automatically be closed within $UpdateNiniteWait seconds"
    Start-Process -FilePath "$($tmp)\ninitechrome.exe" -NoNewWindow
    Write-Host "[.] Waiting $UpdateNiniteWait seconds .."
    Start-Sleep $UpdateNiniteWait # Wait X seconds to make sure the app has updated, usually 30-45s or so at least!! Longer for slower machines!
    Write-Host "[.] Killing the Ninite updater window, hopefully it is stuck at 'Closed'"
    taskkill.exe /f /im $(($KillProcess -split "\\")[-1])  # Grab filename from full path if given
  } else {
    Write-Host "[.] Running the Ninite Chrome updater, please close this window by hitting DONE when complete!"
    Start-Process -FilePath $OutFile -NoNewWindow -Wait
  }
}



Function Update-Chrome {
  Write-Host "[.] Downloading newest Chrome update from Ninite.com .."
  Invoke-WebRequest -UserAgent $AgentString -Uri "https://ninite.com/chrome/ninite.exe" -OutFile "$($tmp)\ninitechrome.exe"
  Write-Host "[.] Killing all chrome browser windows .."
  taskkill.exe /f /im chrome.exe
  Write-Host "[.] Waiting 5 seconds .."
  Start-Sleep 5 # Wait 5 seconds to make sure this is completed
  if ($Automated) {
    Write-Host "[.] Running the Ninite chrome updater, this window will automatically be closed within $UpdateBrowserWait seconds"
    Start-Process -FilePath "$($tmp)\ninitechrome.exe" -NoNewWindow
    Write-Host "[.] Waiting $UpdateBrowserWait seconds .."
    Start-Sleep $UpdateBrowserWait # Wait X seconds to make sure the app has updated, usually 30-45s or so at least!! Longer for slower machines!
    Write-Host "[.] Killing the Ninite Chrome updater window!"
    taskkill.exe /f /im ninite.exe
    taskkill.exe /f /im ninitechrome.exe
  } else {
    Write-Host "[.] Running the Ninite Chrome updater, please close this window by hitting DONE when complete!"
    Start-Process -FilePath "$($tmp)\ninitechrome.exe" -NoNewWindow -Wait
  }
}

Function Update-Firefox {
  Write-Host "[.] Downloading newest Firefox update from Ninite.com .."
  Invoke-WebRequest -UserAgent $AgentString -Uri "https://ninite.com/firefox/ninite.exe" -OutFile "$($tmp)\ninitefirefox.exe"
  Write-Host "[.] Killing all firefox browser windows .."
  taskkill.exe /f /im firefox.exe
  Write-Host "[.] Waiting 5 seconds .."
  Start-Sleep 5 # Wait 5 seconds to make sure this is completed
  if ($Automated) {
    Write-Host "[.] Running the Ninite firefox updater, this window will automatically be closed within $UpdateBrowserWait seconds"
    Start-Process -FilePath "$($tmp)\ninitefirefox.exe" -NoNewWindow
    Write-Host "[.] Waiting $UpdateBrowserWait seconds .."
    Start-Sleep $UpdateBrowserWait # Wait X seconds to make sure the app has updated
    Write-Host "[.] Killing the Ninite firefox updater window!"
    taskkill.exe /f /im ninite.exe
    taskkill.exe /f /im ninitefirefox.exe
  } else {
    Write-Host "[.] Running the Ninite firefox updater, please close this window by hitting DONE when complete!"
    Start-Process -FilePath "$($tmp)\ninitefirefox.exe" -NoNewWindow -Wait
  }
}

# Test's if the script is running in an elevated fashion (required for HKLM edits)
function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# This is just to make setting regkey's easier (Used for CVE-2023-36884 , QID 92038)
function Set-RegKey {
    param (
        $Path,
        $Name,
        $Value,
        [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
        $PropertyType = "DWord"
    )
    if (-not $(Test-Path -Path $Path)) {
        # Check if path does not exist and create the path
        New-Item -Path $Path -Force | Out-Null
    }
    if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
        # Update property and print out what it was changed from and changed to
        $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "[Error] Unable to Set registry key for $Name please see below error!"
            Write-Error $_
            exit 1
        }
        Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
    }
    else {
        # Create property with value
        try {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "[Error] Unable to Set registry key for $Name please see below error!"
            Write-Error $_
            exit 1
        }
        Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
    }
}

# All the microsoft office products with their corresponding dword value
$RemediationValues = @{ "Excel" = "Excel.exe"; "Graph" = "Graph.exe"; "Access" = "MSAccess.exe"; "Publisher" = "MsPub.exe"; "PowerPoint" = "PowerPnt.exe"; "OldPowerPoint" = "PowerPoint.exe" ; "Visio" = "Visio.exe"; "Project" = "WinProj.exe"; "Word" = "WinWord.exe"; "Wordpad" = "Wordpad.exe" }

################################################################################################################## MAIN ############################################################################################################
################################################################################################################## MAIN ############################################################################################################
################################################################################################################## MAIN ############################################################################################################

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
    Stop-Transcript
    exit
  }
}

# These variables should be referenced globally:
. "$($ConfigFile)"
. "$($QIDsListFile)"

# Check for newer version of script before anything..
Update-Script  # CHECKS FOR SCRIPT UPDATES, UPDATES AND RERUNS IF POSSIBLE
if (Update-QIDLists) { . "$($QIDsListFile)" }

# Lets check the Config first for $ServerName, as that is our default..
if ($ServerName) {
  if (Test-Connection -ComputerName $ServerName -Count 1 -Delay 1 -Quiet -ErrorAction SilentlyContinue) {
    Write-Output "[.] Checking location \\$($ServerName)\$($CSVLocation) .."
    if (Get-Item "\\$($ServerName)\$($CSVLocation)\Install-SecurityFixes.ps1") {
      Write-Host "[.] Found \\$($ServerName)\$($CSVLocation)\Install-SecurityFixes.ps1 .. Cleared to proceed." -ForegroundColor Green
      $SecAudPath = "\\$($ServerName)\$($CSVLocation)"
    }
  } else {
    # Lets also check SERVER in case config is wrong?
    Write-Output "[.] Checking default location \\SERVER\Data\SecAud .."
    if (Test-Connection -ComputerName "SERVER" -Count 1 -Delay 1 -Quiet -ErrorAction SilentlyContinue) {
      if (Get-Item "\\SERVER\Data\SecAud\Install-SecurityFixes.ps1") {
        $ServerName = "SERVER"
        $CSVLocation = "Data\SecAud"
        $SecAudPath = "\\$($ServerName)\$($CSVLocation)"
        Write-Host "[.] Found \\$($SecAudPath)\Install-SecurityFixes.ps1 .. Cleared to proceed." -ForegroundColor Green
      }
    }    
  }
} else {  # Can't ping $ServerName, lets see if there is a good location, or localhost?
  if (!$Automated) {
    $ServerName = Read-Host "[!] Couldn't ping SERVER or '$($ServerName)' .. please enter the server name where we can find the .CSV file, or press enter to read it out of the current folder: "
    if (!($ServerName)) { 
      $ServerName = "$($env:computername)"
      #$SecAudPath = "\\$($ServerName)\c$\temp\secaud"  # Change this?
      $SecAudPath = "c:\temp\secaud"  # for now..
      if (!(Test-Path $SecAudPath)) {
        New-Item -ItemType Directory -Path $SecAudPath
      }
    }
  } else { 
    Write-Host "[!] ERROR: Can't find a CSV to use, or the servername to check, and -Automated was specified.." -ForegroundColor Red
    exit
  }
}

if (!$OnlyQIDs) {   # If we are not just trying a fix for one CSV, we will also see if we can install the Dell BIOS provider and set WOL to on, and backup Bitlocker keys to AD if possible
  if (Get-OSType -eq 1) {
    #Install-DellBiosProvider  # Will only run if value is set in Config
    #Set-DellBiosProviderDefaults # Will only run if value is set in Config  
  }
  Backup-BitlockerKeys # Try to Backup Bitlocker recovery keys to AD
}
$OSVersionInfo = Get-OSVersionInfo
################# ( READ IN CSV AND PROCESS ) #####################

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
Set-Location "$($tmp)"  # Cmd.exe cannot be run from a server share

### Find CSV File name
if (!($CSVFile -like "*.csv")) {  # Check for command line param -CSVFile
  $CSVFilename = Find-ServerCSVFile "$($ServerName)\$($CSVLocation)"
  if ($null -eq $CSVFilename) {
    $CSVFilename = Find-LocalCSVFile "." $OldPwd
  }
} else {
  Write-Verbose "Parameter found: -CSVFile $CSVFile"
  Write-Verbose "Using: $($oldPwd)\$($CSVFile)"
  $CSVFilename = "$($oldPwd)\$($CSVFile)"
}
# READ CSV
if ($null -eq $CSVFilename) {
  Write-Host "[X] Couldn't find CSV file : $CSVFilename " -ForegroundColor Red
  Exit
} else {
  try {
    Write-Verbose "Finding delimeter for $CSVFilename"
    $delimiter = Find-Delimiter $CSVFilename
    Write-Host "[.] Importing data from $CSVFilename" -ForegroundColor Yellow
    $CSVData = Import-CSV $CSVFilename -Delimiter $delimiter | Sort-Object "Vulnerability Description"
  } catch {
    Write-Host "[X] Couldn't open CSV file : $CSVFilename " -ForegroundColor Red
    Set-Location $pwd
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
$QIDsAdded = @()
$CurrentQID = ""
$CSVData | ForEach-Object {
# Search by title:
  $CurrentQID=($_.QID).Replace('.0','') 
  if ($CurrentQIDsAdded -notcontains $CurrentQID) {
    if ($_.Title -like "Apple iCloud for Windows*") {
      if (!($QIDsAppleiCloud -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsAddedQIDsAppleiTunes' 
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "Apple iTunes for Windows*") {
      if (!($QIDsAppleiTunes -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsAppleiTunes' 
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "Chrome*") {
      if (!($QIDsTeamviewer -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsTeamViewer' 
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "Firefox*") {
      if (!($QIDsFirefox -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsFirefox'
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "Zoom Client*") {
      if (!($QIDsZoom -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsZoom'
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "TeamViewer*") {
      if (!($QIDsTeamviewer -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsTeamViewer'
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }  
    if ($_.Title -like "Dropbox*") {
      if (!($QIDsDropbox -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsDropbox'
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "Oracle Java*") {            ########
      if (!($QIDsOracleJava -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsOracleJava' 
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "Adopt Open JDK*") {             ############
      if (!($QIDsAdoptOpenJDK -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsAdoptOpenJDK' 
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "VirtualBox*") {
      if (!($QIDsVirtualBox -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsVirtualBox'
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "Adobe Reader*") {  
      if (!($QIDsAdobeReader -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsAdobeReader'
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "Intel Graphics*") {
      if (!($QIDsIntelGraphicsDriver -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsIntelGraphicsDriver'
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "NVIDIA*") {
      if (!($QIDsNVIDIA -contains $CurrentQID)) { 
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsNVIDIA' 
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "Dell Client*") {
      if (!($QIDsDellCommandUpdate -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsDellCommandUpdate' 
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
    }
    if ($_.Title -like "Ghostscript*") {
      if (!($QIDsGhostscript -contains $CurrentQID)) {
        Add-VulnToQIDList $CurrentQID $_.Title  'QIDsGhostScript' 
        . $($QIDsListFile)
        $QIDsAdded+=[int]$CurrentQID
      }
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
  Write-Host "[!] There are no rows applicable to $hostname !! Exiting.." -ForegroundColor Red
  Write-Host "[?] Maybe you meant to pick from a different file? "
  Write-Host $Filenames
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
    $Results = ($_.Results)
    $VulnDesc = ($_."Vulnerability Description")
    if ($Results -like "*vulnerable*") {  # lets try this..
      $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim() 
    }
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

if ($QIDSpecific) {
  Write-Host "[!] Applying fixes for specific QIDs only: $QIDSpecific `n" -ForegroundColor Yellow
  $QIDs = $QIDSpecific
}
foreach ($CurrentQID in $QIDs) {
    $ThisQID = [int]$CurrentQID
    Write-Verbose "-- This QID: $CurrentQID -- Type: $($CurrentQID.GetType())"
    $VulnDesc = (($Rows | Where-Object { $_.QID -eq $ThisQID }) | Select-Object -First 1)."Vulnerability Description"
    $Results = (($Rows | Where-Object { $_.QID -eq $ThisQID }) | Select-Object -First 1)."Results"
    If ($Automated -eq $true) {
      Write-Verbose "[Running in Automated mode]"
    }
    switch ([int]$CurrentQID)
    {
      { 379210,376023,376023,91539,372397,372069,376022 -contains $_ }  { 
        if (Get-YesNo "$_ Remove Dell SupportAssist ? " -Results $Results) {

          $Products = Search-Software "*SupportAssist*" 
          if (Check-Products $Products) {
            Remove-Software -Products $Products -Results $Results
          } else {
            Write-Host "[!] Dell SupportAssist not found!" -ForegroundColor Red
          }     

<#
          $guid = (Get-Package | Where-Object{$_.Name -like "*SupportAssist*"})
          if ($guid) {  ($guid | Select-Object -expand FastPackageReference).replace("}","").replace("{","")  }
          msiexec /x $guid /qn /L*V "$($tmp)\SupportAssist.log" REBOOT=R

          # This might require interaction, in which case run this:
          msiexec /x $guid /L*V "$($tmp)\SupportAssist.log"

          # Or:
          # ([wmi]"\\$env:computername\root\cimv2:Win32_Product.$guid").uninstall()   

#>
        }
      }
      105228 { 
        if (Get-YesNo "$_ Disable guest account and rename to NoVisitors ? " -Results $Results) {
          if ($OSVersion -ge 7) {
            if (Get-LocalUser "Guest") {
              try {
                Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
              } catch { 
                Write-Host "[!] Couldn't run: 'Disable-LocalUser -Name ""Guest"" -ErrorAction SilentlyContinue' even though there is a Guest account found.." 
                break
              }
              Write-Host "[.] Guest account disabled with: 'Disable-LocalUser -Name ""Guest""'"
              Rename-LocalUser -Name "Guest" -NewName "NoVisitors" | Disable-LocalUser
              Write-Host "[.] Guest account renamed with: 'Rename-LocalUser -Name ""Guest"" -NewName ""NoVisitors"" | Disable-LocalUser'"
            } else {
              Write-Host "[!] Skipping: No account named ""Guest"" found."
            }
          } else {
            cmd /c 'net user Guest /active:no'
            Write-Host "[.] Guest account disabled with: 'net user Guest /active:no'"
            cmd /c 'wmic useraccount where name="Guest" rename NoVisitors'
            Write-Host "[.] Guest account renamed with: 'wmic useraccount where name=""Guest"" rename NoVisitors'"
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
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/outlook-x-none_1763a730d8058df2248775ddd907e32694c80f52.cab" -outfile "$($tmp)\outlook-x-none.cab"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\outlook-x-none.cab $($tmp)"
          cmd /c "msiexec /p $($tmp)\outlook-x-none.msp /qn"
        }
      }
      110413 {
        if (Get-YesNo "$_ Fix Microsoft Office Security Update for August 2022? " -Results $Results) { 
          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/msohevi-x-none_a317be1090606cd424132687bc627baffec45292.cab .."
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/msohevi-x-none_a317be1090606cd424132687bc627baffec45292.cab" -outfile "$($tmp)\msohevi-x-none.msp"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\msohevi-x-none.msp $($tmp)"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\msohevi-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\msohevi-x-none.msp"
          cmd /c "msiexec /p $($tmp)\msohevi-x-none.msp /qn"

          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab .."
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab" -outfile "$($tmp)\excel-x-none.cab"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\excel-x-none.msp $($tmp)"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\excel-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\excel-x-none.msp"
          cmd /c "msiexec /p $($tmp)\excel-x-none.msp /qn"

        }
      }
      110412 {
        if (Get-YesNo "$_ Fix Microsoft Office Security Update for July 2022? " -Results $Results) { 
          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab .."
          Invoke-WebRequest -UserAgent $AgentString -Uri "http://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2022/06/vbe7-x-none_1b914b1d60119d31176614c2414c0e372756076e.cab" -outfile "$($tmp)\vbe7-x-none.cab"
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
          # %windir%\Temp\dbutil_2_3.sys   found#
          $Filename = ($Results -split " found")[0].trim().replace("%windir%","$env:windir").replace("%systemdrive%","$env:systemdrive")
          if (Test-Path $Filename) { 
            try {
              Remove-Item $Filename -Force
            } catch {
              Write-Host "[!] Couldn't remove $Filename ! Manual intervention required.." -ForegroundColor Red
            }
            if (!(Test-Path $Filename)) { Write-Host "[+] Removed $Filename" -ForegroundColor Green } 
          } else {
            Write-Host "[!] Error: $Filename -- Not found.." -ForegroundColor Red
          }
        }
      }
      100413 {
        if (Get-YesNo "$_ CVE-2017-8529 - IE Feature_Enable_Print_Info_Disclosure fix ? " -Results $Results) {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" /v iexplore.exe /t REG_DWORD /d 1 /f'
        }
      }
      { 91704 -contains $_ } {
        if (Get-YesNo "$_ Microsoft Windows DNS Resolver Addressing Spoofing Vulnerability (ADV200013) fix ? " -Results $Results) {
          $RegPath = "HKLM:\System\CurrentControlSet\Services\DNS\Parameters"
          Write-Host "[.] Making value change for $RegPath - MaximumUdpPacketSize = DWORD 1221"
          New-ItemProperty -Path $RegPath -Name MaximumUdpPacketSize -Value 1221 -PropertyType DWORD -Force -ErrorAction Continue
          Write-Host "[.] Restarting DNS service.."
          Restart-Service DNS -Force -ErrorAction Continue
          Write-Host "[!] Done!"
        } 
      }
      { 105170,105171 -contains $_ } { 
        if (Get-YesNo "$_ - Windows Explorer Autoplay not Disabled ? " -Results $Results) {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'
            $path2 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\policies\Explorer'
            Write-Host "[.] Setting registry keys in:"
            $path
            $path2
            if (!(Test-Path $path)) {
              Write-Verbose "Creating $($path) as it was not found.."
              $pathonly = Split-Path $path
              $leaf = Split-Path $path -Leaf
              New-Item -Path $pathonly -Leaf $leaf -Force
            }
            if (!(Test-Path $path2)) {
              Write-Verbose "Creating $($path2) as it was not found.."
              $path2only = Split-Path $path2 
              $leaf2 = Split-Path $path2 -Leaf
              New-Item $path2only -Force
              New-Item -Path $path2only -Leaf $leaf2 -Force
            }
            Set-ItemProperty $path -Name NoDriveTypeAutorun -Type DWord -Value 0xFF
            Set-ItemProperty $path -Name NoAutorun -Type DWord -Value 0x1
            try {
              $null = New-Item $path2 -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -ErrorAction SilentlyContinue
              $null = New-Item $path2 -Name NoAutorun -Type DWord -Value 0x1 -ErrorAction SilentlyContinue
            } catch {} # Don't care if these fail, if they already exist..
            Set-ItemProperty $path2 -Name NoDriveTypeAutorun -Type DWord -Value 0xFF
            Set-ItemProperty $path2 -Name NoAutorun -Type DWord -Value 0x1
            Write-Host "[!] Done!"
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
        if (Get-YesNo "$_ - SMB Signing Disabled / Not required (Both LanManWorkstation and LanManServer)) " -Results $Results) {
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
            $GUID= "{D5C69738-B486-402E-85AC-2456D98A64E4}"
            Write-Host "[.] Checking for product: 'Windows 10 Update Assistant' .." -ForegroundColor Yellow
            #$Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like $GUID})
            $Products = Search-Software "Windows 10 Update Assistant" 
            if ($Products) {
              Remove-Software -Products $Products -Results $Results
            } else {
              Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
            } 
            # Try to delete from registry, if it exists
            Remove-RegistryItem $Path
        }
      }

        ####################################################### Installers #######################################
        # Install newest apps via Ninite

      { ($QIDsGhostScript -contains $_) -or ($VulnDesc -like "*GhostScript*" -and ($QIDsGhostScript -ne 1)) } {
        if (Get-YesNo "$_ Install GhostScript 10.01.2 64bit? " -Results $Results) {
          Write-Host "[.] Searching for old versions of GPL Ghostscript .."
          $Products = Search-Software "*Ghostscript" 
          if (Check-Products $Products) {
            Remove-Software -Products $Products -Results $Results
          } else {
            Write-Host "[!] Ghostscript product not found under 'GPL Ghostscript*' : `n    Products: [ $Products ]`n" -ForegroundColor Red
          }              

          $ghostscripturl = "https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs10012/gs10012w64.exe"
          Invoke-WebRequest -UserAgent $AgentString -Uri   $ghostscripturl -OutFile "$($tmp)\ghostscript.exe"
          cmd.exe /c "$($tmp)\ghostscript.exe /S"
          #Delete results file, i.e        "C:\Program Files (x86)\GPLGS\gsdll32.dll found#" as lots of times the installer does not clean this up.. may install the new one in a new location etc
          #$FileToDelete=$results.split(' found')[0]
          $path = Split-Path -Path $results
          $sep=" found#"
          $fileName = ((Split-Path -Path $results -Leaf) -split $sep)[0]
          $FileToDelete="$($path)\$($filename)"
          Write-Host "[.] Removing $($FileToDelete) .."
          Remove-Item $FileToDelete -Force
          if (Test-Path $FileToDelete) {
            Write-Output "[x] Could not delete $($FileToDelete), please remove manually!"
          }
        }
      }
      110330 {  
        if (Get-YesNo "$_ - Install Microsoft Office KB4092465? " -Results $Results) {
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/3/6/E/36EF356E-85E4-474B-AA62-80389072081C/mso2007-kb4092465-fullfile-x86-glb.exe" -outfile "$($tmp)\kb4092465.exe"
            cmd.exe /c "$($tmp)\kb4092465.exe /quiet /passive /norestart"
        }
      }
      372348 {
        if (Get-YesNo "$_ - Install Intel Chipset INF util ? " -Results $Results) {
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://downloadmirror.intel.com/774764/SetupChipset.exe" -OutFile "$($tmp)\setupchipset.exe"
            # https://downloadmirror.intel.com/774764/SetupChipset.exe
            cmd /c "$($tmp)\setupchipset.exe -s -accepteula  -norestart -log $($tmp)\intelchipsetinf.log"
            # This doesn't seem to be working, lets just download it and run it for now..
            #cmd /c "$($tmp)\setupchipset.exe -log $($tmp)\intelchipsetinf.log"
            # may be 'Error: this platform is not supported' ..
        }
      }
      372300 {
        if (Get-YesNo "$_ - Install latest Intel RST ? " -Results $Results) {
            #Invoke-WebRequest -UserAgent $AgentString -Uri "https://downloadmirror.intel.com/655256/SetupRST.exe" -OutFile "$($tmp)\setuprst.exe"
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://downloadmirror.intel.com/773229/SetupRST.exe" -OutFile "$($tmp)\setuprst.exe"
            
            cmd /c "$($tmp)\setuprst.exe -s -accepteula -norestart -log $($tmp)\intelrstinf.log"
            # OR, extract MSI from this exe and run: 
            # msiexec.exe /q ALLUSERS=2 /m MSIDTJBS /i “RST_x64.msi” REBOOT=ReallySuppress
        }   
      }
      { ($QIDsIntelGraphicsDriver  -contains $_) -or ($VulnDesc -like "*Intel Graphics*" -and ($QIDsIntelGraphicsDriver -ne 1)) } {
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
      
      { ($QIDsAppleiCloud -contains $_) -or ($VulnDesc -like "*Apple iCloud*" -and ($QIDsAppleiCloud -ne 1)) } {
        <#
        if (Get-YesNo "$_ Install newest Apple iCloud? ") { 
            Invoke-WebRequest -UserAgent $AgentString -Uri "" -OutFile "$($tmp)\icloud.exe"
            cmd /c "$($tmp)\icloud.exe"
            $QIDsAppleiCloud = 1 # All done, remove variable to prevent this from running twice
        } else { $QIDsAppleiCloud = 1 } # Do not ask again
        #>
        # https://silentinstallhq.com/apple-icloud-install-and-uninstall-powershell/  # THIS SHOULD BE USEFUL.....
        "$_ Can't deploy Apple iCloud via script yet!!! Please install manually! Opening Browser to iCloud page: "
        explorer "https://apps.microsoft.com/store/detail/icloud/9PKTQ5699M62?hl=en-us&gl=us"
      }
      { ($QIDsAppleiTunes -contains $_ ) -or ($VulnDesc -like "*Apple iTunes*" -and ($QIDsAppleiTunes -ne 1))} {
        if (Get-YesNo "$_ Install newest Apple iTunes from Ninite? " -Results $Results) { 
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://ninite.com/itunes/ninite.exe" -OutFile "$($tmp)\itunes.exe"
            cmd /c "$($tmp)\itunes.exe"
            $QIDsAppleiTunes = 1 # All done, remove variable to prevent this from running twice
        } else { $QIDsAppleiTunes = 1 } # Do not ask again
      }
      { ($QIDsChrome -contains $_) -or ($VulnDesc -like "*Google Chrome*" -and ($QIDsChrome -ne 1))} {
        if (Get-YesNo "$_ Check if Google Chrome is up to date? " -Results $Results) { 
          # Type 1 = Google Chrome Prior to 110.0.5481.177/110.0.5481.178 Multiple Vulnerabilities
          # Type 2 = Google Chrome Prior to 113.0.5672.63 Multiple Vulnerabilities
          # Type 3 = Google Chrome Prior to 114.0.5735.106 for Linux and Mac and 114.0.5735.110 for Windows Multiple Vulnerabilities
          Write-Verbose "VulnDesc: $VulnDesc"
          if ($VulnDesc -like "*/*") {  # Type 1
            $VulnDescChromeWinVersion = ((($VulnDesc -split "Prior to") -split "/")[1]).trim()  # Take the first version, which will be oldest..
          } else {
            if ($VulnDesc -like "*Linux and Mac*") { # Type 3
              $VulnDescChromeWinVersion = (((($VulnDesc -split "Prior to") -split "for Windows")[1] -split "Linux and Mac and")[1]).trim()  
            } else { # Type 2
              $VulnDescChromeWinVersion = ((($VulnDesc -split "Prior to")[1] -split "Multiple Vulnerabilities")[0]).trim()
            }
          }
          Write-Verbose "VulnDescChromeWinVersion: $VulnDescChromeWinVersion"
          
          # $Results = %ProgramFiles%\Google\Chrome\Application\114.0.5735.91\chrome.dll file version is 114.0.5735.91#
          # %ProgramFiles(x86)%\Google\Chrome\Application\114.0.5735.91\chrome.dll file version is 114.0.5735.91#
          $ChromeFile = Check-ResultsForFile -Results $Results  # Get the file to check
          if (Test-Path $ChromeFile) {
            $ChromeFileVersion = Get-FileVersion $ChromeFile
            if ($ChromeFileVersion) {
              Write-Verbose "Chrome version found : $ChromeFile - $ChromeFileVersion .. checking against $VulnDescChromeWinVersion"
              if ([version]$ChromeFileVersion -lt [version]$VulnDescChromeWinVersion) {  # Fixed bug 3-28-24 - logic above is 'Prior to version' not 'Prior to or equals version'!!
                Write-Host "[!] Vulnerable version $ChromeFile found : $ChromeFileVersion < $VulnDescChromeWinVersion - Updating.."
                Update-Chrome
              } else {
                Write-Host "[+] Chrome patched version found : $ChromeFileVersion > $VulnDescChromeWinVersion - already patched!" -ForegroundColor Green  # SHOULD never get here, patches go in a new folder..
              }
            } else {
              Write-Host "[-] Chrome Version not found, for $ChromeFile .." -ForegroundColor Yellow
            }
          } else {
            Write-Host "[!] Chrome EXE no longer found: $ChromeFile - likely its already been updated. Let's check.."
            $ChromeFolder = (Split-Path $(Split-Path $ChromeFile -Parent) -Parent) # Back 2 folders, as the parent is already missing if upgraded, lets see what other versions are in the parent
            
            $ChromeFolderItems = Get-ChildItem $ChromeFolder | Where-Object { $_ -like "1*" -or $_ -like "2*" }  # In the future versions will be >114, >200 etc.. This is temporary
            Write-Verbose "[.] Found items in $ChromeFolder : $ChromeFolderItems"
            Foreach ($ChromeFolderItem in $ChromeFolderItems) {
              if (Test-Path "$($ChromeFolder)\$($ChromeFolderItem)\chrome.exe") { $ChromeFolderVersion = $ChromeFolderItem }
              # This should find the current chrome version folder.. i.e C:\Program Files\Google\Chrome\Application\114.0.5735.91
            }

            $NewChromeFile = "$($ChromeFolder)\$($ChromeFolderVersion)\chrome.exe"
            if (Test-Path $NewChromeFile) {
              $ChromeFileVersion = Get-FileVersion $NewChromeFile
              if ($ChromeFileVersion) {
                Write-Verbose "Chrome version found : $NewChromeFile - $ChromeFileVersion - checking against $VulnDescChromeWinVersion"
                if ([version]$ChromeFileVersion -le [version]$VulnDescChromeWinVersion) {
                  Write-Host "[!] Vulnerable version $ChromeFile found : $ChromeFileVersion <= $VulnDescChromeWinVersion - Updating.."
                  Update-Chrome
                } else {
                  Write-Host "[+] Chrome patched version $ChromeFile found : $ChromeFileVersion > $VulnDescChromeWinVersion" -ForegroundColor Green
                }
              }
            } else {
              Write-Host "[!] Error: Couldn't find chrome.exe in any of the folders in $($ChromeFolder) .." -ForegroundColor Red
            }
          }
          $QIDsChrome = 1 # All done, remove variable to prevent this from running twice
        } else { $QIDsChrome = 1 }
      }
      { ($QIDsEdge -contains $_) -or ($VulnDesc -like "*Microsoft Edge*" -and ($QIDsEdge -ne 1)) } {
        if (Get-YesNo "$_ Check if Microsoft Edge is up to date? " -Results $Results) { 
          # Microsoft Edge Based on Chromium Prior to 114.0.1823.37 Multiple Vulnerabilities
          Write-Verbose "VulnDesc: $VulnDesc"
          $EdgeEXE = Check-ResultsForFile -Results $Results
          if (Test-Path $EdgeEXE) {
            #$VulnDescEdgeWinVersion = (((($VulnDesc -split "Prior to") -split "for Windows")[1]) -split " Multiple")[0].trim()
            $ResultsVersion = Check-ResultsForVersion -Results $Results
            $EdgeEXEVersion = Get-FileVersion $EdgeEXE
            Write-Verbose "Edge version found : $EdgeEXE - $EdgeEXEVersion - checking against $ResultsVersion"
            if ($EdgeEXEVersion -le $ResultsVersion) {
              Write-Host "[!] Vulnerable version $EdgeEXE found : $EdgeEXEVersion <= $ResultsVersion - Opening.."
              & $EdgeEXE # This is not automation friendly..
            } else {
              Write-Host "[+] Edge Version found : $EdgeEXEVersion > $ResultsVersion - already patched!" -ForegroundColor Green
            }
          } else {
            Write-Host "[!] Edge EXE no longer found: $EdgeEXE - likely its already been updated."
          }
          $QIDsEdge = 1
        } else { $QIDsEdge = 1 }
      }
      { ($QIDsFirefox -contains $_) -or ($VulnDesc -like "*Mozilla Firefox*" -and ($QIDsFirefox -ne 1)) } {
        if (Get-YesNo "$_ Install newest Firefox from Ninite? " -Results $Results) { 
            #  Firefox - https://ninite.com/firefox/ninite.exe
            Update-Firefox
            $ResultsFolder = Parse-ResultsFolder $Results
            if ($ResultsFolder -like "*AppData*") {
              Remove-Folder $ResultsFolder
            }          
            $QIDsFirefox = 1
        } else { $QIDsFirefox = 1 }
      }      
      { ($QIDsZoom -contains $_) -or ($VulnDesc -like "*Zoom*" -and ($QIDsZoom -ne 1)) } {
        if (Get-YesNo "$_ Install newest Zoom Client from Ninite? " -Results $Results) { 
            #  Zoom client - https://ninite.com/zoom/ninite.exe
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://ninite.com/zoom/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            #If Zoom folder is in another users AppData\Local folder, this will not work
            $FolderFound = $false
            foreach ($Result in $Results) {
              if ($Result -like "*AppData*") {
                $FolderFound = $true
              }
            }
            if ($FolderFound) { Remove-Folder (Parse-ResultsFolder -Results $Results) }
            #Show-FileVersionComparison -Name "Zoom" -Results $Results
            $QIDsZoom = 1
        } else { $QIDsZoom = 1 }
      }
      { ($QIDsTeamViewer -contains $_) -or ($VulnDesc -like "*TeamViewer*" -and ($QIDsTeamViewer -ne 1)) } {
        if (Get-YesNo "$_ Install newest Teamviewer from Ninite? " -Results $Results) { 
            #  Teamviewer - https://ninite.com/teamviewer15/ninite.exe
            Update-ViaNinite -Uri "https://ninite.com/teamviewer15/ninite.exe" -OutFile "$($tmp)\ninite.exe" -KillProcess "TeamViewer.exe" -UpdateString "TeamViewer 15"
            $QIDsTeamViewer = 1
        } else { $QIDsTeamViewer = 1 }
      }
      { ($QIDsDropbox -contains $_) -or ($VulnDesc -like "*Dropbox*" -and ($QIDsDropbox -ne 1)) } {
        if (Get-YesNo "$_ Install newest Dropbox from Ninite? " -Results $Results) { 
            #  Dropbox - https://ninite.com/dropbox/ninite.exe
            Update-ViaNinite -Uri "https://ninite.com/dropbox/ninite.exe" -OutFile "$($tmp)\dropboxninite.exe" -KillProcess "Dropbox.exe" -UpdateString "Dropbox"
            cmd /c "$($tmp)\dropboxninite.exe"
            $QIDsDropbox = 1
        } else { $QIDsDropbox = 1 }
      }
      { ($VulnDesc -like "*VLC*" -and ($QIDsVLC -ne 1)) } {
        if (Get-YesNo "$_ Install newest VLC? " -Results $Results) { 
          #Remove any existing file before downloading..
          if (Test-Path $installerPath) { Remove-Item $InstallerPath -Force }
          Write-Host "[.] Checking for old versions of VLC to remove"
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like '*VLC media player*'})
          if ($Products) {
            Write-Verbose "Products : $Products"
            Remove-Software -Products $Products -Results $Results
          } else {
            Write-Host "[!] VLC products not found under '*VLC media player*' : `n    Products: [ $Products ]`n" -ForegroundColor Red
          }   

          $url1 = "https://www.videolan.org/vlc/download-windows.html"
          $response1 = Invoke-WebRequest -Uri $url1

          # response1 contains a bunch of links, find the ones with ".msi", return the First one.
          $url2 = $response1.Links | Where-Object { $_.href -match ".msi"} | Select-Object href -First 1
          Write-Verbose "Download link 1: $($url2.href)"  # Should be something like "//get.videolan.org/vlc/3.0.18/win32/vlc-3.0.18-win32.msi"
          $response2 = Invoke-WebRequest -Uri ("https:" + $url2.href) # Href is missing the protocol so add it back.

          # response2 contains a bunch of links to Mirror sites, find the First one containing ".msi".
          $url3 = $response2.Links | Where-Object { $_.href -match ".msi"} | Select-Object href -First 1
          Write-Verbose "Download link 2 (redirect to mirror): $($url3.href)" # Should be something like "https://mirror.aarnet.edu.au/pub/videolan/vlc/3.0.18/win32/vlc-3.0.18-win32.msi"
          $filename = Split-Path $url3.href -Leaf # Gets the last part of the URL as the filename.
          $vlcversion = ((($filename -split "vlc-")[1] -split "-win32.msi")[0]).trim()
          write-verbose "VLC Version found: $vlcversion)"
#          $ProgressPreference = 'SilentlyContinue' # Disables the progress meter, showing the progress is incredibly slow
          $installerPath = "$($tmp)\$($vlcFilename)"

          Write-Host "[.] Downloading $vlcUrl - output: $installerPath"
          Invoke-WebRequest -Uri $url3.href -UserAgent $AgentString -OutFile $installerPath -ErrorAction SilentlyContinue

          $Arguments = "/i $installerPath /qn /quiet /norestart WRAPPED_ARGUMENTS=""/S"""
          Write-Host "[.] Running: msiexec.exe $Arguments"
          Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait
          Write-Host "[.] Looks to have finished!"
        }
        $QIDsVLC = 1 # Whether updated or not, don't ask again.
      }
      378839 {
        if (Get-YesNo "$_ Install newest 7-Zip from Ninite? " -Results $Results) { 
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://ninite.com/7-zip/ninite.exe" -OutFile "$($tmp)\7zninite.exe"

          Start-Process -FilePath "$($tmp)\7zninite.exe" # -NoNewWindow
          Write-Host "[.] Waiting $Update7zipWait seconds .."
          Start-Sleep $Update7zipWait # Wait 30 seconds to make sure the app has updated, usually 30s or so at least!! Longer for slower machines!
          Write-Host "[.] Killing the Ninite 7-zip updater window to close it!"
          taskkill.exe /f /im ninite.exe
          taskkill.exe /f /im 7zninite.exe
          Write-Host "[!] Done!"
          $QIDs7zip = 1
        } else { $QIDs7zip = 1 }
      }
  
        ############################
        # Others: (non-ninite)
  
      { ($QIDsOracleJava -contains $_) -or ($VulnDesc -like "*Oracle Java*" -and ($QIDsOracleJava -ne 1))} {
        if (Get-YesNo "$_ Check Oracle Java for updates? " -Results $Results) { 
            #  Oracle Java 17 - https://download.oracle.com/java/17/latest/jdk-17_windows-x64_bin.msi
            #wget "https://download.oracle.com/java/18/latest/jdk-18_windows-x64_bin.msi" -OutFile "$($tmp)\java17.msi"
            #msiexec /i "$($tmp)\java18.msi" /qn /quiet /norestart
            . "c:\Program Files (x86)\Common Files\Java\Java Update\jucheck.exe"
            $SoftwareInstalling.Add("Java")
            $QIDsOracleJava = 1
        } else { $QIDsOracleJava = 1 }
      }
      { ($QIDsAdoptOpenJDK -contains $_) -or ($VulnDesc -like "*Adopt OpenJDK*") } {
        if (Get-YesNo "$_ Install newest Adopt Java JDK? " -Results $Results) { 
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://ninite.com/adoptjavax8/ninite.exe" -OutFile "$($tmp)\ninitejava8x64.exe"
            cmd /c "$($tmp)\ninitejava8x64.exe"
            $QIDsAdoptOpenJDK = 1
        } else { $QIDsAdoptOpenJDK = 1 }
      }
      { ($QIDsVirtualBox -contains $_) -or ($VulnDesc -like "*VirtualBox*" -and ($QIDsVirtualBox -ne 1)) } {
        if (Get-YesNo "$_ Install newest VirtualBox 6.1.36? " -Results $Results) { 
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.virtualbox.org/virtualbox/6.1.36/VirtualBox-6.1.36-152435-Win.exe" -OutFile "$($tmp)\virtualbox.exe"
            cmd /c "$($tmp)\virtualbox.exe"
            $QIDsVirtualBox = 1
        } else { $QIDsVirtualBox = 1 } 
      }
      { ($QIDsDellCommandUpdate -contains $_) -or ($VulnDesc -like "*Dell Command Update*" -and ($QIDsDellCommandUpdate -ne 1))} {
        if (Get-YesNo "$_ Install newest Dell Command Update? " -Results $Results) { 
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like '*Dell Command | Update*'})
          if ($Products) {
            if ([version]$Products.Version -lt [version]$DCUVersion) {
              Remove-Software -Products $Products -Results $Results
            } else {
              Write-Host "[!] Dell Command target version $DCUVersion <= installed version $($Products.Version) ]`n" -ForegroundColor Green
              Break
            }
          } else {
            Write-Host "[!] Dell Command products not found under '*Dell Command | Update*' : `n    Products: [ $Products ]`n" -ForegroundColor Red
          }    
          #wget "https://dl.dell.com/FOLDER08334704M/2/Dell-Command-Update-Windows-Universal-Application_601KT_WIN_4.5.0_A00_01.EXE" -OutFile "$($tmp)\dellcommand.exe"  # OLD AND VULN NOW..
          if (!(Test-Path $DCUFilename)) {
            Write-Host "[.] Downloading latest Dell Command Update as $DCUFilename .."
            Invoke-WebRequest -UserAgent $AgentString -Uri $DCUUrl -OutFile $DCUFilename
          }
          $DCUExe = ((Get-ChildItem "$SecAudPath" | Where-Object {$_.Name -like "Dell-Command-Update-*"} | Sort-Object CreationTime -Descending | Select-Object -First 1).FullName)
          if ($null -ne $DCUEXE -and $DCUFilename -like "$($DCUEXE)*") {  #ugh, this matches <blank>*              
            Write-Host "[+] Found, DCU has already been downloaded: $DCUExe" -ForegroundColor Green
          } else {
            Write-Host "[.] Installing newest Dell command update $DCUversion .." -ForegroundColor Yellow
            if ($null -eq $SecAudPath) {
              Write-Verbose "SecAudPath is blank, setting to C:\Temp\SecAud for now.."
              $SecAudPath = "C:\Temp\SecAud"
              if (!(Test-Path $SecAudPath)) {
                Write-Verbose "Creating $($SecAudPath) as it doesn't exist.."
                $null = New-Item -ItemType Directory $SecAudPath -Force
              }
            }
            Write-Verbose "Downloading $DCUUrl to $($SecAudPath)\$($DCUFilename).."
            Invoke-WebRequest -UserAgent $AgentString -Uri $DCUUrl -OutFile "$($SecAudPath)\$($DCUFilename)"  # Dell doesn't want powershell downloads!    # -UserAgent "I'm using edge, I swear.." <--- used to use this..
            Write-Verbose "Saved to $($SecAudPath)\$($DCUFilename)"
            Write-Verbose "DCUExe $DCUExe"
            $DCUExe = (Get-ChildItem "$SecAudPath" | Where-Object {$_.Name -like "Dell-Command-Update-*"} | Sort-Object CreationTime -Descending | Select-Object -First 1).FullName
            $DCUVersion = (($DCUExe -split "_WIN_")[1] -split "_A0")[0]
          }
          if ($DCUExe) {
            Write-Host "[.] Copying $($DCUExe) to $env:temp .." -ForegroundColor Yellow
            copy-item $DCUExe $env:temp -force -ErrorAction SilentlyContinue
            Write-Host "[.] Launching .. " -ForegroundColor Yellow
            try {
              Start-Process -FilePath "$($env:temp)\$(Split-Path $DCUExe -Leaf)" -ArgumentList "/s"
              Write-Host "[.] Looks to have Launched .. " -ForegroundColor Yellow
            } catch {
              Write-Host "[!] ERROR - $($env:temp)\$(Split-Path $DCUExe -Leaf) could not be launched `n    With Start-Process -FilepPath ""$($DCUExe)"" -ArgumentList ""/s""" -ForegroundColor Red
            }
            Write-Host "[.] Sleeping for a max of $UpdateDellCommandWait seconds.." -NoNewLine
            $installedyet = $false
            while ($InstalledYet -eq $false -and $elapsedtime -lt $UpdateDellCommandWait) {
              Write-Host "." -NoNewLine
              $cmdtime = Measure-Command { $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like '*Dell Command | Update*'}) | Select-Object -First 1 } # Takes 5-10 seconds.. maybe longer.. lets measure
              $elapsedtime += $cmdtime
              if ($Products) {                $InstalledYet = $true              }
            }
            Write-Host ""
            if ($Products) {
              Write-Host "[+] Found, DCU was installed: $(($Products).Version) found" -ForegroundColor Green
            } else {
              Write-Host "[-] DCU couldn't be installed, or isn't done yet after checking 5 times. Check manually!!! " -ForegroundColor Red
              . appwiz.cpl
            }
          } else {
            Write-Host "[X] Download failed!! $DellCommandURL did not write to SecAudPath : $SecAudPath " -ForegroundColor Red
          }
          $QIDsDellCommandUpdate  = 1
        } else { $QIDsDellCommandUpdate  = 1 }
      }
      { 110460 -eq $_ } {
        if (Get-YesNo "$_ Check Office Security Update for March 2024 ? " -Results $Results) {
          # Office ClicktoRun or Office 365 Suite MARCH 2024 Update is not installed   C:\Program Files (x86)\Microsoft Office\root\Office16\GRAPH.EXE  Version is  16.0.17328.20162#
          $ResultsMissing = ($Results -split "is not installed")[0].trim()
          $ResultsVersion = ($Results -split "Version is")[1].trim().replace("#","")
          $CheckEXE = Check-ResultsVersion -Results $Results
          if (Test-Path $CheckEXE) {
            $CheckEXEVersion = Get-FileVersion $CheckEXE
            if ($CheckEXEVersion) {
              Write-Verbose "EXE version found : $CheckEXE - $CheckEXEVersion .. checking against $ResultsVersion"
              if ([version]$CheckEXEVersion -le [version]$ResultsVersion) {
                Write-Host "[!] Vulnerable version $CheckEXE found : $CheckEXEVersion <= $ResultsVersion - Update missing: $ResultsMissing"
              } else {
                Write-Host "[+] EXE patched version found : $CheckEXEVersion > $VulnDescChromeWinVersion - already patched." -ForegroundColor Green  # SHOULD never get here, patches go in a new folder..
              }
            } else {
              Write-Host "[-] EXE Version not found, for $CheckEXE .." -ForegroundColor Yellow
            }
          } else {
            Write-Host "[!] EXE no longer found: $CheckEXE - likely its already been updated. Let's check.."
          }
        }
      }
      { 106069 -eq $_ } {
        if (Get-YesNo "$_ Remove EOL/Obsolete Software: Microsoft Access Database Engine 2010 Service Pack 2 ? " -Results $Results) { 
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'Microsoft Access Database Engine 2010*'})
          if ($Products) {
            Remove-Software -Products $Products -Results $Results
          } else {
            Write-Host "[!] Access Database Engine 2010 not found under 'Microsoft Access Database Engine 2010*' : `n    $Products !!`n" -ForegroundColor Red
          } 
          $pfx86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)") # Powershell is being super clunky about the parenthesis for some reason?? had to resort to this..
          $TestFile = "$($pfx86)\Common Files\Microsoft Shared\Office14\acecore.dll"
          if (Test-Path -Path "$TestFile") {
            Write-Host "[!] File still found: ""$TestFile"" - Removing!"  # I'm a cheater, I know, I'm terrible. Not a good remediation, but its unlikely to be used as a PE, no exploit, just EOL, etc.
            Remove-Item $TestFile -Force
          }
          if (Test-Path -Path "$TestFile") {
            Write-Host "[!] File still found: ""$TestFile"" - NOT FIXED!" -ForegroundColor Red
            Remove-Item $TestFile -Force
          }
        }
      }
      { ($QIDsAdobeReader -contains $_) -or ($VulnDesc -like "*Adobe Reader*" -and ($QIDsAdobeReader -ne 1)) } {
        if (Get-YesNo "$_ Remove older versions of Adobe Reader ? " -Results $Results) { 
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'Adobe Reader*'})
          if ($Products) {
            Write-Host "[.] Products found matching *Adobe Reader* : "
            $Products
            Remove-Software -Products $Products -Results $Results
          } else {
            Write-Host "[!] Adobe products not found under 'Adobe Reader*' : `n    $Products !!`n" -ForegroundColor Red
          }  
        }
        if (Get-YesNo "$_ Install newest Adobe Reader DC ? ") {
          Get-NewestAdobeReader
          #cmd /c "$($tmp)\readerdc.exe"
          $Outfile = "$($tmp)\readerdc.exe"
          # silent install
          Start-Process -FilePath $Outfile -ArgumentList "/sAll /rs /rps /msi /norestart /quiet EULA_ACCEPT=YES" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
          $QIDsAdobeReader = 1
        } else { $QIDsAdobeReader = 1 }
      }
      { $QIDsMicrosoftSilverlight -contains $_ -or ($VulnDesc -like "*Silverlight*" -and ($QIDsMicrosoftSilverlight -ne 1))} {
        if (Get-YesNo "$_ Remove Microsoft Silverlight ? ") {
          Write-Host "[.] Checking for product: '{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00}' (Microsoft Silverlight) .." -ForegroundColor Yellow
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like '{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00}'})
          if ($Products) {
              Remove-Software -Products $Products -Results $Results
              $QIDsMicrosoftSilverlight = 1
          } else {
            Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
            $QIDsMicrosoftSilverlight = 1
          } 
        }
      }
      { $QIDsSQLServerCompact4 -contains $_ } {
        if (Get-YesNo "$_ Remove MS SQL Server Compact 4 ? ") {
          Write-Host "[.] Checking for product: '{78909610-D229-459C-A936-25D92283D3FD}' (SQL Server Compact 4) .." -ForegroundColor Yellow
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like '{78909610-D229-459C-A936-25D92283D3FD}'})
          if ($Products) {
              Remove-Software -Products $Products -Results $Results
              $QIDsSQLServerCompact4 = 1
          } else {
            Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
            $QIDsSQLServerCompact4  = 1
          } 
        }
      }
      { $QIDsMicrosoftAccessDBEngine -contains $_ } {
        if (Get-YesNo "$_ Remove MicrosoftAccessDBEngine ? ") {
          Write-Host "[.] Checking for product: '{9012.. or {90140000-00D1-0409-0000-0000000FF1CE}' (MicrosoftAccessDBEngine) .." -ForegroundColor Yellow
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like '{90120000-00D1-0409-0000-0000000FF1CE}' -or `
                                                            $_.IdentifyingNumber -like '{90140000-00D1-0409-1000-0000000FF1CE}'})
          if ($Products) {
              Remove-Software -Products $Products -Results $Results
              $QIDsMicrosoftAccessDBEngine = 1
          } else {
            Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
            $QIDsMicrosoftAccessDBEngine = 1
          }
        }
      }
      { $QIDsMicrosoftVisualStudioActiveTemplate -contains $_ } {
        $notfound = $true
        if (Get-YesNo "$_ $_ Install Microsoft Visual C++ 2005/8 Service Pack 1 Redistributable Package MFC Security Update? " -Results $Results) { 
          $Installed=get-wmiobject -class Win32_Product | Where-Object{ $_.Name -like '*Microsoft Visual*'} # | Format-Table IdentifyingNumber, Name, LocalPackage -AutoSize
          if ($Installed | Where-Object {$_.IdentifyingNumber -like '{9A25302D-30C0-39D9-BD6F-21E6EC160475}'}) { 
              Write-Host "[!] Found Microsoft Visual C++ 2008 Redistributable - x86 "
              $notfound = $false
              Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe" -OutFile "$($tmp)\vcredist2008x86.exe"
              cmd /c "$($tmp)\vcredist2008x86.exe /q"
              $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | Where-Object { $_.IdentifyingNumber -like '{837b34e3-7c30-493c-8f6a-2b0f04e2912c}'}) {
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable"
            $notfound = $false
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -OutFile "$($tmp)\vcredist2005.exe"
            cmd /c "$($tmp)\vcredist2005.exe /q"
            $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | Where-Object { $_.IdentifyingNumber -like '{710f4c1c-cc18-4c49-8cbf-51240c89a1a2}'}) {
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable - x86"
            $notfound = $false
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -OutFile "$($tmp)\vcredist2005x86.exe"
            cmd /c "$($tmp)\vcredist2005x86.exe /q"
            $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | Where-Object { $_.IdentifyingNumber -like '{6E8E85E8-CE4B-4FF5-91F7-04999C9FAE6A}'}) { #x64
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable - x64 "
            $notfound = $false
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" -OutFile "$($tmp)\vcredist2005x64.exe"
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
      { 378941,378755 -contains $_ } {
        if (Get-YesNo "$_ Install latest MS Teams ? ") {
          $TeamsURL=(IWR "https://teams.microsoft.com/desktopclient/installer/windows/x64").Content
          IWR $TeamsURL -OutFile "$($tmp)/teams.exe"
          . "$($tmp)/teams.exe"
        }
      }



      { $QIDsMicrosoftNETCoreV5 -contains $_ } {
        if (Get-YesNo "$_ Remove .NET Core 5 (EOL) " -Results $Results) { 
          <# Remove one or all of these??
          IdentifyingNumber                      Name                                           LocalPackage
          -----------------                      ----                                           ------------
          {8BA25391-0BE6-443A-8EBF-86A29BAFC479} Microsoft .NET Host FX Resolver - 5.0.17 (x64) C:\Windows\Installer\a3227a.msi
          {5A66E598-37BD-4C8A-A7CB-A71C32ABCD78} Microsoft .NET Runtime - 5.0.17 (x64)          C:\Windows\Installer\a32276.msi
          {E663ED1E-899C-40E8-91D0-8D37B95E3C69} Microsoft .NET Host - 5.0.17 (x64)             C:\Windows\Installer\a3227f.msi


          For now, will remove just the Runtime which I believe is the only vulnerability..  Maybe we remove all 3 though, will find out.
          #>
          Write-Host "[.] Checking for product: '{5A66E598-37BD-4C8A-A7CB-A71C32ABCD78}' (.NET Core 5) .." -ForegroundColor Yellow
          try {
            $Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like '{5A66E598-37BD-4C8A-A7CB-A71C32ABCD78}'})
          } catch {
            Write-Host "[!] Error running command: '(get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like '{5A66E598-37BD-4C8A-A7CB-A71C32ABCD78}'})'" -ForegroundColor Red
            Write-Host "[!] Please remove or update .NET 5 manually." -ForegroundColor Red
            break
          }
          if ($Products) {
              Remove-Software -Products $Products -Results $Results
              $QIDsMicrosoftNETCoreV5 = 1
          } else {
            Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
            $QIDsMicrosoftNETCoreV5 = 1
          }             
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

        if (Get-YesNo "$_ Install SQL Server $SQLVersion $SQLEdition update? " -Results $Results) { 
          if ("$SQLVersion $SQLEdition" -eq "12.2.5000.0 Express Edition") { # SQL Server 2014 Express
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://www.microsoft.com/en-us/download/confirmation.aspx?id=54190&6B49FDFB-8E5B-4B07-BC31-15695C5A2143=1" -OutFile "$($tmp)\sqlupdate.exe"
            cmd /c "$($tmp)\sqlupdate.exe /q"
          }
          if ("$SQLVersion $SQLEdition" -eq "12.2.5000.0 Standard Edition") { # SQL Server 2014
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://www.microsoft.com/en-us/download/confirmation.aspx?id=57474&6B49FDFB-8E5B-4B07-BC31-15695C5A2143=1" -OutFile "$($tmp)\sqlupdate.exe"
            cmd /c "$($tmp)\sqlupdate.exe /q"
          }
        }
      }
      { ($QIDsNVIDIA -contains $_) -or ($VulnDesc -like "*NVIDIA*" -and ($QIDsNVidia -ne 1)) } {
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
              if (Test-Path "c:\windows\system32\nvvsvc.exe") {
                if (Get-YesNo "$_ Remove NVIDIA PrivEsc exe c:\windows\system32\nvvsvc.exe ? ") { 
                  Write-Host "[.] Running: 'taskkill /f /im nvvsvc.exe' .."
                  cmd.exe /c "taskkill /f /im nvvsvc.exe"
                  Write-Host "[.] Running: 'del c:\windows\System32\nvvsvc.exe /f /s /q'  .."
                  cmd.exe /c "del c:\windows\System32\nvvsvc.exe /f /s /q"
                  if (!(Test-Path "c:\windows\system32\nvvsvc.exe")) {
                    Write-Host "[.] Success!"
                  } else {
                    Write-Host "[!] Error deleting %windir%\System32\nvvsvc.exe !! Not fixed."
                  }
                  
                }
              } else {
                Write-Host "[!] Error, can't find C:\Windows\System32\nvvsvc.exe ! Looks like its already been deleted?"
              }
            }
        } else { $QIDsNVIDIA = 1 }
      }
      376609 {
        if (Get-YesNo "$_ Delete nvcpl.dll for NVIDIA GPU Display Driver Multiple Vulnerabilities (May 2022) ? " -Results $Results) { 
          Remove-File "C:\Windows\System32\nvcpl.dll" -Results $Results
        }
      }    
      370468 {
        if (Get-YesNo "$_ Remove Cisco WebEx ? ") {
          Write-Host "[.] Checking for product: 'Cisco WebEx*' " -ForegroundColor Yellow
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'Cisco WebEx*'})
          if ($Products) {
              Remove-Software -Products $Products  -Results $Results
          } else {
            Write-Host "[!] Product not found: 'Cisco WebEx*' !!`n" -ForegroundColor Red
          }    
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
      92053 {
        if (Get-YesNo "$_ Delete Microsoft Windows Defender Elevation of Privilege Vulnerability for August 2023? " -Results $Results) { 
          Write-Host "Active antivirus: $((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).DisplayName -join(" & "))"
          Remove-File "C:\WINDOWS\System32\MpSigStub.exe" -Results $Results
        }
      }      
      91621 {
        if (Get-YesNo "$_ Delete Microsoft Defender Elevation of Privilege Vulnerability April 2020? " -Results $Results) { 
          # This will ask twice due to Remove-File, but I want to offer results first. Could technically add -Results to Remove-File..
          Write-Host "Active antivirus: $((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).DisplayName -join(" & "))"
          Remove-File "C:\WINDOWS\System32\MpSigStub.exe" -Results $Results
        }
      }
      91649 {
        if (Get-YesNo "$_ Delete Microsoft Defender Elevation of Privilege Vulnerability June 2020? " -Results $Results) { 
          Write-Host "Active antivirus: $((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).DisplayName -join(" & "))"
          Remove-File "$($env:ProgramFiles)\Windows Defender\MpCmdRun.exe" -Results $Results
        }
      }
      91972 {
        if (Get-YesNo "$_ Delete Microsoft Windows Malicious Software Removal Tool Security Update for January 2023? " -Results $Results) { 
          Remove-File "$($env:windir)\system32\MRT.exe" -Results $Results
        }
      }
      105803 {
        if (Get-YesNo "$_ Remove EOL/Obsolete Software: Adobe Shockwave Player 12 ? " -Results $Results) { 
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'Adobe Shockwave*'})
          if ($Products) {
              Remove-Software -Products $Products  -Results $Results
          } else {
            Write-Host "[!] Product not found: 'Adobe Shockwave*' !!`n" -ForegroundColor Red
          }    
        }
      }
      106105 {
        if (Get-YesNo "$_ Remove EOL/Obsolete Software: Microsoft .Net Core Version 3.1 Detected? " -Results $Results) { 
          Remove-Folder "$($env:programfiles)\dotnet\shared\Microsoft.NETCore.App\3.1.32" -Results $Results
        }
      }
      378332 {
        if (Get-YesNo "$_ Fix WinVerifyTrust Signature Validation Vulnerability? " -Results $Results) { 
          Write-Output "[.] Creating registry item: HKLM:\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck=1"
          New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust" -Force | Out-Null
          New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null
          New-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value "1" -PropertyType "String" -Force | Out-Null
          
          Write-Output "[.] Creating registry item: HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck=1"
          New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust" -Force | Out-Null
          New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null #  \Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config EnableCertPaddingCheck
          New-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value "1" -PropertyType "String" -Force | Out-Null    
          Write-Output "[!] Done!"
        }
      }
      378936 {
        if (Get-YesNo "$_ Fix Microsoft Windows Curl Multiple Security Vulnerabilities? " -Results $Results) { 
          Write-Host "[.] Showing Curl.exe version comparison.."
          $curlfile = "c:\windows\system32\curl.exe"
          Show-FileVersionComparison -Name $curlfile -Results $Results
          $KB5032189_installed = Get-WuaHistory | Where-Object { $_.Title -like "*5032189*" } 
          if ($KB5032189_installed) {
            Write-Host "[+] KB5032189 found already installed. This is fixed."
          } else {
            Write-Host "[-] KB5032189 not found installed. Showing all Windows update history:"
            Get-WuaHistory | FT
            Write-Host "[.] Opening MSRC page: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38545#securityUpdates"
            explorer "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38545#securityUpdates"
          }
        }
      }
      378931 {
        if (Get-YesNo "$_ Fix Microsoft SQL Server, ODBC and OLE DB Driver for SQL Server Multiple Vulnerabilities for October 2023? " -Results $Results) { 
          $tmp=$env:temp
          Write-Host "[.] Downloading required VC++ Library files: VC_redist.x64.exe and VC_redist.x64.exe" 
          wget "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "$($tmp)\vc_redist.x64.exe"
          wget "https://aka.ms/vs/17/release/vc_redist.x86.exe" -OutFile "$($tmp)\vc_redist.x86.exe"
          Write-Host "[.] Downloading mseoledbsql_19.3.1.msi" 
          wget "https://go.microsoft.com/fwlink/?linkid=2248728" -OutFile "$($tmp)\msoledbsql_19.3.2.msi"
          Write-Host "[.] Running: VC_redist.x64.exe /s"
          . "$($tmp)\VC_redist.x64.exe" "/s"  #this might not be working, didn't seem to work for me.. 
          Write-Host "[.] Running: VC_redist.x86.exe /s" 
          . "$($tmp)\VC_redist.x86.exe" "/s" 
          #. "msiexec" "/i $($tmp)\msoledbsql_19.3.1.msi /qn /quiet" # not working.. figured out it needs this last parameter, below to accept eula
          $params = '/i',"$($tmp)\msoledbsql_19.3.2.msi",'/quiet','/qn','/norestart',"IACCEPTMSOLEDBSQLLICENSETERMS=YES"
          Write-Host "[.] Running: msiexec, params:"
          Write-Host @params 
          & "msiexec.exe" @params 
<#

# THIS NEEDS TO BE CLEANED UP, MAY REMOVE ALL VERSIONS, DISABLING UNTIL FIXED.. Better to look at it by hand I guess for now.

          Write-Host "[.] Waiting 30 seconds for this to complete.."
          start-sleep 30
          Write-Host "[.] Removing older versions of MS SQL ODBC and OLE DB Driver.."
          $ResultVersions = Parse-ResultsVersion $Results
          Write-Verbose "ResultVersions: $ResultVersions"
          if ($ResultVersions) {
            if ($ResultVersions.Count -gt 1) {
              Foreach ($ver in $ResultVersions) {
                Write-Verbose "Version found: $Ver"
                $Products = (get-wmiobject Win32_Product | Where-Object { ($_.Name -like "Microsoft OLE DB Driver*" -or $_.Name -like "Microsoft ODBC Driver*") -and [version]$_.Version -lt [version]"19.3.1.0"})
                if ($Products) {
                  if (Get-YesNo "Remove older product(s): $($Products.Name) $($Products.Version) ") {}
                    Remove-Software -Products $Products  -Results $Results
                  }
                } 
              }
            }
          }
#>
          Write-Host "[.] Please make sure this is installed properly, and old, vulnerable versions are removed, opening appwiz.cpl:"
          . appwiz.cpl
        }
      }      
      379223 { # Windows SMB Version 1 (SMBv1) Detected -- https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server
        if (Get-YesNo "$_ Windows SMB Version 1 (SMBv1) Detected - Disable " -Results $Results) { 
          Write-Host "[.] Get-SMBServerConfiguration status:" -ForegroundColor Yellow
          $SMB1ServerStatus = (Get-SmbServerConfiguration | Format-List EnableSMB1Protocol)
          ($SMB1ServerStatus | Out-String) -Replace("`n","")
          Write-Verbose "[.] Checking Registry for MME SMB1Auditing :"
          if (Get-RegistryEntry -Name SMB1Auditing -ne 1) {  # If our registry key is not set, turn on auditing for a month to see if its in use and dont do anything else yet (but give the option to if they want)
            Write-Host "[+] It appears we have not checked for SMB1 access here. Setting registry setting, enabling auditing for a month." -ForegroundColor Red
            (Set-SmbServerConfiguration -AuditSmb1Access $True -Force | Out-String) -Replace ("`n","")
            Set-RegistryEntry -Name SMB1Auditing 1
            Write-Host "[.] However, we will give you a chance to disable it now, if you prefer:" -ForegroundColor Yellow
          } else {  # If registry key IS set, we ran this last month or more, lets check logs for event 3000 and report
            # Would be really nice to know the last run date here also, for how many days back to check for these events, we'll just do 30 days for now
            $smb1AccessEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SMBServer/Audit'; ID=3000; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue
            if ($smb1AccessEvents) { # we need to know the 3000 event 'Client Address' in it, and report this IP/hostname, move recursively thru the list for each address using SMB1
              Write-Host "[-] Found evidence of SMB1 client access in the event log:" -ForegroundColor Red
              foreach ($thisevent in $smb1AccessEvents) {  
                $eventMessage = $thisevent.Message
                $ipPattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                $clientIP = [regex]::Match($eventMessage, $ipPattern).Value
                Write-Host "[-] Client IP Address: $clientIP" -ForegroundColor Red
              }
              $smb1AccessEvent | Format-List
            } else {
              Write-Host "[+] No evidence of SMB1 client access found in event logs. Safe to disable completely, and disable the check next month." -ForegroundColor Green
              Set-RegistryEntry -Name SMB1Auditing -Value 0
            }
          } # No matter what, we will give them the option to just run this
          if (Get-YesNo "NOTE: Disabling this may break things!!! `n`nRisks:`n  [ ] Old iCAT XP computers `n  [ ] Old copier/scanners (scan to SMB) `n  [ ] Other devices that need to access this computer over SMB1.`n`nIt may be safest to do some monitoring first, by turning on SMB v1 auditing (Set-SmbServerConfiguration -AuditSmb1Access `$True) and checking for Event 3000 in the ""Microsoft-Windows-SMBServer\Audit"" event log next month, and then identifying each client that attempts to connect with SMBv1.`n  I have turned on SMB1 auditing for you now, and the script can automatically check for clients next month and disable this if you aren't sure. `nAre you sure you want to continue removing SMB1? " -Results $Results) { 
            Write-Host "[.] Removing Feature for SMB 1.0:" -ForegroundColor Green
            # CAPTION INSTALLSTATE NAME SMB 1.0/CIFS File Sharing Support SMB Server version 1 is Enabled# 
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
            # HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10 Start = 2 SMB Client version 1 is Enabled#  # <-- This could show up also
            Write-Host "[.] Disabling service MRXSMB10:" -ForegroundColor Green
            if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10")) {
              New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" 
            Write-Host "[.] Done.  A reboot will be needed for this to go into effect. Please test all applications and access after!" -ForegroundColor Yellow
          } else {
            Write-Host "[!] Nothing changed! Please re-run in a month and check back if any systems have used SMB1 to access this machine." -ForegroundColor Green
          }
        }
      }
      376709 {
        # 110251 Microsoft Office Remote Code Execution Vulnerabilities (MS15-022) (Msores.dll) - ClickToRun office removal
        # %programfiles(x86)%\Common Files\Microsoft Shared\Office15\Msores.dll   Version is  15.0.4687.1000#
        if (Get-YesNo "$_ Remove HP Support Assistant Multiple Security Vulnerabilities (HPSBGN03762)? " -Results $Results) { 
          $Products = Get-Products ""
          if ($Products) {
              Remove-Software -Products $Products  -Results $Results
          } else {
            Write-Host "[!] Product not found: 'HP Support Assist*' !!`n" -ForegroundColor Red
          }  
        }       
      }	
      376709 {
        # 376709	HP Support Assistant Multiple Security Vulnerabilities (HPSBGN03762)
        # C:\Program Files (x86)\Hewlett-Packard\HP Support Framework\\HPSF.exe  Version is  8.8.34.31#
        if (Get-YesNo "$_ Remove HP Support Assistant Multiple Security Vulnerabilities (HPSBGN03762)? " -Results $Results) { 
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'HP Support Assist*'})
          if ($Products) {
              Remove-Software -Products $Products  -Results $Results
          } else {
            Write-Host "[!] Product not found: 'HP Support Assist*' !!`n" -ForegroundColor Red
          }  
        }       
      }	
      106116 {        
        if (Get-YesNo "$_ Delete EOL/Obsolete Software: Microsoft Visual C++ 2010 Redistributable Package Detected? " -Results $Results) { 
          Remove-File "$($env:ProgramFiles)\Common Files\Microsoft Shared\VC\msdia100.dll" -Results $Results
          Remove-File "$(${env:ProgramFiles(x86)})\Common Files\Microsoft Shared\VC\msdia100.dll" -Results $Results
        }       
      }	
      110432 {
        $ResultsEXE = "C:\Program Files (x86)\Microsoft Office\root\Office16\GRAPH.EXE"
        $ResultsEXEVersion = Get-FileVersion $ResultsEXE
        if ($ResultsEXEVersion -le 16.0.16227.20258) {
          Write-Host "[!] Vulnerable version $ResultsEXE found : $ResultsEXEVersion <= 16.0.16227.20258"
        }
      }
      $QIDsOffice2007 {
        <#
        HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\12.0\Common\ProductVersion LastProduct = 12.0.6612.1000  KB4092465 is not installed   %ProgramFiles(x86)%\Common Files\Microsoft Shared\Office12\mso.dll  Version is  12.0.6785.5000  KB4461607 is not installed   C:\Program Files (x86)\Microsoft Office\Office12\\excelcnv.exe  Version is  12.0.6787.5000#
        HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\12.0\Common\ProductVersion LastProduct = 12.0.6612.1000  KB4461565 is not installed   C:\Program Files (x86)\Microsoft Office\Office12\\excelcnv.exe  Version is  12.0.6787.5000  KB2597975 is not installed   C:\Program Files (x86)\Microsoft Office\Office12\\Pptview.exe  Version is  12.0.6654.5000#
        HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\12.0\Common\ProductVersion LastProduct = 12.0.6612.1000  KB4461518 is not installed   C:\Program Files (x86)\Microsoft Office\Office12\\excelcnv.exe  Version is  12.0.6787.5000#
        HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\12.0\Common\ProductVersion LastProduct = 12.0.6612.1000  KB4092444 is not installed   %ProgramFiles(x86)%\Common Files\Microsoft Shared\Office12\ogl.dll  Version is  12.0.6776.5000#
        HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\12.0\Common\ProductVersion LastProduct = 12.0.6612.1000  KB4092466 is not installed   C:\Program Files (x86)\Microsoft Office\Office12\\excelcnv.exe  Version is  12.0.6787.5000#
        HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\12.0\Common\ProductVersion LastProduct = 12.0.6612.1000  KB4011202 is not installed   %ProgramFiles(x86)%\Common Files\Microsoft Shared\Office12\ogl.dll  Version is  12.0.6776.5000#
        HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\12.0\Common\ProductVersion LastProduct = 12.0.6612.1000  KB4011207 is not installed   %ProgramFiles(x86)%\Microsoft Office\Office12\ppcnv.dll  Version is  12.0.6776.5000#
        HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\12.0\Common\ProductVersion LastProduct = 12.0.6612.1000  KB4092444 is not installed   %ProgramFiles(x86)%\Common Files\Microsoft Shared\Office12\ogl.dll  Version is  12.0.6776.5000#
        HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\12.0\Common\ProductVersion LastProduct = 12.0.6612.1000  KB4011202 is not installed   %ProgramFiles(x86)%\Common Files\Microsoft Shared\Office12\ogl.dll  Version is  12.0.6776.5000#
        #>
        $Path="HKLM\SOFTWARE\Wow6432Node\Microsoft\Office\12.0\Common\ProductVersion\LastProduct"
        if (Get-YesNo "$_ Microsoft Office and Microsoft Office Services and Web Apps Security Update 2018/2019 " -Results $Results) {
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like "*Office 2007*"})
          if ($Products) {
            Write-Host "[!] WARNING: Office 2007 product found! Can't auto-fix this.. Need one or more of these KB's installed: "
            Write-Host "  KB4092464, KB4461565, KB4461518, KB4092444, KB4092466, KB4011202, KB4011207, KB4011202"
            Write-Host "[!] Product found installed:"
            Write-Host "$Products"
          } else {
            # If Office2007 is not installed, it should be safe to remove these conversion apps that may be vulnerable.
            $Result = (($Results -split('is not installed'))[1] -split ('Version is'))[0].trim()
            if (Test-Path $Result) {
              if (Get-YesNo "Delete $Result ?") {
                Write-Verbose "Removing file $Result"
                Remove-File $Result
                if (!(Test-Path $Result)) {
                  Write-Verbose "Removed file $Result"
                } else {
                  Write-Host "[!] ERROR: Couldn't remove $Result !!"
                }
              }
            }
            if (Get-Item $Path) {
              if (Get-YesNo "Delete registry item $Path ?") {
                Remove-RegistryItem $Path
              }
              # $QIDsOffice2007 = 1 # Not doing this, need to check for each EXE
            } else {
              Write-Verbose "Looks like registry key $Path was already removed."
            }
          }
        }
      }
      91850 {
        # $Results = "Microsoft vulnerable Office app detected  Version     '18.2008.12711.0'#""
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Office app Remote Code Execution (RCE) Vulnerability $AppxVersion" -Results $Results) {
          Remove-SpecificAppXPackage -Name "Office" -Version $AppxVersion -Results $Results # "18.2008.12711.0"
        }
      }
      91848 {
        # Multiple versions can be found in one result..
        # Microsoft vulnerable Microsoft Desktop Installer detected  Version     '1.4.3161.0'
        # Microsoft vulnerable Microsoft Desktop Installer detected  Version     '1.21.3133.0'#
        $AppxVersions = Get-VersionResults -Results $Results
        if (Get-YesNo "$_ Remove Microsoft.DesktopAppInstaller vulnerable versions $AppxVersions " -Results $Results) {
          ForEach ($AppxVersion in $AppxVersions) {
            Write-Host "[.] Removing Microsoft.DesktopAppInstaller version $AppxVersion .."
            Remove-SpecificAppXPackage -Name "Microsoft.DesktopAppInstaller" -Version $AppxVersion -Results $Results
          }
        }
      }

      91866 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library HEVC Video and VP9 Extensions Remote Code Execution (RCE) Vulnerability for February 2022" -Results $Results) {

          # $Results = Microsoft vulnerable Microsoft.VP9VideoExtensions detected  Version     '1.0.41182.0'#

          #  91866 Remove Microsoft Windows Codecs Library HEVC Video and VP9 Extensions Remote Code Execution (RCE) Vulnerability for February 2022 ..                                                                                                                                                  
          #  You cannot call a method on a null-valued expression.                                                                                                         
          #  At \\dc-server\data\SecAud\Install-SecurityFixes.ps1:1020 char:3                                                                                              
          #  +   $VersionResults = ($Results -split "'")[1].replace("'","").replace( ...                                                                                   
          #  +   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                                                                                           
          #  + CategoryInfo          : InvalidOperation: (:) [], RuntimeException                                                                                          
          #  + FullyQualifiedErrorId : InvokeMethodOnNull        

          Remove-SpecificAppXPackage -Name "HEIFImageExtension" -Version "1.0.42352.0"
          Remove-SpecificAppXPackage -Name "Microsoft.VP9VideoExtensions" -Version $AppxVersion -Results $Results # "1.0.41182.0" 
        }
      }
      91914 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft.VP9VideoExtensions Version 1.0.41182.0" -Results $Results) {
          Remove-SpecificAppXPackage -Name "Microsoft.VP9VideoExtensions" -Version $AppxVersion -Results $Results # "1.0.41182.0" 
        }
      }
      91869 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library Remote Code Execution (RCE) Vulnerability for March 2022" -Results $Results) {
          #Microsoft vulnerable Microsoft.VP9VideoExtensions detected  Version     '1.0.41182.0'  !!!! wrong appx..
          #Microsoft vulnerable Microsoft.HEIFImageExtension detected  Version     '1.0.42352.0'#
          Remove-SpecificAppXPackage -Name "HEIFImageExtension" -Version $AppxVersion -Results $Results # "1.0.41182.0" 
        }
      }
      91847 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft.HEIFImageExtension Version 1.0.42352.0" -Results $Results) {
          Remove-SpecificAppXPackage -Name "HEIF" -Version $AppxVersion -Results $Results # "1.0.42352.0" 
        }
      }
      91845 {   
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library HEVC Video And Web Media Extensions Remote Code Execution (RCE) Vulnerability for December 2021" -Results $Results) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0"
        }
      }
      91914 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft.Windows.Photos Version 2021.21090.10007.0" -Results $Results) {
          Remove-SpecificAppXPackage -Name "Microsoft.Windows.Photos" -Version $AppxVersion -Results $Results # "2021.21090.10007.0" 
        }
      }
      91819 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft HEVCVideoExtension Version 0.33232.0 " -Results $Results) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      }
      91773 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft 3D Viewer Multiple Vulnerabilities - June 2021" -Results $Results) {
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version $AppxVersion -Results $Results # "7.2009.29132.0" 
        }
      }
      91834 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft 3D Viewer Remote Code Execution (RCE) Vulnerability - November 2021" -Results $Results) {
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version $AppxVersion -Results $Results # "7.2009.29132.0" 
        }
      }
      92117 { # Microsoft 3D Viewer Remote Code Execution (RCE) Vulnerability - February 2024
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft 3D Viewer Remote Code Execution (RCE) Vulnerability - February 2024" -Results $Results) {
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version $AppxVersion -Results $Results # Microsoft vulnerable Microsoft.Microsoft3DViewer detected  Version     '7.2307.27042.0'#
        }
      }
      91774 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Paint 3D Remote Code Execution Vulnerability - June 2021" -Results $Results) {
          Remove-SpecificAppXPackage -Name "MSPaint" -Version $AppxVersion -Results $Results # "6.2009.30067.0" 
        }
      }
      91871 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Paint 3D Remote Code Execution (RCE) Vulnerability for March 2022" -Results $Results) {
          Remove-SpecificAppXPackage -Name "MSPaint" -Version $AppxVersion -Results $Results # Microsoft vulnerable Microsoft.MSPaint detected  Version     '1.0.68.0'#
        }
      }
      91761 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library and VP9 Video Extensions Multiple Vulnerabilities" -Results $Results) {
          Remove-SpecificAppXPackage -Name "VP9VideoExtensions" -Version $AppxVersion -Results $Results # "1.0.32521.0" 
        }
      }
      91775 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows VP9 Video Extension Remote Code Execution Vulnerability  " -Results $Results) {
          Remove-SpecificAppXPackage -Name "VP9VideoExtensions" -Version $AppxVersion -Results $Results # "1.0.32521.0" 
        }
      }
      91919 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library HEVC Video and AV1 Extensions Remote Code Execution (RCE) Vulnerability for June 2022" -Results $Results) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      }
      91788 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library High Efficiency Video Coding (HEVC) Video Extensions Remote Code Execution (RCE) Vulnerabilities" -Results $Results) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      }
      91726 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library Remote Code Execution Vulnerabilities - January 2021 " -Results $Results) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      }   
      91885 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft HEVC Video Extensions Remote Code Execution (RCE) Vulnerability for April 2022" -Results $Results) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      } 
      91855 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft HEVC Video Extensions Remote Code Execution (RCE) Vulnerability for January 2022" -Results $Results) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      } 
      91820 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft MPEG-2 Video Extension Remote Code Execution (RCE) Vulnerability " -Results $Results) {
          Remove-SpecificAppXPackage -Name "MPEG2VideoExtension" -Version $AppxVersion -Results $Results # "1.0.22661.0" 
        }
      } 
      378131 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Microsoft Windows Snipping Tool Information Disclosure Vulnerability" -Results $Results) {
          Remove-SpecificAppXPackage -Name "Microsoft.ScreenSketch" -Version $AppxVersion -Results $Results # "10.2008.2277.0"
        }
      }
      91974 {
        # Vulnerable version of Microsoft 3D Builder detected  Version     '18.0.1931.0'#
        $AppxVersion = ($results -split "'")[1].replace("'","").replace("#","").trim()  # Cheating here, using ' is probably easier anyway...
        if (Get-YesNo "$_ Microsoft 3D Builder Remote Code Execution (RCE) Vulnerability for January 2023" -Results $Results) {
          Remove-SpecificAppXPackage -Name "Microsoft.3DBuilder" -Version $AppxVersion -Results $Results # "18.0.1931.0"
        }
      }
      91975 { 
        # Vulnerable version of Microsoft 3D Builder detected  Version     '18.0.1931.0'#
        write-Verbose "Results: $Results"
        $AppxVersion = ($results -split "'")[1].replace("'","").replace("#","").trim() # Cheating here, using ' is probably easier anyway...
        write-Verbose "AppxVersion: $AppxVersion"
        if (Get-YesNo "$_ Microsoft 3D Builder Remote Code Execution (RCE) Vulnerability for February 2023" -Results $Results) {
          Remove-SpecificAppXPackage -Name "Microsoft.3DBuilder" -Version $AppxVersion -Results $Results # "18.0.1931.0"
        }
      }
      92030 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Microsoft Raw Image Extension and VP9 Video Extension Information Disclosure Vulnerability" -Results $Results) {
          Remove-SpecificAppXPackage -Name "VP9VideoExtensions" -Version $AppxVersion -Results $Results # "1.0.52781.0"
        }
      }
      92032 {  # Vulnerable Microsoft Paint 3D detected  Version     '6.2105.4017.0'  Version     '6.2203.1037.0'#
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Microsoft Paint 3D Remote Code Execution (RCE) Vulnerability for July 2023" -Results $Results) {
          Remove-SpecificAppXPackage -Name "MSPaint" -Version "6.2105.4017.0" -Results $Results # "6.2105.4017.0"
          Remove-SpecificAppXPackage -Name "MSPaint" -Version "6.2203.1037.0" -Results $Results # "6.2203.1037.0"
        }
      }
      92061 {  # Microsoft vulnerable Microsoft.Microsoft3DViewer detected  Version     '7.2105.4012.0'  Version     '7.2211.24012.0'  Version     '7.2107.7012.0'#
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Microsoft 3D Viewer Remote Code Execution (RCE) Vulnerability - September 2023" -Results $Results) {
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version "7.2105.4012.0" -Results $Results 
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version "7.2211.24012.0" -Results $Results 
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version "7.2107.7012.0" -Results $Results 
        }
      }
      92049 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Microsoft Windows Codecs Library HEVC Video Extensions Remote Code Execution (RCE) Vulnerability for August 2023" -Results $Results) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "2.0.61591.0" 
        }
      }
      92067 {
        if (Get-YesNo "$_ Microsoft HTTP/2 Protocol Distributed Denial of Service (DoS) Vulnerability" -Results $Results) {
          Write-Host "[.] Disabling HTTP/2 TLS with registry key: HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\EnableHttp2Tls=0" -ForegroundColor Yellow
          Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name EnableHttp2Tls -Value 0
          Write-Host "[+] Done!" -ForegroundColor Green
        }
      }
      #HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters EnableHttp2Tls
      378985 { #Disable-TLSCipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA
        $AllCipherSuites = (Get-TLSCipherSuite).Name
        $CipherSuites = ((Get-TLSCipherSuite) | ? {$_.Name -like '*DES*'}).Name
        if (Get-YesNo "$_ Birthday attacks against Transport Layer Security (TLS) ciphers with 64bit block size Vulnerability (Sweet32)" -Results $Results) {
          if ($CipherSuites -ne $null) {
            foreach ($CipherSuite in $CipherSuites) {
              Write-Host "[.] TLS Cipher suite(s) found: $CipherSuite - Disabling." -ForegroundColor Yellow
              Disable-TLSCipherSuite $CipherSuite
              if ((Get-TlsCipherSuite -Name DES) -or (Get-TlsCipherSuite -Name 3DES)) {
                Write-Host "[!] ERROR: Cipher suites still found!! Results:" -ForegroundColor Red
                Get-TlsCipherSuite -Name DES
                Get-TlsCipherSuite -Name 3DES
                Write-Host "[!] Please remove manually!" -ForegroundColor Red
              } else {
                Write-Host "[+] Cipher Suite removed." -ForegroundColor Green
              }
            }
          } else {
            Write-Host "[.] TLS Cipher suite(s) not found for DES or 3DES - Looks like this might have been fixed already? Investigate manually if not." -ForegroundColor Yellow
            Write-Host "[.] Listing all TLS Cipher suites:" -ForegroundColor Yellow
            $AllCipherSuites            
          }
          # Also apply registry fixes:  NOTE: Creating reg keys with '/' character will not work correctly, so there is a fix, they can be created this way:
            # Write-Host "[ ] Creating Ciphers subkeys (with /).." -ForegroundColor Green
            # $key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
            # $null = $key.CreateSubKey('AES 128/128')
          $RegItems = @("Triple DES 168/168","DES 56/56")
          Foreach ($Regitem in $Regitems) {
            Write-Host "[.] Creating new key for SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$($RegItem) "
            #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$($RegItem)" -Name Enabled -Force -ErrorAction Continue | Out-Null  # WONT WORK because of "/" character in key.. Hack below.
            $key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
            $null = $key.CreateSubKey($RegItem)
            Write-Host "[.] Setting property for $RegItem - Enabled = DWORD 0"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\""$($RegItem)""" -Name Enabled -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
          }
          Foreach ($Regitem in $Regitems) {
            $Property=(Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$($RegItem)" -ErrorAcion SilentlyContinue).Property
            if ($Property -eq "Enabled") {
              Write-Host "[.] Checking for created keys: $RegItem : $($Property) - GOOD" -Foregroundcolor Green
            } else {
              Write-Host "[.] Checking for created keys: $RegItem : $($Property) - ERROR, or key does not exist! Listing cipher keys:" -Foregroundcolor Red
              Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\*"
            }
          }
        }
      }      

      92038 {
        if (Get-YesNo "$_ Microsoft Office and Windows HTML Remote Code Execution Vulnerability (Zero Day) for July 2023" -Results $Results) {
          $OfficeProducts = "All"   # Lets just add all the keys here..
          Write-Host "[.] Applying remediation for ALL Office products.."
          if ($OfficeProducts -notlike "All") {
              $OfficeProducts = $OfficeProducts.split(',') | ForEach-Object { $_.Trim() }
              $RemediationTargets = $RemediationValues.GetEnumerator() | ForEach-Object { $_ | Where-Object { $OfficeProducts -match $_.Key } }
          }
          else {
              $RemediationTargets = $RemediationValues.GetEnumerator()
          }
          # Path to all the registry keys
          $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION"
          # We'll want to display an error if we don't have anything to do
          if ($RemediationTargets) { 
              # For Each product we're targeting we'll set the regkey. The Set-RegKey function already checks if it was succesful and will display an error and exit if it fails
              $RemediationTargets | ForEach-Object { 
                  Write-Verbose "$($_.Name) was selected for remediation."
                  if (-not $Undo) {
                      Set-RegKey -Path $Path -Name $_.Value -Value 1
                      Write-Verbose "Success!"
                  }
              }
              Write-Host "[!] Completed. A reboot may be required." -Foregroundcolor Green
          }
          else {
              Write-Host $RemediationTargets
              Write-Warning "No products were selected! The valid value's for -OfficeProducts is listed below you can also use a comma seperated list or simply put 'All'."
              $RemediationValues | Sort-Object Name | Format-Table | Out-String | Write-Host
              Write-Error "ERROR: Nothing to do!"
              exit 1
          }
        }
      }

      371476 {
        if (Get-YesNo "$_ Fix Intel Proset Wireless Software" -Results $Results) {
          Write-Host "[.] Checking for product: 'Intel PROset*' " -ForegroundColor Yellow
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'Intel PROset*'})
          if ($Products) {
            & ncpa.cpl
            if (Get-YesNo "$_ Remove Intel PROset Wireless software (Check NCPA.cpl first!)? ") {
              Remove-Software -Products $Products  -Results $Results
            }
          } else {
            Write-Host "[!] Product not found: 'Intel PROset*' !!`n" -ForegroundColor Red
          }
          if (Test-Path "$($env:programfiles)\intel\wifi") {
            if (Get-YesNo "$_ Remove the folder also ($($env:programfiles)\intel\wifi) ? ") {
              Write-Host "[.] Removing $($env:programfiles)\intel\wifi\ recursively.."
              Remove-Folder "$($env:programfiles)\intel\wifi" -Results $Results
            }
          }
        }

      }
      
      90019 {
        $LmCompat = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa").LmCompatibilityLevel
        if ($LmCompat -eq 5) {
          Write-Output "$_ Fix already in place it appears: LMCompatibilityLevel = 5, Good!"
        } else {
          if (Get-YesNo "$_ Fix LanMan/NTLMv1 Authentication? Currently LmCompatibilityLevel = $LmCompat ? " -Results $Results) { 
            <#
            0- Clients use LM and NTLM authentication, but they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
            1- Clients use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
            2- Clients use only NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controller accepts LM, NTLM, and NTLMv2 authentication.
            3- Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
            4- Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM authentication responses, but it accepts NTLM and NTLMv2.
            5- Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM and NTLM authentication responses, but it accepts NTLMv2.
            #>
            if (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel") {
              Write-Output "[+] Setting registry item: HKLM\System\CurrentControlSet\Control\Lsa LMCompatibilityLevel = 5"
              Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value "5" -Force | Out-Null
            } else {
              Write-Output "[+] Creating registry item: HKLM\System\CurrentControlSet\Control\Lsa LMCompatibilityLevel = 5"
              New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value "5" -Force | Out-Null
            }
            Write-Output "[.] Checking fix: HKLM\System\CurrentControlSet\Control\Lsa LMCompatibilityLevel = 5"
            if ((Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa").LmCompatibilityLevel -eq 5) {
              Write-Output "[+] Found: LMCompatibilityLevel = 5, Good!"
            } else {
              Write-Output "[+] Found: LMCompatibilityLevel = $((Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa").LmCompatibilityLevel) - not 5!"
            }
          }
        }
      }
      372294 {
        if (Get-YesNo "$_ Fix service permissions issues? " -Results $Results) {
          $ServicePermIssues = Get-ServicePermIssues -Results $Results
          Write-Verbose "IN MAIN LOOP: Returned from Get-ServicePermIssues: $ServicePermIssues"
          foreach ($file in $ServicePermIssues) {
            if (!(Get-ServiceFilePerms $file)) {
              Write-Output "[+] Permissions look good for $file ..."
            } else { # FIX PERMS.
              $objACL = Get-ACL $file
              Write-Output "[.] Checking owner of $file .. $($objacl.Owner)"
              # Check for file owner, to resolve problems setting inheritance (if needed)
              if ($objacl.Owner -notlike "*$($env:USERNAME)") { # also allow [*\]User besides just User
                #if (Get-YesNo "Okay to take ownership of $file as $($env:USERNAME) ?") {   
                if ($true) {   # Lets just do this..
                  $objacl.SetOwner([System.Security.Principal.NTAccount] $env:USERNAME)
                } else { 
                  Write-Verbose "[.] WARNING: Likely the changes will fail, we are not the owner."
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
                Write-Verbose "[.] Turning off inheritance for $file"
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
              if (!(Get-ServiceFilePerms $file)) {
                Write-Output "[+] Permissions are good for $file "
              } else {
                Write-Output "[!] WARNING: Permissions NOT fixed on $file .. "
                Get-FilePerms "$($file)"
              }
            }
          }
          <# 
          # Old code to check with accesschk.. couldn't get this quite right.. would be nice!!!
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
      $QIDsMSXMLParser4 {
        if (Get-YesNo "$_ Install MSXML Parser 4.0 SP3 update? " -Results $Results) { 
          Write-Host "[.] Downloading installer to $($tmp)\msxml.exe .."
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/A/7/6/A7611FFC-4F68-4FB1-A931-95882EC013FC/msxml4-KB2758694-enu.exe" -OutFile "$($tmp)\msxml.exe"
          Write-Host "[.] Running installer: $($tmp)\msxml.exe .."
          cmd /c "$($tmp)\msxml.exe /quiet /qn /norestart /log $($tmp)\msxml.log"
        }
        $QIDsMSXMLParser4 = 1
      }

    ############################################
      # Default - QID not found!  3-28-24 - Lets check for specific Results here. I don't know what the QID numbers will be, but for now, if there are specific KB's in the results, it is likely missing these patches
      #   But - lets check that those patches are not installed.
      Default {
        if ($Results -like "*KB*" -and $Results -like "*is not installed*") {
          if (Get-YesNo "$_ Check if KB is installed for $VulnDesc " -Results $Results) { 
            Write-Verbose "- Found $_ is related to a KB, contains 'KB' and 'is not installed'"
            # Lets check the file versioning stuff instead as it is a better source of truth if a patch is installed or not, thanks Microsoft
            $ResultsMissing = ($Results -split "is not installed")[0].trim()
            # This can have multiple versions, ugh.
            # KB5033920 is not installed  %windir%\Microsoft.NET\Framework64\v4.0.30319\System.dll Version is 4.8.9172.0 %windir%\Microsoft.NET\Framework\v4.0.30319\System.dll Version is 4.8.9172.0 KB5034275 or KB5034274 or KB5034276 is not installed#"
            
            $ResultsVersion = Check-ResultsForVersion -Results $Results  # split everything after space, [version] cannot have a space in it.. Also should work for multiple versions, we will just check the first result.
            Write-Verbose "ResultsVersion : $ResultsVersion"
            $CheckEXE = Check-ResultsForFiles -Results $Results # Get Multiple EXE/DLL FileNames to check, from $Results 
            Write-Verbose "CheckEXE: $CheckEXE"
            if (Test-Path $CheckEXE) {
              $CheckEXEVersion = Get-FileVersion $CheckEXE
              Write-Verbose "Get-FileVersion results: $CheckEXEVersion"
              if ($CheckEXEVersion) {
                Write-Verbose "EXE/DLL version found : $CheckEXE - $CheckEXEVersion .. checking against -- $ResultsVersion --"
                if ([version]$CheckEXEVersion -lt [version]$ResultsVersion) {
                  Write-Host "[!] Vulnerable version of $CheckEXE found : $CheckEXEVersion <= $ResultsVersion - Update missing: $ResultsMissing" -ForegroundColor Red
                  if ($CheckOptionalUpdates -and -not $AlreadySetOptionalUpdates) {
                    Write-Host "[!] It is possible that Optional Windows updates are disabled, checking.." -ForegroundColor Red
                    Write-Verbose "NOTE: Othis only applies to Windows 10, version 2004 (May 2020 Update) and later:"
                    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                    $valueName = "AllowOptionalContent"

                    if (Test-Path -Path $registryPath) {
                      $value = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

                      if ($value -and $value.$valueName -eq 1) {
                          Write-Host "[!] The 'AllowOptionalContent' value is already set to 1. Optional Updates reg key has been applied already. Please remediate manually for now or check again next month."
                      }
                      else {
                          Set-ItemProperty -Path $registryPath -Name $valueName -Value 1 -Type DWord
                          Write-Host "[+] The $registryPath value 'AllowOptionalContent' value has been set to 1." -ForegroundColor Green
                      }
                    }
                    else {
                      New-Item -Path $registryPath -Force | Out-Null
                      New-ItemProperty -Path $registryPath -Name $valueName -Value 1 -PropertyType DWord -Force | Out-Null
                      Write-Host "The registry key $registryPath has been created and the 'AllowOptionalContent' value has been set to 1."
                      $AlreadySetOptionalUpdates = $true
                    }
                  }

                } else {
                  Write-Host "[+] EXE/DLL patched version found : $CheckEXEVersion > $ResultsVersion - already patched." -ForegroundColor Green  # SHOULD never get here, patches go in a new folder..
                }
              } else {
                Write-Host "[-] EXE/DLL Version not found, for $CheckEXE .." -ForegroundColor Yellow
              }
            } else {
              Write-Host "[!] EXE/DLL no longer found: $CheckEXE - likely its already been updated. Let's check.."
            }
          }
        } else {  # Not sure what this vuln is yet!
          Write-Host "[X] Skipping QID $_ - $VulnDesc" -ForegroundColor Red
        }
      }
    }

<#        # File Version check boilerplate code
        $ResultsEXE = "$env:windir\system32\SnippingTool.exe"
        Write-Host "[.] Checking if $ResultsEXE exists.."
        if (Test-Path $ResultsEXE) {
          Write-Host "[.] Checking $ResultsEXE version.."
          $ResultsEXEVersion = Get-FileVersion $ResultsEXE
          if ([version]$ResultsEXEVersion -lt [version]10.2008.3001.0) {
            Write-Host "[!] Vulnerable version $ResultsEXE found : $ResultsEXEVersion < 10.2008.3001.0"  -ForegroundColor Red
            Write-Host "[!] Please update Snipping Tool manually!!!" -ForegroundColor Red
            & explorer "https://apps.microsoft.com/store/detail/snipping-tool/9MZ95KL8MR0L?hl=en-us&gl=us"
          } else {
            Write-Host "[!] Fixed version $ResultsEXE found : $ResultsEXEVersion >= 10.2008.3001.0. Already patched"  -ForegroundColor Green
          }
        } else {
          Write-Host "[!] Snipping tool doesn't exist at $ResultsEXE .. Please check Microsoft Store for updates manually! Opening.."
          & explorer "ms-windows-store:"
          Write-Host "[.] Trying to update Store apps with command: 'echo Y | winget upgrade -h --all' - Note - there may be a few UAC prompts for this!"
          . "cmd.exe" "/c echo Y | winget upgrade -h --all"
        }
Generic 
        #>
}




if ($SoftwareInstalling.Length -gt 0) {
  Write-Host "[.] Checking for finished software upgrading: $SoftwareInstalling"
  #
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
Write-Host "`n"
Exit
