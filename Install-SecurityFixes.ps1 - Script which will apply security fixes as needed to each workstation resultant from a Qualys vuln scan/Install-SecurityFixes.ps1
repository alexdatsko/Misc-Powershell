[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Automated = $false,    # this allows us to run without supervision and apply all changes (could be dangerous!)
  [switch] $NoAuto,                # this allows us to turn off the registry value for Automated and ReRun 
  [string] $CSVFile,               # Allow user to pick a CSV file on the commandline
  [int[]] $OnlyQIDs,               # Allow user to pick a list of QID(s) to remediate
  [int] $QID,                      # Allow user to pick one QID to remediate
  [int[]] $SkipQIDs,               # Allow a list of QIDs to skip
  [int] $SkipQID,                  # Allow user to pick one QID to skip
  [switch] $Help,                  # Allow -Help to display help for parameters
  [switch] $Update,                # Allow -Update to only update the script then exit
  [switch] $SkipAPI,               # Set this to $true to not try to make any calls to the API
  [switch] $Risky,                 # Allows for risky behavior like kililng the ninite.exe installer when updating an Application (if Winget is not installed), this should be false for slow machines!
  [switch] $PowerOpts = $false,    # This switch will set all Power options on Windows to never fall asleep or hibernate.
  [switch] $AddScheduledTask = $false,       # This switch will install a scheduled task to run the script first thursday of each month and reboot after
  [switch] $AutoUpdateAdobeReader = $false,  # Auto update adobe reader, INCLUDING REMOVAL OF OLD PRODUCT WHICH COULD BE LICENSED!!! if this flag is set
  [string] $hostname = $env:computername,    # Set the hostname of this computer to a variable
  [string] $SecAudPath = (Get-Location),     # Where to check for the latest CSV file
  [string] $LogPath = "C:\Program Files\MQRA\logs",   # Where to copy log files to after.  (Should be overwritten from the config file if existing there.)
  [string] $tmp = "$($env:temp)\SecAud",              # "temp" Temporary folder to save downloaded files to, this will be overwritten when checking config ..
  [string] $dateshort = (Get-Date -Format "yyyy-MM-dd_HH-mm-ss"),                     # Consistent date format..
  [string] $LogFile = "$($tmp)\$($hostname)_Install-SecurityFixes_$($dateshort).log"  # Save Log to %temp% first.
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
.PARAMETER Update
    Updates the script (if an update is available on github) and then exits.
.PARAMETER SkipAPI
    If true, the app will not make any calls to the MQRA API
.PARAMETER CSVFile
    Specifies the path to the CSV file to use.
.PARAMETER AddScheduledTask
    This flag will add the Scheduled Task for this script to run every 2 weeks on Thursday evening at 11pm (unless otherwise adjusted) automatically.
.PARAMETER Automated
    In automated mode, all fixes will be applied automatically without keyboard input.  Reboots will be scheduled for 5m after all fixes are applied.
.PARAMETER AutoUpdateAdobeReader
    This flag will cause Adobe Reader to be automatically REMOVED (including Licensed Versions!) and updated to free Adobe Reader DC newest version
.PARAMETER NoAuto
    This is a fix to make sure the script will not re-run as automated next time.
.PARAMETER QID
    Pick a certain QID to remediate, i.e 105170
.PARAMETER OnlyQIDs
    Pick a smaller list of QIDs to remediate, i.e 1,2,5
.PARAMETER SkipQID
    Pick a certain QID to skip + ignore
.PARAMETER SkipQIDs
    Pick a smaller list of QIDs to skip and not remediate, i.e 1,2,5
.PARAMETER PowerOpts
    This flag will change all of the machines Power options to NEVER time out, so workstation will stay on and available.
.PARAMETER Verbose
    Enables verbose output for detailed information.
#>
"

#### VERSION ###################################################

# No comments after the version number on the next line- Will screw up updates!
$Version = "0.50.50"
# New in this version:  Delimiter issues in batch import, added a little debugging around Import-CSV

$VersionInfo = "v$($Version) - Last modified: 7/3/2025"


# CURRENT BUGS TO FIX:
#    - Copy script log and upload
#    - Notepad++ - check 

#### VERSION ###################################################

if ($Help) {
  $parameterNames = $PSBoundParameters.Keys -join ', '
  Write-Verbose "Providing help for $parameterNames .."
  # Lets just print this here for now, because I can't seem to get the appropriate Get-Help commands to work, ugh.

  Write-Host $AllHelp
  exit
}

# ----------- Script specific vars:  ---------------
$pwd = Get-Location
$apiBaseUrl = "https://api.mme-sec.us/api/v1"
$AgentString = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"
$OLE19x64Url = "https://go.microsoft.com/fwlink/?linkid=2278038"
$DCUUrl = "https://dl.dell.com/FOLDER11914075M/1/Dell-Command-Update-Application_6VFWW_WIN_5.4.0_A00.EXE"
$ghostscripturl = "https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs10031/gs10031w64.exe"
$AdobeReaderUpdateUrl = "https://rdc.adobe.io/reader/products?lang=mui&site=enterprise&os=Windows%2011&country=US&nativeOs=Windows%2010&api_key=dc-get-adobereader-cdn"
$NetCore6NewestUpdate = "https://download.visualstudio.microsoft.com/download/pr/396abf58-60df-4892-b086-9ed9c7a914ba/eb344c08fa7fc303f46d6905a0cb4ea3/dotnet-sdk-6.0.428-win-x64.exe"

$MQRAUserAgent = "MQRA $Version PS"        # Useragent for API communications
$MQRAdir = "C:\Program Files\MQRA"      # This should never change
$Log = "$($MQRADir)\logs"               # Save Logs to MQRA folder
$ConfigFile = "$($pwd)\_config.ps1"     # Configuration file 
$OldConfigFile = "$oldpwd\_config.ps1"  # Configuration file  (old location)
$SQLiteDB = "$($MQRADir)\client.db"     # SQLite DB (eventually..)
$TimeoutSec = 10                        # How many seconds until Invoke-RestMethod times out

$DCUFilename = ($DCUUrl -split "/")[-1]
$DCUVersion = (($DCUUrl -split "_WIN_")[1] -split "_A0")[0]
$OSVersion = ([environment]::OSVersion.Version).Major
$SoftwareInstalling=[System.Collections.ArrayList]@()
$QIDsAdded = @()
$QIDSpecific = @()
$RebootRequired = $false                     # This value is used to clarify if a reboot is needed at the end of a run

# These values are overwritten in the config, but loaded here in case the config is missing:
$CheckOptionalUpdates = $true                # Set this to false to ignore Optional Updates registry value
$AlreadySetOptionalUpdates = $false          # This is to make sure we do not keep trying to set the Optional Updates registry value.
$oldPwd = $pwd                               # Grab location script was run from
$UpdateBrowserWait = 60                      # Default to 60 seconds for updating Chrome, Edge or Firefox with -Automated. Can be overwritten in Config, for slower systems.. 
$UpdateNiniteWait = 120                      # How long to wait for the Ninite updater to finish and then force-close, default 90 seconds
$UpdateDellCommandWait = 60                  # How long to wait for Dell Command Update to re-install/update
$SoftwareInstallWait = 60                    # How long to wait for generic software to finish installing
$LogToEventLog = $true                       # Set this to $false to not log to event viewer Application log, source "MQRA", also picked up in _config.ps1

# Applications we currently support updating through WinGet:
$WingetApplicationList = @("Chrome","MSEdge","Firefox","Brave","Teamviewer 15","Irfanview","Notepad++","Zoom client","Dropbox","7-zip","Visual Studio Code","iTunes","iCloud","VLC","Putty")   
$WinGetOpts = "-h --accept-source-agreements --accept-package-agreements"

##################################################### QIDLists.ps1 contents

# QIDLists - These variables contain the list of vulnerabilities that can be fixed by the script. It is kept in a separate file so it can be updated programatically.
#    Note: to make these lists, copy large list of QIDs related to out of date app, 1 per line to a file, which you can copy from Excel and paste into a txt file. 
#          in linux, cat filename | sort | uniq | tr -s '\n' ','
#          delete the first and last comma if exists..

$QIDsAppleiCloud = 371058,371249,371292,371367,371588,371708,371813,372150,372200,372313,372369,372373,372374,372464,372819,372851,373343,373495,373503
$QIDsAppleiTunes = 371057,371222,371294,371368,371680,371710,371816,372149,372196,372309,372351,372372,372466,372812,373324,374108,374163,375508,375801,375876,376488,376647,376649,376650,376654
$QIDsChrome = 115077,115149,115166,119485,119493,119539,119601,119609,119627,119708,119743,119750,119773,119872,119930,119950,120059,120198,120220,120235,120297,120338,120405,120456,120560,120697,120725,120803,120812,120988,121201,121225,121283,121317,121362,121395,121485,121517,121583,121586,121622,121719,121757,121798,121813,121825,121840,121844,121893,122052,122075,122091,122127,122366,122485,122579,122630,122695,122725,122745,122829,122842,122867,123023,123141,123188,123196,123266,123364,123385,123501,123525,123570,123596,123704,123721,123740,123798,123869,123967,124153,124185,124379,124390,124410,124589,124693,124746,124758,124772,124865,124907,370005,370014,370067,370091,370109,370124,370134,370151,370162,370226,370249,370288,370339,370356,370376,370419,370446,370485,370546,370566,370613,370619,370643,370678,370691,370741,370763,370780,370808,370829,370889,370916,370950,370970,370974,370990,371003,371097,371172,371250,371268,371319,371327,371365,371378,371614,371639,371679,371692,371758,371771,371782,371820,371848,372020,372048,372050,372073,372111,372117,372166,372177,372186,372247,372286,372323,372342,372365,372403,372408,372410,372411,372438,372455,372476,372491,372517,372525,372534,372555,372572,372575,372576,372578,372579,372584,372630,372634,372636,372638,372639,372640,372829,372873,372894,373151,373319,373342,373368,373387,373421,373485,373510,373544,373714,373995,373998,374167,374531,374832,374876,375080,375091,375119,375319,375378,375426,375445,375459,375461,375505,375546,375595,375622,375638,375718,375738,375761,375784,375821,375846,375875,375883,375923,375948,375966,376000,376055,376140,376159,376734,376828,377960,378040,378059,378123,378340,378417,378426,378455,378496,378549,378676,378734,378777,378799,378818
$QIDsEdge = 374833,375094,375097,375327,375342,375385,375446,375456,375463,375499,375526,375575,375596,375618,375627,375628,375641,375660,375737,375742,375793,375822,375830,375843,375861,375868,375884,375927,375952,375974,376010,376092,376158,376166,376229,376288,376374,376393,376424,376446,376480,376500,376510,376528,376542,376572,376599,376646,376660,376666,376685,376715,376719,376744,376800,376829,376844,376964,376966,377593,377613,377636,377720,377732,377757,377798,377805,377840,377894,377923,377935,377964,378000,378001,378034,378067,378128,378358,378418,378442,378471,378502,378546
$QIDsFirefox = 115077,115149,115166,119485,119493,119539,119601,119609,119627,119708,119743,119750,119773,119872,119930,119950,120059,120198,120220,120235,120297,120338,120405,120456,120560,120697,120725,120803,120812,120988,121201,121225,121283,121317,121362,121395,121485,121517,121583,121586,121622,121719,121757,121798,121813,121825,121840,121844,121893,122052,122075,122091,122127,122366,122485,122579,122630,122695,122725,122745,122829,122842,122867,123023,123141,123188,123196,123266,123364,123385,123501,123525,123570,123596,123704,123721,123740,123798,123869,123967,124153,124185,124379,124390,124410,124589,124693,124746,124758,124772,124865,124907,370005,370014,370067,370091,370109,370124,370134,370151,370162,370226,370249,370288,370339,370356,370376,370419,370446,370485,370546,370566,370613,370619,370643,370678,370691,370741,370763,370780,370808,370829,370889,370916,370950,370970,370974,370990,371003,371097,371172,371250,371268,371319,371327,371365,371378,371614,371639,371679,371692,371758,371771,371782,371820,371848,372020,372048,372050,372073,372111,372117,372166,372177,372186,372247,372286,372323,372342,372365,372392,372403,372408,372410,372411,372438,372445,372455,372476,372481,372490,372491,372517,372525,372534,372555,372572,372575,372576,372578,372579,372584,372630,372634,372636,372638,372639,372640,372825,372829,372873,372894,373103,373120,373151,373319,373320,373342,373368,373387,373388,373421,373485,373490,373510,373542,373544,373714,373989,373995,373998,374166,374167,374531,374576,374827,374832,374876,374918,375080,375091,375100,375119,375209,375319,375378,375408,375426,375445,375459,375461,375478,375505,375542,375546,375595,375606,375622,375638,375642,375712,375718,375738,375753,375761,375784,375821,375824,375833,375846,375875,375883,375923,375945,375948,375966,376000,376015,376055,376140,376143,376159,376237,376387,376447,376458,376519,376574,376625,376643,376705,376758,376828,377600
$QIDsZoom = 371344,372477,372832,373366,375391,375487,375805,376046,376117,376624,376638,376640,376957,376960,376967,376970,376973,377083,377687,377694,377756,378079,378097,378580,378581,378582,378583,378585,378814,378783
$QIDsTeamviewer = 371174,372386,373335,371077,372237
$QIDsPutty = 379655,379295
$QIDsDropbox = 111111 # Dummy entry, none found yet..
$QIDsOracleJava = 123168,123519,123714,124169,124567,124882,370087,370161,370280,370371,370469,370610,370727,370887,371079,371265,371528,371749,372013,372163,372333,372508,373156,373540,374873,375477,375729,375964,376252,376546,376733,377642,377904,378425,378673
$QIDsAdoptOpenJDK = 376436,376423
$QIDsVirtualBox = 372509,372512,372542,373154,373553,374881,375481,375736,375967,376255,376548,376736
$QIDsAdobeReader = 116893,117797,118087,118319,118438,118486,118670,118782,118956,119053,119076,119145,119594,119768,119838,120103,120295,120777,120866,121176,121442,121711,121867,122484,122663,123021,123265,123579,123662,124151,124506,124767,370084,370154,370277,370364,370499,370650,370948,371060,371132,371210,371230,371317,371372,371395,371638,371659,371729,371777,375845,375953,377630
$QIDsIntelGraphicsDriver = 370842,371696,371263,370842
$QIDsNVIDIA = 370263,376609,376042,376247,375689,372472,372875,373158,375727
#$QIDsUpdateMicrosoftStoreApps = 91914,91834,91869,91866,91847,91764,91773,91774,91775,91761,91834,91871,91919,92015,91726
$QIDsFlash = 115231,120098,122742,122827,122866,123022,123140,123181,123187,123259,123399,123524,123580,123601,123702,123712,123797,123963,124152,124154,124208,124388,124421,124690,124779,124872,370060,370083,370131,370155,370260,370756,370819,370869,370934,370996,371062,371138,371185,371320,371330,371361,371646,371731,371780,371835,372106,372381,372457,372853,373520
$QIDsMSXMLParser4 = 105457
$QIDsSpectreMeltdown = 91537,91462,91426,91428
$QIDsMicrosoftAccessDBEngine = 106067,106069
$QIDsSQLServerCompact4 = 106023
$QIDsDellCommandUpdate = 376132
$QIDsMicrosoftVisualStudioActiveTemplate = 90514
$QIDsMicrosoftNETCoreV5 = 106089
$QIDsMicrosoftSilverlight = 106028
$QIDsGhostScript = 371157
$QIDsOffice2007 = 110330,110327,110325,110324,110323,110320
$QIDsVLC = 379007,379008
$QIDsMSTeams = 378941,378755
$QIDsIrfanView = 379695
$QIDsNotepadPP = 378819,379100
$QIDs_dotNET_Core6 = 92112,92080,92100,92155,92129,92180
$MicrosoftODBCOLEDB = 378931,379596,380160
$QIDsVsCode = 380598
$QIDs7zip = 378839


################################################### INITIAL CHECKS ########

Write-Verbose "Checking for specific parameters.."
if ($OnlyQIDs) {
  $QIDSpecific=[System.Collections.Generic.List[int]]$OnlyQIDs
  Write-Verbose "-OnlyQIDs parameter found: $QIDSpecific"
}
if ($QID) {
  $QIDSpecific=[int]$QID
  Write-Verbose "-QID parameter found: $QIDSpecific"
}

if ($SkipQID) {
  if (-not $SkipQIDs) {
    $SkipQIDs = [int]$SkipQID  # Use the same SkipQIDs parameter, should work for one as well
    if ([int]$SkipQID -gt 0) {
      Write-Verbose "-SkipQID parameter found: $SkipQID"
    } else {
      Write-Verbose "-SkipQID parameter invalid: $SkipQID"
    }
  } else {
    Write-Host "[!] ERROR: Can't use -SkipQID and -SkipQIDs simultaneously.."
    exit
  }
}

if ($SkipQIDs) {
  try {
    $SkipQIDs=[System.Collections.Generic.List[int]]$SkipQIDs
    Write-Verbose "-SkipQIDs parameter found: $SkipQIDs"
    
  } catch {
    Write-Verbose "-SkipQIDs INVALID parameter found: $SkipQIDs"
  }
} else {
  $SkipQIDs = @()
}
Write-Verbose "Done checking parameters"
if (!(Test-Path $tmp)) { $null = New-Item -ItemType Directory $tmp | Out-Null }

# Start a transscript of what happens while the script is running, but stop any currently running transcript so we can start a new one!
try {
  Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
}
catch [System.InvalidOperationException]{}

$dateshort= Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
try {
  #$script:LogFile = "$($tmp)\$($hostname)_Install-SecurityFixes_$($dateshort).log"  # Already set up top, date is diff now..
  Start-Transcript $script:LogFile -ErrorAction SilentlyContinue
} catch {
  if ($Error[0].Exception.Message -match 'Transcript is already in progress') {
    Write-Warning '[!] Start-Transcript: Already running.'
  } else {
    # re-throw the error if it's not the expected error
    throw $_
  }
}

if (Get-Command winget -ErrorAction SilentlyContinue) {
  $WinGetInstalled = $true
  Write-Output "[+] Winget is installed."
} else {
  $WinGetInstalled = $false
  Write-Output "[-] Winget is not installed."
}

function Create-IfNotExists {
  param (
    [string]$directory
  )
  if (!(Test-Path $directory)) {
    $null = New-Item -ItemType directory -Path $directory -Force | Out-Null
  }
}

Create-IfNotExists "$MQRAdir"
Create-IfNotExists "$($MQRAdir)\logs"
Create-IfNotExists "$($MQRAdir)\scans"
Create-IfNotExists "$($MQRAdir)\temp"
Create-IfNotExists "$($MQRAdir)\db"
Create-IfNotExists "$($MQRAdir)\backup"

####################################################### GENERAL FUNCTIONS #######################################################

function Create-FixDB {
  $dbPath = "C:\Program Files\MQRA\db"
  $csvFile = "$dbPath\QIDsFixed.csv"

  if (-not (Test-Path $dbPath)) {
      New-Item -ItemType Directory -Path $dbPath -Force | Out-Null
  }

  if (-not (Test-Path $csvFile)) {
      @"
QID,Datefixed
"@ | Set-Content -Path $csvFile -Force
  }
  return $true
}

function Set-Fix {
  param (
      [Parameter(Mandatory)]
      [string]$QID,
      [string]$dbPath = "C:\Program Files\MQRA\db\QIDsFixed.csv",
      [switch]$Remove
  )
  if ($QID -eq 0) { return $null }
  if (-not (Test-Path $dbPath)) {
      Create-FixDB
  }
  if ($Remove) {  #lets remove this line if -Remove is added..
     $filecontents = Get-Content -Path $dbPath
     foreach ($line in $Filecontents) {
      if (!($line -like "*$($QID)*")) {
        $newcontents += $line
      }
     }
     $newcontents | Set-Content -Path $dbPath
     return $true
  }
  $dateFixed = (Get-Date).ToString("yyyy-MM-dd")
  $entry = "$QID,$dateFixed"
  Add-Content -Path $dbPath -Value $entry
  return $true
}

function Get-Fix {
  param (
      [Parameter(Mandatory)]
      [string]$QID,
      [string]$dbPath = "C:\Program Files\MQRA\db\QIDsFixed.csv"
  )
  if ($QID -eq 0) { return $false } # some Get-YesNo have no QID, because its the question is not related to a QID fix
  if (-not (Test-Path $dbPath)) {
      Create-FixDB
      return $false
  }

  $csvContent = Import-Csv -Path $dbPath
  $record = $csvContent | Where-Object { $_.QID -eq $QID }
  if ($record) {
    if ($record.Datefixed) {
#      return $false
      return $record.Datefixed 
    } else {
      return $false
    }
  } else {
    return $false
  }
}


function Write-Event { 
  param (
    [string]$LogName = 'Application',
    [string]$Source = 'MQRA',
    [string]$Type = 'Information',
    [int]$EventID = 2500,
    [string]$Msg
  )

  if ($LogToEventLog) {
    if (!( [System.Diagnostics.EventLog]::SourceExists($Source) )) {
        New-EventLog -LogName "Application" -Source $Source 
    }
    Write-EventLog -LogName "Application" -Source $Source -EntryType $Type -EventId $eventID -Message $Msg
  }
}

function Init-Script {
  param (
    [boolean]$Automated = $false
  )
  if ($NoAuto) {
    Write-Host "[!] -NoAuto detected!  Resetting Registry values for Automated and ReRun to false.." -ForegroundColor Green
    Set-RegistryEntry -Name "ReRun" -Value $false
    $ReRunReg = $false
    $Automated = $false
    $script:Automated = $false
  }

  $ReRunReg = Get-RegistryEntry -Name "ReRun"
  Write-Verbose "Init-Script: Automated (param) : $Automated"
  Write-Verbose "Init-Script: ReRun (Reg key) : $ReRunReg"
  if ($ReRunReg -eq $true) { $Automated = $true ; $ReRunReg = $false ; Set-RegistryEntry -Name "ReRun" -Value $false  }
  
  if ($Automated) {
    Write-Host "`n[!] Running in automated mode!`n"   -ForegroundColor Red
  }
  
  # Self-elevate the script if required
  if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
      Write-Output "`n[!] Not running under Admin context - Re-launching as admin!"
      if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
          $Command = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
          if ($Automated) {
            Set-RegistryEntry -Name "ReRun" -Value $true
          }
          Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $Command
          Set-Location $pwd
          Exit
    }
  }

  # Change title of window
  $host.ui.RawUI.WindowTitle = "$($env:COMPUTERNAME) - Install-SecurityFixes.ps1"

  # Try to use TLS 1.2, this fixes many SSL problems with downloading files, before TLS 1.2 is not secure any longer.
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  Write-Host "[.] Check if $env:tmp is writable .." -NoNewLine
  $TestFile = Join-Path $env:tmp ([System.Guid]::NewGuid().ToString())
  $TmpPath = "C:\ProgramData\SecAud"  # Backup temporary folder, this should be world writeable on any Windows system if it doesn't exist..
  try {
      Set-Content -Path $TestFile -Value "Test" -ErrorAction Stop
      Write-Host "Good."
      #Write-Verbose "$env:tmp is writable."
      $TmpPath = $env:tmp
  } catch {
      Write-Warning "$env:tmp is not writable. Using $TmpPath instead."
      if (-not (Test-Path $TmpPath)) {
          try {
              $null = New-Item -ItemType Directory -Path $TmpPath -Force | Out-Null
              Write-Host "Failed! Created $TmpPath folder."
          } catch {
              throw "Failed to create $TmpPath folder. Error: $($_.Exception.Message)"
          }
      }
  } finally {
      Remove-Item $TestFile -ErrorAction SilentlyContinue
  }
}
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
         [string] $results,
         [string] $QID = 0)
  
  $done = 0
  $SkipQIDs = $script:SkipQIDs
  
  if ((Get-Fix -QID $QID) -eq $false) {
    if (-not $script:Automated) {    # Catch the global var or the registry entry
      Write-Verbose "Qid: $QID - SkipQIDs: $SkipQIDs"
      if ($SkipQIDs -notcontains $QID) {
        while ($done -eq 0) {
          $yesno = Read-Host  "`n[?] $text [y/N/a/s/?] "
          if ($yesno.ToUpper()[0] -eq 'Y') { Set-Fix -QID $QID; return $true } 
          if ($yesno.ToUpper()[0] -eq 'N' -or $yesno -eq '') { return $false } 
          if ($yesno.ToUpper()[0] -eq 'A') { $script:Automated = $true; Write-Host "[!] Enabling Automated mode! Ctrl-C to exit"; Set-Fix -QID $QID; return $true } 
          if ($yesno.ToUpper()[0] -eq '?') { Print-YesNoHelp } 
          if ($yesno.ToUpper()[0] -eq 'S') { 
              Write-Host "[i] Results: " -ForegroundColor Yellow
              foreach ($result in $Results) {
                Write-Host "$($result)" -ForegroundColor Yellow
              }
          }
        } 
      } else {
        Write-Host "[i] SKIPPING: part of $SkipQIDs" -ForegroundColor Red
        return $false
      }
    } else {  # Automated mode. Show results for -Verbose, then apply fix
      if ($SkipQIDs -notcontains $QID) {
        Write-Verbose "[i] AUTOMATED: Results: "
        foreach ($result in $Results) {
          Write-Verbose "$($result)"
        }
        Write-Host "[+] AUTOMATED: $QID - Choosing yes for $text .."
        Set-Fix -QID $QID
        return $true
      } else {
        Write-Host "[i] SKIPPING: part of $SkipQIDs" -ForegroundColor Red
        return $false
      }
    }
  } else {
    $FixedDate = Get-Fix -QID $QID
    if (($FixedDate -ne $false) -and (-not $QIDSpecific)) {
      Write-Host "[+] Skipping QID $($QID): Already fixed on $FixedDate" -ForegroundColor Green
    } else {
      Set-Fix -QID $QID -Remove # if date = $false we should try to remove this line??
    }
  }
}

################################################# SCRIPT FUNCTIONS ###############################################

function Set-RegistryEntry {   # STRINGS ONLY!
    param(
        [string]$Path = "HKLM:\Software\MME Consulting Inc\Install-SecurityFixes",
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][object]$Value
    )

    if (-Not(Test-Path -Path $Path)) {
        Write-Verbose "Set-RegistryEntry: !! (Test-Path -Path $Path) - Creating"
        New-Item -Path $Path -Force | Out-Null
    }
    $ValueAsString = $Value.ToString()
    if ($ValueString -eq $Value) {
      Write-Verbose "Set-RegistryEntry: Creating (value as string): Set-ItemProperty -Path $Path -Name $Name -Value $ValueAsString"
      Set-ItemProperty -Path $Path -Name $Name -Value $ValueAsString
    } else {
      Write-Verbose "Set-RegistryEntry: Creating: (value = ?) Set-ItemProperty -Path $Path -Name $Name -Value $Value"
      Set-ItemProperty -Path $Path -Name $Name -Value $Value
    }
}

function Get-RegistryEntry {
  param(
      [string]$Path = "HKLM:\Software\MME Consulting Inc\Install-SecurityFixes",
      [string]$Name
  )
  $Reg = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue)
  if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {  # If the path exists, check if the property exists
    if (($Reg).PSObject.Properties.Name -contains $Name) {
      Write-Verbose "Get-RegistryEntry: !! The property exists, return its value : $Path / $Name  = $(($Reg).$Name)"
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

function Show-RegistryValues {
    param(
        [string]$Path = "HKLM:\Software\MME Consulting Inc\Install-SecurityFixes"
    )

    if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
        $RegValues = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue

        if ($RegValues) {
            Write-Host "Registry values in $Path :"
            $RegValues.PSObject.Properties | ForEach-Object {
                Write-Host "  $($_.Name) = $($_.Value)"
            }
        } else {
            Write-Host "No values found in $Path"
        }
    } else {
        Write-Host "Registry path $Path does not exist"
    }
}

function Remove-RegistryEntry {
    param(
        [string]$Path = "HKLM:\Software\MME Consulting Inc\Install-SecurityFixes",
        [string]$Name
    )

    if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
        $Reg = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue

        if ($Reg.PSObject.Properties.Name -contains $Name) {
            Write-Verbose "Removing registry value: $Path\$Name"
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        } else {
            Write-Verbose "Registry value not found: $Path\$Name"
        }
    } else {
        Write-Verbose "Registry path not found: $Path"
    }
}
<# # # Setting and pulling string/integer values from registry: # # #

Set-RegistryEntry -Name "IntegerValue" -Value 42
Set-RegistryEntry -Name "StringValue" -Value "Hello, World!"
Set-RegistryEntry -Name "BooleanValue" -Value $true

Show-RegistryValues

$IntegerValue = [int](Get-RegistryEntry -Name "IntegerValue")
$StringValue = Get-RegistryEntry -Name "StringValue"
$BooleanValue = [bool](Get-RegistryEntry -Name "BooleanValue")

Remove-RegistryEntry -Name "IntegerValue" 
Remove-RegistryEntry -Name "StringValue" 
Remove-RegistryEntry -Name "BooleanValue" 

Show-RegistryValues
#>


function Get-OSVersion {
  return [version](Get-CimInstance Win32_OperatingSystem).version
}

function Report-OSVersion {
  $OSVersion = [version](Get-OSVersion)
  if ($OSVersion -le [version]10.0.19045) { return "Win10" }
  if ($OSVersion -gt [version]10.0.19045) { return "Win11" }
  return "unknown"
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
          Write-Verbose "Temp file: $FilenameTemp , Perm file: $FilenamePerm"
          $null = Copy-Item "$($FilenameTmp)" "$($FilenamePerm)" -Force -ErrorAction SilentlyContinue | out-null
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
  if ($script:Automated) { $vars += " -Automated" }
  if ($script:Verbose) { $vars += " -Verbose" }
  if ($script:CSVFile) { $vars += " -CSVFile $script:CSVFile" }
  if ($script:QIDSpecific) { $vars += " -QID $script:QIDSpecific" }
  if ($script:QIDS) { $vars += " -QID $script:QID" }
  if ($script:Help) { $vars += " -Help" }
  Write-Verbose "Get-Vars: Vars = '$Vars'"
  return $vars
}

Function Update-Script {
  # For 0.32 I am assuming $pwd is going to be the correct path
  Write-Host "[.] Checking for updated version of script on github.. Current Version = $($Version)"
  $url = "https://raw.githubusercontent.com/alexdatsko/Misc-Powershell/main/Install-SecurityFixes.ps1%20-%20Script%20which%20will%20apply%20security%20fixes%20as%20needed%20to%20each%20workstation%20resultant%20from%20a%20Qualys%20vuln%20scan/Install-SecurityFixes.ps1"
  Create-IfNotExists $MQRADir
  if (Update-ScriptFile -URL $url -FilenameTmp "$($tmp)\Install-SecurityFixes.ps1" -FilenamePerm "$($MQRAdir)\Install-SecurityFixes.ps1" -VersionStr '$Version = *' -VersionToCheck $Version) {
    Write-Verbose "Automated: $Automated"
    Write-Verbose "script:Automated: $script:Automated"
    if ($script:Update) { 
      Write-Host "[!] Script flag -Update mode only detected, exiting!"
      exit
    } else {
      Write-Host "[+] Update found, re-running script .."
      Stop-Transcript
      $Vars = Get-Vars
      Write-Verbose "Re-running script with Vars: '$Vars'"
      if ($script:Automated) {
        Write-Verbose "Script was run as automated, setting ReRun reg entry to true."
        Set-RegistryEntry -Name "ReRun" -Value $true
      }
      . "$($MQRAdir)\Install-SecurityFixes.ps1" $Vars  # Dot source and run from here once, then exit.
      Stop-Transcript
      exit
    }
  } else {
    Write-Host "[-] No update found for $($Version)."
    #return $false
  }
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
                Start-Process -Wait "$env:temp\SecAud\vc2012redist_x64.exe" -ArgumentList "/install /passive /quiet /norestart" 
                $RebootRequired = $true
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
  param( 
    [Parameter(Mandatory=$true)]
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

function Replace-PercentVars {
  param(
    $CheckFile
  )
  $CheckFile = $CheckFile.replace("%ProgramFiles%",(Resolve-Path -Path "$env:ProgramFiles").Path).trim()
  $CheckFile = $CheckFile.replace("%ProgramFiles(x86)%",(Resolve-Path -Path "${env:ProgramFiles(x86)}").Path).trim()
  $CheckFile = $CheckFile.replace("%windir%",(Resolve-Path -Path "${env:WinDir}").Path).trim()
  $CheckFile = $CheckFile.replace("%SYSTEMROOT%",(Resolve-Path -Path "${env:SYSTEMROOT}").Path).trim()
  return $CheckFile
}

function Check-Reg {
  param (
    $RegKey,
    $RegName,
    $RegType,
    $RegValue,
    $SettingName
  )
  $checkvar = "1" # Default to disabled
  if ($RegKey -like "HKEY_LOCAL_MACHINE*") {
    $RegKey=$RegKey.replace("HKEY_LOCAL_MACHINE","HKLM:")
    Write-Verbose "[.] Replacing HKEY_LOCAL_MACHINE with HKLM: Result- $RegKey"
  }
  $ErrorActionPreference="SilentlyContinue"  # Workaround for this terminating error of not being able to find nonexisting reg values with Get-ItemProperty / Get-ItemPropertyValue
  if (Get-ItemProperty -Path $RegKey -ErrorAction SilentlyContinue) { # if RegKey exists
    Write-Verbose "$RegKey exists."
    $RegValueVar = Get-ItemProperty -Path $RegKey | Select-Object -ExpandProperty $RegName  # if RegName doesn't exist.. This will not throw an error
    if ($RegValueVar -eq $RegValue) {
      Write-Host "[.] [$($SettingName)] - $($RegName) is Enabled, good." -ForegroundColor Green
      $checkvar = 0
    } else {
      Write-Host "[!] [$($SettingName)] - $($RegName) is DISABLED." -ForegroundColor Red
      $checkvar = 1
    }
    Write-Verbose "$RegKey = $RegValueVar" 
  } else {
    Write-Host "[!] [$($SettingName)] - $($RegName) is DISABLED!  $RegKey doesn't exist!" -ForegroundColor Red
    $checkvar = 1
  }
  $ErrorActionPreference="Continue" # Set back to standard error termination setting
  return $checkvar
}

function Get-PowerScheme {
	[CmdletBinding()][OutputType([object])]
	param ()
	
	#Get the currently active power scheme
	$Query = powercfg.exe /getactivescheme
	#Get the alias name of the active power scheme
	$ActiveSchemeName = ($Query.Split("()").Trim())[1]
	#Get the GUID of the active power scheme
	$ActiveSchemeGUID = ($Query.Split(":(").Trim())[1]
	$Query = powercfg.exe /query $ActiveSchemeGUID
	$GUIDAlias = ($Query | Where-Object { $_.Contains("GUID Alias:") }).Split(":")[1].Trim()
	$Scheme = New-Object -TypeName PSObject
	$Scheme | Add-Member -Type NoteProperty -Name PowerScheme -Value $ActiveSchemeName
	$Scheme | Add-Member -Type NoteProperty -Name GUIDAlias -Value $GUIDAlias
	$Scheme | Add-Member -Type NoteProperty -Name GUID -Value $ActiveSchemeGUID
	Return $Scheme
}

function Set-PowerSchemeSettings {
	[CmdletBinding()]
	param
	(
		[string]
		$MonitorTimeoutAC,
		[string]
		$MonitorTimeoutDC,
		[string]
		$DiskTimeoutAC,
		[string]
		$DiskTimeoutDC,
		[string]
		$StandbyTimeoutAC,
		[string]
		$StandbyTimeoutDC,
		[string]
		$HibernateTimeoutAC,
		[string]
		$HibernateTimeoutDC
	)
	
	$Scheme = Get-PowerScheme
	If (($MonitorTimeoutAC -ne $null) -and ($MonitorTimeoutAC -ne "")) {
		Write-Host "[.] Setting monitor timeout on AC to"$MonitorTimeoutAC" minutes....." -NoNewline
		$Switches = "/change" + [char]32 + "monitor-timeout-ac" + [char]32 + $MonitorTimeoutAC
		$TestKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\" + $Scheme.GUID + "\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"
		$TestValue = $MonitorTimeoutAC
		$PowerIndex = "ACSettingIndex"
	}
	If (($MonitorTimeoutDC -ne $null) -and ($MonitorTimeoutDC -ne "")) {
		Write-Host "[.] Setting monitor timeout on DC to"$MonitorTimeoutDC" minutes....." -NoNewline
		$Switches = "/change" + [char]32 + "monitor-timeout-dc" + [char]32 + $MonitorTimeoutDC
		$TestKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\" + $Scheme.GUID + "\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"
		$TestValue = $MonitorTimeoutDC
		$PowerIndex = "DCSettingIndex"
	}
	If (($DiskTimeoutAC -ne $null) -and ($DiskTimeoutAC -ne "")) {
		Write-Host "Setting disk timeout on AC to"$DiskTimeoutAC" minutes....." -NoNewline
		$Switches = "/change" + [char]32 + "disk-timeout-ac" + [char]32 + $DiskTimeoutAC
		$TestKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\" + $Scheme.GUID + "\0012ee47-9041-4b5d-9b77-535fba8b1442\6738e2c4-e8a5-4a42-b16a-e040e769756e"
		$TestValue = $DiskTimeoutAC
		$PowerIndex = "ACSettingIndex"
	}
	If (($DiskTimeoutDC -ne $null) -and ($DiskTimeoutDC -ne "")) {
		Write-Host "[.] Setting disk timeout on DC to"$DiskTimeoutDC" minutes....." -NoNewline
		$Switches = "/change" + [char]32 + "disk-timeout-dc" + [char]32 + $DiskTimeoutDC
		$TestKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\" + $Scheme.GUID + "\0012ee47-9041-4b5d-9b77-535fba8b1442\6738e2c4-e8a5-4a42-b16a-e040e769756e"
		$TestValue = $DiskTimeoutDC
		$PowerIndex = "DCSettingIndex"
	}
	If (($StandbyTimeoutAC -ne $null) -and ($StandbyTimeoutAC -ne "")) {
		Write-Host "[.] Setting standby timeout on AC to"$StandbyTimeoutAC" minutes....." -NoNewline
		$Switches = "/change" + [char]32 + "standby-timeout-ac" + [char]32 + $StandbyTimeoutAC
		$TestKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\" + $Scheme.GUID + "\238c9fa8-0aad-41ed-83f4-97be242c8f20\29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
		$TestValue = $StandbyTimeoutAC
		$PowerIndex = "ACSettingIndex"
	}
	If (($StandbyTimeoutDC -ne $null) -and ($StandbyTimeoutDC -ne "")) {
		Write-Host "[.] Setting standby timeout on DC to"$StandbyTimeoutDC" minutes....." -NoNewline
		$Switches = "/change" + [char]32 + "standby-timeout-dc" + [char]32 + $StandbyTimeoutDC
		$TestKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\" + $Scheme.GUID + "\238c9fa8-0aad-41ed-83f4-97be242c8f20\29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
		$TestValue = $StandbyTimeoutDC
		$PowerIndex = "DCSettingIndex"
	}
	If (($HibernateTimeoutAC -ne $null) -and ($HibernateTimeoutAC -ne "")) {
		Write-Host "[.] Setting hibernate timeout on AC to"$HibernateTimeoutAC" minutes....." -NoNewline
		$Switches = "/change" + [char]32 + "hibernate-timeout-ac" + [char]32 + $HibernateTimeoutAC
		$TestKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\" + $Scheme.GUID + "\238c9fa8-0aad-41ed-83f4-97be242c8f20\9d7815a6-7ee4-497e-8888-515a05f02364"
		[int]$TestValue = $HibernateTimeoutAC
		$PowerIndex = "ACSettingIndex"
	}
	If (($HibernateTimeoutDC -ne $null) -and ($HibernateTimeoutDC -ne "")) {
		Write-Host "[.] Setting hibernate timeout on DC to"$HibernateTimeoutDC" minutes....." -NoNewline
		$Switches = "/change" + [char]32 + "hibernate-timeout-dc" + [char]32 + $HibernateTimeoutDC
		$TestKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\" + $Scheme.GUID + "\238c9fa8-0aad-41ed-83f4-97be242c8f20\9d7815a6-7ee4-497e-8888-515a05f02364"
		$TestValue = $HibernateTimeoutDC
		$PowerIndex = "DCSettingIndex"
	}
	$ErrCode = (Start-Process -FilePath "powercfg.exe" -ArgumentList $Switches -WindowStyle Minimized -Wait -Passthru).ExitCode
	$RegValue = (((Get-ItemProperty $TestKey).$PowerIndex) /60)
	#Round down to the nearest tenth due to hibernate values being 1 decimal off
	$RegValue = $RegValue - ($RegValue % 10)
	If (($RegValue -eq $TestValue) -and ($ErrCode -eq 0)) {
		Write-Host "Success" -ForegroundColor Yellow
		$Errors = $false
	} else {
		Write-Host "Failed" -ForegroundColor Red
		$Errors = $true
	}
	Return $Errors
}

function Set-PowerSettingsNeverSleep {
  #Hardcoded Power Scheme Settings to never go to sleep on us, lets not change the monior, but disk timeout, sleep, and hibernate are now set to never
#  $Errors = Set-PowerSchemeSettings -MonitorTimeoutAC 60
#  $Errors = Set-PowerSchemeSettings -MonitorTimeoutDC 60
  $Errors = Set-PowerSchemeSettings -DiskTimeOutAC 0
  $Errors = Set-PowerSchemeSettings -DiskTimeOutDC 0
  $Errors = Set-PowerSchemeSettings -StandbyTimeoutAC 0
  $Errors = Set-PowerSchemeSettings -StandbyTimeoutDC 0
  $Errors = Set-PowerSchemeSettings -HibernateTimeoutAC 0
  $Errors = Set-PowerSchemeSettings -HibernateTimeoutDC 0
  if ($Errors) {
    # Catch any errors?
  }
}

######################################### UPDATE RELATED FUNCTIONS ######################

function Update-VCPP14 {
  param (
    [string]$arch = "x64"
  )

  if ($arch -eq "x64" -or $arch -eq "both" -or $arch -eq "*") {
    Write-Host "[.] Downloading required VC++ 14 Library file: VC_redist.x64.exe .."  -ForegroundColor Yellow
    #Write-Host "[!] BE CAREFUL NOT TO CLICK RESTART... " -ForegroundColor Red
    Invoke-WebRequest "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "$($tmp)\vc_redist.x64.exe"
    Write-Host "[.] Running: VC_redist.x64.exe /install /passive /quiet /norestart"    
    Start-Process "$($tmp)\VC_redist.x64.exe" -ArgumentList "/install /passive /quiet /norestart" -Wait  -NoNewWindow
  }
  if ($arch -eq "x86" -or $arch -eq "both" -or $arch -eq "*") {
    Write-Host "[.] Downloading required VC++ 14 Library file: VC_redist.x86.exe .."  -ForegroundColor Yellow
    #Write-Host "[!] BE CAREFUL NOT TO CLICK RESTART... " -ForegroundColor Red
    Invoke-WebRequest "https://aka.ms/vs/17/release/vc_redist.x86.exe" -OutFile "$($tmp)\vc_redist.x86.exe"
    Write-Host "[.] Running: VC_redist.x86.exe /install /passive /quiet /norestart"
    Start-Process "$($tmp)\VC_redist.x86.exe" -ArgumentList "/install /passive /quiet /norestart" -Wait -NoNewWindow
  }
}


function Check-ResultsForFiles {
    param(
        [Parameter(Mandatory = $true)][string] $Results
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

  # 110462	Microsoft Office Remote Code Execution (RCE) Vulnerability for April 2024	4				
  #   Office ClicktoRun or Office 365 Suite APRIL 2024 Update is not installed   C:\Program Files (x86)\Microsoft Office\root\Office16\GRAPH.EXE  Version is  16.0.17425.20146#


  # Refactored 4/19/24, reverted, ugh
  foreach ($Result in ($Results -split('Version is').trim())) {  # Lets catch multiples like the first example
    if ($Result -like "*.dll*") {
      if ($Result -like "*%windir%*") {
        $CheckFile = $env:windir+(($Result -split "%windir%")[1]).trim()   # THESE WILL NOT WORK WITH SPACES IN THE PATH
      } else {
        if ($Result -like "*%systemdrive%*") {
          $CheckFile = $env:systemdrive+(($Result -split "%systemdrive%")[1]).trim() # ..
        } else {
          if ($Result -like "*Program Files (x86)*") {
            $CheckFile = $env:systemdrive+"\Program Files (x86)"+(($Result -split "Program Files \(x86\)")[1]).trim() # ..works if filename is always at the end of a line
          } else {
            Write-Verbose "- Can't split $Result"
          }
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
            if ($Result -like "*Program Files (x86)*") {
              $CheckFile = $env:systemdrive+"\Program Files (x86)"+(($Result -split "Program Files \(x86\)")[1]).trim() # ..
            } else {
              Write-Verbose "- Can't split $Result"
            }
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
              if ($Result -like "*Program Files (x86)*") {
                $CheckFile = $env:systemdrive+"\Program Files (x86)\"+(($Result -split "Program Files (x86)\")[1]).trim() # ..
              } else {
                Write-Verbose "- Can't split $Result"
              }
            }
          }
        }
      }
    }
    Write-Verbose "CheckFile : $CheckFile"
    if ($CheckFile) {
      $CheckFile = Replace-PercentVars $CheckFile     
      $CheckFiles += $CheckFile
    } else {
      Write-Host "[!] CheckFile empty!!"
    }
  }
  return $CheckFiles
}

function Check-ResultsForFile {  # 03-28-2024
  param( [Parameter(Mandatory=$true)]
    [string] $Results
  )
  # This returns a SINGULAR Filename from the $Results. The first one only..

  # Example:
  #   KB5033920 is not installed  %windir%\Microsoft.NET\Framework64\v2.0.50727\System.dll Version is 2.0.50727.9175 %windir%\Microsoft.NET\Framework\v2.0.50727\System.dll Version is 2.0.50727.9175 %windir%\Microsoft.NET\Framework64\v4.0.30319\System.dll Version is 4.8.9206.0 %windir%\Microsoft.NET\Framework\v4.0.30319\System.dll Version is 4.8.9206.0 KB5034275 or KB5034274 or KB5034276 is not installed#

  # Errors 5/2/24:
  # $Results="KB5036892 is not installed  %windir%\system32\ntoskrnl.exe  Version is  10.0.19041.4239#""
  
  # Errors Multiples 5/3/24:
  # KB5037036 or KB5037035 is not installed  %windir%\Microsoft.NET\Framework64\v4.0.30319\System.dll Version is 4.8.9220.0 %windir%\Microsoft.NET\Framework\v4.0.30319\System.dll Version is 4.8.9220.0#

  # Lets check the results for ' is' and replace the path stuff with actual values, as %vars% are not powershell friendly variables ..
  # There might be more variable expansion I can do, will add it here when needed
  if ($Results -clike "*Version is*") {   # ack, -clike compares case also, -like does NOT, forgot about this.
    if ($Results -clike "*is not installed*") {
      $CheckFile = (($Results -split "is not installed")[1]).trim()
      if ($Results -clike "*Version is*") {
        $CheckFile = (($CheckFile -split "Version is")[0]).trim() # Remove rest of string..
        Write-Verbose "split1: $CheckFile"
      }
    } else {
      $CheckFile = (($Results -split "Version is")[0]).trim()
      write-Verbose "split2: $CheckFile"
    }
  } else {
    if ($Results -clike "*file version is*") {
      $CheckFile = (($Results -split "file version is")[0]).replace("#","").trim()
    }
  }
  Write-Verbose "PreFinal Check-ResultsForFile : [ $CheckFile ]"
  $CheckFile = Replace-PercentVars $CheckFile
  Write-Verbose "Final Check-ResultsForFile : [ $CheckFile ]"
  return $CheckFile
}

function Check-ResultsForVersion {  
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
  # 8-28-24:
  #   110473 Office ClicktoRun or Office 365 Suite AUGUST 2024 Update is not installed   C:\Program Files (x86)\Microsoft Office\root\Office16\GRAPH.EXE  Version is  16.0.17830.20138#
  #   110474 Office ClicktoRun or Office 365 Suite AUGUST 2024 Update is not installed   C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE  Version is  16.0.17830.20138#

  if ($Results -clike "*Version is*") {   # ack, -clike compares case also, -like does NOT, forgot about this.
    $CheckVersion = (($Results -split "Version is ")[1].trim() -split " ")[0].replace("#","").trim()
  } else {
    if ($Results -clike "*file version is*") {
      $CheckVersion = ((($Results -split "file version is")[1]) -split " ")[0].replace("#","").trim()
    } else {
      Write-Verbose "- unable to parse $Results !!"
    }
  }
  Write-Verbose "Final Check-ResultsForVersion : $CheckVersion"
  return $CheckVersion
}

function Check-ResultsForKB {
  param( [Parameter(Mandatory=$true)]
    [string] $Results
  )

  $CheckKB = @()

  if ($Results -clike "*KB*") {   # compares for uppercase KB only
    $ResSplit = $Results.split(' ')
    foreach ($result in $ResSplit) {
      if ($result -like "KB*") {
        $CheckKB += $result
      }
    }
  } else {
    Write-Host "[-] No 'KB' found in Results : $Results" 
  }
  Write-Verbose "Final Check-ResultsForKB : $CheckKB"
  return $CheckKB
}

################################################# CONFIG FUNCTIONS ###############################################


function MD5hash {
  param
    ( 
      [string]$intext
    )
    return [System.BitConverter]::ToString((New-Object Security.Cryptography.MD5CryptoServiceProvider).ComputeHash([Text.Encoding]::UTF8.GetBytes($intext))).Replace("-", "").ToLower()
}

function Copy-FilesToMQRAFolder {  
  param (
    [string]$ConfigFolder = (Get-Location),
    [string]$NewConfigFolder = "C:\Program Files\MQRA"
  )

  if (!(Test-Path -Path "$($NewConfigFolder)\Install-SecurityFixes.ps1")) {
    if (!(Test-Path -Path (Split-Path $NewConfigFolder -Parent))) {
      try {
        Write-Host "[.] Creating folder: '$NewConfigFolder'" -ForegroundColor Yellow
        $null = New-Item -Itemtype Directory -Path $NewConfigFolder -ErrorAction SilentlyContinue | Out-Null
      } catch {
        Write-Host "[!] Couldn't create folder: $(Split-Path $NewConfigFolder -Parent)" -ForegroundColor Red
      }
    }
  } else {
    if (Test-Path -Path "$($NewConfigFolder)\_config.ps1") {  # Both script and config are here..
      Write-Host "[+] [Copy-ConfigFile] $($NewConfigFolder)\_config.ps1 already exists, nothing to do." -ForegroundColor Green
      return $true
    }
  }
  Foreach ($File in @("Install-SecurityFixes.ps1","_config.ps1","*.csv")) {
    Write-Host "[+] Copying file from: '$($ConfigFolder)\$($file)' to '$($NewConfigFolder)\$($file)'" -ForegroundColor Yellow
    try {
      $null = Copy-Item -Path "$($ConfigFolder)\$($file)" -Destination "$($NewConfigFolder)\" -Force | Out-Null
    } catch {
      Write-Host "[+] Error copying file from: '$($ConfigFolder)\$($file)' to '$($NewConfigFolder)\$($file)':  $_ " -ForegroundColor Red
      return $false
    }
#    Set-Location $NewConfigFolder
    Write-Host "[.] Creating folders: logs, temp, db, backup" -ForegroundColor Yellow
    new-item -itemtype Directory -Path "logs" -ErrorAction SilentlyContinue
    new-item -itemtype Directory -Path "temp"  -ErrorAction SilentlyContinue
    new-item -itemtype Directory -Path "db"  -ErrorAction SilentlyContinue
    new-item -itemtype Directory -Path "backup"  -ErrorAction SilentlyContinue
    return $true
  }
  exit
}

function Find-ConfigFileLine {
  param (
    [string]$ConfigFile = "_config.ps1",
    [string]$ConfigLine
  )
  # CONTEXT Search, a match needs to be found but NOT need to be exact line, i.e '$QIDsFlash = 1,2,3,4' returns true if '#$QIDsFlash = 1,2,3,4,9999,12345' is found..
  $ConfigContents = (Get-Content -path $ConfigFile -ErrorAction SilentlyContinue)
  ForEach ($str in $ConfigContents) {
    if ($str -like "*$($ConfigLine)*") {
      return $str
    }
  }
  return $false
}

function Set-ConfigFileLine {
  param (
    [string]$ConfigFile = $script:ConfigFile,
    [string]$ConfigOldLine,
    [string]$ConfigNewLine
  )
  if ($ConfigOldLine -eq "") {
    Add-Content -path $ConfigFile -Value $ConfigNewContents
  } else {

    if (Get-YesNo "Change [$($ConfigOldLine)] in $($ConfigFile) to [$($ConfigNewLine)] ?") {
      if ($ConfigOldLine -eq '') {
        Add-Content -path $ConfigFile -Value $ConfigContentsNew
        return $true
      }
      Write-Verbose "Changing line in $($ConfigFile): `n  Old: [$($ConfigOldLine)] `n  New: [$($ConfigNewLine)]"
      $ConfigContents = (Get-Content -path $ConfigFile)
      $ConfigContentsNew=@()
      ForEach ($str in $ConfigContents) {
        if ($str -like "$($ConfigOldLine)*") {
          Write-Verbose "Replaced: `n$str with: `n$ConfigNewLine"
          $ConfigContentsNew += $ConfigNewLine
        } else {
          $ConfigContentsNew += $str
        }
      }
      Set-Content -path $ConfigFile -Value $ConfigContentsNew
    }
  }
}

function Remove-ConfigFileLine {  # Wrapper for Change-ConfigFileLine 
  param ([string]$ConfigOldLine)
  Set-ConfigFileLine -ConfigFile $ConfigFile -ConfigOldLine $ConfigOldLine -ConfigNewLine ""
}

function Add-ConfigFileLine {  # Wrapper for Change-ConfigFileLine 
  param ([string]$ConfigNewLine)
  Add-Content -path $ConfigFile -value $ConfigNewLine
}

function Check-ConfigForBadValues {
  Write-Verbose "[Check-ConfigForBadValues]"
  $UniqueIDFound = Find-ConfigFileLine -ConfigFile $script:ConfigFile -ConfigLine "UniqueId ="
  if ($UniqueIDFound) {
    Write-Verbose "[Check-ConfigForBadValues] UniqueID line found: $UniqueIDFound"
    $UniqueID = ($UniqueIDFound -replace('$UniqueID = ',''))
    Write-Verbose "[Check-ConfigForBadValues] UniqueID  found: $UniqueID"
    if ($UniqueID -notcontains '"') {
      Set-ConfigFileLine -ConfigFile $script:ConfigFile -ConfigOldLine '$UniqueId = ' -ConfigNewLine '$UniqueID = "'+$UniqueID+'"'   # Add the UniqueID with double quotes around it back to the config file..
    }
  }
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
    [array]$Filenames,
    [string]$Newest = 0  # If no filename is sent as newest, we will pick first one on the list if they hit enter
  )
  
  $i=0
  $Filenames | ForEach-Object {
    Write-Host "[$i] $_" -ForegroundColor Gray
    $i += 1
  }

  if (!($Newest -eq 0)) {  # Just pick newest file if one is provided??
    Write-Host "[+] Pick-File: Returning newest file $($Location)\$($Filenames[$Newest]) .." -ForegreoundColor Green 
    return "$($Location)\$($Filenames[$Newest])"
  }
  if ((-not $script:Automated) -and ($i -gt 1)) {
    Write-Host "[$i] EXIT" -ForegroundColor Blue
    $Selection = Read-Host "Select file to import, [Enter=Newest] ?"
    if ($Selection -eq $i) { Write-Host "[-] Exiting!" -ForegroundColor Gray; exit }
    if ([string]::IsNullOrEmpty($Selection)) { $Selection = $Filenames[$Newest] } else {
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
  [array]$Filenames = (Get-ChildItem "$($Location)\*Internal*.csv"  | Sort-Object LastWriteTime -Descending).Name # Find only internal scans
  $Newest = $Filenames | Select-Object -First 1
  return $Newest
  if ($Filenames.Length -lt 1) {  # If no files found in $Location, check $OldPwd
    Write-Verbose "Checking for CSV in Location: $OldPwd"
    [array]$Filenames = (Get-ChildItem "$($OldPwd)\*Internal*.csv" | Sort-Object LastWriteTime -Descending).Name  
    $Newest = $Filenames | Select-Object -First 1
    return $Newest
  } 
  

  # Used to Pick-File from here, why bother.. automate
}

function Find-ServerCSVFile {
  param ([string]$Location)
  $Servername = $script:Servername
  Write-Verbose "[Find-ServerCSVFile] Server Name: $Servername"
  Write-Verbose "[Find-ServerCSVFile] Location: $Location"
  if (!(Test-Connection -ComputerName $servername -Count 2 -Delay 1 -Quiet)) {
    Write-Verbose "[!] Can't access '$($serverName)', skipping Find-ServerCSVFile!"
    return $null
  }
  if ($null -eq $Location) { $Location = "data\secaud" }  # Default to \\$servername\data\secaud if can't read from config..
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

################################################# VULN REMED FUNCTIONS ###############################################

function Check-WinREVersion {
    # QID 92167 - Windows Recovery Environment (WinRE) is a recovery environment that can repair common causes of unbootable operating systems.
    #   The vulnerability pertains to a previous installer version which has been superseded by the new WinRE installer.  Affected version  WinRE
    #   image based on the installed operating system. 
    #       Windows 10, version 21H2 and Windows 10, version 22H2:     WinRE Version must be >= 10.0.19041.3920 
    #       Windows 11, version 21H2:                                  WinRE Version must be >= 10.0.22000.2710 
    #       Windows Server 2022:                                       WinRE Version must be >= 10.0.20348.2201 
    $osInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $winreVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').WinREVersion

    $requiredVersions = @{
        "Windows 11 Pro 21H2" = [version]"10.0.22000.2710"
        "Windows 11 Home 21H2" = [version]"10.0.22000.2710"
        "Windows 11 Educational 21H2" = [version]"10.0.22000.2710"
        "Windows Server 2022 Standard 21H2" = [version]"10.0.20348.2201"
        "Windows Server 2022 Datacenter 21H2" = [version]"10.0.20348.2201"
        "Windows 10 Pro 21H2" = [version]"10.0.19041.3920"
        "Windows 10 Home 21H2" = [version]"10.0.19041.3920"
        "Windows 10 Educational 21H2" = [version]"10.0.19041.3920"
        "Windows 10 Pro 22H2" = [version]"10.0.19041.3920"
        "Windows 10 Home 22H2" = [version]"10.0.19041.3920"
        "Windows 10 Educational 22H2" = [version]"10.0.19041.3920"
    }

    $osName = $osInfo.ProductName
    $osBuild = $osInfo.DisplayVersion
    if ($requiredVersions.ContainsKey("$osName $osBuild")) {
        $requiredVersion = $requiredVersions["$osName $osBuild"]
        if ([version]$winreVersion -ge $requiredVersion) {
          Write-Host "[+] WinRE Version ($winreVersion) meets the requirement for $osName." -ForegroundColor Green
        } else {
          Write-Host "[-] WinRE Version ($winreVersion) is below the required version for $osName. Minimum required: $requiredVersion." -ForegroundColor Red
          Write-Host "[-] Opening browser to Microsoft SafeOS Dynamic update page: https://www.catalog.update.microsoft.com/Search.aspx?q=Safe+OS" -ForegroundColor White
          & explorer https://www.catalog.update.microsoft.com/Search.aspx?q=Safe+OS
        }
    } else {
      Write-Host "[!] OS $osName is not listed for checking."  -ForegroundColor green
    }
    # Win10 22h2 download:
    # wget "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/crup/2024/10/windows10.0-kb5044615-x64_4b85450447ef0e6750ea0c0b576c6ba6605d2e4c.cab" -outfile "$($tmp)\10-22h2update.cab"
}


function Test-IsType
{
    param(
        [object]$InputObject,
        [string]$TypeName
    )

    return $InputObject.PSTypeNames -contains $TypeName 
}

function Search-Software {
  param(
    [string]$SoftwareName)

  $SearchString="*$($SoftwareName)*"
  $Results = (get-wmiobject Win32_Product | Where-Object { $_.Name -like $SearchString })
  if ($Results) {
    return $Results
  } else {
    $Results = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -like $SearchString }
    if ($Results) {
      if ($Results.UninstallString) {
        return $Results.UninstallString
      } # else we get the error below
    }
    Write-Host "[!] No WMI entry, or registry uninstallstring found.. no way to uninstall this automatically it appears!" -ForegroundColor Red
    return $null
  }
}

function Remove-SoftwareByName {
  param (
      [string]$SoftwareName
  )

  # Attempt to uninstall using registry
  $registrySoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                      Where-Object { $_.DisplayName -like "*$SoftwareName*" }
  if ($registrySoftware) {
    foreach ($software in $registrySoftware) {
      if ($software.PSChildName.length -eq 36) {  # if it looks like it has a real GUID, probably real..
        Write-Host "[-] Uninstalling $($software.DisplayName)..." -ForegroundColor Yellow
        if ($software.UninstallString) {
          $cmd,$args = ($software.UninstallString).split(' ')
          Write-Verbose "Running: Start-Process -FilePath $cmd -ArgumentList ""$args /qn""  -Wait"
          Start-Process -FilePath $cmd -ArgumentList "$args /qn" -Wait
          Write-Verbose "Assuming everything went well.. "
          return $true
        }
        else {
          Write-Host "[.] Uninstall string not found for $($software.DisplayName)."
          return $false
        }
      }
    }
  }
  else {
    Write-Host "[.] Software '$SoftwareName' not found in registry either."
    return $false
  }
}


function Remove-Software {
  param ($Products,
         $Results)
  
  if (Test-IsType $Products "System.String") {
    Write-Verbose "String product name returned from registry vs GWMI.. Trying to remove via registry .."
    $cmd = (($Products -split '.exe')[0]+'.exe' -replace '"','') # yuck. 
    $arguments = (($Products -split '.exe')[1] -replace '"','') # Hacky af, idk what we might run into here yet..
    Write-Verbose "Removing: Start-Process -FilePath $cmd -ArgumentList ""$args /qn""  -Wait"
    Start-Process -FilePath $cmd -ArgumentList "$arguments /qn" -Wait
    Write-Verbose "Assuming everything went well.. "
    return $true
  }
  foreach ($Product in $Products) { # Remove multiple products if passed.. This only works if found by 
    $Guid = $Product | Select-Object -ExpandProperty IdentifyingNumber
    $Name = $Product | Select-Object -ExpandProperty Name
    if (Get-YesNo "Uninstall $Name - $Guid ") { 
        Write-Host "[.] Removing $Guid (Waiting max of 30 seconds after).. "
        $x=0
        Start-Process "msiexec.exe" -ArgumentList "/x $Guid /quiet /qn" -NoNewWindow # -Wait
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

function Get-Products {
  param (
    [string]$ProductName
  )
  $ProductSearch = "*$($ProductName)*"
  Write-Host "[.] Searching for $ProductSearch using Get-WmiObject Win_32Product .."  -ForegroundColor Yellow
  $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like $ProductSearch})
  return $Products
}

function Check-MultipleVersionsInstalled  {
  param (
    [string]$Name,
    [string]$Results
  )
  Write-Host "[.] Searching for multiple versions of $Name .."
  $ProductsArray = Get-Products -ProductName $Name
  if ($ProductsArray.Count -gt 1) {
    if ($ProductsArray[0].IdentifyingNumber[0] -eq '{') {
      Write-Host "[+] $ProductsArray.Name - $ProductsArray.IdentifyingNumber"  -ForegroundColor Yellow
    }
  } else {
    Write-Host "[-] Only 1 app appears to be installed: "
    $ProductsArray
  }
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

function Set-AdobeDefaults {
  # This should set Adobe Reader DC to be the default application for PDF files.

  # Define the Adobe Reader executable path
  $adobePath = "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"

  # Define the ProgID for Adobe Reader
  $adobeProgID = "AcroExch.Document.DC"

  # Step 1: Set the file association for .pdf files
  $extension = ".pdf"

  # Step 2: Update the UserChoice registry key for the current user
  # Retrieve the SID of the current user
  $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $sid = $user.Value

  # Construct the UserChoice registry path
  $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$extension\UserChoice"

  # Set the ProgID
  Set-RegistryEntry -path $regPath -name "ProgId" -value $adobeProgID

  # Set the Hash (leave empty for simplicity)
  $hash = ""
  Set-RegistryEntry -path $regPath -name "Hash" -value $hash

  # Step 3: Update the DefaultProgram for the current user
  $defaultProgramPath = "HKCU:\Software\Classes\$adobeProgID\shell\open\command"
  Set-RegistryEntry -path $defaultProgramPath -name "(default)" -value "`"$adobePath`" `%1"

  # Output the results
  Write-Output "File association for .pdf set to $adobeProgID"
  Write-Output "Default program for $adobeProgID set to $adobePath `%1"
  Write-Output "UserChoice registry updated for $extension"
  
  # Inform the user that the operation is complete
  Write-Output "[!] Adobe Reader is now set as the default PDF application."

}

function Get-NewestAdobeReader {
    # determining the latest version of Reader
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"
    $result = Invoke-RestMethod -Uri $AdobeReaderUpdateURL `
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
  
  $RelevantList = @("Everyone", "Users", "Authenticated Users", "Domain Users")
  Write-Verbose "Relevant user list: $RelevantList"
  $Output = @()
  ForEach ($FileToCheck in $FilesToCheck) {
      $Acl = Get-Acl -Path $FileToCheck   #.FullName   #Not using object from gci
      ForEach ($Access in $Acl.Access) {
          Write-Verbose "Identity for $($FileToCheck):       $($Access.IdentityReference)"          
          $match = $RelevantList | Where-Object { $Access.IdentityReference -match $_ }
          if ($match) {
            foreach ($CurrentRight in $Access.FileSystemRights) {
                  Write-Verbose "FileSystemRights: $CurrentRight"
                  if (($CurrentRight -match "FullControl") -or ($CurrentRight -like "*Write*") -or ($CurrentRight -like "*Append*")) {
                      $Properties = [ordered]@{
                          'Folder Name'   = $FileToCheck
                          'Group/User'    = $Access.IdentityReference
                          'Permissions'   = $CurrentRight
                          'Inherited'     = $Access.IsInherited
                      }
                      $Output += New-Object -TypeName PSObject -Property $Properties
                  }
              }
          }
      }
  }
  Return $Output
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
      $null = ((takeown.exe /a /r /d Y /f $($FolderToDelete)) | Tee-Object -Append -FilePath "$($tmp)/_takeown.log")
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
    if ($split -like '*.exe*' -or $split -like '*.dll*') {  # may be more matching extensions here eventually..
      $Paths += $split.Trim()
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
    if ($split -like "*.exe*" -or $split -like "*.dll*") {
      #ignore, this is the filename
    } else { # this should be the version
      $Versions += $split.Trim().replace('#','')
    }
  }
  return $Versions
}

function Show-FileVersionComparison {
  [CmdletBinding()]
  param ([string]$Name, $Results)

  if ($Results -like "* Version is *") {
    $EXEFiles = @(Parse-ResultsFile $Results)
    $EXEFileVersions = @(Parse-ResultsVersion $Results)
    Write-Verbose "Results: $Results"
    Write-Verbose "EXEFiles: $EXEFiles"
    Write-Verbose "EXEFileVersions: $EXEFileVersions"

    for ($i = 0; $i -lt $EXEFiles.Length; $i++) {
      $EXEFile = $EXEFiles[$i]
      $EXEFileVersion = $EXEFileVersions[$i]
      Write-Verbose "EXEFile: $EXEFile"
      Write-Verbose "EXEFileVersion: $EXEFileVersion"

      if (Test-Path -Path "$EXEFile") {
        $CurrentEXEFileVersion = "$(((Get-ChildItem $EXEFile -File).VersionInfo.FileVersion).Replace(",","."))"
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
      } else {  # Not FullyDecrypted should mean its bitlockered..
        Write-Host "[!] Found C: Bitlockered, checking for other bitlockered drives."
        $BLVs = (Get-BitLockerVolume).MountPoint | Where-Object { (Get-BitLockerVolume -MountPoint $_).VolumeStatus -eq 'FullyEncrypted' } | Sort-Object
        foreach ($BLV in $BLVs) { 
          if (Get-BitLockerVolume -MountPoint $BLV -ErrorAction SilentlyContinue) {
            try {
              Write-Host "[.] Backing up Bitlocker Keys for $BLV to AD.."
              Backup-BitLockerKeyProtector -MountPoint $BLV -KeyProtectorId (Get-BitLockerVolume -MountPoint $BLV).KeyProtector[1].KeyProtectorId -ErrorAction SilentlyContinue | Out-Null
            } catch { 
              Write-Host "[!] ERROR: Could not access BitlockerKeyProtector for $BLV !!"
              $BLVol = Get-BitLockerVolume
              $BLVol | Select-Object MountPoint,CapacityGB,VolumeStatus
            }
          }
        }
      }
    } else {
      Write-Output "[-] Skipping backup of Bitlocker keys."
    }
  }
}

function Get-FileVersion {
  param ([string]$FileNameToTest)

  try {
    if (Test-Path -Path $FileNameToTest) {
      $ThisVersion = (Get-Item $FileNameToTest -ErrorAction SilentlyContinue).VersionInfo.ProductVersion  # or FileVersion??
    } else {
      Write-Verbose "! File $FileNameToTest not found !"
      return $false
    }
  } catch {
    Write-Verbose "! File $FileNameToTest not found, or unknown error checking.. !"
    return $false
  }
  return $ThisVersion
}

function Get-ChromeVersion {
  try {
    if (Test-Path -Path "c:\program files (x86)\Google\Chrome\Application\Chrome.exe") {
      $ThisVersion = (Get-Item $FileNameToTest -ErrorAction SilentlyContinue).VersionInfo.ProductVersion  # or FileVersion??
    } else {
      if (Test-Path -Path "c:\program files\Google\Chrome\Application\Chrome.exe") {
        $ThisVersion = (Get-Item $FileNameToTest -ErrorAction SilentlyContinue).VersionInfo.ProductVersion  # or FileVersion??
      } else {
        Write-Host "! Chrome EXE file not found, or unknown error checking.. !" -ForegroundColor Red
      }
    }
  } catch {
    Write-Host "[!] Chrome EXE file not found, or unknown error checking.. !`n" -ForegroundColor Red
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
    $SplitResults = (($Results) -csplit "version is").trim()
  } else {
    # assuming its like this instead, outdated UWP app detection:
    # "Vulnerable Microsoft Paint 3D detected  Version     '6.2105.4017.0'  Version     '6.2203.1037.0'#"
    # or:
    # "Vulnerable version of Microsoft 3D Builder detected  Version     '20.0.3.0'#"
    $SplitResults = (($Results) -csplit "Version").trim()
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

  # 92063 example
  # $Results = "Vulnerable version of Microsoft 3D Builder detected  Version     '20.0.3.0'#"
  # Splits to:
  # 


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
        Write-Host "NOTE: Version param of Remove-SpecificAppxPackage is blank: [$($Version)] .. setting to VersionResults."
        $Version = $VersionResults
      }
      Write-Verbose "VersionResults: $VersionResults"
      Write-Verbose "Version: $Version"
      if ([System.Version]$AppVersion -le [System.Version]$Version) {    # VERSION CHECK
        Write-Host "[!] $($i): Vulnerable version of store app found : $AppName - [$($AppVersion)] <= [$($Version)]"  -ForegroundColor Red
        if (Get-YesNo "$AppName - $AppVersion <= $Version .  Remove? ") {  # Final check, in case there are issues getting $Version or $VersionResults ..
          Write-Host "[.] Removing $AppName :" -ForegroundColor Green
          try {
            $null = (Remove-AppxPackage -Package $AppName -ErrorAction SilentlyContinue)            # Remove
          } catch { } # Ignore errors..
          Write-Host "[.] Removing $AppName -AllUsers :" -ForegroundColor Green
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
    Write-Host "[!] No results found from '(Get-AppXPackage *$Name* -AllUsers)' -- Please check Microsoft Store for updates manually! "
    # explorer "ms-windows-store:"
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
          $RebootRequired = $true
        }
      }
      foreach ($result in $RechecksProvisioned) {
        $AppVersion = [System.Version]($Result).Version
        $AppName = ($Result).PackageName
        if ([System.Version]$AppVersion -le [System.Version]$Version) {
          Write-Host "[!] Vulnerable version of Provisioned Appx Package still found : $AppName - $AppVersion <= $Version"  -ForegroundColor Red
          Write-Verbose "result: $result"
          Write-Host "[!] Please either reboot and test again, or fix manually.." -ForegroundColor Red
          $RebootRequired = $true
        }
      }
    }
  }
}

Function Update-Application {
  param(
    [string]$Uri,
    [string]$OutFile,
    [string]$KillProcess,
    [string]$UpdateString
  )
  if ($WinGetInstalled -and $WingetApplicationList -contains $UpdateString) { 
    Write-Host "[+] Using WinGet to update $UpdateString (if possible).."
    if ($UpdateString -eq "Chrome") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update Google.Chrome $WinGetOpts" }
    if ($UpdateString -eq "MSEdge") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update Microsoft.Edge $WinGetOpts" }
    if ($UpdateString -eq "Firefox") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update Mozilla.Firefox $WinGetOpts" }
    if ($UpdateString -eq "Brave") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update Brave.Brave $WinGetOpts" }
    if ($UpdateString -eq "Teamviewer 15") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update TeamViewer.TeamViewer $WinGetOpts" }
    if ($UpdateString -eq "Irfanview") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update IrfanSkiljan.IrfanView $WinGetOpts" }
    if ($UpdateString -eq "Notepad++") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update Notepad++.Notepad++ $WinGetOpts" }
    if ($UpdateString -eq "Zoom client") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update Zoom.Zoom $WinGetOpts" }
    if ($UpdateString -eq "Dropbox") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update Dropbox.Dropbox $WinGetOpts" }
    if ($UpdateString -eq "7-zip") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update 7zip.7zip $WinGetOpts" }
    if ($UpdateString -eq "Visual Studio Code") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update Microsoft.VisualStudioCode $WinGetOpts" }
    if ($UpdateString -eq "Apple iTunes") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update Apple.iTunes $WinGetOpts" }
    if ($UpdateString -eq "Apple iCloud") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update Apple.iCloud $WinGetOpts" }
    if ($UpdateString -eq "VLC") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update VideoLAN.VLC $WinGetOpts" }
    if ($UpdateString -eq "Putty") { Start-Process "winget" -NoNewWindow -Wait -ArgumentList "update PuTTY.PuTTY $WinGetOpts" }
    
    
    Write-Host "[+] Done."
  } else {
    # Lets use Ninite to update..
    Write-Host "[.] Updating to newest $UpdateString using Ninite.."
    Write-Host "[.] Downloading $uri from Ninite, to: $OutFile .."
    Invoke-WebRequest -UserAgent $AgentString -Uri $Uri -OutFile $OutFile
    Write-Host "[.] Killing all $Updatestring processess ( $KillProcess ) .."
    taskkill.exe /f /im $(($KillProcess -split "\\")[-1]) # Works without a \ in $KillProcess either.
    Write-Host "[.] Waiting 5 seconds .."
    Start-Sleep 5 # Wait 5 seconds to make sure all processes are killed, could take longer.
    if ($script:Automated) {
      Write-Host "[.] Running the Ninite updater, this window will automatically be closed within $UpdateNiniteWait seconds"
      Start-Process -FilePath "$($OutFile)" -NoNewWindow  # -Wait   # This will wait forever for ninite
      Write-Host "[.] Waiting $UpdateNiniteWait seconds .."
      Start-Sleep $UpdateNiniteWait # Wait X seconds to make sure the app has updated, usually 30-45s or so at least!! Longer for slower machines!
      Write-Host "[.] Killing the Ninite updater window, hopefully it is stuck at 'Done'"
      taskkill.exe /f /im $(($OutFile -split "\\")[-1])  # Grab filename from full path if given
    } else {
      Write-Host "[.] Running the Ninite $Updatestring updater, please close this window by hitting DONE when complete! Otherwise, we will kill the proce after $UpdateNiniteWait seconds."
      Start-Process -FilePath $OutFile -NoNewWindow -Wait
      if ($Risky) {
        Start-Sleep $UpdateNiniteWait # Wait X seconds to make sure the app has updated, usually 30-45s or so at least!! Longer for slower machines! Set to 120s-12/16/24
        Write-Host "[.] Killing the Ninite updater window, hopefully it is stuck at 'Done'"
        taskkill.exe /f /im $(($Outfile -split "\\")[-1])  # Grab filename from full path if given
      } else {
        Write-Host "[-] Not killing the ninite.exe updater as this is risky, please close the window yourself!!"
      }
    }
  }
}

Function Update-Chrome {
  Write-Host "[.] Killing all chrome browser windows .."
  taskkill.exe /f /im chrome.exe
  Write-Host "[.] Updating to newest Chrome.."
  Update-Application -Uri "https://ninite.com/chrome/ninite.exe" -Outfile "$($tmp)\ninitechrome.exe" -UpdateString "Chrome" -KillProcess "chrome.exe"
}

Function Update-Firefox {
  Write-Host "[.] Killing all Firefox browser windows .."
  taskkill.exe /f /im firefox.exe
  Write-Host "[.] Updating to newest Firefox.."
  Update-Application -Uri "https://ninite.com/firefox/ninite.exe" -OutFile "$($tmp)\ninitefirefox.exe" -UpdateString "Firefox" -KillProcess "firefox.exe"
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

function Check-ScheduledTask {
  param (
    [string]$ComputerName = (hostname),
    [string]$ServerName
  )
  Write-Host "`n[+] Checking Scheduled Task .." -ForegroundColor Yellow
  $Serverhostname = [string](Get-RegistryEntry -Name "ServerName")
  Write-Verbose "ServerName found in registry: $Serverhostname"
  if ($Serverhostname -eq "0") {  # ServerName should be set by here if we've read the CSV.. its not set in registry if we get "0"
    Set-RegistryEntry -Name "ServerName" -Value $ServerName
    Write-Verbose "ServerName set in registry: $ServerName"
    $Serverhostname = $ServerName
  }
  if ($ST_IgnoreComputers -notcontains $ComputerName -and ((Get-OSType) -eq 1)) {  # Workstation OS only! No servers, and make sure its not on a skip list
    # Task properties
    $taskName = "MME - MQRA - Install-SecurityFixes.ps1 -Automated"
    $taskPath = "c:\windows\system32\windowspowershell\v1.0\powershell.exe"
    if ($Serverhostname = ".") { # catch non-domain systems
      $taskAction = "-exec bypass -noninteractive -c 'sl c:\Program Files\MQRA; .\Install-SecurityFixes.ps1 -Automated'"
    } else {
      
      $taskAction = "-exec bypass -noninteractive -c 'sl c:\Program Files\MQRA; .\Install-SecurityFixes.ps1 -Automated'"
    }
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskAction 
    $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -WakeToRun

    # Check $ST_DayOfWeek and $ST_StartTime for sane values first....
    if (-not $ST_StartTime) {
      $ST_StartTime = Get-Date -Format "23:00:00"
      $ST_StartTimeHours = $ST_StartTime.Substring(0,2)  # get number of hours from date format
      Write-Verbose "ST_StartTimeHours = $ST_StartTimeHours"
    }
    if (-not $ST_DayOfWeek) {
      $ST_DayOfWeek = 4 # Thursday
    }
    Write-Verbose "ST_StartTime: $ST_StartTime ST_DayOfWeek: $ST_DayOfWeek"
    #$FirstRun = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $ST_DayOfWeek -WeeksInterval 1 -At $ST_StartTime -RandomDelay 01:00:00
    $FirstRun = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $ST_DayOfWeek -WeeksInterval 1 -At $ST_StartTime  -RandomDelay 01:00:00

    #IGNORING 2nd run date now, can retrigger remotely eventually..
    #$SecondRunDate = (Get-Date -Day 14).AddHours($ST_StartTimeHours)
    #$SecondRun = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $ST_DayOfWeek -At $SecondRunDate -RandomDelay 01:00:00

    # Validate if task exists and settings match
    $taskRequiresUpdate = $false
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Verbose "Task found, checking actions and triggers.."
        # Check if the action and triggers match expected settings
        $existingEnabled = ($exitingTask.State -eq "Enabled") 
        $existingAction = $existingTask.Actions | Where-Object {$_.Execute -eq "powershell.exe" -and $_.Arguments -eq $taskAction}
        $existingTriggers = $existingTask.Triggers | Where-Object {($_.DaysOfWeek -eq $ST_DayOfWeek) -and ($_.At -eq $ST_StartTime)}
        Write-Verbose "ExistingAction: $existingAction"
        Write-Verbose "ExistingTriggers: ($($existingTriggers.Count)): DaysOfWeek: $(($existingTriggers).DaysOfWeek) At: $(($existingTriggers).At) Startboundary: $(($existingTriggers).StartBoundary)"
        Write-Verbose "ActualTriggers: $(($existingTask.Triggers | Select-Object *))"

        if (-not $existingEnabled -or -not $existingAction -or $existingTriggers.Count -ne 1) {   # Fix eventually for 2nd run?
            Write-Verbose "No task found, task will be added."
            $taskRequiresUpdate = $true
        }
    } 
    if ($taskRequiresUpdate) {
      Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      try {
        $null = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $FirstRun -RunLevel Highest -User "SYSTEM" -Settings $taskSettings | Out-Null  # ... Add $SecondRun
        Write-Host "[+] Scheduled task '$taskName' has been created or updated." -ForegroundColor Green
      } catch {
        Write-Host "[!] Error with Register-ScheduledTask:  $_" -ForegroundColor Red
      }
    }
  } else {
    Write-Host "[+] Scheduled task will not be created on $($ComputerName), per _config.ps1"  -ForegroundColor Yellow
  }
}


###################################################################### API Related Calls ##################

########## API UTILITY FUNCTIONS

function Log {
  param (
    [string]$Data = "`r`n",
    [string]$ForegroundColor,
    [string]$Logfile = $script:ApiLogfile,
    [switch]$Both = $false
  )
  $eol = [Environment]::NewLine
  if ($LogFile -eq "") { $LogFile = "$($log)\api.log" }  # not passing this from script scope at times..
  try {
    "[API] $Data" | Out-File $LogFile -Append -ErrorAction SilentlyContinue
  } catch {   # don't care if file is missing, can't write is an issue though
    $_.Exception.Message
    Write-Host "[couldn't log][API] $Data"
  }
  if ($Both) {
    $Data             
  }

}

function MD5hash {
  param
    ( 
      [string]$in
    )
    return [System.BitConverter]::ToString((New-Object Security.Cryptography.MD5CryptoServiceProvider).ComputeHash([Text.Encoding]::UTF8.GetBytes($in))).Replace("-", "").ToLower()
}
 
function Get-ConfigFileLine {
  param (
      [string]$Search = "*",
      [string]$ConfigFile = "$($script:MQRADir)\_config.ps1"
  )
  if (!(Test-Path "$ConfigFile")) { "" | Set-Content $ConfigFile }
  $content = Get-Content $ConfigFile -ErrorAction SilentlyContinue

  foreach ($line in $content) {
      if ($line -like "$Search*") {
#          Log "Line: $line"
#          Log "Search: $Search*"
          
          # Split the line by '=' and process the second part
          $parts = $line -split '='
          if ($parts.Count -gt 1) {
              $value = $parts[1].Trim()
              # Remove surrounding quotes, if present
              if (($value.StartsWith('"') -or $value.StartsWith("'")) -and
                  ($value.EndsWith('"') -or $value.EndsWith("'"))) {
                  $value = $value.Substring(1, $value.Length - 2)
              }
#              Log "Returning Config line: $value"
              return $value
          }
      }
  }
  return $false
}




function Set-ConfigFileLine {
  param ( 
    [string]$OldLine,  # "" here will add $NewLine string to end of file
    [string]$NewLine,
    [string]$ConfigFile = "$($MQRADir)\_config.ps1"
  )
  if (!(Test-Path "$ConfigFile")) { "" | Set-Content $ConfigFile }
  $content = Get-Content $ConfigFile
  $content | Set-Content "$($configFile).bak" # make backup
  if (-not $OldLine) {
    Add-Content -Path $ConfigFile -Value $NewLine
    return $true
  }

  "" | Set-Content "$($configFile)" # empty config file
  foreach ($line in $content) {
    if ($line -like "*$($OldLine)*") {
      Add-Content -Path $ConfigFile -Value $NewLine
    } else {
      Add-Content -Path $ConfigFile -Value $line
    }
  }
}

function Put-UniqueId {
  param (
    [string]$UniqueId,
    [string]$configfile = "$($MQRADir)\_config.ps1"
  )
  Log "[+] [Put-UniqueId] : $UniqueId" 
  $UniqueIdFound = Get-ConfigFileLine '$UniqueId = '
  $UniqueIdLine = '$UniqueId = "'+$UniqueId+'"'
  if (!($UniqueIdFound)) {
    Set-ConfigFileLine -OldLine '' -NewLine $UniqueIdLine
    Log "[+] Saved UniqueId to $configfile" -ForegroundColor Green
  } else {
    Set-ConfigFileLine -OldLine '$UniqueId =' -NewLine $UniqueIdLine
    Log "[+] Overwrite UniqueId in $configfile" -ForegroundColor Yellow
  }
}

function Get-UniqueId {
  param (
    [string]$FilePath = '$($MQRADir)\_config.ps1'
  )
  try {
    (Get-Content $filepath -ErrorAction SilentlyContinue) | ForEach-Object {
      if ($_ -match '^\$UniqueId\s*=') {
        $UniqueId = ($_ -split "UniqueId =")[1].trim().replace('"','')
      }
    } 
  } catch {
    Log "=== [Get-UniqueId] couldn't read from config.. $_"
    return $false
  }
  if ($UniqueId.length -eq 16) { return $UniqueId } else { return $false }
}

function New-UniqueId {
  $UniqueId = -join ((65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object {[char]$_})
  return $UniqueId
}

function Show-FixData { 
  param (
    [psobject]$FixData
  )

  foreach ($key in $FixData.Keys) {
    Log "[FixData]  $key : $($FixData[$key])"
  }
}

function Verify-Data {
  param (
        $requiredKeys = @('qualys_ids', 'description', 'note'),
        [Parameter(Mandatory=$true)]
        [psobject]$Data
  )

  if ($Data) {
    foreach ($key in $requiredKeys) {
        if (-not $Data.ContainsKey($key)) {
            Log "[Verify-Data] -Data doesn't contain $key"
            return $false
        }
    }
    return $true
  }
}


############ API FUNCTIONS

function API-GetClientGuid {
  param (
        [string]$AccountName,
        [string]$APIRoute = "/client/lookup",
        [string]$Method = "POST",
        [string]$UserAgent = $script:UserAgent,
        [string]$APIKey,
        [string]$UniqueID
    )

    Log "[API-GetClientGuid] ---------- $uri $UserAgent $Method $(($Headers).Authorization)"
    $uri = "$($script:apiBaseUrl)$($APIRoute)"
    $headers = @{
        'Authorization' = "Bearer $APIKey"
    }
    $body = @{
        uniqueid = $UniqueID
        apikey = $APIKey
        accountname = $AccountName
    } | ConvertTo-Json
    Log "---- body: uniqueid: $($body.uniqueid) apikey: $($body.apikey) accountname: $($body.accountname)"
    try {
        Log "[API-GetClientGuid] Calling IRM : -Uri '$uri' -UserAgent '$UserAgent' -Method '$Method' `
                      -Headers Authorization $(($Headers).Authorization) -Body $($body|Select-Object *|Format-List)" -ForegroundColor Yellow
        $Resp = Invoke-RestMethod -Uri $uri -UserAgent $UserAgent -Method $Method -Headers $headers -Body $body
        Log "[API-GetClientGuid] Response: $($Resp)"
        return ($Resp)
    } catch {
        Log "[API-GetClientGuid] Error: StatusCode: $_.Exception.Response.StatusCode.value__"
        $resp
        return '{"error":"' + $_.Exception.Response.ReasonPhrase + '"}'
    }
    return '{"error":"unknown"}'
}

function API-FileDownload {
    param (
        [string]$APIRoute = "/api/v1/import/fullinternal",
        [string]$Method = "POST",
        [string]$UserAgent = "$MQRAAgent",
        [string]$APIKey,
        [string]$ClientGuid,
        [string]$Filename,
        [string]$UniqueID
    )

    $uri = "$($script:apiBaseUrl)$($APIRoute)"  # Ensure $apiBaseUrl is defined elsewhere
    Log "[API-FileUpload] uri: $uri"
    $headers = @{
        'Authorization' = "Bearer $APIKey"
    }

    try {
        $body = @{
            uniqueid = $UniqueID
            apikey = $APIKey
            client_guid = $ClientGuid
            filename = $Filename
        } | ConvertTo-Json -Depth 100

        Log "[API-FileDownload] Calling IRM with file upload: IRM -Uri $uri -Method $Method -Headers $($headers|Select-Object *|Format-List) -Body {not shown}"
        Log "[API-FileDownload] Body: "
        Log ($body | Select-Object *)
        $Response = Invoke-RestMethod -Uri $uri -Method "POST" -Headers $headers -Body $body

        #Log "[API-FileDownload] Response: $($Resp | select *|fl)"
        if ($Response."csv_content") {
          $Response.csv_content | Set-Content "$FileName"
          Log "[API-FileDownload] File downloaded successfully" 
          return $true
        } else {
           Log "[API-FileDownload] Response does not contain 'csv_content': $($Response | ConvertFrom-Json)"
          return $false
        }
        return ($Response)
    } catch {
        Log "[API-FileDownload] Error: StatusCode: $_.Exception.Response.StatusCode.value__"
        return '{"error":"' + $_.Exception.Response.ReasonPhrase + '"}'
    }
    return '{"error":"unknown"}'
}

function API-FileUpload {
    param (
        [string]$APIRoute = "/api/v1/import/fullinternal",
        [string]$Method = "POST",
        [string]$UserAgent = "APItest.ps1",
        [string]$APIKey,
        [string]$ClientGuid,
        [string]$Filename,
        [string]$UniqueID
    )

    $uri = "$($script:apiBaseUrl)$($APIRoute)"  # Ensure $apiBaseUrl is defined elsewhere
    Log "[API-FileUpload] uri: $uri"
    $headers = @{
        'Authorization' = "Bearer $APIKey"
    }

    try {
        $body = @{
            uniqueid = $UniqueID
            apikey = $APIKey
            client_guid = $ClientGuid
            filename = (Split-Path $Filename -Leaf)
            file = (Get-Content -Path $Filename)
        } | ConvertTo-Json -Depth 100

        Log "[API-FileUpload] Calling IRM with file upload: IRM -Uri $uri -Method $Method -Headers $($headers|Select-Object *|Format-List) -Body {not shown}"
        Log "[API-FileUpload] Body: "
        Log "$($body | Select-Object *)"
        $Response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body $body

        Log "[API-FileUpload] Response: $($Resp | Select-Object *|Format-List)"
        $key = "Message"
        if (-not $Response.ContainsKey($key)) {
            Log "[API-FileUpload] Response doesn't contain $key"
            return $false
        }
        if ($Response."Message") {
          if ($Response["Message"] -like "*imported successfully*") {
            Log "[API-FileUpload] Response shows file imported successfully!" 
            return $true
          } else {
            Log "[API-FileUpload] Response doesn't show a successful file import." 
            return $false
          }
        } else {
           Log "[API-FileUpload] Response does not contain 'Message': $($Response | ConvertFrom-Json)"
          return $false
        }
        return ($Response)
    } catch {
        Log "[API-FileUpload] Error: StatusCode: $_.Exception.Response.StatusCode.value__"
        return '{"error":"' + $_.Exception.Response.ReasonPhrase + '"}'
    }

    return '{"error":"unknown"}'
}


Function API-Call {
  param (
    [string]$APIRoute, 
    [string]$UniqueID = "", 
    [string]$APIKey = "", 
    [string]$AccountName = "",
    [string]$AssetInventory = "",
    [string]$NetBios = "",
    [string]$Domain = "",
    [string]$Lanipv4 = "",
    [string]$Lanipv6 = "",
    [string]$Wanipv4 = "",
    [string]$Filename = "",
    [string]$ScanSummary = "",
    [string]$ClientScan = "",
    [string]$ClientGuid = "",
    [string]$QID = "",
    [string]$Method = "POST",
    [string]$Useragent = "$Script:UserAgent",
    [string]$Logs,
    [psobject]$FixData = "?"
  )
  $domain = $env:userdnsdomain

  $url = "$($script:apiBaseUrl)$($APIRoute)"   # $APIRoute should have initial /
 
  $headers = @{
      'Content-Type' = 'application/json'
      'Authorization' = "Bearer $APIkey"
  }
  if ($APIRoute -eq "/remed") { # /Remed
    Log "[API-Call] Fixdata: $(Show-FixData $FixData)"
    if (Verify-Data -Data $FixData) {
      $qualys_ids = ($FixData["qualys_ids"] -replace "\n","" -replace "\\","")  | ConvertTo-Json
      $description = $FixData["description"]
      $note = $FixData["note"]
    } else {
      Log "[!] Error: $FixData is missing one or more required fields."
    }
    $body = @{                            # /Remed
        apikey = $APIKey
        uniqueid = $uniqueID
        filename = $FileName
        qualys_ids = $qualys_ids
        description = $description
        note = $note
    } | ConvertTo-Json
  } else {
    if ($APIRoute -eq "/hello") {         # /Hello
      if (!($APIKey)) { $APIKey = $HelloMsg }
      $body = @{
        uniqueid = $uniqueID
        netbios = $NetBios
        domain = $Domain
        wanipv4 = $wanipv4
        lanipv4 = $lanipv4
        lanipv6 = $lanipv6
#        assetinventory = $AssetInventory
#        accountname = $AccountName
        apikey = $APIKey
      }   | ConvertTo-Json
    } else { 
      if ($APIRoute -eq "/sendlogs") {    # /Sendlogs
        $body = @{  
          uniqueid = $uniqueID
          apikey = $APIKey
          clientscan = $ClientScan
          name = "QID $QID"
          logs = $Logs
        } | ConvertTo-Json
      } else {
        if ($APIRoute -eq "/clientscan/csv") { # /Clientscan/CSV
          $body = @{  
            uniqueid = $uniqueID
            apikey = $APIKey
            filename = $Filename
          } | ConvertTo-Json
        } else {
          if ($APIRoute -eq "/clientscan/latest") { # /ClientScan/Latest
            $body = @{ 
              uniqueid = $uniqueID
              apikey = $APIKey
            } | ConvertTo-Json
          } else {
            if ($APIRoute -eq "/checkin" -or $APIRoute -eq '/checkout') { # /Checkin or /Checkout
              $body = @{ 
                uniqueid = $uniqueID
                apikey = $APIKey
              } | ConvertTo-Json
            } else {
              if ($APIRoute -eq "/test") {
                $body = @{ 
                  test = "test"
                } | ConvertTo-Json
              }
             }
          }
        }
      }
    }
  }
  try {
    Log "[API-Call] Calling IRM : -Uri '$url' -UserAgent '$UserAgent' -Method '$Method' -Headers '$($headers | out-string) $($headers.Value)' -Body '$body'"
    $Resp = Invoke-RestMethod -Uri $url -UserAgent $UserAgent -Method $Method -Headers $headers -Body $body -Contenttype 'application/json' -TimeoutSec $TimeoutSec
    Log "[API-Call] response: $($Resp)"
    return ($Resp)
  } catch {
    Log "[API-Call] Error: StatusCode: $($_.Exception.Response.StatusCode.value__)"
#    Log "[API-Call] Error: StatusDescription: $_.Exception.Response.ReasonPhrase"
#    Log "[API-Call]  Error: raw text: $($Response)"
    return '{"error": '+$_.Exception.Response.ReasonPhrase+'"}'
  }
 
  return '{"error":"unknown"}'
}
 
 
function API-Remed {
  param (
    [string]$APIKey,
    [psobject]$FixData,
    [string]$APIRoute,
    [string]$UniqueID = "",
    [string]$AccountName = "",
    [string]$AssetInventory = "",
    [string]$ScanSummary = "",
    [string]$NetBios = $script:hostname,
    [string]$FileName = ""
  )
  if (!($SkipAPI)) {  
    $APIRoute = "/remed"
    Log "[API-REMED] API-Call:
    APIKey: $APIKey
    FixData: $($FixData)
    APIRoute: $APIRoute
    UniqueID: $UniqueID
    Accountname: $AccountName
    AssetInventory: $AssetInventory
    ScanSummary: $ScanSummary
    NetBios: $NetBios
    FileName: $FileName"
    $Response = API-Call -APIRoute $APIRoute -UniqueId $UniqueID -APIKey $APIKey -FixData $FixData -AccountName $AccountName `
                        -AssetInventory $AssetInventory -NetBios $NetBios -Filename $Filename -ScanSummary $ScanSummary
    Log "[API-Remed] Response: $response"
    if ($(($Response)."status") -like "*Remediation recorded*") {
      return $true
    } else {
      return $false
    }
    if ($Response."error") {  
      return $false
    } else {
      return $false
    }
  } else {
     # API Call skipped...
  }
}
 
function API-Check {
  param (
    [string]$UniqueID,
    [string]$APIKey,
    [string]$Direction
  )
  if (!($SkipAPI)) {
    $APIRoute = "/check$($Direction)"
    $Response = API-Call -APIRoute $APIRoute -UniqueId $UniqueID -APIKey $APIKey
    if ($Response -like "*timestamp recorded*") {
      if ($Response -like "*timestamp recorded*") {
        Log "[API-Check] Check$($Direction) Succeeded"
        return $true
      } else {
        Log "[API-Check] Check$($Direction) Failed - no timestamp recorded"
        return $false
      }
    } else {
        Log "[API-Check] Check$($Direction) Failed - couldn't find 'timestamp recorded' in response."
        return $false
    }
  } else {
    Log "[-] Skipping API calls.. SkipAPI=true"
  }
}
 
function API-Hello {
  param ( 
    [string]$UniqueID,
    [string]$AccountName,
    [string]$AssetInventory,
    [string]$domain,
    [string]$hostname = (hostname).ToUpper(),
    [string]$lanipv4 = ((Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notlike '*Loopback*' }).IPAddress),
    [string]$lanipv6 = ((Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv6' -and $_.InterfaceAlias -notlike '*Loopback*' }).IPAddress),
    [string]$wanipv4 = (Invoke-WebRequest "ifconfig.me").Content,
    [string]$HelloMsg = "65f7218ee72d8aeab272130a042de1e3"
  )
  $domain = $env:userdnsdomain
  $NetBios = $hostname
  if (!($SkipAPI)) {  
    $APIRoute = "/hello"
    $Resp = API-Call -APIRoute $APIRoute -APIKey $HelloMsg -NetBios $NetBIOS -domain $domain -lanipv4 $lanipv4 -lanipv6 $lanipv6 -wanipv4 $wanipv4 -uniqueid $UniqueId

    Log "------ Resp.StatusCode: $($Resp.statuscode)"
    if ($Resp -like "*api_key*") {
      $APIKey = $Resp."api_key"
      if ($APIKey.Length -ge 64) {   # Better check here
        Log "[API-Hello] Hello Succeeded. API Key = $APIKey "  -ForegroundColor Green
        return $ApiKey
      } else {
        Log "[API-Hello] Hello FAILED!" -ForegroundColor Red
        return $false
      }
    }  
  }
}
 
####################### API KEY FUNCTIONS #################################################

function API-StoreKey {
  param (
    [string]$APIKey,
    [string]$filepath = "($MQRADir)\_config.ps1"
  )
  $APIKeyFound = Get-ConfigFileLine '$APIKey = ' -Configfile $filepath
  $APIKeyLine = '$APIKey = "'+$APIKey+'"'
  if (!($APIKeyFound)) {
    Set-ConfigFileLine -ConfigFile $filepath -OldLine '' -NewLine $APIKeyLine
    Log "[+] Saved new API Key to $filepath" -ForegroundColor Green
    return $true
  } else {
    Set-ConfigFileLine -ConfigFile $filepath -OldLine '$APIKey =' -NewLine $APIKeyLine
    Log "[+] Overwrite API Key in $filepath" -ForegroundColor Green
    return $true
  }
  return $false
}

function API-SendLogs {
  param (
    [string]$UniqueID,
    [string]$APIKey,
    [string]$ClientScan,
    [string]$LogFile,
    [string]$QID
  )
  if (!($SkipAPI)) {
    $APIRoute = "/sendlogs"
    $Logs = Get-Content $LogFile
    $Response = API-Call -APIRoute $APIRoute -UniqueId $UniqueID -APIKey $APIKey -ClientScan $ClientScan -Logs $Logs -QID $QID
    if ($Response."messages") {
      Log "messages"
      if ($Response."messages" -like "*Logs received*") {
        Log "logs received"
        return $true
      } else {
       return $false
      }
    }
  } else {
    Write-Host "[-] Skipping API calls.. SkipAPI=true"
  }
}

function API-GetLatestClientScan {
  param (
    [string]$UniqueID,
    [string]$APIKey
  )
  if (!($SkipAPI)) {
    $APIRoute = "/clientscan/latest"
    $Response = API-Call -APIRoute $APIRoute -Method "POST" -UniqueId $UniqueID -APIKey $APIKey
    if ($Response."filename") {
      if ($Response."filename" -like "*.csv*") {
        return $Response."filename"
      } else {
       return $false
      }
    }
  } else {
    Write-Host "[-] Skipping API calls.. SkipAPI=true"
  }
}


############################## API SCAN UPLOADS and DOWNLOADS ##################################################

function API-DownloadScan {
  param (
    [string]$UniqueID,
    [string]$APIKey,
    [string]$Filename,
    [string]$WriteTo = "$($MQRAdir)\scans"
  )
  if (!($SkipAPI)) {
    $APIRoute = "/clientscan/csv"
    $Response = API-Call -APIRoute $APIRoute -Method "POST" -UniqueId $UniqueID -APIKey $APIKey -Filename $Filename
    if ($Response."csv_content") {
      $Response."csv_content" | Set-Content "$($WriteTo)\$($Filename)"
      Log "[+] Recieved CSV, saved to '$($WriteTo)\$($Filename)'"
      return "$($WriteTo)\$($Filename)"
    } else {
     return $false
    }
  } else {
    Write-Host "[-] Skipping API calls.. SkipAPI=true"
  }
}

function API-UploadScan {
  param (
    [string]$Filename, 
    [string]$UniqueID, 
    [string]$ClientGuid, 
    [string]$APIKey,
    [string]$Type
  )

  $APIRoute = "/import/full$($type)"
  if (!($SkipAPI)) {
    Log "[API-UploadScan] launching API-FileUpload APIRoute: $APIRoute UniqueID: $UniqueId APIKey: $APIKey Filename: $Filename ClientGuid: $ClientGuid"
    $Response = API-FileUpload -APIRoute $APIRoute -UniqueID $UniqueID -APIKey $APIKey -Filename $Filename -ClientGuid $ClientGuid
    if ($Response) { return $true } else { return $false }
  } else {
    Log "[-] Skipping API calls.. SkipAPI=true"
  }
}

function API-CheckScan {
  param (
        $APIRoute = "/clientscan/latest",
        $UniqueId,
        $APIKey,
        $AccountName,
        $NetBios
  )
  if (!($SkipAPI)) {
    Log "[API-CheckScan] launching API-Call APIRoute: $APIRoute UniqueID: $UniqueId APIKey: $APIKey"
    $Response = API-Call -APIRoute $APIRoute -UniqueID $UniqueID -APIKey $APIKey
    Log "[API-CheckScan] API-Call response: $Response"
    if ($Response.filename) { return $Response.filename } else { return $false }
  } else {
    Log "[-] Skipping API calls.. SkipAPI=true"
  }
}	

function API-Test {
  param (
    [switch]$ping
  )

  $APIRoute = "/test"
  if (!($SkipAPI)) {
    Log "[API-Test] launching API-Call APIRoute: $APIRoute "
    if ($ping) {
      $ping=(ping -n 1 -w 3 mqra.mme-sec.us | findstr /i reply).split(' ')[4].split('=')[1].split('ms')[0]  # Test-Netconnection sucks
      $Response = API-Call -APIRoute $APIRoute 
      if ($Response) { return $ping } else { return $false }
    } else {
      $Response = API-Call -APIRoute $APIRoute 
      if ($Response) { return $true } else { return $false }
    }
  } else {
    Log "[-] Skipping API calls.. SkipAPI=true"
  }
}


# All the microsoft office products with their corresponding dword value
$RemediationValues = @{ "Excel" = "Excel.exe"; "Graph" = "Graph.exe"; "Access" = "MSAccess.exe"; "Publisher" = "MsPub.exe"; "PowerPoint" = "PowerPnt.exe"; "OldPowerPoint" = "PowerPoint.exe" ; "Visio" = "Visio.exe"; "Project" = "WinProj.exe"; "Word" = "WinWord.exe"; "Wordpad" = "Wordpad.exe" }

################################################################################################################## MAIN ############################################################################################################
################################################################################################################## MAIN ############################################################################################################
################################################################################################################## MAIN ############################################################################################################



########################################################## PRE API STUFF THAT MUST BE DONE IMMEDIATELY!! ########################################################################


# Lets copy everything to MQRA folder before going any further
if (!(Test-Path -Path "C:\Program Files\MQRA\_config.ps1")) {
  if (Copy-FilesToMQRAFolder) {
    $ConfigFile = "C:\Program Files\MQRA\_config.ps1"
  }
  Check-ConfigForBadValues
  #set-location "C:\Program Files\MQRA"
} else {
  $ConfigFile = "C:\Program Files\MQRA\_config.ps1"
  #set-location "C:\Program Files\MQRA"
}

Init-Script -Automated $Automated
Write-Event -type "information" -eventid 100 -msg "Script starting"

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


Write-Host "[.] Loading config from $(Get-Location) .." -ForegroundColor Yellow
. "./_config.ps1"

Update-Script  # CHECKS FOR SCRIPT UPDATES, UPDATES AND RERUNS IF NECESSARY

# CONFIG AND OTHER FILES  HAVE BEEN COPIED ALREADY BY HERE..

####################################################### MAIN API CODE #######################################################

Write-Host "[.] Starting API routines .." -ForegroundColor Yellow        
$datetime = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
Log;Log;Log;Log "################################################################################################# API START $datetime" -Both
$UniqueId = Get-UniqueId
if (!($UniqueId)) {
  $UniqueId = New-UniqueId
  Put-UniqueId $UniqueId
  Log "[+] Created and stored UniqueId: $UniqueId" -Both
} else {
  Log "[+] Found UniqueId: $UniqueId" -Both
}

$APIKey = (Get-ConfigFileLine -Search '$APIKey = ' -ConfigFile "C:\Program Files\MQRA\_config.ps1")
if ($APIKey) {
  Log "[+] Got API key" -ForegroundColor Green -Both
} else {
  Log "[-] Couldn't get API key from $configfile !!" -ForegroundColor Red -Both
  $APIKey = $null
}

if (!($ping = API-Test)) {
  Log "[-] ERROR: API not functional."  -ForegroundColor Red -Both
  $SkipAPI = $true
} else {
  $colors = @("Red","Orange","Yellow","Light Green","Green")
  $pings = @(125,100,75,50,25)
  foreach ($ping in $pings) {
    if ($ping -gt 100) {
        $color = $colors[0]
    } elseif ($ping -gt 75) {
        $color = $colors[1]
    } elseif ($ping -gt 50) {
        $color = $colors[2]
    } elseif ($ping -gt 25) {
        $color = $colors[3]
    } else {
        $color = $colors[4]
    }
  }
  #$color = $colors[$ping]
  Log "[+] API up and running, MQRA server: $($ping)ms"  -ForegroundColor $color -Both
}

Log;Log "-------------- API-CheckIn ---------------------------" -Both
if (!(API-Check -Direction "in" -UniqueID $UniqueID -APIKey $APIKey)) {   # "in" must stay lowercase!
  Log "[API] Failed Checkin. Trying Hello.." -Both
  Log;Log "-------------- API-Hello tests ---------------------------" -Both
  $Result = API-Hello -APIKey $APIKey -UniqueID $UniqueID -NetBios $NetBios -hostname $hostname
  Log "--- API-Hello Result: $Result" -Both
  if ($Result.length -eq 64) {
    $APIKey = $Result
  } else {
    Log "--- Bad Response: $Result" -Both  # not sure?
  }
  if ($APIKey) {
    Log "[+] Hello success! API_Key = $APIKey" -Both
    if (API-StoreKey -APIKey $APIKey -FilePath "C:\Program Files\MQRA\_config.ps1") {
      Log "[+] Success, updated C:\Program Files\MQRA\_config.ps1 file with API key." -ForegroundColor Green
    } else {
      Log '[-] Error replacing $APIKey line in _config.ps1 file! Check permissions or file exists, etc' -ForegroundColor Red -Both
    }
    if ($APIKey = Get-ConfigFileLine -Search '$APIKey = ') {
      Log "[+] Success, got API key from _config.ps1" -ForegroundColor Yellow
    }

    Log;Log "-------------- API-CheckIn tests ---------------------------"
    if (API-Check -Direction "in" -UniqueID $UniqueID -APIKey $APIKey) {   # "in" must stay lowercase!
      Log "[+] Checkin Success." -Both
    } else {
      Log "[-] Checkin Failure!" -Both
    } 
  } else {
    Log "[-] Hello Failure! ... "
    #Log "[-] Hello Failure! ... Skipping API for now." -Both
    #$SkipAPI = $true
  }
} else {
  Log "[+] Checkin: Success!" -ForegroundColor Green -Both
}

$Filename = API-GetLatestClientScan -UniqueID $UniqueId -APIKey $APIKey
if ($Filename) {
  Log "[+] Received Filename: '$Filename'" -ForegroundColor Green
} else {
  Log "[-] API-GetLatestClientScan - Couldn't get filename!!" -ForegroundColor Red
}
$CSVPath = "$($MQRADir)\scans\"
$FileDown = API-DownloadScan -WriteTo $CSVPath -Filename $Filename -UniqueID $UniqueId -APIKey $APIKey
if (Test-Path -Path $FileDown -ErrorAction SilentlyContinue) {
  Log "[+] Downloaded Filename: '$FileDown'" -ForegroundColor Green
  $CSVFilename = $FileDown
  $CSVFile = $FileDown
} else {
  Log "[-] API-DownloadScan Couldn't get filename!!" -ForegroundColor Red
}


$datetime = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
Log "################################################################################################# API END $datetime"

#######################################################

# Lets find a CSV file.. lets check the Config 1st, Registry 2nd, default hostnames 3rd for a place with our CSV file shared in \\$serverName\Data\SecAud

<#
if (-not $CSVFile) {   # Pass all this crap up if I've passed -CSVFile or we've downloaded 1 from the API
  $ServerName = "SERVER" # start with this..
  if (Test-Connection -ComputerName $ServerName -Count 1 -Delay 1 -Quiet -ErrorAction SilentlyContinue) {
    Write-Output "[.] Checking location \\$($ServerName)\$($CSVLocation) .."
    if (Get-Item "\\$($ServerName)\$($CSVLocation)\Install-SecurityFixes.ps1" -ErrorAction SilentlyContinue) {
      Write-Host "[.] Found \\$($ServerName)\$($CSVLocation)\Install-SecurityFixes.ps1 .. Cleared to proceed." -ForegroundColor Green
      $SecAudPath = "\\$($ServerName)\$($CSVLocation)"
    }
  } else {
    # Lets also check SERVER, DC-SERVER, localhost in case config is wrong?
    $ServerNames = "SERVER","DC-SERVER","DC","DC1",($env:computername)
    foreach ($ServerName in $ServerNames) {
      Write-Output "[.] Checking default locations: \\$($ServerName)\Data\SecAud .."
      if (Test-Connection -ComputerName "$($ServerName)" -Count 1 -Delay 1 -Quiet -ErrorAction SilentlyContinue) {
        if (Get-Item "\\$($ServerName)\Data\SecAud\Install-SecurityFixes.ps1" -ErrorAction SilentlyContinue) {
          $ServerName = "$($ServerName)"
          $CSVLocation = "Data\SecAud"
          $script:ServerShare = "$($ServerName)\$($CSVLocation)"
          $SecAudPath = "\\$($ServerName)\$($CSVLocation)"
          Write-Host "[.] Found \\$($SecAudPath)\Install-SecurityFixes.ps1 .. Cleared to proceed." -ForegroundColor Green
        }
      } else { Write-Output "[-] No response found, Trying next.." }
    }
  }
}

#>
if (!($CSVFile.ToUpper() -like "*.CSV")) {  
  Write-Host "[.] Searching for files modified within the last 30 days that match the pattern '*_Internal_*.csv' in path - $SecAudPath"
  $dateLimit = (Get-Date).AddDays(-30)
  $files = Get-ChildItem -Path $SecAudPath -Filter "*_Internal_*.csv" -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $dateLimit } | Sort-Object $_.LastWriteTime -Descending

  if ($files.Count -gt 0) {
    # Use the full path of the first found file
    $CSVFilename = $files[0].FullName
    $CSVFile = $CSVFilename  # This needs to be set below as well
    Write-Host "[+] Latest CSV File found: $CSVFilename" -ForegroundColor Green
  } else {
    Write-Host "[-] No recent (within 30d) matching CSV files found in [ $path ] "
    $files = Get-ChildItem -Path $SecAudPath -Filter "*_Internal_*.csv" -File -ErrorAction SilentlyContinue 
    if ($files) {
      Write-Host "[-] List of files found MORE THAN 30 days old: " -ForegroundColor Yellow
      $files
    } else {
      $files = Get-ChildItem -Path $SecAudPath
      Write-Host "[-] No matching CSV Files found in $SecAudPath"
      $files
    }
    Write-Host "[!] ERROR: Can't find a CSV to use, or the servername to check.." -ForegroundColor Red
    Write-Verbose "Creating Log: Application Source: Type: Error ID: 2500 - CSV not found"
    Write-Event -type "error" -eventid 2500 -msg "Error - CSV not found"
    exit
  }
  Set-RegistryEntry -Name "ServerName" -Value $ServerName # This should be legit or we don't get out of the above, without a CSV.
} else {
  $CSVFilename = $CSVFile
}

if (!$OnlyQIDs) {   # If we are not just trying a fix for one CSV, we will also see if we can install the Dell BIOS provider and set WOL to on, and backup Bitlocker keys to AD if possible
  if ([int](Get-OSType) -eq 1) {
    if ($PowerOpts) {
      Set-PowerSettingsNeverSleep  # Lets set this machine to never go to sleep, via registry. Disk, Sleep, and Hibernate time are set to 0.
    }
    #Install-DellBiosProvider  # Will only run if value is set in Config
    #Set-DellBiosProviderDefaults # Will only run if value is set in Config  
  }
  Backup-BitlockerKeys # Try to Backup Bitlocker recovery keys to AD
}
$OSVersionInfo = Get-OSVersionInfo

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
#Set-Location "$($tmp)"  # Fix for Cmd.exe cannot be run from a server share..


################# ( READ IN CSV AND PROCESS ) #####################



########### Scheduled task check:
if ($AddScheduledTask) { Check-ScheduledTask ; Exit }

if ($null -eq $CSVFilename) {
  Write-Host "[X] Couldn't find CSV file : $CSVFilename " -ForegroundColor Red
  Exit
} else {
  #if ($CSVFilename -ne $(Split-Path $CSVFilename -leaf) -and $CSVFilename -like "*\\") {
    #$delimiter = Find-Delimiter $CSVFilename
    #Write-Verbose "Splitting path for $CSVFilename to $(Split-Path $CSVFilename -leaf)"
    #$CSVFilename = Split-Path $CSVFilename -leaf  # Lets just split the damn path off here if its part of a unc path \\
  #}
  $CSVFullpath = $CSVFilename  # "$($oldpwd)\$(Split-Path $CSVFilename -leaf)" # Lets look in the old folder for this, where it should be..
  try { 
    Write-Verbose "Finding delimeter for $CSVFullPath"
    #$delimiter = Find-Delimiter $CSVFullPath   # Removed for now, batch imports break this...
    $delimiter = ","
    Write-Host "`n[.] Importing data from $CSVFullPath" -ForegroundColor Yellow
    $CSVData = Import-CSV $CSVFullPath -Delimiter $delimiter | Sort-Object "Vulnerability Description"
  } catch {
    Write-Host "[X] An error occurred: $($_.Exception.Message)"
    Write-Host "[X] Hex Content of first line: "
    (Get-Content $CSVFullPath -First 1) | Format-Hex
    $header = (Get-Content $CSVFullPath -First 1).Split($delimiter)
    $header | Group-Object | Where-Object { $_.Count -gt 1 }
    Write-Host "[X] Header line from Get-Content: $header"
    Write-Host "[X] Couldn't open CSV file : $CSVFullPath " -ForegroundColor Red
    Write-Host 
    Set-Location $pwd
    Exit
  }
  if (!($CSVData)) {
    Write-Host "[X] Couldn't read CSV data from file : $CSVFullPath " -ForegroundColor Red
    Exit
  } else {
    Write-Host "[i] Read CSV data from : $CSVFullPath - Good." -ForegroundColor Cyan
  }
}

# We've found CSV file, now perform API Related calls, checkin, and/or hello as needed

######## Find if there are any new vulnerabilities not listed ########

$Rows = @()
$QIDsAdded = @()
$CurrentQID = ""
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
} else {
  # Report check-in to MQRA cloud
}

# FIND QIDS FROM THESE ROWS
$QIDs = @()
$QIDsVerbose = @()
$Rows | ForEach-Object {
  $ThisQID=[int]$_.QID.replace(".0","")
  if ($QIDsIgnored -notcontains $ThisQID -and $SkipQIDs -notcontains $ThisQID) {  # FIND QIDS TO IGNORE
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
    if ($SkipQIDs -contains $ThisQID) { $skipped = "[Skipped via param]" } else { $skipped = "" }
    $QIDsVerbose += "[Ignored: QID$($ThisQID) - [$($_.Title)] $($skipped)"
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
if ($SkipQIDs) {
  Write-Host "[!] Skipping specific QIDs: $SkipQIDs `n" -ForegroundColor Red
}
foreach ($CurrentQID in $QIDs) {
    $ThisQID = [int]$CurrentQID
    Write-Verbose "-- This QID: $CurrentQID -- Type: $($CurrentQID.GetType())"
    $VulnDesc = (($Rows | Where-Object { $_.QID -eq $ThisQID }) | Select-Object -First 1)."Vulnerability Description"
    $Results = (($Rows | Where-Object { $_.QID -eq $ThisQID }) | Select-Object -First 1)."Results"
    If ($script:Automated -eq $true) {
      Write-Verbose "[Running in Automated mode]"
    }
    switch ([int]$CurrentQID) {
      { 379210,376023,376023,91539,372397,372069,376022 -contains $_ }  { 
        if (Get-YesNo "$_ Remove Dell SupportAssist ? " -Results $Results -QID $ThisQID) {
          $Products = Search-Software "*SupportAssist*" 
          if ($Products) {
            Remove-Software -Products $Products -Results $Results | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-DellSupportAssist.log"
          } else {
            Write-Host "[!] Dell SupportAssist not found!" -ForegroundColor Red   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-DellSupportAssist.log"
          }     
          $RebootRequired = $true
        }
      }
      105228 { 
        if (Get-YesNo "$_ Disable guest account and rename to NoVisitors ? " -Results $Results -QID $ThisQID) {
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
            start-process -wait 'net' -argumentlist 'user Guest /active:no'
            Write-Host "[.] Guest account disabled with: 'net user Guest /active:no'"
            Start-process -wait 'wmic' -argumentlist 'useraccount where name="Guest" rename NoVisitors'
            Write-Host "[.] Guest account renamed with: 'wmic useraccount where name=""Guest"" rename NoVisitors'"
          }
        }  
      }
      { $QIDsSpectreMeltdown -contains $_ } {
        if (Get-YesNo "$_ Fix spectre4/meltdown ? " -Results $Results -QID $ThisQID) {
          $out = @()
          if ($(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management').FeatureSettingsOverride -ne 72) {
            $out += "Set $((Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'FeatureSettingsOverride' -Value 72 -Force).PSPath) to 72"
          } else { $out += "[.] FeatureSettingsOverride already set correctly to 72.." }
          if ($(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management').FeatureSettingsOverrideMask -ne 3) {
            $out += "Set $((Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'FeatureSettingsOverrideMask' -Value 3 -Force).PSPath) to 3"
          } else { $out += "[.] FeatureSettingsOverrideMask already set correctly to 3.." }
          if ($(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization').MinVmVersionForCpuBasedMitigations -ne '1.0') {
            $out += "Set $((Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' -Name 'MinVmVersionForCpuBasedMitigations' -Value '1.0' -Force).PSPath) to '1.0'"
          } else { $out += "[.] Virtualization\MinVmVersionForCpuBasedMitigation already set correctly to '1.0'.." }
          Foreach ($line in $out) { if ($line) { Write-Host $line -ForegroundColor White } }
          $QIDsSpectreMeltdown = 1
          $RebootRequired = $true
        } else { $QIDsSpectreMeltdown = 1 }
      }
      110414 {
        if (Get-YesNo "$_ Fix Microsoft Outlook Denial of Service (DoS) Vulnerability Security Update August 2022 ? " -Results $Results -QID $ThisQID) { 
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/outlook-x-none_1763a730d8058df2248775ddd907e32694c80f52.cab" -outfile "$($tmp)\outlook-x-none.cab"
          Start-Process -Wait "C:\Windows\System32\expand.exe" -argumentlist "-F:* $($tmp)\outlook-x-none.cab $($tmp)"
          Start-Process -Wait "msiexec.exe" -ArgumentList "/p $($tmp)\outlook-x-none.msp /qn"
          $RebootRequired = $true
        }
      }
      110413 {
        if (Get-YesNo "$_ Fix Microsoft Office Security Update for August 2022? " -Results $Results -QID $ThisQID) { 
          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/msohevi-x-none_a317be1090606cd424132687bc627baffec45292.cab .."
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/msohevi-x-none_a317be1090606cd424132687bc627baffec45292.cab" -outfile "$($tmp)\msohevi-x-none.msp"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\msohevi-x-none.msp $($tmp)"
          Start-Process -Wait "C:\Windows\System32\expand.exe" -ArgumentList "-F:* $($tmp)\msohevi-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\msohevi-x-none.msp"
          Start-Process -Wait "msiexec.exe" -ArgumentList "/p $($tmp)\msohevi-x-none.msp /qn"

          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab .."
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab" -outfile "$($tmp)\excel-x-none.cab"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\excel-x-none.msp $($tmp)"
          Start-Process -Wait "C:\Windows\System32\expand.exe" -ArgumentList "-F:* $($tmp)\excel-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\excel-x-none.msp"
          Start-Process -Wait "msiexec.exe" -ArgumentList "/p $($tmp)\excel-x-none.msp /qn"
          $RebootRequired = $true
        }
      }
      110412 {
        if (Get-YesNo "$_ Fix Microsoft Office Security Update for July 2022? " -Results $Results -QID $ThisQID) { 
          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab .."
          Invoke-WebRequest -UserAgent $AgentString -Uri "http://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2022/06/vbe7-x-none_1b914b1d60119d31176614c2414c0e372756076e.cab" -outfile "$($tmp)\vbe7-x-none.cab"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\vbe7-x-none.msp $($tmp)"
          Start-Process -Wait "C:\Windows\System32\expand.exe" -ArgumentList "-F:* $($tmp)\excel-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\vbe7-x-none.msp"
          Start-Process -Wait "msiexec.exe" -ArgumentList "/p $($tmp)\vbe7-x-none.msp /qn"
          $RebootRequired = $true
        }
      }
      110416 { 
        if (Get-YesNo "$_ Fix Microsoft Office Security Update for Sept 2023? " -Results $Results -QID $ThisQID) { 
          Write-Host "[.] Downloading CAB: https://download.microsoft.com/download/b/3/9/b3928d9f-ef05-4832-ab2b-d99d5628c9c4/mso2013-kb5002477-fullfile-x86-glb.exe .."
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/b/3/9/b3928d9f-ef05-4832-ab2b-d99d5628c9c4/mso2013-kb5002477-fullfile-x86-glb.exe" -outfile "$($tmp)\mso2013-kb5002477.exe"
          #Write-Host "[.] Running installer: : "$($tmp)\mso2013-kb5002477.exe"
          #cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\excel-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\mso2013-kb5002477.exe"
          Start-Process -Wait "msiexec.exe" -ArgumentList "/i $($tmp)\mso2013-kb5002477.exe /qn"
          $RebootRequired = $true
        }       
      }
      92176 {
        if (Get-YesNo "$_ Update Microsoft .NET 3.5 and 4.8 Cumulative Update for Oct 2024? " -Results $Results -QID $ThisQID) { 
          Write-Host "[.] Downloading CABs: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/09/windows10.0-kb5044029-x64-ndp481_7636169b12979c1597e66706e08b6f8557a3fa31.msu"
          Write-Host "[.] Downloading CABs: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/09/windows10.0-kb5044020-x64-ndp48_01927b68990bab8f4b74bfc58e91b0cb2c99f983.msu"
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/09/windows10.0-kb5044029-x64-ndp481_7636169b12979c1597e66706e08b6f8557a3fa31.msu" -outfile "$($tmp)\ndp481.msu"
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/09/windows10.0-kb5044020-x64-ndp48_01927b68990bab8f4b74bfc58e91b0cb2c99f983.msu" -outfile "$($tmp)\ndp48.msu"
          Write-Host "[.] Installing patch: $($tmp)\ndp481.msu"
          Start-Process -Wait "wusa.exe" -ArgumentList "$($tmp)\ndp481.msu /quiet /norestart"
          Write-Host "[.] Installing patch: $($tmp)\ndp48.msu"
          Start-Process -Wait "wusa.exe" -ArgumentList "$($tmp)\ndp48.msu /quiet /norestart"
          $RebootRequired = $true
        }
      }
      91738 {
        if (Get-YesNo "$_  - fix ipv4 source routing bug/ipv6 global reassemblylimit? " -Results $Results -QID $ThisQID) { 
            netsh int ipv4 set global sourceroutingbehavior=drop
            Netsh int ipv6 set global reassemblylimit=0
            $RebootRequired = $true
        }
      }
      375589 {  
        if (Get-YesNo "$_ - Delete Dell DbUtil_2_3.sys ? " -Results $Results -QID $ThisQID) {
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
          $RebootRequired = $true
        }
      }
      100413 {
        if (Get-YesNo "$_ CVE-2017-8529 - IE Feature_Enable_Print_Info_Disclosure fix ? " -Results $Results -QID $ThisQID) {
          New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Force
          Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Name 'iexplore.exe' -Value 1 -Force
        }
        $RebootRequired = $true
      }
      { 91704 -contains $_ } {
        if (Get-YesNo "$_ Microsoft Windows DNS Resolver Addressing Spoofing Vulnerability (ADV200013) fix ? " -Results $Results -QID $ThisQID) {
          $RegPath = "HKLM:\System\CurrentControlSet\Services\DNS\Parameters"
          Write-Host "[.] Making value change for $RegPath - MaximumUdpPacketSize = DWORD 1221"
          New-ItemProperty -Path $RegPath -Name MaximumUdpPacketSize -Value 1221 -PropertyType DWORD -Force -ErrorAction Continue
          Write-Host "[.] Restarting DNS service.."
          Restart-Service DNS -Force -ErrorAction Continue
          Write-Host "[!] Done!"
        } 
      }
      { 105170,105171 -contains $_ } { 
        if (Get-YesNo "$_ - Windows Explorer Autoplay not Disabled ? " -Results $Results -QID $ThisQID) {
          $check = @()
          $check += Check-Reg -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -RegName "NoDriveTypeAutoRun" -RegValue "255" -SettingName "Autoplay - Disabled (for computer)"
          $check += Check-Reg -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -RegName "NoAutoRun" -RegValue "1" -SettingName "Autoplay - Disabled (for computer)"
          $check += Check-Reg -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"  -RegName "NoDriveTypeAutoRun" -RegValue "255" -SettingName "Autoplay - Disabled (for user)"
          $check += Check-Reg -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"  -RegName "NoAutoRun" -RegValue "1" -SettingName "Autoplay - Disabled (for user)"
          if ($check -contains 1) { 
            Write-Host "[!] Making registry changes for [Autoplay - Disabled (for computer)]" -ForegroundColor Yellow
            $HKLMPath = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"
            if (-not (Test-Path $HKLMPath)) {
                New-Item -Path $HKLMPath -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoDriveTypeAutorun" -Value 0xFF -Type DWord -Force
            Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoAutorun" -Value 0x1 -Type DWord -Force
            $HKCUPath = "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"
            if (-not (Test-Path $HKCUPath)) {
                New-Item -Path $HKCUPath -Force | Out-Null
            }
            Set-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoDriveTypeAutorun" -Value 0xFF -Type DWord -Force
            Set-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoAutorun" -Value 0x1 -Type DWord -Force
            $check = @()
            $check += Check-Reg -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -RegName "NoDriveTypeAutoRun" -RegValue "255" -SettingName "Autoplay - Disabled (for computer)"
            $check += Check-Reg -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -RegName "NoAutoRun" -RegValue "1" -SettingName "Autoplay - Disabled (for computer)"
            $check += Check-Reg -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"  -RegName "NoDriveTypeAutoRun" -RegValue "255" -SettingName "Autoplay - Disabled (for user)"
            $check += Check-Reg -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"  -RegName "NoAutoRun" -RegValue "1" -SettingName "Autoplay - Disabled (for user)"
            if (!($check)) {
              Write-Host "[!] Looks like all settings are resolved."  
            }
            $RebootRequired = $true
          } else { 
            Write-Host "[!] Looks like this has already been resolved."
          }
        }
      }
      90044 {
        if (Get-YesNo "$_ - Allowed SMB Null session ? " -Results $Results -QID $ThisQID) {
          $out = @()
          Write-Host "[.] Adding new registry entries for SMB Null session."
          $out += (New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1 -PropertyType DWord -Force).PSPath
          $out += (New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -PropertyType DWord -Force).PSPath
          $out += (New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0 -PropertyType DWord -Force).PSPath
          Foreach ($line in $out) { Write-Host $line }
          $RebootRequired = $true
        }
      }
      90007 {
        if (Get-YesNo "$_ - Enabled Cached Logon Credential ? " -Results $Results -QID $ThisQID) {
           Write-Host "[!] This is problematic at times, ignoring it in all environments for now. " -ForegroundColor Red
# to fix vuln:
#          New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Value '0' -PropertyType String -Force
# to set back to defaults:
#          New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Value '10' -PropertyType String -Force
        }
      }
      90043 {
        if (Get-YesNo "$_ - SMB Signing Disabled / Not required (Both LanManWorkstation and LanManServer)) " -Results $Results -QID $ThisQID) {
          $out = @()
          $out += (New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters' -Name 'EnableSecuritySignature' -Value 1 -PropertyType DWord -Force).PSPath
          $out += (New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -PropertyType DWord -Force).PSPath
          $out += (New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' -Name 'EnableSecuritySignature' -Value 1 -PropertyType DWord -Force).PSPath
          $out += (New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -PropertyType DWord -Force).PSPath
          Foreach ($line in $out) { Write-Verbose $line }
          $RebootRequired = $true
        }
      }
      91805 {
        if (Get-YesNo "$_ - Remove Windows10 UpdateAssistant? " -Results $Results -QID $ThisQID) {
            $Name="UpdateAssistant"
            $Path = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{D5C69738-B486-402E-85AC-2456D98A64E4}"
            $GUID= "{D5C69738-B486-402E-85AC-2456D98A64E4}"
            Write-Host "[.] Checking for product: 'Windows 10 Update Assistant' .." -ForegroundColor Yellow
            #$Products = (get-wmiobject Win32_Product | Where-Object { $_.IdentifyingNumber -like $GUID})
            $Products = Search-Software "Windows 10 Update Assistant" 
            if ($Products) {
              Remove-Software -Products $Products -Results $Results
            } else {
              Write-Host "[!] Software not found: $Products !!`n" -ForegroundColor Red
            } 
            # Try to delete from registry, if it exists
            Remove-RegistryItem $Path
            $RebootRequired = $true
        }
      }
      105943 {
        if (Get-YesNo "$_ Remove Adobe Flash? " -Results $Results -QID $ThisQID) {
          Write-Host "[.] Checking for product: '*Adobe Flash*' .." -ForegroundColor Yellow
          $Products = Search-Software "Adobe Flash" 
          if ($Products) {
            Remove-Software -Products $Products -Results $Results
          } else {
            Write-Host "[!] Software not found: $Products !!`n" -ForegroundColor Red
          } 
          # Try to delete from registry, if it exists
          Remove-RegistryItem $Path
          $RebootRequired = $true
      }
      }
      92194	{
        if (Get-YesNo "$_ Remove Microsoft Visual Studio 2010 Tools for Office? " -Results $Results -QID $ThisQID) {
          Write-Host "[.] Checking for product: '*Microsoft Visual Studio 2010 Tools*' .." -ForegroundColor Yellow
          $Products = Search-Software "Microsoft Visual Studio 2010 Tools for Office" 
          if ($Products) {
            Remove-Software -Products $Products -Results $Results
          } else {
            Write-Host "[!] Software not found: $Products !!`n" -ForegroundColor Red
          } 
          # Try to delete paths from registry, if it still exists
          $Path = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9495AEB4-AB97-39DE-8C42-806EEF75ECA7}"
          Remove-RegistryItem $Path
          $Path = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Visual Studio 2010 Tools for Office Runtime (x64)"
          Remove-RegistryItem $Path
          $RebootRequired = $true
        }
      }
      ###################################################### START OF UPDATERS ################################################
      ####################################################### Installers #######################################
        # Install newest apps via Winget or Ninite, using $UpdateString

      110330 {  
        if (Get-YesNo "$_ - Install Microsoft Office KB4092465? " -Results $Results -QID $ThisQID) {
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/3/6/E/36EF356E-85E4-474B-AA62-80389072081C/mso2007-kb4092465-fullfile-x86-glb.exe" -outfile "$($tmp)\kb4092465.exe"
            Start-Process -Wait "$($tmp)\kb4092465.exe" -ArgumentList "/quiet /passive /norestart"
            $RebootRequired = $true
        }
      }
      372348 {
        if (Get-YesNo "$_ - Install Intel Chipset INF util ? " -Results $Results -QID $ThisQID) {
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://downloadmirror.intel.com/774764/SetupChipset.exe" -OutFile "$($tmp)\setupchipset.exe"
            # https://downloadmirror.intel.com/774764/SetupChipset.exe
            start-process -Wait "$($tmp)\setupchipset.exe" -ArgumentList "-s -accepteula  -norestart -log $($tmp)\intelchipsetinf.log"
            # This doesn't seem to be working, lets just download it and run it for now..
            #cmd /c "$($tmp)\setupchipset.exe -log $($tmp)\intelchipsetinf.log"
            # may be 'Error: this platform is not supported' ..
            $RebootRequired = $true
        }
      }
      372300 {
        if (Get-YesNo "$_ - Install latest Intel RST ? " -Results $Results -QID $ThisQID) {
            #Invoke-WebRequest -UserAgent $AgentString -Uri "https://downloadmirror.intel.com/655256/SetupRST.exe" -OutFile "$($tmp)\setuprst.exe"
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://downloadmirror.intel.com/773229/SetupRST.exe" -OutFile "$($tmp)\setuprst.exe"
            
            start-process -Wait "$($tmp)\setuprst.exe" -ArgumentList " -s -accepteula -norestart -log $($tmp)\intelrstinf.log"
            # OR, extract MSI from this exe and run: 
            # msiexec.exe /q ALLUSERS=2 /m MSIDTJBS /i “RST_x64.msi” REBOOT=ReallySuppress
            $RebootRequired = $true
        }   
      }
      
     
      { ($QIDsGhostScript -contains $_) -or ($VulnDesc -like "*GhostScript*" -and ($QIDsGhostScript -ne 1)) } {
        if (Get-YesNo "$_ Install GhostScript 10.03.1 64bit? " -Results $Results -QID $ThisQID) {
          Write-Host "[.] Searching for old versions of GPL Ghostscript .."
          $Products = Search-Software "*Ghostscript*" 
          if ($Products) {
            if ($Automated) {
              Write-Host "This product CAN NOT be removed automatically anymore with 10.01 and > : You will need to remediate manually!!"
            } else {
              Remove-Software -Products $Products -Results $Results
            }
          } else {
            Write-Host "[!] Ghostscript product not found under 'GPL Ghostscript*' : `n    Products: [ $Products ]`n" -ForegroundColor Red            
          } 
          if ($Automated) {
            Write-Host "This product CAN NOT be installed automatically anymore with 10.01 and > : You will need to remediate manually!!"
          } else {
            Invoke-WebRequest -UserAgent $AgentString -Uri   $ghostscripturl -OutFile "$($tmp)\ghostscript.exe"
            Start-Process -Wait "$($tmp)\ghostscript.exe" -ArgumentList "/S"
            #Delete results file, i.e        "C:\Program Files (x86)\GPLGS\gsdll32.dll found#" as lots of times the installer does not clean this up.. may install the new one in a new location etc
            $path = Split-Path -Path $results
            $sep=" found#"
            $fileName = ((Split-Path -Path $results -Leaf) -split $sep)[0]
            $FileToDelete="$($path)\$($filename)"
            if (Test-Path $FileToDelete) {
              Write-Host "[.] Removing $($FileToDelete) .."
              Remove-Item $FileToDelete -Force
              if (Test-Path $FileToDelete) {
                Write-Output "[x] Could not delete $($FileToDelete), please remove manually!"
              }
            }
          }
        }
        $QIDsGhostScript = 1
      }
      { ($QIDsIntelGraphicsDriver  -contains $_) -or ($VulnDesc -like "*Intel Graphics*" -and ($QIDsIntelGraphicsDriver -ne 1)) } {
        if (Get-YesNo "$_ Install newest Intel Graphics Driver? " -Results $Results -QID $ThisQID) { 
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
        if (Get-YesNo "$_ Install newest Apple iCloud ? " -Results $Results -QID $ThisQID) { 
          Update-Application -Uri "https://ninite.com/icloud/ninite.exe" -Outfile "$($tmp)\NiniteiCloud.exe" -Killprocess "iCloud.exe" -UpdateString "Apple iCloud"
        }
        $QIDsAppleiCloud = 1
      }
      { ($QIDsAppleiTunes -contains $_ ) -or ($VulnDesc -like "*Apple iTunes*" -and ($QIDsAppleiTunes -ne 1))} {
        if (Get-YesNo "$_ Install newest Apple iTunes ? " -Results $Results -QID $ThisQID) { 
          Update-Application -Uri "https://ninite.com/itunes/ninite.exe" -Outfile "$($tmp)\NiniteiTunes.exe" -Killprocess "iTunes.exe" -UpdateString "Apple iTunes"
        }
        $QIDsAppleiTunes = 1
      }
      { ($QIDsChrome -contains $_) -or ($VulnDesc -like "*Google Chrome*" -and ($QIDsChrome -ne 1))} {
        if (Get-YesNo "$_ Check if Google Chrome is up to date? " -Results $Results -QID $ThisQID) { 
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
              if ([version]$ChromeFileVersion -lt [version]$VulnDescChromeWinVersion) {  # Fixed bug 3-28-24 - logic above is 'Prior to version' not 'Prior to or equals version'!! vuln desc is 'prior to version ...'
                Write-Host "[!] Vulnerable version $ChromeFile found : $ChromeFileVersion < $VulnDescChromeWinVersion - Updating.." -ForegroundColor Red
                Update-Chrome
                #Post-update check
                $ChromeFileVersion = Get-ChromeVersion
                if ($ChromeFileVersion) {
                  if ([version]$ChromeFileVersion -lt [version]$VulnDescChromeWinVersion) { 
                    Write-Host "[.] Post-update check: Chrome version found : $ChromeFileVersion <= $VulnDescChromeWinVersion - Needs attention still!" -ForegroundColor Red
                  } else {
                    Write-Host "[.] Post-update check: Chrome version found : $ChromeFileVersion > $VulnDescChromeWinVersion - Good!" -ForegroundColor Green
                  }
                } else {
                  Write-Host "[.] Post-update check: Chrome file missing, probably good if its been updated." -ForegroundColor Yellow
                }
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
        if (Get-YesNo "$_ Check if Microsoft Edge is up to date? " -Results $Results -QID $ThisQID) { 
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
        if (Get-YesNo "$_ Install newest Firefox? " -Results $Results -QID $ThisQID) { 
            #  Firefox - https://ninite.com/firefox/ninite.exe
            Update-Firefox
            $ResultsFolder = Parse-ResultsFolder $Results
            if ($ResultsFolder -like "*AppData*") {
              Remove-Folder $ResultsFolder
            }          
            $QIDsFirefox = 1
        } else { $QIDsFirefox = 1 }
      }      
      { ($QIDsIrfanView -contains $_) -or ($VulnDesc -like "*IrfanView*" -and ($QIDsIrfanView -ne 1)) } {
        if (Get-YesNo "$_ Install newest IrfanView? " -Results $Results -QID $ThisQID) { 
            $IrfanviewUrl = "https://ninite.com/irfanview/ninite.exe"
            Update-Application -Uri $IrfanviewUrl -Outfile "NiniteIrfanview.exe" -Killprocess "Irfanview.exe" -UpdateString "Irfanview"
        }
        $QIDsIrfanView = 1
      }      
      { ($QIDsNotepadPP -contains $_) -or ($VulnDesc -like "Notepad++*" -and ($QIDsNotepadPP -ne 1)) } {
        if (Get-YesNo "$_ Install newest Notepad++? " -Results $Results -QID $ThisQID) { 
            $NotepadPPurl = "https://ninite.com/notepadplusplus/ninite.exe"
            Update-Application -Uri $NotepadPPUrl -Outfile "NiniteNotepadPP.exe" -Killprocess "notepad++.exe" -UpdateString "Notepad++"
            $QIDsNotepadPP = 1
        } else { $QIDsNotepadPP = 1 }
      }

      { ($QIDsZoom -contains $_) -or ($VulnDesc -like "*Zoom*" -and ($QIDsZoom -ne 1)) } {
        if (Get-YesNo "$_ Install newest Zoom Client? " -Results $Results -QID $ThisQID) { 
            Update-Application "https://ninite.com/zoom/ninite.exe" -OutFile "$($tmp)\ninite.exe" -KillProcess 'ninite.exe' -UpdateString "Zoom client"

            #If Zoom folder is in another users AppData\Local folder, this will not work
            $FolderFound = $false
            foreach ($Result in $Results) {
              if ($Result -like "*AppData*") {
                $FolderFound = $true
              }
            }
            if ($FolderFound) { Remove-Folder (Parse-ResultsFolder -Results $Results) }
            Show-FileVersionComparison -Name "Zoom" -Results $Results
            Check-MultipleVersionsInstalled -Name "Zoom" -Results $Results
            $QIDsZoom = 1
        } else { $QIDsZoom = 1 }
      }
      { ($QIDsPutty -contains $_) -or ($VulnDesc -like "*Putty*" -and ($QIDsPutty -ne 1)) } {
      #379655	Putty (Pageant) Secret Keys Disclosure Vulnerability (CVE-2024-31497)
      #379295	Putty Terrapin Attack SSH Connection Weakening Vulnerability
        if (Get-YesNo "$_ Install newest Putty? " -Results $Results -QID $ThisQID) { 
            #  Teamviewer - https://ninite.com/teamviewer15/ninite.exe
            Update-Application -Uri "https://ninite.com/putty/ninite.exe" -OutFile "$($tmp)\ninite.exe" -KillProcess "putty.exe" -UpdateString "Putty"
            $QIDsPutty = 1
        } else { $QIDsPutty = 1 }
      }

      { ($QIDsTeamViewer -contains $_) -or ($VulnDesc -like "*TeamViewer*" -and ($QIDsTeamViewer -ne 1)) } {
        if (Get-YesNo "$_ Install newest Teamviewer? " -Results $Results -QID $ThisQID) { 
            #  Teamviewer - https://ninite.com/teamviewer15/ninite.exe
            Update-Application -Uri "https://ninite.com/teamviewer15/ninite.exe" -OutFile "$($tmp)\ninite.exe" -KillProcess "TeamViewer.exe" -UpdateString "TeamViewer 15"
            if (!(Search-Software "TeamViewer")) {
              if (Get-YesNo "$_ Teamviewer appears to not be installed, should we remove the old Teamviewer registry entry?" -Results $Results -QID $ThisQID) {
                $registryPath = 'HKLM:\SOFTWARE\TeamViewer'
                $backupFolder = 'C:\Program Files\MQRA\backup'
                $backupFile = Join-Path $backupFolder 'TeamViewerRegistryBackup.reg'
                if (!(Test-Path -Path $backupFolder)) {
                    New-Item -ItemType Directory -Path $backupFolder -Force
                }
                reg export "HKLM\SOFTWARE\TeamViewer" $backupFile /y
                Remove-Item -Path $registryPath -Recurse -Force
              }
            }
            $QIDsTeamViewer = 1
        } else { $QIDsTeamViewer = 1 }
      }
      { ($QIDsDropbox -contains $_) -or ($VulnDesc -like "*Dropbox*" -and ($QIDsDropbox -ne 1)) } {
        if (Get-YesNo "$_ Install newest Dropbox? " -Results $Results -QID $ThisQID) { 
            #  Dropbox - https://ninite.com/dropbox/ninite.exe
            Update-Application -Uri "https://ninite.com/dropbox/ninite.exe" -OutFile "$($tmp)\dropboxninite.exe" -KillProcess "Dropbox.exe" -UpdateString "Dropbox"
            $QIDsDropbox = 1
        } else { $QIDsDropbox = 1 }
      }
      { ($VulnDesc -like "*VLC*" -and ($QIDsVLC -ne 1)) } {
        if (Get-YesNo "$_ Install newest VLC? " -Results $Results -QID $ThisQID) { 
          #Remove any existing file before downloading..
          Update-Application -Uri "https://ninite.com/vlc/ninite.exe" -OutFile "$($tmp)\vlcninite.exe" -KillProcess "vlc.exe"  -Updatestring "VLC" 
        }
        $QIDsVLC = 1 # Whether updated or not, don't ask again.
      }
      $QIDs7zip {
        if (Get-YesNo "$_ Install newest 7-Zip? " -Results $Results -QID $ThisQID) { 
          Update-Application -Uri "https://ninite.com/7-zip/ninite.exe" -OutFile "$($tmp)\7zninite.exe" -KillProcess "7zfm.exe"  -Updatestring "7-Zip" 
        }
        $QIDs7zip = 1
      }
      $QIDsVSCode {
        if (Get-YesNo "$_ Install newest Microsoft Visual Studio Code update? " -Results $Results -QID $ThisQID) {  
          Update-Application -Uri "https://ninite.com/vscode/ninite.exe" -OutFile "$($tmp)\vscninite.exe" -KillProcess "code.exe"  -Updatestring "Visual Studio Code" 
        }
        $QIDsVSCode = 1
      }
        ############################
        # Others: (non-ninite)
  
      { ($QIDsOracleJava -contains $_) -or ($VulnDesc -like "*Oracle Java*" -and ($QIDsOracleJava -ne 1))} {
        if (Get-YesNo "$_ Check Oracle Java for updates? " -Results $Results -QID $ThisQID) { 
            #  Oracle Java 17 - https://download.oracle.com/java/17/latest/jdk-17_windows-x64_bin.msi
            #wget "https://download.oracle.com/java/18/latest/jdk-18_windows-x64_bin.msi" -OutFile "$($tmp)\java17.msi"
            #msiexec /i "$($tmp)\java18.msi" /qn /quiet /norestart
            . "c:\Program Files (x86)\Common Files\Java\Java Update\jucheck.exe"
            # "C:\Program Files (x86)\Java\jre1.8.0_151" 
            $SoftwareInstalling.Add("Java")
        }
        $QIDsOracleJava = 1
      }
      { ($QIDsAdoptOpenJDK -contains $_) -or ($VulnDesc -like "*Adopt OpenJDK*") } {
        if (Get-YesNo "$_ Install newest Adopt Java JDK? " -Results $Results -QID $ThisQID) { 
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://ninite.com/adoptjavax8/ninite.exe" -OutFile "$($tmp)\ninitejava8x64.exe"
            cmd /c "$($tmp)\ninitejava8x64.exe"
        }
        $QIDsAdoptOpenJDK = 1
      }
      { ($QIDsVirtualBox -contains $_) -or ($VulnDesc -like "*VirtualBox*" -and ($QIDsVirtualBox -ne 1)) } {
        if (Get-YesNo "$_ Install newest VirtualBox 6.1.36? " -Results $Results -QID $ThisQID) { 
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.virtualbox.org/virtualbox/6.1.36/VirtualBox-6.1.36-152435-Win.exe" -OutFile "$($tmp)\virtualbox.exe"
            cmd /c "$($tmp)\virtualbox.exe"    
        } 
        $QIDsVirtualBox = 1
      }
      { ($QIDsDellCommandUpdate -contains $_) -or ($VulnDesc -like "*Dell Command Update*" -and ($QIDsDellCommandUpdate -ne 1))} {
        if (Get-YesNo "$_ Install newest Dell Command Update? " -Results $Results -QID $ThisQID) { 
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
              if ($Products) {  $InstalledYet = $true  }
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
        }
        $QIDsDellCommandUpdate  = 1
      }
      { ($QIDsAdobeReader -contains $_) -or ($VulnDesc -like "*Adobe Reader*" -and ($QIDsAdobeReader -ne 1)) } {
        if ((!($Automated)) -or ($Automated -and ($AutoUpdateAdobeReader))) {  
          if (Get-YesNo "$_ Remove older versions of Adobe Reader ? " -Results $Results -QID $ThisQID) { 
            $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'Adobe Reader*'})
            if ($Products) {
              Write-Host "[.] Products found matching *Adobe Reader* : "
              $Products
              Remove-Software -Products $Products -Results $Results
            } else {
              Write-Host "[!] Adobe products not found under 'Adobe Reader*' : `n    $Products !!`n" -ForegroundColor Red
            }  
          }
          if (Get-YesNo "$_ Install newest Adobe Reader DC ? " -Results $Results -QID $ThisQID) {
            Get-NewestAdobeReader
            #cmd /c "$($tmp)\readerdc.exe"
            $Outfile = "$($tmp)\readerdc.exe"
            # silent install
            Start-Process -FilePath $Outfile -ArgumentList "/sAll /rs /rps /msi /norestart /quiet EULA_ACCEPT=YES" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
          }
          $QIDsAdobeReader = 1
        } else {
          Write-Host "[!] Skipping Adobe Reader vulns for automated, not sure if I should remove old and install newest Reader DC etc."
        }
      }
      { $QIDsMicrosoftSilverlight -contains $_ -or ($VulnDesc -like "*Silverlight*" -and ($QIDsMicrosoftSilverlight -ne 1))} {
        if (Get-YesNo "$_ Remove Microsoft Silverlight ? " -Results $Results -QID $ThisQID) {
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
        if (Get-YesNo "$_ Remove MS SQL Server Compact 4 ? "  -Results $Results -QID $ThisQID) {
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
        if (Get-YesNo "$_ Remove MicrosoftAccessDBEngine ? " -Results $Results -QID $ThisQID) {
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
        if (Get-YesNo "$_ $_ Install Microsoft Visual C++ 2005/8 Service Pack 1 Redistributable Package MFC Security Update? " -Results $Results -QID $ThisQID) { 
          $Installed=get-wmiobject -class Win32_Product | Where-Object{ $_.Name -like '*Microsoft Visual*'} # | Format-Table IdentifyingNumber, Name, LocalPackage -AutoSize
          if ($Installed | Where-Object {$_.IdentifyingNumber -like '{9A25302D-30C0-39D9-BD6F-21E6EC160475}'}) { 
              Write-Host "[!] Found Microsoft Visual C++ 2008 Redistributable - x86 "
              $notfound = $false
              Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe" -OutFile "$($tmp)\vcredist2008x86.exe"
              cmd /c "$($tmp)\vcredist2008x86.exe /install /passive /quiet /norestart"
              $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | Where-Object { $_.IdentifyingNumber -like '{837b34e3-7c30-493c-8f6a-2b0f04e2912c}'}) {
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable"
            $notfound = $false
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -OutFile "$($tmp)\vcredist2005.exe"
            cmd /c "$($tmp)\vcredist2005.exe  /install /passive /quiet /norestart"
            $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | Where-Object { $_.IdentifyingNumber -like '{710f4c1c-cc18-4c49-8cbf-51240c89a1a2}'}) {
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable - x86"
            $notfound = $false
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -OutFile "$($tmp)\vcredist2005x86.exe"
            cmd /c "$($tmp)\vcredist2005x86.exe  /install /passive /quiet /norestart"
            $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | Where-Object { $_.IdentifyingNumber -like '{6E8E85E8-CE4B-4FF5-91F7-04999C9FAE6A}'}) { #x64
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable - x64 "
            $notfound = $false
            Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" -OutFile "$($tmp)\vcredist2005x64.exe"
            cmd /c "$($tmp)\vcredist2005x64.exe  /install /passive /quiet /norestart"  # /q
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
      { $QIDsMSTeams -contains $_ } {
        if (Get-YesNo "$_ Install latest MS Teams ? " -Results $Results -QID $ThisQID) {
          $TeamsURL=(Invoke-WebRequest "https://teams.microsoft.com/desktopclient/installer/windows/x64").Content
          Invoke-WebRequest $TeamsURL -OutFile "$($tmp)/teams.exe"
          . "$($tmp)/teams.exe"
          Write-Host ""
          Start-Sleep 10
          $CheckEXEs = Check-ResultsForFiles -Results $Results
          foreach ($CheckEXE in $CheckEXEs) {  # could return multiple results!
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
        $QIDsMSTeams = 1
      }
      106233 {
        if (Get-YesNo "$_ Remove .NET Core 7 " -Results $Results -QID $ThisQID) { 
          Write-Host "[.] Checking for product: '.NET Core 7' .." -ForegroundColor Yellow
          try {
            $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like '*.NET Core 7*'})
          } catch {
            Write-Host "[!] Error running command: '$Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like '*.NET Core 7*' })'" -ForegroundColor Red
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

      { $QIDsMicrosoftNETCoreV5 -contains $_ } {
        if (Get-YesNo "$_ Remove .NET Core 5 (EOL) " -Results $Results -QID $ThisQID) { 
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
      { ($QIDsNVIDIA -contains $_) -or ($VulnDesc -like "*NVIDIA*" -and ($QIDsNVidia -ne 1)) } {
        if (Get-YesNo "$_ Install newest NVidia drivers ? " -Results $Results -QID $ThisQID) { 
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
      { $MicrosoftODBCOLEDB -contains $_ } {
        if (Get-YesNo "$_ Fix Microsoft SQL Server, ODBC and OLE DB Driver for SQL Server Multiple Vulnerabilities ? " -Results $Results -QID $ThisQID) { 
          # %SYSTEMROOT%\System32\msoledbsql19.dll  Version is  19.3.1.0  %SYSTEMROOT%\SysWOW64\msoledbsql19.dll  Version is  19.3.1.0#
          # %SYSTEMROOT%\System32\msodbcsql18.dll  Version is  18.3.1.1  %SYSTEMROOT%\SysWOW64\msodbcsql18.dll  Version is  18.3.1.1#
          
          # 05-02-24
          # 379596	Microsoft SQL Server ODBC and OLE DB Driver for SQL Server Multiple Vulnerabilities for April 2024	
          <#   Affected Software:  Microsoft ODBC Driver 17 for SQL Server on Windows version prior to 17.10.6.1  
               Microsoft ODBC Driver 18 for SQL Server on Windows version prior to 18.3.3.1  
               Microsoft ODBC Driver 17 for SQL Server on Linux version prior to 17.10.6.1  
               Microsoft ODBC Driver 18 for SQL Server on Linux version prior to 18.3.3.1  
               Microsoft SQL Server 2022 for x64-based Systems (GDR)   
               Microsoft SQL Server 2019 for x64-based Systems (GDR)   
               Microsoft SQL Server 2022 for x64-based Systems ( (CU 12))   
               Microsoft SQL Server 2019 for x64-based Systems (CU 25)   
               Microsoft OLE DB Driver 19 for SQL Server version prior to 19.3.3.0  
               Microsoft OLE DB Driver 18 for SQL Server version prior to 18.7.2.0  #>
          #   %SYSTEMROOT%\System32\msoledbsql.dll  Version is  18.6.7.0  %SYSTEMROOT%\SysWOW64\msoledbsql.dll  Version is  18.6.7.0#
          # New version: Microsoft OLE DB Driver 18 for SQL Server version prior to 18.7.2.0
          # x86 installer: https://go.microsoft.com/fwlink/?linkid=2266858  https://download.microsoft.com/download/2/6/1/2613c841-cf12-4ba3-b0f8-50dcc195faa4/en-US/18.7.2.0/x86/msoledbsql.msi
          # x64 installer: https://go.microsoft.com/fwlink/?linkid=2266757  https://download.microsoft.com/download/2/6/1/2613c841-cf12-4ba3-b0f8-50dcc195faa4/en-US/18.7.2.0/x64/msoledbsql.msi
          
          # 8/15/24 - these just keep coming..
          # %SYSTEMROOT%\System32\msoledbsql19.dll  Version is  19.3.2.0  %SYSTEMROOT%\SysWOW64\msoledbsql19.dll  Version is  19.3.2.0#
          # 19.3.5.0 OLE DB x64 download : https://go.microsoft.com/fwlink/?linkid=2278038
          # Added OLE DB vars

# 12-6-2024
#          %SYSTEMROOT%\System32\msoledbsql.dll  Version is  18.7.2.0  %SYSTEMROOT%\SysWOW64\msoledbsql.dll  Version is  18.7.2.0#	Customers are advised to refer to  CVE-2024-37320 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37320), CVE-2024-20701 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-20701), CVE-2024-21317 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21317), CVE-2024-21331 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21331), CVE-2024-21425 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21425), CVE-2024-37319 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37319), CVE-2024-35272 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-35272), CVE-2024-35271 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-35271), CVE-2024-38087 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-38087), CVE-2024-21303 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21303), CVE-2024-37321 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37321), CVE-2024-21428 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21428), CVE-2024-21415 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21415), CVE-2024-37324 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37324), CVE-2024-21449 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21449), CVE-2024-37326 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37326), CVE-2024-37327 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37327), CVE-2024-37328 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37328), CVE-2024-37329 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37329), CVE-2024-37330 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37330), CVE-2024-37334 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37334), CVE-2024-37333 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37333), CVE-2024-37336 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37336), CVE-2024-28928 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-28928), CVE-2024-35256 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-35256), CVE-2024-38088 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-38088), CVE-2024-37322 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37322), CVE-2024-21332 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21332) for more information regarding the vulnerabilities and their patches.  Patch:  Following are links for downloading patches to fix the vulnerabilities:   CVE-2024-37320 (https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-37320)

# 03-24-2025 - 18.7.4 is newest: https://download.microsoft.com/download/2/6/1/2613c841-cf12-4ba3-b0f8-50dcc195faa4/en-US/18.7.4.0/x64/msoledbsql.msi

          if ($Results -like "*oledbsql*" -and $Results -like "*19*") { $OLEODBCUrl="https://download.microsoft.com/download/f/1/3/f13ce329-0835-44e7-b110-44decd29b0ad/en-US/19.3.5.0/x64/msoledbsql.msi"; $LicenseTerms="IACCEPTMSOLEDBSQLLICENSETERMS=YES"; $OLEODBC="19.3.5 OLE"; $ProductCheck = "Microsoft OLE DB Driver" } else { #19.3.2 OLE
            if ($Results -like "*oledbsql*" -and $Results -like "*18*") { $OLEODBCUrl="https://download.microsoft.com/download/2/6/1/2613c841-cf12-4ba3-b0f8-50dcc195faa4/en-US/18.7.4.0/x64/msoledbsql.msi"; $LicenseTerms="IACCEPTMSOLEDBSQLLICENSETERMS=YES"; $OLEODBC="18.7.4 OLE"; $ProductCheck = "Microsoft OLE DB Driver"  } else { #18.7.4 OLE
              if ($Results -like "*odbcsql*") { $OLEODBCUrl="https://go.microsoft.com/fwlink/?linkid=2266640"; $LicenseTerms="IACCEPTMSODBCDBSQLLICENSETERMS=YES"; $OLEODBC="18.3.3.1 ODBC"; $ProductCheck = "Microsoft ODBC DB Driver" } else { #18.3.3.1 ODBC
                $OLEODBCUrl="NOPE"
              }
            }
          }

          $RemovalAfter = $false
          $AlreadyPatched = $false
          $ResultsVersion = Check-ResultsForVersion -Results $Results  # split everything after space, [version] cannot have a space in it.. Also should work for multiple versions, we will just check the first result.
          Write-Verbose "ResultsVersion : $ResultsVersion"
          $CheckFile = Check-ResultsForFile -Results $Results # Get SINGLE EXE/DLL FileNames to check, from $Results  (Changed from multiple 5/2/24)
          Write-Host "[.] Checking File: $CheckFile"
          if (Test-Path $CheckFile) {
            $CheckFileVersion = Get-FileVersion $CheckFile
            Write-Verbose "Get-FileVersion results: $CheckFileVersion"
            if ($CheckFileVersion) {
              Write-Verbose "EXE/DLL version found : $CheckFile - $CheckFileVersion .. checking against -- $ResultsVersion --"
              if ([version]$CheckFileVersion -le [version]$ResultsVersion) {
                Write-Host "[!] Vulnerable version of $CheckFile found : $CheckFileVersion <= $ResultsVersion - Update missing: $ResultsMissing" -ForegroundColor Red
                $RemovalAfter = $true
              } else {
                Write-Host "[+] EXE/DLL patched version found : $CheckFileVersion > $ResultsVersion - already patched." -ForegroundColor Green  
                $AlreadyPatched = $true
              }
            } else {
              Write-Host "[-] EXE/DLL Version not found, for $CheckFile .." -ForegroundColor Yellow
            }
          } else {
            Write-Host "[!] EXE/DLL no longer found: $CheckFile - likely its already been updated. Let's check.."
          }

          if ($OLEODBCUrl -eq 'NOPE') {
            Write-Host "[!] Something went wrong.. Results could not be parsed for oledbsql or odbcsql !!"
            Write-Host "Results = [ $Results ]"
          } else {
            if (-not $AlreadyPatched) {
              Update-VCPP14 -arch "both" # Update the VCPP 17 x86 and x64 to newest, unfortunately this may still ask to reboot..

              Write-Host "[.] Downloading msoleodbcsql.msi from $OLEODBCUrl for $OLEODBC.."
              Invoke-WebRequest $OLEODBCUrl -OutFile "$($tmp)\msoleodbcsql.msi"
              $params = '/quiet','/qn','/norestart',"$licenseterms"
              Write-Host "[.] Running: $($tmp)\msoleodbcsql.msi , params:"
              Write-Host @params 
              . cmd.exe /c "$($tmp)\msoleodbcsql.msi" @params 
              Write-Host "[.] Waiting $SoftwareInstallWait seconds for installation to complete.."
              Start-Sleep $SoftwareInstallWait
              # Check for installation, 
              # If not, check for reason in get-winevent 
              if ($RemovalAfter) {
                $Products = Get-Products $ProductCheck
                if ($Products) {
                  foreach ($Product in $Products) {
                    if ($Product.Version -lt [version]($OLEODBC -split " ")[0]) {
                      Write-Host "[!] Removal of old version needed: $($Product.Version)" -ForegroundColor Red
                      Remove-Software -Products $Product
                      Write-Host "[!] Removal complete."
                    }
                  }
                }
              }
              Write-Host "[.] Please make sure this is installed properly, and old, vulnerable versions are removed, opening appwiz.cpl:"
              . appwiz.cpl
            } else {
              Write-Verbose "Already patched.. moving on."
            }
          }
        }
        $MicrosoftODBCOLEDB = 1
      }   

      ###################################################### END OF UPDATERS ################################################

      { 106069 -eq $_ } {
        if (Get-YesNo "$_ Remove EOL/Obsolete Software: Microsoft Access Database Engine 2010 Service Pack 2 ? " -Results $Results -QID $ThisQID) { 
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
      91304 {  # Microsoft Security Update for SQL Server (MS16-136)
        $inst = (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -ErrorAction SilentlyContinue).InstalledInstances
        foreach ($i in $inst)
        {
          $p = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL').$i
          $SQLVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Version
          $SQLEdition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Edition
        }  # Version lists: https://sqlserverbuilds.blogspot.com/

        if (Get-YesNo "$_ Install SQL Server $SQLVersion $SQLEdition update? " -Results $Results -QID $ThisQID) { 
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
      376609 {
        if (Get-YesNo "$_ Delete nvcpl.dll for NVIDIA GPU Display Driver Multiple Vulnerabilities (May 2022) ? " -Results $Results -QID $ThisQID) { 
          Remove-File "C:\Windows\System32\nvcpl.dll" -Results $Results
        }
      }    
      370468 {
        if (Get-YesNo "$_ Remove Cisco WebEx ? "  -Results $Results -QID $ThisQID) {
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
        if (Get-YesNo "$_ Install reg key for Microsoft SQL Server sqldmo.dll ActiveX Buffer Overflow Vulnerability - Zero Day (CVE-2007-4814)? " -Results $Results -QID $ThisQID) { 
          # Set: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{10020200-E260-11CF-AE68-00AA004A34D5}  Compatibility Flags 0x400
          New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility" -Name "{10020200-E260-11CF-AE68-00AA004A34D5}"
          New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{10020200-E260-11CF-AE68-00AA004A34D5}" -Name "Compatibility Flags" -Value 0x400
        }
      }
	
      100269 {
        if (Get-YesNo "$_ Install reg keys for Microsoft Internet Explorer Cumulative Security Update (MS15-124)? " -Results $Results -QID $ThisQID) { 
          New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
          New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Name "iexplore.exe" -Value 1
          New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
          New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Name "iexplore.exe" -Value 1
        } 
      }
      90954 {
        if (Get-YesNo "$_ Install reg key for 2012 Windows Update For Credentials Protection and Management (Microsoft Security Advisory 2871997) (WDigest plaintext remediation)? " -Results $Results -QID $ThisQID) { 
          New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
        }
      }
      92053 {
        if (Get-YesNo "$_ Delete Microsoft Windows Defender Elevation of Privilege Vulnerability for August 2023? " -Results $Results -QID $ThisQID) { 
          Write-Host "Active antivirus: $((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).DisplayName -join(" & "))"
          Remove-File "C:\WINDOWS\System32\MpSigStub.exe" -Results $Results
        }
      }      
      91621 {
        if (Get-YesNo "$_ Delete Microsoft Defender Elevation of Privilege Vulnerability April 2020? " -Results $Results -QID $ThisQID) { 
          # This will ask twice due to Remove-File, but I want to offer results first. Could technically add -Results to Remove-File..
          Write-Host "Active antivirus: $((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).DisplayName -join(" & "))"
          Remove-File "C:\WINDOWS\System32\MpSigStub.exe" -Results $Results
        }
      }
      91649 {
        if (Get-YesNo "$_ Delete Microsoft Defender Elevation of Privilege Vulnerability June 2020? " -Results $Results -QID $ThisQID) { 
          Write-Host "Active antivirus: $((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).DisplayName -join(" & "))"
          Remove-File "$($env:ProgramFiles)\Windows Defender\MpCmdRun.exe" -Results $Results
        }
      }
      91972 {
        if (Get-YesNo "$_ Delete Microsoft Windows Malicious Software Removal Tool Security Update for January 2023? " -Results $Results -QID $ThisQID) { 
          Remove-File "$($env:windir)\system32\MRT.exe" -Results $Results
        }
      }
      92183 { 
        if (Get-YesNo "$_ Microsoft Visual C++ [14] Redistributable Installer Elevation of Privilege Vulnerability "  -Results $Results -QID $ThisQID) {
          Update-VCPP14 -arch "both"  # Update for x86 and x64
        }
      }
      105803 {
        if (Get-YesNo "$_ Remove EOL/Obsolete Software: Adobe Shockwave Player 12 ? " -Results $Results -QID $ThisQID) { 
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'Adobe Shockwave*'})
          if ($Products) {
              Remove-Software -Products $Products  -Results $Results
          } else {
            Write-Host "[!] Product not found: 'Adobe Shockwave*' !!`n" -ForegroundColor Red
          }    
        }
      }
      106105 {
        if (Get-YesNo "$_ Remove EOL/Obsolete Software: Microsoft .Net Core Version 3.1 Detected? " -Results $Results -QID $ThisQID) { 
          Remove-Folder "$($env:programfiles)\dotnet\shared\Microsoft.NETCore.App\3.1.32" -Results $Results   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-NETCore3_removal.log"
          $RebootRequired = $true
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-NETCore3_removal.log"
        }
      }
      378332 {
        if (Get-YesNo "$_ Fix WinVerifyTrust Signature Validation Vulnerability? " -Results $Results -QID $ThisQID) { 
          Write-Output "[.] Creating registry item: HKLM:\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck=1"   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-WinVerifyTrust.log"
          New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust" -Force -ErrorAction Continue   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-WinVerifyTrust.log"
          New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Force -ErrorAction Continue   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-WinVerifyTrust.log"
          New-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value "1" -PropertyType "String" -Force -ErrorAction Continue   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-WinVerifyTrust.log"
          
          Write-Output "[.] Creating registry item: HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck=1"   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-WinVerifyTrust.log"
          New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust" -Force -ErrorAction Continue | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-WinVerifyTrust.log"
          New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force -ErrorAction Continue  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-WinVerifyTrust.log"
          New-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value "1" -PropertyType "String" -Force | Out-Null    
          Write-Output "[!] Done!"
          $RebootRequired = $true
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-WinVerifyTrust.log"
        }
      }
      378936 {
        if (Get-YesNo "$_ Fix Microsoft Windows Curl Multiple Security Vulnerabilities? " -Results $Results -QID $ThisQID) { 
          Write-Host "[.] Showing Curl.exe version comparison.."  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-Curl.log"
          $curlfile = "c:\windows\system32\curl.exe"
          Show-FileVersionComparison -Name $curlfile -Results $Results  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-Curl.log"
          $KB5032189_installed = Get-WuaHistory | Where-Object { $_.Title -like "*5032189*" } 
          if ($KB5032189_installed) {
            Write-Host "[+] KB5032189 found already installed. This is fixed."  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-Curl.log"
          } else {
            Write-Host "[-] KB5032189 not found installed. Showing all Windows update history:"  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-Curl.log"
            Get-WuaHistory | Format-Table
            Write-Host "[.] Opening MSRC page: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38545#securityUpdates" | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-Curl.log"
            if (-not $Automated) { explorer "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38545#securityUpdates" }
          }
          #$RebootRequired = $true
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-Curl.log"
        }
      }
  
      379223 { # Windows SMB Version 1 (SMBv1) Detected -- https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server
        if (Get-YesNo "$_ Windows SMB Version 1 (SMBv1) Detected - Disable " -Results $Results -QID $ThisQID) { 
          Write-Host "[.] Get-SMBServerConfiguration status:" -ForegroundColor Yellow | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
          $SMB1ServerStatus = (Get-SmbServerConfiguration | Format-List EnableSMB1Protocol)
          (($SMB1ServerStatus | Out-String) -Replace("`n","")) | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
          Write-Host "[.] Checking Registry for MME SMB1Auditing :" | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
          if (Get-RegistryEntry -Name "SMB1Auditing" -ne 1) {  # If our registry key is not set, turn on auditing for a month to see if its in use and dont do anything else yet (but give the option to if they want)
            Write-Host "[+] It appears we have not checked for SMB1 access here. Setting registry setting, enabling auditing for a month." -ForegroundColor Red | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
            (Set-SmbServerConfiguration -AuditSmb1Access $True -Force | Out-String) -Replace ("`n","")
            Set-RegistryEntry -Name "SMB1Auditing" -Value 1 | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
            Write-Host "[.] However, we will give you a chance to disable it now, if you prefer:" -ForegroundColor Yellow | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
          } else {  # If registry key IS set, we ran this last month or more, lets check logs for event 3000 and report
            # Would be really nice to know the last run date here also, for how many days back to check for these events, we'll just do 30 days for now
            $smb1AccessEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SMBServer/Audit'; ID=3000; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue
            if ($smb1AccessEvents) { # we need to know the 3000 event 'Client Address' in it, and report this IP/hostname, move recursively thru the list for each address using SMB1
              Write-Host "[-] Found evidence of SMB1 client access in the event log:" -ForegroundColor Red | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
              foreach ($thisevent in $smb1AccessEvents) {  
                  $eventMessage = $thisevent.Message
                  $pattern = "Client Address: (.*)" 
                  $match = [regex]::Match($eventMessage, $pattern)
                  if ($match.Success) {
                      $clientIP = $match.Groups[1].Value # Capture only the group, not the entire match
                      Write-Host "[-] Client IP Address: $clientIP" -ForegroundColor Red | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
                  }
              }
              $smb1AccessEvent | Format-List
            } else {
              Write-Host "[+] No evidence of SMB1 client access found in event logs. Safe to disable completely, and disable the check next month." -ForegroundColor Green | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
              Set-RegistryEntry -Name SMB1Auditing -Value 0 | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
            }
          } # No matter what, we will give them the option to just run this
          if (-not $script:Automated) {
            if (Get-YesNo "NOTE: If you go further, disabling SMB1 may break things!!! `n`nRisks:`n  [ ] Old iCAT XP computers `n  [ ] Old copier/scanners (scan to SMB) `n  [ ] Other devices that need to access this computer over SMB1.`n`nAre you sure you want to continue " -Results $Results -QID $ThisQID) {  
              # Write-Host "It may be safest to do some monitoring first, by turning on SMB v1 auditing (Set-SmbServerConfiguration -AuditSmb1Access `$True) and checking for Event 3000 in the ""Microsoft-Windows-SMBServer\Audit"" event log next month, and then identifying each client that attempts to connect with SMBv1."
              # Write-Host "I have turned on SMB1 auditing for you now, and the script can automatically check for clients next month and disable this if you aren't sure."
              Write-Host "`n[.] Removing Feature for SMB 1.0:" -ForegroundColor Green | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
              # CAPTION INSTALLSTATE NAME SMB 1.0/CIFS File Sharing Support SMB Server version 1 is Enabled# 
              Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
              # HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10 Start = 2 SMB Client version 1 is Enabled#  # <-- This could show up also
              Write-Host "[.] Disabling service MRXSMB10:" -ForegroundColor Green | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
              if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10")) {
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force -ErrorAction Continue | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
                $RebootRequired = $true
    
              }
              Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -ErrorAction Continue | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
              Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start"  -ErrorAction Continue | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
              Write-Host "[.] Done.  A reboot will be needed for this to go into effect. Please test all applications and access after!" -ForegroundColor Yellow | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
              $RebootRequired = $true
            } else {
              Write-Host "[!] Nothing changed! Please re-run in a month and check back if any systems have used SMB1 to access this machine." -ForegroundColor Green | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
            }
          } else {
              Write-Host "[.] Refusing to remove feature for SMB 1.0 with -Automated, if you want to do this we can modify the code to allow it" -ForegroundColor Yellow | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-SMB1Disable.log"
          }  
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-SMB1Disable.log"
        }
      }
      110251 {
        # 110251 Microsoft Office Remote Code Execution Vulnerabilities (MS15-022) (Msores.dll) - ClickToRun office removal
        # %programfiles(x86)%\Common Files\Microsoft Shared\Office15\Msores.dll   Version is  15.0.4687.1000#
        
        # Click To Run Office version can be removed, usually causes this - this is unfinished

        if (Get-YesNo "$_ Remove Microsoft Office Remote Code Execution Vulnerabilities (MS15-022) (Msores.dll) - ClickToRun office removal? " -Results $Results -QID $ThisQID) { 
          #$Products = Get-Products "Microsoft Office"    # This will select ANY version with that string in the name like the actual version installed alongside Click-To-Run..
          $Products = Get-WmiObject Win32_Product | Where-Object { $_.Name -like "Microsoft Office (en-US)" -or $_.Name -like "Microsoft Office (fr-fr)" -or $_.Name -like "Microsoft Office (es-es)" }
          # NOT 100% sure this works...

          foreach ($ProductName in $Products.Name) {
              if (Get-YesNo "[?] Remove $ProductName ") {
                Remove-Software -Products $ProductName -Results $Results | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-MSOffice-C2R_MS15-022.log"
              }
          } else {
            Write-Host "[!] Product not found: (MS Office click-to-run version with 'Microsoft Office (xx-xx)' in the name).. Please remove manually/update script !!`n" -ForegroundColor Red  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-MSOffice-C2R_MS15-022.log"
            if (-not $Automated) { appwiz.cpl }
          }  
          $RebootRequired = $true
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-MSOffice-C2R_MS15-022.log"
        }       
      }	
      376709 {
        # 376709	HP Support Assistant Multiple Security Vulnerabilities (HPSBGN03762)
        # C:\Program Files (x86)\Hewlett-Packard\HP Support Framework\\HPSF.exe  Version is  8.8.34.31#
        if (Get-YesNo "$_ Remove HP Support Assistant Multiple Security Vulnerabilities (HPSBGN03762)? " -Results $Results -QID $ThisQID) { 
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like 'HP Support Assist*'})
          if ($Products) {
              Remove-Software -Products $Products  -Results $Results | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-HPSupportAssist.log"
          } else {
            Write-Host "[!] Product not found: 'HP Support Assist*' !!`n" -ForegroundColor Red
          }  
          $RebootRequired = $true
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-HPSupportAssist.log"

        }       
      }	
      106116 {        
        if (Get-YesNo "$_ Delete EOL/Obsolete Software: Microsoft Visual C++ 2010 Redistributable Package Detected? " -Results $Results -QID $ThisQID) { 
          Remove-File "$($env:ProgramFiles)\Common Files\Microsoft Shared\VC\msdia100.dll" -Results $Results   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-MSVC_2010.log"
          Remove-File "$(${env:ProgramFiles(x86)})\Common Files\Microsoft Shared\VC\msdia100.dll" -Results $Results    | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-MSVC_2010.log"
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-MSVC_2010.log"
        }       
      }	
<#      110432 {  # This was not finished..
        if (Get-YesNo "$_ Microsoft Office Security Update for April 2023 ?" -Results $Results -QID $ThisQID) {
          $ResultsEXE = "C:\Program Files (x86)\Microsoft Office\root\Office16\GRAPH.EXE"
          $ResultsEXEVersion = Get-FileVersion $ResultsEXE
          if ($ResultsEXEVersion -le 16.0.16227.20258) {
            Write-Host "[!] Vulnerable version $ResultsEXE found : $ResultsEXEVersion <= 16.0.16227.20258"
          }
        }
      }  #>
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
        if (Get-YesNo "$_ Microsoft Office and Microsoft Office Services and Web Apps Security Update 2018/2019 " -Results $Results -QID $ThisQID) {
          $Products = (get-wmiobject Win32_Product | Where-Object { $_.Name -like "*Office 2007*"})
          if ($Products) {
            Write-Host "[!] WARNING: Office 2007 product found! Can't auto-fix this.. Need one or more of these KB's installed: "   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-OfficeWebAppsSecUpdate2018-2019.log" 
            Write-Host "  KB4092464, KB4461565, KB4461518, KB4092444, KB4092466, KB4011202, KB4011207, KB4011202"   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-OfficeWebAppsSecUpdate2018-2019.log"
            Write-Host "[!] Product found installed:"   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-OfficeWebAppsSecUpdate2018-2019.log"
            Write-Host "$Products"
          } else {
            # If Office2007 is not installed, it should be safe to remove these conversion apps that may be vulnerable.
            $Result = (($Results -split('is not installed'))[1] -split ('Version is'))[0].trim()
            if (Test-Path $Result) {
              if (Get-YesNo "Delete $Result ?") {
                Write-Host "[.] Removing file: $Result"  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-OfficeWebAppsSecUpdate2018-2019.log"
                Remove-File $Result
                if (!(Test-Path $Result)) {
                  Write-Host "[+] Removed file $Result"   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-OfficeWebAppsSecUpdate2018-2019.log"
                } else {
                  Write-Host "[!] ERROR: Couldn't remove $Result !!"   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-OfficeWebAppsSecUpdate2018-2019.log"
                }
              }
            }
            if (Get-Item $Path) {
              if (Get-YesNo "Delete registry item $Path ?") {
                Remove-RegistryItem $Path   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-OfficeWebAppsSecUpdate2018-2019.log"
                $RebootRequired = $true
              }
              # $QIDsOffice2007 = 1 # Not doing this, need to check for each EXE
            } else {
              Write-Host "[.] Looks like registry key $Path was already removed."    | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-OfficeWebAppsSecUpdate2018-2019.log"
            }
            API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-OfficeWebAppsSecUpdate2018-2019.log"
          }
        }
      }
      91850 {
        # $Results = "Microsoft vulnerable Office app detected  Version     '18.2008.12711.0'#""  
        # Microsoft vulnerable Office app detected  Version     '17.10314.31700.1000'# 5/10/24
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Office app Remote Code Execution (RCE) Vulnerability $AppxVersion" -Results $Results -QID $ThisQID) {
          if ($Results -like "*Microsoft vulnerable Office app detected*") {
            Write-Host "`n[!] This needs manual remediation:" -Foregroundcolor Red 
            Write-Host "  $Results" -ForegroundColor White

          }
          Remove-SpecificAppXPackage -Name "Microsoft.MicrosoftOfficeHub" -Version $AppxVersion -Results $Results  # 5/10/24
          #Remove-SpecificAppXPackage -Name "Office" -Version "18.2008.12711.0" -Results $Results   # "18.2008.12711.0"   # Not sure what to do here, we will search out ANYthing with 'office' in the name, not good. specificity needed..
        }
      }
      91848 {
        # Multiple versions can be found in one result..
        # Microsoft vulnerable Microsoft Desktop Installer detected  Version     '1.4.3161.0'
        # Microsoft vulnerable Microsoft Desktop Installer detected  Version     '1.21.3133.0'#
        $AppxVersions = Get-VersionResults -Results $Results
        if (Get-YesNo "$_ Remove Microsoft.DesktopAppInstaller vulnerable versions $AppxVersions " -Results $Results -QID $ThisQID) {
          ForEach ($AppxVersion in $AppxVersions) {
            Write-Host "[.] Removing Microsoft.DesktopAppInstaller version $AppxVersion .."
            Remove-SpecificAppXPackage -Name "Microsoft.DesktopAppInstaller" -Version $AppxVersion -Results $Results
          }
        }
      }
      { $Results -like '*Office ClicktoRun or Office 365 Suite*'} {
        if (Get-YesNo "$_ Check $VulnDesc ? " -Results $Results -QID $ThisQID) {
          # 110460 Office ClicktoRun or Office 365 Suite MARCH 2024 Update is not installed   C:\Program Files (x86)\Microsoft Office\root\Office16\GRAPH.EXE  Version is  16.0.17328.20162#
          # 110465 Office ClicktoRun or Office 365 Suite MAY 2024 Update is not installed   C:\Program Files (x86)\Microsoft Office\root\Office16\GRAPH.EXE  Version is  16.0.17531.20140#
          # 110473	Microsoft Office Security Update for August 2024
          # 110474	Microsoft Outlook Remote Code Execution (RCE) Vulnerability for August 2024

          # 110473 Office ClicktoRun or Office 365 Suite AUGUST 2024 Update is not installed   C:\Program Files (x86)\Microsoft Office\root\Office16\GRAPH.EXE  Version is  16.0.17830.20138#
          # 110474 Office ClicktoRun or Office 365 Suite AUGUST 2024 Update is not installed   C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE  Version is  16.0.17830.20138#
          # Problem was $CheckEXE = Check-ResultsForVersion -Results $Results .... should be File


          $ResultsMissing = ($Results -split "is not installed")[0].trim()
          $ResultsVersion = ($Results -split "Version is")[1].trim().replace("#","")
          $CheckEXE = Check-ResultsForFile -Results $Results
          if (Test-Path $CheckEXE) {
            $CheckEXEVersion = Get-FileVersion $CheckEXE
            if ($CheckEXEVersion) {
              Write-Verbose "EXE version found : $CheckEXE - $CheckEXEVersion .. checking against $ResultsVersion"
              if ([version]$CheckEXEVersion -le [version]$ResultsVersion) {
                Write-Host "[!] Vulnerable version $CheckEXE found : $CheckEXEVersion <= $ResultsVersion - Update missing: $ResultsMissing" -ForegroundColor Red
                #sl "C:\Program Files\Common Files\Microsoft Shared\ClickToRun"
                #& "OfficeC2RClient.exe" /update user displaylevel=false forceappshutdown=true
                Write-Host "[+] Attempting to patch with C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe /update user displaylevel=false forceappshutdown=true .. This could take 30-60s"  -ForegroundColor Green
                $arguments = "/update user displaylevel=false forceappshutdown=true"
                Start-Process "C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe" -ArgumentList $arguments -Wait
                Write-Host "[+] Done, should be patched." -ForegroundColor Green
              } else {
                Write-Host "[+] EXE patched version found : $CheckEXEVersion > $ResultsVersion - already patched." -ForegroundColor Green  # SHOULD never get here, patches go in a new folder..
              }
            } else {
              Write-Host "[-] EXE Version not found, for $CheckEXE .." -ForegroundColor Yellow
            }
          } else {
            Write-Host "[!] EXE no longer found: $CheckEXE - likely its already been updated. Let's test again just in case.."
            $CheckEXE = Check-ResultsForVersion -Results $Results
            if (Test-Path $CheckEXE) {
              $CheckEXEVersion = Get-FileVersion $CheckEXE
              if ($CheckEXEVersion) {
                Write-Verbose "EXE version found : $CheckEXE - $CheckEXEVersion .. checking against $ResultsVersion"
                if ([version]$CheckEXEVersion -le [version]$ResultsVersion) {
                  Write-Host "[!] Vulnerable version $CheckEXE still found : $CheckEXEVersion <= $ResultsVersion - Update missing: $ResultsMissing" -ForegroundColor Red
                } else {
                  Write-Host "[+] EXE patched version found : $CheckEXEVersion > $ResultsVersion - good!" -ForegroundColor Green  # SHOULD never get here, patches go in a new folder..  
                }  
              }
            } else {
              Write-Host "[!] EXE no longer found: $CheckEXE - Same issue. Likely update has been applied." -ForegroundColor Green
            }
          }
          $RebootRequired = $true
          #API-SendLogs -QID $ThisQID -LogFile 
        }
      }

      91866 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library HEVC Video and VP9 Extensions Remote Code Execution (RCE) Vulnerability for February 2022" -Results $Results -QID $ThisQID) {

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
        if (Get-YesNo "$_ Remove Microsoft.VP9VideoExtensions Version 1.0.41182.0" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft.VP9VideoExtensions" -Version $AppxVersion -Results $Results # "1.0.41182.0" 
        }
      }
      91869 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library Remote Code Execution (RCE) Vulnerability for March 2022" -Results $Results -QID $ThisQID) {
          #Microsoft vulnerable Microsoft.VP9VideoExtensions detected  Version     '1.0.41182.0'  !!!! wrong appx..
          #Microsoft vulnerable Microsoft.HEIFImageExtension detected  Version     '1.0.42352.0'#
          Remove-SpecificAppXPackage -Name "HEIFImageExtension" -Version $AppxVersion -Results $Results # "1.0.41182.0" 
        }
      }
      91847 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft.HEIFImageExtension Version 1.0.42352.0" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "HEIF" -Version $AppxVersion -Results $Results # "1.0.42352.0" 
        }
      }
      91845 {   
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library HEVC Video And Web Media Extensions Remote Code Execution (RCE) Vulnerability for December 2021" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0"
        }
      }
      91914 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft.Windows.Photos Version 2021.21090.10007.0" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft.Windows.Photos" -Version $AppxVersion -Results $Results # "2021.21090.10007.0" 
        }
      }
      91819 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft HEVCVideoExtension Version 0.33232.0 " -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      }
      91773 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft 3D Viewer Multiple Vulnerabilities - June 2021" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version $AppxVersion -Results $Results # "7.2009.29132.0" 
        }
      }
      91834 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft 3D Viewer Remote Code Execution (RCE) Vulnerability - November 2021" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version $AppxVersion -Results $Results # "7.2009.29132.0" 
        }
      }
      92117 { # Microsoft 3D Viewer Remote Code Execution (RCE) Vulnerability - February 2024
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft 3D Viewer Remote Code Execution (RCE) Vulnerability - February 2024" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version $AppxVersion -Results $Results 
        }
      }
      92133 {
        $AppxVersion = ($results -csplit "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Outlook for Windows Spoofing Vulnerability for April 2024" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "OutlookForWindows" -Version $AppxVersion -Results $Results # Vulnerable version of Microsoft OutlookForWindows detected  Version     '1.2023.1214.201'#
          #These PoS put 'version' twice in this vuln result, just to screw me up, I swear xD  Luckily, there is -csplit which will match case.
        }
      }
      91774 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Paint 3D Remote Code Execution Vulnerability - June 2021" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "MSPaint" -Version $AppxVersion -Results $Results # "6.2009.30067.0" 
        }
      }
      91871 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Paint 3D Remote Code Execution (RCE) Vulnerability for March 2022" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "MSPaint" -Version $AppxVersion -Results $Results # Microsoft vulnerable Microsoft.MSPaint detected  Version     '1.0.68.0'#
        }
      }
      91761 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library and VP9 Video Extensions Multiple Vulnerabilities" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "VP9VideoExtensions" -Version $AppxVersion -Results $Results # "1.0.32521.0" 
        }
      }
      91775 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows VP9 Video Extension Remote Code Execution Vulnerability  " -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "VP9VideoExtensions" -Version $AppxVersion -Results $Results # "1.0.32521.0" 
        }
      }
      91919 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library HEVC Video and AV1 Extensions Remote Code Execution (RCE) Vulnerability for June 2022" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      }
      91788 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library High Efficiency Video Coding (HEVC) Video Extensions Remote Code Execution (RCE) Vulnerabilities" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      }
      91726 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft Windows Codecs Library Remote Code Execution Vulnerabilities - January 2021 " -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      }   
     91764 { #91764 - Microsoft Windows Codecs Library Web Media Extension Remote Code Execution Vulnerability      
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Microsoft Windows Codecs Library Web Media Extension Remote Code Execution Vulnerability " -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft.WebMediaExtensions" -Version $AppxVersion -Results $Results #   '1.0.20875.0'# 
        }
      }   

      91885 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft HEVC Video Extensions Remote Code Execution (RCE) Vulnerability for April 2022" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      } 
      91855 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft HEVC Video Extensions Remote Code Execution (RCE) Vulnerability for January 2022" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "1.0.33232.0" 
        }
      } 
      91820 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Remove Microsoft MPEG-2 Video Extension Remote Code Execution (RCE) Vulnerability " -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "MPEG2VideoExtension" -Version $AppxVersion -Results $Results # "1.0.22661.0" 
        }
      } 
      378131 {
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Microsoft Windows Snipping Tool Information Disclosure Vulnerability" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft.ScreenSketch" -Version $AppxVersion -Results $Results # "10.2008.2277.0"
        }
      }
      91974 {
        # Vulnerable version of Microsoft 3D Builder detected  Version     '18.0.1931.0'#
        $AppxVersion = ($results -split "'")[1].replace("'","").replace("#","").trim()  # Cheating here, using ' is probably easier anyway...
        if (Get-YesNo "$_ Microsoft 3D Builder Remote Code Execution (RCE) Vulnerability for January 2023" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft.3DBuilder" -Version $AppxVersion -Results $Results # "18.0.1931.0"
        }
      }
      91975 { 
        # Vulnerable version of Microsoft 3D Builder detected  Version     '18.0.1931.0'#
        write-Verbose "Results: $Results"
        $AppxVersion = ($results -split "'")[1].replace("'","").replace("#","").trim() # Cheating here, using ' is probably easier anyway...
        write-Verbose "AppxVersion: $AppxVersion"
        if (Get-YesNo "$_ Microsoft 3D Builder Remote Code Execution (RCE) Vulnerability for February 2023" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft.3DBuilder" -Version $AppxVersion -Results $Results # "18.0.1931.0"
        }
      }
      92030 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        # Microsoft vulnerable Microsoft.VP9VideoExtensions detected  Version     '1.0.52781.0'#
        if (Get-YesNo "$_ Microsoft Raw Image Extension and VP9 Video Extension Information Disclosure Vulnerability" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "VP9VideoExtensions" -Version $AppxVersion -Results $Results # "1.0.52781.0"
        }
      }
      92032 {  # Vulnerable Microsoft Paint 3D detected  Version     '6.2105.4017.0'  Version     '6.2203.1037.0'#
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Microsoft Paint 3D Remote Code Execution (RCE) Vulnerability for July 2023" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "MSPaint" -Version "6.2105.4017.0" -Results $Results # "6.2105.4017.0"
          Remove-SpecificAppXPackage -Name "MSPaint" -Version "6.2203.1037.0" -Results $Results # "6.2203.1037.0"
        }
      }
      92061 {  # Microsoft vulnerable Microsoft.Microsoft3DViewer detected  Version     '7.2105.4012.0'  Version     '7.2211.24012.0'  Version     '7.2107.7012.0'#
        $AppxVersion = ($results -csplit "Version")[1].replace("'","").replace("#","").trim()
        if (Get-YesNo "$_ Microsoft 3D Viewer Remote Code Execution (RCE) Vulnerability - September 2023" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version "7.2105.4012.0" -Results $Results 
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version "7.2211.24012.0" -Results $Results 
          Remove-SpecificAppXPackage -Name "Microsoft3DViewer" -Version "7.2107.7012.0" -Results $Results 
        }
      }
      92063 { # Vulnerable version of Microsoft 3D Builder detected  Version     '20.0.3.0'#
        $AppxVersion = ($results -csplit "Version")[1].replace("'","").replace('Vulnerable version of','').replace("#","").trim() 
        if (Get-YesNo "$_ Microsoft 3D Builder Remote Code Execution (RCE) Vulnerability - September 2023" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "Microsoft.3DBuilder" -Version $AppxVersion -Results $Results # "20.0.3.0" 
        }
      }  
      92049 { 
        $AppxVersion = ($results -split "Version")[1].replace("'","").replace("#","").trim()   #
        if (Get-YesNo "$_ Microsoft Windows Codecs Library HEVC Video Extensions Remote Code Execution (RCE) Vulnerability for August 2023" -Results $Results -QID $ThisQID) {
          Remove-SpecificAppXPackage -Name "HEVCVideoExtension" -Version $AppxVersion -Results $Results # "2.0.61591.0" 
        }
      }
      92067 {
        if (Get-YesNo "$_ Microsoft HTTP/2 Protocol Distributed Denial of Service (DoS) Vulnerability" -Results $Results -QID $ThisQID) {
          Write-Host "[.] Disabling HTTP/2 TLS with registry key: HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\EnableHttp2Tls=0" -ForegroundColor Yellow   | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-HTTP2ddos.log"
          Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name EnableHttp2Tls -Value 0  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-HTTP2ddos.log"
          Write-Host "[+] Done!" -ForegroundColor Green
          $RebootRequired = $true
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-HTTP2ddos.log"
        }
      }
      92167 {
        if (Get-YesNo "$_ Check if Microsoft Windows Update Stack Elevation of Privilege Vulnerability is fixed " -Results $Results -QID $ThisQID) { 
          # needs Dynamic SafeOS Update: https://www.catalog.update.microsoft.com/Search.aspx?q=Safe+OS
          Check-WinREVersion
        }
      }
      #HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters EnableHttp2Tls
      378985 { #Disable-TLSCipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA
        $AllCipherSuites = (Get-TLSCipherSuite).Name
        $CipherSuites = ((Get-TLSCipherSuite) | Where-Object {$_.Name -like '*DES*'}).Name
        if (Get-YesNo "$_ Birthday attacks against Transport Layer Security (TLS) ciphers with 64bit block size Vulnerability (Sweet32)" -Results $Results -QID $ThisQID) {
          if ($null -ne $CipherSuites) {
            foreach ($CipherSuite in $CipherSuites) {
              Write-Host "[.] TLS Cipher suite(s) found: $CipherSuite - Disabling." -ForegroundColor Yellow  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
              Disable-TLSCipherSuite $CipherSuite  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
              if ((Get-TlsCipherSuite -Name DES) -or (Get-TlsCipherSuite -Name 3DES)) {
                Write-Host "[!] ERROR: Cipher suites still found!! Results:" -ForegroundColor Red
                Get-TlsCipherSuite -Name DES  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
                Get-TlsCipherSuite -Name 3DES  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
                Write-Host "[!] Please remove manually!" -ForegroundColor Red  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
              } else {
                Write-Host "[+] Cipher Suite removed." -ForegroundColor Green  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
              }
            }
          } else {
            Write-Host "[.] TLS Cipher suite(s) not found for DES or 3DES - Looks like this might have been fixed already? Investigate manually if not." -ForegroundColor Yellow  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
            Write-Host "[.] Listing all TLS Cipher suites:" -ForegroundColor Yellow  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
            $AllCipherSuites         | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
          }
          # Also apply registry fixes:  NOTE: Creating reg keys with '/' character will not work correctly, so there is a fix, they can be created this way:
            # Write-Host "[ ] Creating Ciphers subkeys (with /).." -ForegroundColor Green
            # $key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
            # $null = $key.CreateSubKey('AES 128/128')
          $RegItems = @("Triple DES 168/168","DES 56/56")
          Foreach ($Regitem in $Regitems) {
            Write-Host "[.] Creating new key for SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$($RegItem) "  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
            #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$($RegItem)" -Name Enabled -Force -ErrorAction Continue | Out-Null  # WONT WORK because of "/" character in key.. Hack below.
            $key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
            $null = $key.CreateSubKey($RegItem)
            Write-Host "[.] Setting property for $RegItem - Enabled = DWORD 0"  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\""$($RegItem)""" -Name Enabled -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
          }
          Foreach ($Regitem in $Regitems) {
            $Property=(Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$($RegItem)" -ErrorAction SilentlyContinue).Property 
            if ($Property -eq "Enabled") {
              Write-Host "[.] Checking for created keys: $RegItem : $($Property) - GOOD" -Foregroundcolor Green | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
            } else {
              Write-Host "[.] Checking for created keys: $RegItem : $($Property) - ERROR, or key does not exist! Listing cipher keys:" -Foregroundcolor Red | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-TLSCiphers.log"
              Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\*"
            }
          }
          $RebootRequired = $true
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-TLSCiphers.log"
        }
      }      

      92038 {
        if (Get-YesNo "$_ Microsoft Office and Windows HTML Remote Code Execution Vulnerability (Zero Day) for July 2023" -Results $Results -QID $ThisQID) {
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
              Write-Host "[!] Completed. A reboot may be required." -Foregroundcolor Green | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-MSOffice-HTML-RCE-July2023.log"
              $RebootRequired = $true
          }
          else {
              Write-Host $RemediationTargets | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-MSOffice-HTML-RCE-July2023.log"
              Write-Warning "No products were selected! The valid value's for -OfficeProducts is listed below you can also use a comma seperated list or simply put 'All'." | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-MSOffice-HTML-RCE-July2023.log"
              $RemediationValues | Sort-Object Name | Format-Table | Out-String | Write-Host
              Write-Error "ERROR: Nothing to do!"
              exit 1
          }
          $RebootRequired = $true
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-MSOffice-HTML-RCE-July2023.log"
        }
      }
      371263 {
        if (Get-YesNo "$_ Fix Intel Graphics drivers" -Results $Results -QID $ThisQID) {
          foreach($gpu in Get-WmiObject Win32_VideoController) {  
            Write-Host $gpu.Description  | Tee-Object -Append -FilePath "$($log)\$($ThisQID)-intelgrfx.log"
            $GpuName = ""
            if ($gpu.Description -like '*Intel*') {
              $IntelcardFound = $true
              if ($gpu.Description -like "*HD Graphics 4*") { 
                $GpuName = "Intel 5xx" 
                $GPUWin10 = "https://www.intel.com/content/www/us/en/download/18799/intel-graphics-driver-for-windows-15-45.html"
                $GPUWin11 = "n/a"
              }
              if ($gpu.Description -like "*HD Graphics 54*" -or $gpu.Description -like "*HD Graphics Iris" -or $gpu.Description -like "*HD Graphics 53*" -or $gpu.Description -like "*HD Graphics 51*" -or $gpu.Description -like "*HD Graphics P5*") { 
                $GpuName = "Intel 5xx" 
                $GPUWin10 = "https://www.intel.com/content/www/us/en/download/18388/intel-graphics-driver-for-windows-10-15-40-4th-gen.html"
                $GPUWin11 = "n/a"
              }
              if ($gpu.Description -like "*HD Graphics 6*") { 
                $GpuName = "Intel 6xx" 
                $GPUWin10 = "https://www.intel.com/content/www/us/en/download/762755/intel-6th-10th-gen-processor-graphics-windows.html"
                $GPUWin11 = "https://www.intel.com/content/www/us/en/download/762755/intel-6th-10th-gen-processor-graphics-windows.html"
              }
              if ($gpu.Description -like "*HD Graphics 7*") { 
                $GpuName = "Intel 7xx"  
                $GPUWin11 = "https://www.intel.com/content/www/us/en/download/776137/intel-7th-10th-gen-processor-graphics-windows.html"
                $GPUWin10 = "https://www.intel.com/content/www/us/en/download/776137/intel-7th-10th-gen-processor-graphics-windows.html"
              }
              if ($gpu.Description -like "*ARC Pro*") { 
                $GpuName = "Intel ARC Pro" 
                $GPUWin11 = "https://www.intel.com/content/www/us/en/download/741626/intel-arc-pro-graphics-windows.html"
                $GPUWin10 = "https://www.intel.com/content/www/us/en/download/741626/intel-arc-pro-graphics-windows.html"
              }
              if ($gpu.Description -like "*ARC*") { 
                $GpuName = "Intel ARC" 
                $GPUWin10 = "https://www.intel.com/content/www/us/en/download/785597/intel-arc-iris-xe-graphics-windows.html"
                $GPUWin11 = "n/a"
              }
            }
          }
          if ($Intelcardfound) {
            if ($GPUName) {
              $OSVersion = [version](Get-OSVersion)
              if ($OSVersion -le [version]10.0.19045) { 
                "[+] GPU Update URL (Win 10): $GPUWin10" | Tee-Object -Append -FilePath  "$($log)\$($ThisQID)-intelgrfx.log" ; 
                if (-not $Automated) { explorer $GPUWin10 }
              }
              if ($OSVersion -gt [version]10.0.19045) {  
                if ($GPUWin11 = "n/a") {
                  $FixData = @{
                    "FixNote" = "Unfixable, no Win11 Drivers available."
                    "FixDate" = "n/a"
                  }
                  "[-] GPU Update not available for Win 11!! Launching API-Remed FixData:  $FixData" | Tee-Object -Append -FilePath  "$($log)\$($ThisQID)-intelgrfx.log" ; 
                  API-Remed -QID $ThisQID -FixData $FixData
                } else {
                  "[+] GPU Update URL (Win 11): $GPUWin11" | Tee-Object -Append -FilePath  "$($log)\$($ThisQID)-intelgrfx.log" ; 
                  if (-not $Automated) { explorer $GPUWin11 } 
                }
              }
            } else {
              if (-not $Automated) {
                Write-Host "[!] Please fix manually, opening https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00166.html :" -Foregroundcolor Yellow | Tee-Object -Append -FilePath  "$($log)\$($ThisQID)-intelgrfx.log"
                explorer.exe "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00166.html"
              } else {
                "[!] Please fix manually: Win11: $($GPUWin11)`nWin10: $($GPUWin10)" | Tee-Object -Append -FilePath  "$($log)\$($ThisQID)-intelgrfx.log"
              }
            }
          } else {
            Write-Host "[!] No Intel card found! or, program error.."
          }
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-intelgrfx.log"
          $RebootRequired = $true
        }
      }
      371476 {
        if (Get-YesNo "$_ Fix Intel Proset Wireless Software" -Results $Results -QID $ThisQID) {
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
          $RebootRequired = $true
        }
        API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-intelwireless.log"
      }
      
      90019 {
        $LmCompat = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa").LmCompatibilityLevel
        if ($LmCompat -eq 5) {
          Write-Output "$_ Fix already in place it appears: LMCompatibilityLevel = 5, Good!" | Tee-Object -append "$($log)\$($ThisQID)-ntlmv1.log"
        } else {
          if (Get-YesNo "$_ Fix LanMan/NTLMv1 Authentication? Currently LmCompatibilityLevel = $LmCompat ? " -Results $Results -QID $ThisQID) { 
            <#
            0- Clients use LM and NTLM authentication, but they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
            1- Clients use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
            2- Clients use only NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controller accepts LM, NTLM, and NTLMv2 authentication.
            3- Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
            4- Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM authentication responses, but it accepts NTLM and NTLMv2.
            5- Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM and NTLM authentication responses, but it accepts NTLMv2.
            #>
            if (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel") {
              Write-Output "[+] Setting registry item: HKLM\System\CurrentControlSet\Control\Lsa LMCompatibilityLevel = 5" | Tee-Object -append "$($log)\$($ThisQID)-ntlmv1.log"
              Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value "5" -Force | Out-Null
            } else {
              Write-Output "[+] Creating registry item: HKLM\System\CurrentControlSet\Control\Lsa LMCompatibilityLevel = 5" | Tee-Object -append "$($log)\$($ThisQID)-ntlmv1.log"
              New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value "5" -Force | Out-Null
            }
            Write-Output "[.] Checking fix: HKLM\System\CurrentControlSet\Control\Lsa LMCompatibilityLevel = 5" | Tee-Object -append "$($log)\$($ThisQID)-ntlmv1.log"
            if ((Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa").LmCompatibilityLevel -eq 5) {
              Write-Output "[+] Found: LMCompatibilityLevel = 5, Good!" | Tee-Object -append "$($log)\$($ThisQID)-ntlmv1.log"
            } else {
              Write-Output "[+] Found: LMCompatibilityLevel = $((Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa").LmCompatibilityLevel) - not 5!" | Tee-Object -append "$($log)\$($ThisQID)-ntlmv1.log"
            }
            $RebootRequired = $true
          }
        }
        API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-ntlmv1.log"
      }
      372294 {
        if (Get-YesNo "$_ Fix service permissions issues? " -Results $Results -QID $ThisQID) {
          $ServicePermIssues = Get-ServicePermIssues -Results $Results
          Write-Verbose "IN MAIN LOOP: Returned from Get-ServicePermIssues: $ServicePermIssues"
          foreach ($file in $ServicePermIssues) {
            if (!(Get-ServiceFilePerms $file)) {
              "[+] Permissions look good for $file ..." | Tee-Object -append "$($tmp)\serviceperms.log"
            } else { # FIX PERMS.
              $objACL = Get-ACL $file
              Write-Output "[.] Checking owner of $file .. $($objacl.Owner)" | Tee-Object -append "$($tmp)\serviceperms.log"
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
                Set-ACL $file -AclObject $objACL  | Tee-Object -append "$($tmp)\serviceperms.log"
              } catch {
                Write-Output "[!] ERROR: Couldn't set owner to $($env:Username) on $($file) .." | Tee-Object -append "$($tmp)\serviceperms.log"
              }
              $objACL = Get-ACL $file
              Write-Verbose "[.] Checking inheritance for $file - $(!($objacl.AreAccessRulesProtected)).."
              if (!($objACL.AreAccessRulesProtected)) {  # Inheritance is turned on.. Lets turn it off for this one file.
                # Remove inheritance, resulting ACLs will be limited
                Write-Verbose "[.] Turning off inheritance for $file"
                $objacl.SetAccessRuleProtection($true,$true)  # 1=protected?, 2=copy inherited ACE? we will modify below
                #$objacl.SetAccessRuleProtection($true,$false)  # 1=protected?, 2=drop inherited rules
                try {
                  Set-ACL $file -AclObject $objACL  | Tee-Object -append "$($tmp)\serviceperms.log"
                } catch {
                  Write-Output "[!] ERROR: Couldn't set inheritance on $($file) .." | Tee-Object -append "$($tmp)\serviceperms.log"
                }
              }
              Write-Output "[.] Removing Everyone full permissions on $file .." | Tee-Object -append "$($tmp)\serviceperms.log"
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
                Set-ACL $file -AclObject $objACL  | Tee-Object -append "$($tmp)\serviceperms.log"
              } catch {
                Write-Output "[!] ERROR: Couldn't remove Everyone-full permissions on $file .." | Tee-Object -append "$($tmp)\serviceperms.log"
              }

              # .. Remove write/append/etc from 'Users'. First remove Users rule completely. 
              Write-Output "[.] Removing Users-Write/Modify/Append permissions on $file .." | Tee-Object -append "$($tmp)\serviceperms.log"
              $objUser = New-Object System.Security.Principal.NTAccount("Users") 
              $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                  ($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
              $objACL = Get-ACL $file 
              try {
                $objACL.RemoveAccessRuleAll($objACE) 
              } catch {
                Write-Output "[!] ERROR: Couldn't reset Users permissions on $file .." | Tee-Object -append "$($tmp)\serviceperms.log"
              }
              # Then add ReadAndExecute only for Users
              $Right = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
              $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                  ($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
              $objACL.AddAccessRule($objACE) 
              try {
                Set-ACL $file -AclObject $objACL  
              } catch {
                Write-Output "[!] ERROR: Couldn't modify Users to R+X permissions on $file .." | Tee-Object -append "$($tmp)\serviceperms.log"
              }

              # .. Remove write/append/etc from 'Authenticated Users'. First remove Users rule completely. 
              Write-Output "[.] Removing Authenticated Users-Write/Modify/Append permissions on $file .." | Tee-Object -append "$($tmp)\serviceperms.log"
              $objUser = New-Object System.Security.Principal.NTAccount("Authenticated Users") 
              $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                  ($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
              $objACL = Get-ACL $file 
              try {
                $objACL.RemoveAccessRuleAll($objACE) 
              } catch {
                Write-Output "[!] ERROR: Couldn't reset Authenticated Users permissions on $file .." | Tee-Object -append "$($tmp)\serviceperms.log"
              }
              # Then add ReadAndExecute only for Authenticated Users
              $Right = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
              $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                  ($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
              $objACL.AddAccessRule($objACE) 
              try {
                Set-ACL $file -AclObject $objACL  
              } catch {
                Write-Output "[!] ERROR: Couldn't modify Users to R+X permissions on $file .." | Tee-Object -append "$($tmp)\serviceperms.log"
              }


              # Check that issue is actually fixed
              if (!(Get-ServiceFilePerms $file)) {
                Write-Output "[+] Permissions are good for $file " | Tee-Object -append "$($tmp)\serviceperms.log"
              } else {
                Write-Output "[!] WARNING: Permissions NOT fixed on $file .. " | Tee-Object -append "$($tmp)\serviceperms.log"
                Get-FilePerms "$($file)" | Tee-Object -append "$($log)\$($ThisQID)-serviceperms.log"
              }
              $RebootRequired = $true
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
          API-SendLogs -QID $ThisQID -LogFile "$($tmp)\serviceperms.log"
        }
      }
      $QIDsMSXMLParser4 {
        if (Get-YesNo "$_ Install MSXML Parser 4.0 SP3 update? " -Results $Results -QID $ThisQID) { 
          Write-Host "[.] Downloading installer to $($tmp)\msxml.exe .."
          Invoke-WebRequest -UserAgent $AgentString -Uri "https://download.microsoft.com/download/A/7/6/A7611FFC-4F68-4FB1-A931-95882EC013FC/msxml4-KB2758694-enu.exe" -OutFile "$($tmp)\msxml.exe"
          Write-Host "[.] Running installer: $($tmp)\msxml.exe .."
          Start-Process -Wait "$($tmp)\msxml.exe" -ArgumentList "/quiet /qn /norestart /log $($tmp)\msxml.log"
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-msxml.log"
        }
        $QIDsMSXMLParser4 = 1
      }
      { $QIDs_dotNET_Core6 -contains $_ }  { 
        if (Get-YesNo "$_ Install newest .NET Core 6.0.36 update? " -Results $Results -QID $ThisQID) { 
          Write-Host "[.] Downloading installer to $($tmp)\netcore.exe .."
          
          Invoke-WebRequest -UserAgent $AgentString -Uri $NetCore6NewestUpdate -OutFile "$($tmp)\netcore.exe" | Tee-Object -Append "$($tmp)\netcore.log"
          Write-Host "[.] Running installer: $($tmp)\netcore.exe .."
          Start-Process -Wait "$($tmp)\netcore.exe" -ArgumentList "/install /quiet /norestart /log $($tmp)\netcore.log"
          API-SendLogs -QID $ThisQID -LogFile "$($log)\$($ThisQID)-netcore.log"
        }
        $QIDs_dotNET_Core6 = 1
      }


    ############################################
      # Default - QID not found!  3-28-24 - Lets check for specific Results here. I don't know what the QID numbers will be, but for now, if there are specific KB's in the results, it is likely missing these patches
      #   But - lets check that those patches are not installed.
      Default {
        if (($Results -like "*KB*" -or $Results -like "*GRAPH.EXE*" -or $Results -like 'Office ClicktoRun*' -or $Results -like 'Office 365 Suite*') -and $Results -like "*is not installed*") {
          if (Get-YesNo "(Default) $_ Check if KB is installed for $VulnDesc " -Results $Results -QID $ThisQID) { 
            Write-Verbose "- Found $_ is related to a KB, contains 'KB' and 'is not installed'"
            # Lets check the file versioning stuff instead as it is a better source of truth if a patch is installed or not, thanks Microsoft
            $ResultsMissing = ($Results -split "is not installed")[0].trim()
            # This can have multiple versions, ugh.
            # KB5033920 is not installed  %windir%\Microsoft.NET\Framework64\v4.0.30319\System.dll Version is 4.8.9172.0 %windir%\Microsoft.NET\Framework\v4.0.30319\System.dll Version is 4.8.9172.0 KB5034275 or KB5034274 or KB5034276 is not installed#"
            
            $ResultsVersion = Check-ResultsForVersion -Results $Results  # split everything after space, [version] cannot have a space in it.. Also should work for multiple versions, we will just check the first result.
            $ResultsKB = Check-ResultsForKB -Results $Results
            Write-Verbose "ResultsVersion : $ResultsVersion"
            $CheckEXE = ((Check-ResultsForFile -Results $Results) -Replace "`r","" -Replace "`n","") # Get SINGLE EXE/DLL FileNames to check, from $Results  (Changed from multiple 5/2/24), fixed line endings 5/3/24
            Write-Verbose "CheckEXE: $CheckEXE"
            if (Test-Path $CheckEXE) {
              $CheckEXEVersion = Get-FileVersion $CheckEXE
              Write-Verbose "Get-FileVersion results: $CheckEXEVersion"
              if ($CheckEXEVersion) {
                Write-Verbose "EXE/DLL version found : $CheckEXE - $CheckEXEVersion .. checking against -- $ResultsVersion --"
                if ([version]$CheckEXEVersion -le [version]$ResultsVersion) {
                  Write-Host "[!] Vulnerable version of $CheckEXE found : $CheckEXEVersion <= $ResultsVersion - Update missing: $ResultsMissing" -ForegroundColor Red
                  if ($CheckOptionalUpdates -and -not $AlreadySetOptionalUpdates) {
                    Write-Host "[!] It is possible that Optional Windows updates are disabled, checking.." -ForegroundColor Red
                    Write-Verbose "NOTE: This only applies to Windows 10, version 2004 (May 2020 Update) and later:"
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
                          $RebootRequired = $true
                      }
                    } else {
                      New-Item -Path $registryPath -Force | Out-Null
                      New-ItemProperty -Path $registryPath -Name $valueName -Value 1 -PropertyType DWord -Force | Out-Null
                      Write-Host "The registry key $registryPath has been created and the 'AllowOptionalContent' value has been set to 1."
                      $RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
                      New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" `
                      -Name "AllowMUUpdateService" `
                      -PropertyType DWORD `
                      -Value 1 `
                      -Force

                      Write-Host "The registry key $registryPath \ 'AllowMuUpdateService' value has been set to 1."
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

# Disabling the file deletion step for now, EPDR keeps killing the script for being 'suspicious' at this point.
#Write-Host "[.] Deleting all temporary files from $tmp .."
#Remove-Item -Path "$tmp" -Recurse -Force -ErrorAction SilentlyContinue

Set-RegistryEntry -Name "ReRun" -Value $false

if (!($script:Automated)) {
  $null = Read-Host "--- Press enter to exit ---"
} else {
  if ($RebootRequired) {
    Write-Host "`n[AUTOMATED REBOOT] Suspending Bitlocker for 1 reboot.."
    Suspend-BitLocker -mountpoint c -rebootcount 1
    manage-bde -protectors -disable c: -rebootcount 1     # Just in case the powershell didn't work? shouldn't hurt
    Write-Host "`n[AUTOMATED REBOOT] Setting reboot for 5 minutes from now, please use 'shutdown /a' to abort!"
    shutdown /r /f /t 300
  }
  Write-Host "`n[AUTOMATED REBOOT] No automated reboot required."
}

Write-Host "[o] Done! Stopping transcript" -ForegroundColor Green
Set-Location $oldpwd
Stop-Transcript
Write-Host "[+] Log written to: $script:LogFile , copying to $LogPath `n"`
Create-IfNotExists $LogPath
try {
  Copy-Item $script:LogFile $LogPath -Force
  if (Test-Path -Path "$($LogPath)\$($LogFile)") {
    Write-Host "[+] Log copied to: $LogPath `n"
  } else {
    Write-Host "[-] Couldn't copy log!! $($LogPath)\$($LogFile) not written.. `n"
  }
} catch {
  Write-Error "[!] Log copy failed! $_" | Tee-Object -Append -FilePath  $script:LogFile 
}
Log $(API-SendLogs -UniqueId $UniqueId -APIKey $APIKey -LogFile $script:LogFile)

if (API-Check -Direction "out" -UniqueID $UniqueID -APIKey $APIKey) { 
  Log "[API] [+] Checked out @ $datetime" 
} else {
  Log "[API] [-] Failed checkout @ $datetime"
}

Write-Event -type "information" -eventid 101 -msg "Script ended"
Exit


 