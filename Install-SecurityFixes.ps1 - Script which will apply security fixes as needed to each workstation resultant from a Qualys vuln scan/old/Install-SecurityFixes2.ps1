#########################################
# Install-SecurityFixes.ps1
# Alex Datsko - alex.datsko@mmeconsulting.com
#

param (
  [switch] $Automated = $false
)

#Clear
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

Write-Host "`r`n================================================================" -ForegroundColor DarkCyan
Write-Host "[i] Install-SecurityFixes.ps1" -ForegroundColor Cyan
Write-Host "[i]   v0.18 - Last modified: 9/21/22" -ForegroundColor Cyan
Write-Host "[i]   Alex Datsko - alex.datsko@mmeconsulting.com" -ForegroundColor Cyan
$hostname = $env:COMPUTERNAME
$datetime = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
Write-Host "[i] Date / Time : $datetime" -ForegroundColor Cyan
Write-Host "[i] Computername : $hostname" -ForegroundColor Cyan

# Configuration items:

$ServerName = "SERVER"                       # Change as needed!
$tmp = "$($env:temp)\SecAud"                 # Temporary folder to save downloaded files to
$oldPwd = $pwd                               # Grab location script was run from

if ($Automated) {
  Write-Host "`n[!] Running in automated mode!`n"   -ForegroundColor Red
}

# NOTATE QIDS Used for specific apps (WIP!)

#    Note: to make these lists, copy large list of QIDs related to out of date app, 1 per line to a file
#          in linux, cat filename | sort | uniq | tr -s '\n' ','
#          delete the first and last comma if exists..

$QIDsChrome = 376828,376734,115077,115149,115166,119485,119493,119539,119601,119609,119627,119708,119743,119750,119773,119872,119930,119950,120059,120198,120220,120235,120297,120338,120405,120456,120560,120697,120725,120803,120812,120988,121201,121225,121283,121317,121362,121395,121485,121517,121583,121586,121622,121719,121757,121798,121813,121825,121840,121844,121893,122052,122075,122091,122127,122366,122485,122579,122630,122695,122725,122745,122829,122842,122867,123023,123141,123188,123196,123266,123364,123385,123501,123525,123570,123596,123704,123721,123740,123798,123869,123967,124153,124185,124379,124390,124410,124589,124693,124746,124758,124772,124865,124907,370005,370014,370067,370091,370109,370124,370134,370151,370162,370226,370249,370288,370339,370356,370376,370419,370446,370485,370546,370566,370613,370619,370643,370678,370691,370741,370763,370780,370808,370829,370889,370916,370950,370970,370974,370990,371003,371097,371172,371250,371268,371319,371327,371365,371378,371614,371639,371679,371692,371758,371771,371782,371820,371848,372020,372048,372050,372073,372111,372117,372166,372177,372186,372247,372286,372323,372342,372365,372403,372408,372410,372411,372438,372455,372476,372491,372517,372525,372534,372555,372572,372575,372576,372578,372579,372584,372630,372634,372636,372638,372639,372640,372829,372873,372894,373151,373319,373342,373368,373387,373421,373485,373510,373544,373714,373995,373998,374167,374531,374832,374876,375080,375091,375119,375319,375378,375426,375445,375459,375461,375505,375546,375595,375622,375638,375718,375738,375761,375784,375821,375846,375875,375883,375923,375948,375966,376000,376055,376140,376159
$QIDsFirefox = 376758,370739,370747,370821,370827,370836,370938,370991,371026,371173,371216,371231,371276,371374,371615,371649,371702,371797,371841,371849,371851,372001,372061,372102,372136,372176,372190,372276,372324,372325,372392,372445,372481,372490,372825,373103,373120,373320,373326,373388,373490,373542,373989,374166,374576,374827,374918,375100,375209,375408,375478,375542,375606,375642,375712,375753,375824,375833,375945
<#
#firefox newest
375100
374576
373989
373542
372392
376758
376705
376643
376625
376574
376519
375833
375753
375712
375606
375542
375478
375408
375209
374918
374827
374166
373490
373388
373320
373103
372825
372490
372481
372445
376458
376447
376387
376237
376143
376015
375945
375824
375642
373120
375100
374576
373989
373542
372392
376758
376705
376643
376625
376574
376519
375833
375753
375712
375606
375542
375478
375408
375209
374918
374827
374166
373490
373388
373320
373103
372825
372490
372481
372445
376458
376447
376387
376237
376143
376015
375945
375824
375642
373120
376758
376705
376643
376625
376574
376519
375833
375753
375712
375606
376458
376447
376387
376237
376143
376015
375945
375824
375642
376758
376705
376643
376625
376574
376519
#>
$QIDsZoom = 376638,376624,376640,371344,372477,372832,373366,375391,375487,375805,376046,376117,376973
$QIDsTeamviewer15 = 371174,372386,373335
$QIDsDropbox = 111111 # Dummy entry, none found yet
$QIDsOracleJava = 370280,370371,370469,370610,370727,370887,371079,371265,371528,371749,372013,372163,372333,372508,373156,373540,374873,375477,375729,375964
$QIDsAdoptOpenJDK = 376436,376423
$QIDsOracleJavaSE = 376733,376546,376252
$QIDsVirtualBox = 375967,376255,376548,372509,372512,372542,373154,373553,374881,375481,375736,375967,376736,376255
$QIDsAdobeReader = 116893,117797,118087,118319,118438,118486,118670,118782,118956,119053,119076,119145,119594,119768,119838,120103,120295,120777,120866,121176,121442,121711,121867,122484,122663,123021,123265,123579,123662,124151,124506,124767,370084,370154,370277,370364,370499,370650,375845,375953
$QIDsIntelGraphicsDriver = 370842,371696,371263
$QIDNVIDIAPrivEsc = 370263
$QIDSpectreMeltdown = 91537,91462,91426,91428
$QIDsMicrosoftAccessDBEngine= 106067,106069
$QIDsSQLServerCompact4 = 106023
$QIDsDellCommandUpdate = 376132
$QIDsMicrosoftVisualStudioActiveTemplate = 90514
$QIDsMicrosoftNETCoreV5 = 106089
$QIDsMicrosoftSilverlight = 106028
$QIDsUpdateMicrosoftStoreApps = 91914,91834,91869,91866
#91914	Microsoft Photos App Remote Code Execution (RCE) Vulnerability for June 2022
#91869	Microsoft Windows Codecs Library Remote Code Execution (RCE) Vulnerability for March 2022
#91866	Microsoft Windows Codecs Library HEVC Video and VP9 Extensions Remote Code Execution (RCE) Vulnerability for February 2022
#91834	Microsoft 3D Viewer Remote Code Execution (RCE) Vulnerability - November 2021

if (!(Test-Path $tmp)) { New-Item -ItemType Directory $tmp }
Start-Transcript "$($tmp)\Install-SecurityFixes.log"

# Try to use TLS 1.2, this fixes many SSL problems with downloading files
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-YesNo {
  param ([string] $text)

  if (!($Automated)) { 
    $yesno = Read-Host  "[?] $text [n] "
    if ($yesno.ToUpper()[0] -eq 'Y') { return $true } else { return $false }
  } else { 
    Write-Output "[.] Applying fix for $text .."
    return $true
  }
}

function Remove-Software {
  param ($Products)

    $Guid = $Products | Select -ExpandProperty IdentifyingNumber
    $Name = $Products | Select -ExpandProperty Name
    if (Get-YesNo "Uninstall $Name - $Guid ") { 
        Write-Output "[.] Removing $Guid (Waiting max of 30 seconds after).."
        $x=0
        cmd /c "msiexec /x $Guid /qn"
        Write-Host "[.] Checking for removal of $Guid .." -ForegroundColor White -NoNewline
        while ($x -lt 5) {
            Start-sleep 5
            Write-Host "." -ForegroundColor White -NoNewLine
            $x+=1
            $Products = (get-wmiobject Win32_Product | where { $_.IdentifyingNumber -like "$Guid"}) 
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

function Find-LocalCSVFile {
  param ([string]$Location)
    
    write-Host "Find-LocalCSVFile $Location $OldPwd"

    # FIGURE OUT CSV Filename
    $i = 0
    if (($null -eq $Location) -or ("." -eq $Location)) { $Location = $OldPwd }
    [array]$Filenames = Get-ChildItem "$($Location)\*.csv" | % { $_.Name }
    $Filenames | Foreach-Object {
      Write-Host "[$i] $_" -ForegroundColor Blue
      $i += 1
    }
    if (!($Automated)) {
      Write-Host "[$i] EXIT" -ForegroundColor Blue
      $Max = $i
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
  if (!($null -eq $Location)) { $Location = "data\secaud" }
  if (Test-Path "\\$($ServerName)\$($Location)") {
    $CSVFilename=(gci "\\$($ServerName)\$($Location)" -Filter "*.csv" | sort LastWriteTime | select -last 1).FullName
    Write-Host "[i] Found file: $CSVFileName" -ForegroundColor Blue
    return $CSVFilename 
  } else {
    return $null
  }
}

############################################# MAIN ###############################################
if (!(Test-Path $($tmp))) {
  try {
    Write-Host "[ ] Creating $($tmp) .." -ForegroundColor Gray
    New-Item $($tmp) -ItemType Directory
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

$CSVFilename = Find-ServerCSVFile "$($ServerName)"
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
  $QIDs += [int]$_.QID
  $QIDsVerbose += "[QID $([int]$_.QID)] - [$($_.Title)]"
}
Write-Host "[i] QIDs found: $($QIDs.Count) - $QIDs" -ForegroundColor Cyan
ForEach ($Qv in $QIDsVerbose) {
  Write-Host $Qv
}
# $QIDs

if (!($QIDs)) {
  Write-Host "[X] No QIDs found to fix for $hostname !! Exiting " -ForegroundColor Red
  exit
}
Write-Host "`n"

############################################################################################################################################################################################
# APPLY FIXES FOR QIDs

foreach ($QID in $QIDs) {
    $ThisQID = $QID
    $ThisTitle = (($Rows | where { $_.QID -eq $ThisQID }) | select -First 1).Title
    switch ([int]$QID)
    {
      376023 { 
        if (Get-YesNo "$_ Remove SupportAssist ? ") {
          $guid = (Get-Package | ?{$_.Name -like "*SupportAssist*"})
          if ($guid) {  ($guid | select -expand FastPackageReference).replace("}","").replace("{","")  }
          msiexec /x $guid /qn /L*V "$($tmp)\SupportAssist.log" REBOOT=R
          
          # This might require interaction, in which case run this:
          msiexec /x $guid /L*V "$($tmp)\SupportAssist.log"

          # Or:
          # ([wmi]"\\$env:computername\root\cimv2:Win32_Product.$guid").uninstall()   
        }
      }
      105228 { 
        if (Get-YesNo "$_ Disable guest account and rename to NoVisitors ? ") {
            Rename-LocalUser -Name "Guest" -NewName "NoVisitors" | Disable-LocalUser
        }
      }
      { $QIDSpectreMeltdown -contains $_ } {
        if (Get-YesNo "$_ Fix spectre/meltdown ? ") {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 0 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f'
            #cmd /c 'reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" '
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f'
            $QIDSpectreMeltdown = 1
        } else { $QIDSpectreMeltdown = 1 }
      }
      110414 {
        if (Get-YesNo "$_ Fix Microsoft Outlook Denial of Service (DoS) Vulnerability Security Update August 2022 ? ") { 
          wget "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/outlook-x-none_1763a730d8058df2248775ddd907e32694c80f52.cab" -outfile "$($tmp)\outlook-x-none.cab"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\outlook-x-none.cab $($tmp)"
          cmd /c "msiexec /p $($tmp)\outlook-x-none.msp /qn"
        }
      }
      110413 {
        if (Get-YesNo "$_ Fix Microsoft Office Security Update for August 2022? ") { 
          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/msohevi-x-none_a317be1090606cd424132687bc627baffec45292.cab .."
          wget "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/msohevi-x-none_a317be1090606cd424132687bc627baffec45292.cab" -outfile "$($tmp)\msohevi-x-none.msp"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\msohevi-x-none.msp $($tmp)"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\msohevi-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\msohevi-x-none.msp"
          cmd /c "msiexec /p $($tmp)\msohevi-x-none.msp /qn"

          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab .."
          wget "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab" -outfile "$($tmp)\excel-x-none.cab"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\excel-x-none.msp $($tmp)"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\excel-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\excel-x-none.msp"
          cmd /c "msiexec /p $($tmp)\excel-x-none.msp /qn"

        }
      }
      110412 {
        if (Get-YesNo "$_ Fix Microsoft Office Security Update for July 2022? ") { 
          Write-Host "[.] Downloading CAB: https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/07/excel-x-none_355a1faf5d9fb095c7be862eb16105cfb2f24ca2.cab .."
          wget "http://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2022/06/vbe7-x-none_1b914b1d60119d31176614c2414c0e372756076e.cab" -outfile "$($tmp)\vbe7-x-none.cab"
          Write-Host "[.] Extracting cab: C:\Windows\System32\expand.exe -F: $($tmp)\vbe7-x-none.msp $($tmp)"
          cmd /c "C:\Windows\System32\expand.exe -F:* $($tmp)\excel-x-none.msp $($tmp)"
          Write-Host "[.] Installing patch: $($tmp)\vbe7-x-none.msp"
          cmd /c "msiexec /p $($tmp)\vbe7-x-none.msp /qn"
        }
      }
      91738 {
        if (Get-YesNo "$_  - fix ipv4 source routing bug/ipv6 global reassemblylimit? ") { 
            netsh int ipv4 set global sourceroutingbehavior=drop
            Netsh int ipv6 set global reassemblylimit=0
        }
      }
      375589 {  
        if (Get-YesNo "$_ - Delete Dell DbUtil_2_3.sys ? ") {
            cmd /c 'del c:\users\dbutil_2_3*.sys /s /f /q'
        }
      }
      100413 {
        if (Get-YesNo "$_ CVE-2017-8529 - IE Feature_Enable_Print_Info_Disclosure fix ? ") {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" /v iexplore.exe /t REG_DWORD /d 1 /f'
        }
      }
      { 105170,105171 -contains $_ } { 
        if (Get-YesNo "$_ - Windows Explorer Autoplay not Disabled ? ") {
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
        if (Get-YesNo "$_ - Allowed SMB Null session ? ") {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f'
        }
      }
      90007 {
        if (Get-YesNo "$_ - Enabled Cached Logon Credential ? ") {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f'
        }
      }
      90043 {
        if (Get-YesNo "$_ - SMB Signing Disabled / Not required ? ") {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters"  /v EnableSecuritySignature /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters"  /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
        }
      }
      91805 {
        if (Get-YesNo "$_ - Remove Windows10 UpdateAssistant? ") {
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
        if (Get-YesNo "$_ Update all store apps? ") {
          Write-Host "[!] Updating store apps.." -ForegroundColor Yellow
          $namespaceName = "root\cimv2\mdm\dmmap"
          $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
          $wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
          $result = $wmiObj.UpdateScanMethod()
          Write-Host "[!] Done!" -ForegroundColor Green
        }
      }
      
        ####################################################### Installers #######################################
        # Install newest apps via Ninite

      110330 {  
        if (Get-YesNo "$_ - Install Microsoft Office KB4092465? ") {
            wget "https://download.microsoft.com/download/3/6/E/36EF356E-85E4-474B-AA62-80389072081C/mso2007-kb4092465-fullfile-x86-glb.exe" -outfile "$($tmp)\kb4092465.exe"
            cmd.exe /c "$($tmp)\kb4092465.exe /quiet /passive /norestart"
        }
      }
      372348 {
        if (Get-YesNo "$_ - Intel Chipset INF util ? ") {
            wget "https://downloadmirror.intel.com/30553/eng/setupchipset.exe" -OutFile "$($tmp)\setupchipset.exe"
            cmd /c '"$($tmp)\setupchipset.exe" -s -accepteula  -norestart -log "$($tmp)\intelchipsetinf.log"'
        }
      }
      372300 {
        if (Get-YesNo "$_ - Intel RST ? ") {
            wget "https://downloadmirror.intel.com/655256/SetupRST.exe" -OutFile "$($tmp)\setuprst.exe"
            cmd /c """$($tmp)\setuprst.exe"" -s -accepteula -norestart -log ""$($tmp)\intelrstinf.log"""
            # OR, extract MSI from this exe and run: 
            # msiexec.exe /q ALLUSERS=2 /m MSIDTJBS /i “RST_x64.msi” REBOOT=ReallySuppress
        }   
      }
      { $QIDsIntelGraphicsDriver  -contains $_ } {
        if (Get-YesNo "$_ QID $_ Install newest Intel Graphics Driver? "
    ) { 
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
      { $QIDsChrome -contains $_ } {
        if (Get-YesNo "$_ Install newest Google Chrome? "
    ) { 
            #  Google Chrome - https://ninite.com/chrome/ninite.exe
            wget "https://ninite.com/chrome/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            $QIDsChrome = 1 # All done, remove variable to prevent this from running twice
        } else { $QIDsChrome = 1 }
      }
      { $QIDsFirefox -contains $_ } {
        if (Get-YesNo "$_ Install newest Firefox? "
    ) { 
            #  Firefox - https://ninite.com/firefox/ninite.exe
            wget "https://ninite.com/firefox/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            $QIDsFirefox = 1
        } else { $QIDsFirefox = 1 }
      }
      { $QIDsZoom -contains $_ } {
        if (Get-YesNo "$_ Install newest Zoom Client? "
    ) { 
            #  Zoom client - https://ninite.com/zoom/ninite.exe
            wget "https://ninite.com/zoom/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            $QIDsZoom = 1
        } else { $QIDsZoom = 1 }
      }
      { $QIDsTeamViewer15 -contains $_ } {
        if (Get-YesNo "$_ Install newest Teamviewer 15? "
    ) { 
            #  Teamviewer - https://ninite.com/teamviewer15/ninite.exe
            wget "https://ninite.com/teamviewer15/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            $QIDsTeamViewer15 = 1
        } else { $QIDsTeamViewer15 = 1 }
      }
      { $QIDsDropbox -contains $_ } {
        if (Get-YesNo "$_ Install newest Dropbox? "
    ) { 
            #  Dropbox - https://ninite.com/dropbox/ninite.exe
            wget "https://ninite.com/dropbox/ninite.exe" -OutFile "$($tmp)\ninite.exe"
            cmd /c "$($tmp)\ninite.exe"
            $QIDsDropbox = 1
        } else { $QIDsDropbox = 1 }
      }
  
        ############################
        # Others: (non-ninite)
  
      { $QIDsOracleJava -contains $_ } {
        if (Get-YesNo "$_ Check Oracle Java for updates? ") { 
            #  Oracle Java 17 - https://download.oracle.com/java/17/latest/jdk-17_windows-x64_bin.msi
            #wget "https://download.oracle.com/java/18/latest/jdk-18_windows-x64_bin.msi" -OutFile "$($tmp)\java17.msi"
            #msiexec /i "$($tmp)\java18.msi" /qn /quiet /norestart
            . "c:\Program Files (x86)\Common Files\Java\Java Update\jucheck.exe"
            $QIDsOracleJava = 1
        } else { $QIDsOracleJava = 1 }
      }
      { $QIDsOracleJavaSE -contains $_ } {
        if (Get-YesNo "$_ Check Oracle JAva for updates? ") { 
            #wget "https://download.oracle.com/java/18/latest/jdk-18_windows-x64_bin.msi" -OutFile "$($tmp)\java18.msi"
            #msiexec /i "$($tmp)\java18.msi" /qn /quiet /norestart
            . "c:\Program Files (x86)\Common Files\Java\Java Update\jucheck.exe"
            $QIDsOracleJavaSE  = 1
        } else { $QIDsOracleJavaSE  = 1 }
      }
      { $QIDsAdoptOpenJDK -contains $_ } {
        if (Get-YesNo "$_ Install newest Adopt Java JDK? ") { 
            wget "https://ninite.com/adoptjavax8/ninite.exe" -OutFile "$($tmp)\ninitejava8x64.exe"
            cmd /c "$($tmp)\ninitejava8x64.exe"
            $QIDsAdoptOpenJDK = 1
        } else { $QIDsAdoptOpenJDK = 1 }
      }
      { $QIDsVirtualBox -contains $_ } {
        if (Get-YesNo "$_ Install newest VirtualBox 6.1.36? ") { 
            wget "https://download.virtualbox.org/virtualbox/6.1.36/VirtualBox-6.1.36-152435-Win.exe" -OutFile "$($tmp)\virtualbox.exe"
            cmd /c "$($tmp)\virtualbox.exe"
            $QIDsVirtualBox = 1
        } else { $QIDsVirtualBox = 1 } 
      }
      { $QIDsDellCommandUpdate -contains $_ } {
        if (Get-YesNo "$_ Install newest Dell Command Update? ") { 
            #wget "https://dl.dell.com/FOLDER08334704M/2/Dell-Command-Update-Windows-Universal-Application_601KT_WIN_4.5.0_A00_01.EXE" -OutFile "$($tmp)\dellcommand.exe"
            cmd /c "\\server\data\secaud\Dell-Command-Update-Application_W4HP2_WIN_4.5.0_A00_02.EXE /s"
            $QIDsDellCommandUpdate  = 1
        } else { $QIDsDellCommandUpdate  = 1 }
      }
      { $QIDsAdobeReader -contains $_ } {
        if (Get-YesNo "$_ Install newest Adobe Reader DC? ") { 
            #  Adobe Reader DC - https://get.adobe.com/reader/download/?installer=Reader_DC_2021.007.20099_English_Windows(64Bit)&os=Windows%2010&browser_type=KHTML&browser_dist=Chrome&dualoffer=false&mdualoffer=true&cr=false&stype=7442&d=McAfee_Security_Scan_Plus&d=McAfee_Safe_Connect
            wget "https://get.adobe.com/reader/download/?installer=Reader_DC_2021.007.20099_English_Windows(64Bit)&os=Windows%2010&browser_type=KHTML&browser_dist=Chrome&dualoffer=false&mdualoffer=true&cr=false&stype=7442&d=McAfee_Security_Scan_Plus&d=McAfee_Safe_Connect" -OutFile "$($tmp)\readerdc.exe"
            cmd /c "$($tmp)\readerdc.exe"
            $QIDsAdobeReader = 1
        } else { $QIDsAdobeReader = 1 }
      }
      { $QIDsMicrosoftSilverlight -contains $_ } {
        $Products = (get-wmiobject Win32_Product | where { $_.IdentifyingNumber -like '{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00}'})
        if ($Products) {
            Remove-Software $Products
            $QIDsMicrosoftSilverlight = 1
        } else {
          Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
          $QIDsMicrosoftSilverlight = 1
        } 
      }
      { $QIDsSQLServerCompact4 -contains $_ } {
        $Products = (get-wmiobject Win32_Product | where { $_.IdentifyingNumber -like '{78909610-D229-459C-A936-25D92283D3FD}'})
        if ($Products) {
            Remove-Software $Products
            $QIDsSQLServerCompact4 = 1
        } else {
          Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
          $QIDsSQLServerCompact4  = 1
        } 
      }
      { $QIDsMicrosoftAccessDBEngine -contains $_ } {
        $Products = (get-wmiobject Win32_Product | where { $_.IdentifyingNumber -like '{90120000-00D1-0409-0000-0000000FF1CE}' -or `
                                                           $_.IdentifyingNumber -like '{90140000-00D1-0409-1000-0000000FF1CE}'})
        if ($Products) {
            Remove-Software $Products
            $QIDsMicrosoftAccessDBEngine = 1
        } else {
          Write-Host "[!] Guids not found: $Products !!`n" -ForegroundColor Red
          $QIDsMicrosoftAccessDBEngine = 1
        }
      }
      { $QIDsMicrosoftVisualStudioActiveTemplate -contains $_ } {
        $notfound = $true
        if (Get-YesNo "$_ $_ Install Microsoft Visual C++ 2005/8 Service Pack 1 Redistributable Package MFC Security Update? ") { 
          $Installed=get-wmiobject -class Win32_Product | ?{ $_.Name -like '*Microsoft Visual*'} # | Format-Table IdentifyingNumber, Name, LocalPackage -AutoSize
          if ($Installed | where {$_.IdentifyingNumber -like '{9A25302D-30C0-39D9-BD6F-21E6EC160475}'}) { 
              Write-Host "[!] Found Microsoft Visual C++ 2008 Redistributable - x86 "
              $notfound = $false
              wget "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe" -OutFile "$($tmp)\vcredist2008x86.exe"
              cmd /c "$($tmp)\vcredist2008x86.exe /q"
              $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | where { $_.IdentifyingNumber -like '{837b34e3-7c30-493c-8f6a-2b0f04e2912c}'}) {
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable"
            $notfound = $false
            wget "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -OutFile "$($tmp)\vcredist2005.exe"
            cmd /c "$($tmp)\vcredist2005.exe /q"
            $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | where { $_.IdentifyingNumber -like '{710f4c1c-cc18-4c49-8cbf-51240c89a1a2}'}) {
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable - x86"
            $notfound = $false
            wget "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -OutFile "$($tmp)\vcredist2005x86.exe"
            cmd /c "$($tmp)\vcredist2005x86.exe /q"
            $QIDsMicrosoftVisualStudioActiveTemplate = 1
          }
          if ($Installed | where { $_.IdentifyingNumber -like '{6E8E85E8-CE4B-4FF5-91F7-04999C9FAE6A}'}) { #x64
            Write-Host "[!] Found Microsoft Visual C++ 2005 Redistributable - x64 "
            $notfound = $false
            wget "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" -OutFile "$($tmp)\vcredist2005x64.exe"
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
            #>
      }
      { $QIDNVIDIAPrivEsc -contains $_ } {
        if (Get-YesNo "$_ Install newest Adobe Reader DC? ") { 
            $NvidiacardFound = $false
            Write-Host "[.] Video Cards found:"
            foreach($gpu in Get-WmiObject Win32_VideoController) {  
              Write-Host $gpu.Description
              if ($gpu.Description -like '*NVidia*') {
                $NvidiacardFound = $true
              }
            }
            if ($NvidiacardFound){
              Start-Process "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" -ArgumentList "https://www.nvidia.com/download/index.aspx"
              Write-Host "[!] Download and install latest NVidia drivers.. Manual fix."
            } else {
              Write-Host "[!] No NVIDIA Card found, should be save to remove."
              if (Get-YesNo "$_ Remove NVIDIA PrivEsc exe c:\windows\system32\nvvsvc.exe ? "
          ) { 
                cmd.exe /c "taskkill /f /im nvvsvc.exe"
                cmd.exe /c "del %windir%\System32\nvvsvc.exe"
              }
            }
        } else { $QIDNVIDIAPrivEsc = 1 }
      }
      19472 {
        if (Get-YesNo "$_ Install reg key for Microsoft SQL Server sqldmo.dll ActiveX Buffer Overflow Vulnerability - Zero Day (CVE-2007-4814)? ") { 
          # Set: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{10020200-E260-11CF-AE68-00AA004A34D5}  Compatibility Flags 0x400
          New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility" -Name "{10020200-E260-11CF-AE68-00AA004A34D5}"
          New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{10020200-E260-11CF-AE68-00AA004A34D5}" -Name "Compatibility Flags" -Value 0x400
        }
      }
	
      100269 {
        if (Get-YesNo "$_ Install reg keys for Microsoft Internet Explorer Cumulative Security Update (MS15-124)? ") { 
          New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
          New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Name "iexplore.exe" -Value 1
          New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
          New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Name "iexplore.exe" -Value 1
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
Remove-Item -Path "$tmp" -Force -ErrorAction SilentlyContinue
Stop-Transcript
if (!($Automated)) {
  $null = Read-Host "--- Press enter to exit ---"
}


