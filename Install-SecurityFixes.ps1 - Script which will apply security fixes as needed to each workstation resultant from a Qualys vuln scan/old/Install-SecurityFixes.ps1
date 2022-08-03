#########################################
# Install-SecurityFixes.ps1
# Alex Datsko - alex.datsko@mmeconsulting.com
#

#Clear
# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Output "`n[!] Not running as Administrative user - Re-launching as admin!"
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $Command = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $Command
        Exit
 }
}

Write-Host "`r`n============================================================================================" -ForegroundColor DarkCyan
Write-Host "[i] Install-SecurityFixes.ps1" -ForegroundColor Cyan
Write-Host "[i]   v0.13 - Last modified: 8/02/22" -ForegroundColor Cyan
Write-Host "[i]   Alex Datsko - alex.datsko@mmeconsulting.com" -ForegroundColor Cyan
$hostname = $env:COMPUTERNAME
$datetime = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
Write-Host "[i] Date / Time : $datetime" -ForegroundColor Cyan
Write-Host "[i] Computername : $hostname" -ForegroundColor Cyan

$ServerName = "SERVER"           # Change as needed!

# NOTATE QIDS Used for specific apps (WIP!)

#    Note: to make these lists, copy large list of QIDs related to out of date app, 1 per line to a file
#          in linux, cat filename | sort | uniq | tr -s '\n' ','
#          delete the first and last comma if exists..

$QIDsChrome = 115077,115149,115166,119485,119493,119539,119601,119609,119627,119708,119743,119750,119773,119872,119930,119950,120059,120198,120220,120235,120297,120338,120405,120456,120560,120697,120725,120803,120812,120988,121201,121225,121283,121317,121362,121395,121485,121517,121583,121586,121622,121719,121757,121798,121813,121825,121840,121844,121893,122052,122075,122091,122127,122366,122485,122579,122630,122695,122725,122745,122829,122842,122867,123023,123141,123188,123196,123266,123364,123385,123501,123525,123570,123596,123704,123721,123740,123798,123869,123967,124153,124185,124379,124390,124410,124589,124693,124746,124758,124772,124865,124907,370005,370014,370067,370091,370109,370124,370134,370151,370162,370226,370249,370288,370339,370356,370376,370419,370446,370485,370546,370566,370613,370619,370643,370678,370691,370741,370763,370780,370808,370829,370889,370916,370950,370970,370974,370990,371003,371097,371172,371250,371268,371319,371327,371365,371378,371614,371639,371679,371692,371758,371771,371782,371820,371848,372020,372048,372050,372073,372111,372117,372166,372177,372186,372247,372286,372323,372342,372365,372403,372408,372410,372411,372438,372455,372476,372491,372517,372525,372534,372555,372572,372575,372576,372578,372579,372584,372630,372634,372636,372638,372639,372640,372829,372873,372894,373151,373319,373342,373368,373387,373421,373485,373510,373544,373714,373995,373998,374167,374531,374832,374876,375080,375091,375119,375319,375378,375426,375445,375459,375461,375505,375546,375595,375622,375638,375718,375738,375761,375784,375821,375846,375875,375883,375923,375948,375966,376000,376055,376140,376159
$QIDsFirefox = 370739,370747,370821,370827,370836,370938,370991,371026,371173,371216,371231,371276,371374,371615,371649,371702,371797,371841,371849,371851,372001,372061,372102,372136,372176,372190,372276,372324,372325,372392,372445,372481,372490,372825,373103,373120,373320,373326,373388,373490,373542,373989,374166,374576,374827,374918,375100,375209,375408,375478,375542,375606,375642,375712,375753,375824,375833,375945
$QIDsZoom = 371344,372477,372832,373366,375391,375487,375805,376046,376117 
$QIDsTeamviewer15 = 371174,372386,373335
$QIDsDropbox = 111111 # Dummy entry, none found yet
$QIDsOracleJava = 370280,370371,370469,370610,370727,370887,371079,371265,371528,371749,372013,372163,372333,372508,373156,373540,374873,375477,375729,375964
$QIDsAdoptOpenJDK = 376436,376423
$QIDsVirtualBox = 372509,372512,372542,373154,373553,374881,375481,375736,375967
$QIDsAdobeReader = 116893,117797,118087,118319,118438,118486,118670,118782,118956,119053,119076,119145,119594,119768,119838,120103,120295,120777,120866,121176,121442,121711,121867,122484,122663,123021,123265,123579,123662,124151,124506,124767,370084,370154,370277,370364,370499,370650,375845,375953
$QIDsIntelGraphicsDriver = 370842,371696,371263
$QIDNVIDIAPrivEsc = 370263
$QIDSpectreMeltdown = 91537,91462,91426,91428
$QIDsMicrosoftAccessDBEngine= 106067,106069
$QIDsSQLServerCompact4 = 106023
#{78909610-D229-459C-A936-25D92283D3FD} Microsoft SQL Server Compact 4.0 SP1 x64 ENU

Start-Transcript

function Remove-Software {
  param ($Products)

    $Guid = $Products | Select -ExpandProperty IdentifyingNumber
    $Name = $Products | Select -ExpandProperty Name
    $yesno = Read-Host "[ ] Uninstall $Name - $Guid [n] "
    if ($yesno.ToUpper()[0] -eq 'Y') { 
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

function Find-LocalCSVFilename {
  param ([string]$Location)

    # FIGURE OUT CSV Filename
    $i = 0
    [array]$Filenames = Get-ChildItem "$($Location)\*.csv" | % { $_.Name }
    $Filenames | Foreach-Object {
      Write-Host "[$i] $_" -ForegroundColor Blue
      $i += 1
    }
    Write-Host "[$i] EXIT" -ForegroundColor Blue
    $Max = $i
    $Selection = Read-Host "Select file to import, [Enter=Exit] ?"
    if (($Selection -eq "") -or ($Selection -eq $i)) { Write-Host "[-] Exiting!" -ForegroundColor Gray ; exit }
    $Sel = [int]$Selection
    if (@($Filenames).length -gt 1) {
      $CSVFilename = $Filenames[$Sel]
    } else {
      if (@($Filenames).length -gt 0) {
        $CSVFilename = $Filenames  # If there is only 1, we are only grabbing the first letter above.. This will get the whole filename.
      }
    }
    Write-Host "[i] Picked file: $CSVFileName" -ForegroundColor Blue
    Return $CSVFileName
}

function Find-ServerCSVFile {
  param ([string]$Location)
  if (!($null -eq $Location)) { $Location = "data\secaud" }
  if (Test-Path "\\$($ServerName)\$($Location)") {
    $CSVFilename=(gci "\\$($ServerName)\$($Location)" -Filter "*.csv" | sort LastWriteTime | select -last 1).FullName
    Write-Host "[i] Found file: $CSVFileName" -ForegroundColor Blue
    return $CSVFilename 
  } else {
    return $null
  }
}

if (!(Test-Path C:\Temp)) {
  try {
    Write-Host "[ ] Creating c:\Temp .." -ForegroundColor Gray
    New-Item C:\Temp -ItemType Folder
  } catch {
    Write-Host "[X] Couldn't create folder C:\Temp !! This is needed for temporary storage." -ForegroundColor Red
    Exit
  }
}

Set-Location "C:\Temp"  # Cmd.exe cannot be run from a server share

$CSVFilename = Find-ServerCSVFile "$($ServerName)"
if (!(Test-Path $CSVFilename)) {
  $CSVFilename = Find-LocalCSVFile "."
}
# READ CSV
if (!(Test-Path($CSVFilename))) {
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
        $yesno = Read-Host "[ ] QID376023- Remove SupportAssist ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
          $guid = (Get-Package | ?{$_.Name -like "*SupportAssist*"})
          if ($guid) {  ($guid | select -expand FastPackageReference).replace("}","").replace("{","")  }
          msiexec /x $guid /qn /L*V "C:\temp\SupportAssist.log" REBOOT=R
          
          # This might require interaction, in which case run this:
          msiexec /x $guid /L*V "C:\temp\SupportAssist.log"

          # Or:
          # ([wmi]"\\$env:computername\root\cimv2:Win32_Product.$guid").uninstall()   
        }
      }
      105228 { 
        $yesno = Read-Host "[ ] QID105228 - disable guest account and rename ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
            Rename-LocalUser -Name "Guest" -NewName "GuestAcctNew" | Disable-LocalUser
        }
      }
      { $QIDSpectreMeltdown -contains $_ } {
        $yesno = Read-Host "[ ] QID91537,91462,91426 - spectre/meltdown ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 0 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f'
            #cmd /c 'reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" '
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f'
            $QIDSpectreMeltdown = 1
        } else { $QIDSpectreMeltdown = 1 }
      }
      91738 {
        $yesno = Read-Host "[ ] QID 91738(?) - fix ipv4 source routing bug/ipv6 global reassemblylimit? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') { 
            netsh int ipv4 set global sourceroutingbehavior=drop
            Netsh int ipv6 set global reassemblylimit=0
        }
      }
      375589 {  
        $yesno = Read-Host "[ ] QID375589 - Delete Dell DbUtil_2_3.sys ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
            cmd /c 'del c:\users\dbutil_2_3*.sys /s /f /q'
        }
      }
      100413 {
        $yesno = Read-Host "[ ] QID100413 - CVE-2017-8529 - IE Feature_Enable_Print_Info_Disclosure fix ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" /v iexplore.exe /t REG_DWORD /d 1 /f'
        }
      }
      { 105170,105171 -contains $_ } { 
        $yesno = Read-Host "[ ] QID105170, QID105171 - Windows Explorer Autoplay not Disabled ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
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
        $yesno = Read-Host "[ ] QID90044 - Allowed SMB Null session ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f'
        }
      }
      90007 {
        $yesno = Read-Host "[ ] QID90007 - Enabled Cached Logon Credential ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f'
        }
      }
      90043 {
        $yesno = Read-Host "[ ] QID90043 - SMB Signing Disabled / Not required ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters"  /v EnableSecuritySignature /t REG_DWORD /d 1 /f'
            cmd /c 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters"  /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
        }
      }
      91805 {
        $yesno = Read-Host "[ ] QID91805 - Remove Windows10 UpdateAssistant? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
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
        ####################################################### Installers #######################################
        # Install newest apps via Ninite

      372348 {
        $yesno = Read-Host "[ ] QID372348 - Intel Chipset INF util ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
            wget "https://downloadmirror.intel.com/30553/eng/setupchipset.exe" -OutFile c:\Temp\setupchipset.exe
            cmd /c '"c:\temp\setupchipset.exe" -s -accepteula  -norestart -log "c:\temp\intelchipsetinf.log"'
        }
      }
      372300 {
        $yesno = Read-Host "[ ] QID372300 - Intel RST ? [n] " ; if ($yesno.ToUpper()[0] -eq 'Y') {
            wget "https://downloadmirror.intel.com/655256/SetupRST.exe" -OutFile c:\Temp\setuprst.exe
            cmd /c '"c:\temp\setuprst.exe" -s -accepteula -norestart -log "c:\temp\intelrstinf.log"'
            # OR, extract MSI from this exe and run: 
            # msiexec.exe /q ALLUSERS=2 /m MSIDTJBS /i “RST_x64.msi” REBOOT=ReallySuppress
        }   
      }
      { $QIDsIntelGraphicsDriver  -contains $_ } {
        $yesno = Read-Host "[ ] QID $_ Install newest Intel Graphics Driver? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
            #  Intel Graphics driver - https://www.intel.com/content/www/us/en/support/products/80939/graphics.html
            $CPUName = (gwmi win32_processor).Name
            if ($CPUName.Contains("i3-")) { 
              $CPUModel=$CPUName.split('-')[1].split(' ')[0]   # Hope this stays working.. Looks good here.
              $CPUGeneration = $CPUModel[0]
              # Use this to pick the correct driver from the Intel page..
            
            } else {
              if ($CPUName -contains "i5") { 
              } else {
                if ($CPUName -contains "i7") { 
                } else {
                  if ($CPUName -contains "i9") { 
                    $rest=$CPUName.split('i9-')[1]
                    $rest
                    exit
                  } else {
                    Write-Output "[X] Error: No Intel CPU found!"
                    exit
                  }
                }
              }
            }
            wget "https://downloadmirror.intel.com/30196/a08/win64_15.40.5171.exe" -OutFile c:\Temp\intelgraphics.exe
            cmd /c 'c:\temp\intelgraphics'
            $QIDsIntelGraphicsDriver = 1 # All done, remove variable to prevent this from running twice
        } else { $QIDsIntelGraphicsDriver=1 }
      }
 
      { $QIDsChrome -contains $_ } {
        $yesno = Read-Host "[ ] Install newest Google Chrome? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
            #  Google Chrome - https://ninite.com/chrome/ninite.exe
            wget "https://ninite.com/chrome/ninite.exe" -OutFile c:\Temp\ninite.exe
            cmd /c 'c:\temp\ninite.exe'
            $QIDsChrome = 1 # All done, remove variable to prevent this from running twice
        } else { $QIDsChrome = 1 }
      }
      { $QIDsFirefox -contains $_ } {
        $yesno = Read-Host "[ ] Install newest Firefox? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
            #  Firefox - https://ninite.com/firefox/ninite.exe
            wget "https://ninite.com/firefox/ninite.exe" -OutFile c:\Temp\ninite.exe
            cmd /c 'c:\temp\ninite.exe'
            $QIDsFirefox = 1
        } else { $QIDsFirefox = 1 }
      }
      { $QIDsZoom -contains $_ } {
        $yesno = Read-Host "[ ] Install newest Zoom Client? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
            #  Zoom client - https://ninite.com/zoom/ninite.exe
            wget "https://ninite.com/zoom/ninite.exe" -OutFile c:\Temp\ninite.exe
            cmd /c 'c:\temp\ninite.exe'
            $QIDsZoom = 1
        } else { $QIDsZoom = 1 }
      }
      { $QIDsTeamViewer15 -contains $_ } {
        $yesno = Read-Host "[ ] Install newest Teamviewer 15? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
            #  Teamviewer - https://ninite.com/teamviewer15/ninite.exe
            wget "https://ninite.com/teamviewer15/ninite.exe" -OutFile c:\Temp\ninite.exe
            cmd /c 'c:\temp\ninite.exe'
            $QIDsTeamViewer15 = 1
        } else { $QIDsTeamViewer15 = 1 }
      }
      { $QIDsDropbox -contains $_ } {
        $yesno = Read-Host "[ ] Install newest Dropbox? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
            #  Dropbox - https://ninite.com/dropbox/ninite.exe
            wget "https://ninite.com/dropbox/ninite.exe" -OutFile c:\Temp\ninite.exe
            cmd /c 'c:\temp\ninite.exe'
            $QIDsDropbox = 1
        } else { $QIDsDropbox = 1 }
      }
  
        ############################
        # Others: (non-ninite)
  
      { $QIDsOracleJava -contains $_ } {
        $yesno = Read-Host "[ ] Install newest Oracle Java 17? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
            #  Oracle Java 17 - https://download.oracle.com/java/17/latest/jdk-17_windows-x64_bin.msi
            wget "https://download.oracle.com/java/17/latest/jdk-17_windows-x64_bin.msi" -OutFile c:\Temp\java17.msi
            msiexec /i 'c:\temp\java17.msi' /qn /quiet /norestart
            $QIDsOracleJava = 1
        } else { $QIDsOracleJava = 1 }
      }
      { $QIDsAdoptOpenJDK -contains $_ } {
        $yesno = Read-Host "[ ] Install newest Adopt Java JDK? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
            wget "https://ninite.com/adoptjavax8/ninite.exe" -OutFile c:\Temp\ninitejava8x64.exe
            cmd /c "c:\temp\ninitejava8x64.exe"
            $QIDsAdoptOpenJDK = 1
        } else { $QIDsAdoptOpenJDK = 1 }
      }
      { $QIDsVirtualBox -contains $_ } {
        $yesno = Read-Host "[ ] Install newest VirtualBox 6.1.30? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
            #  Virtualbox - https://download.virtualbox.org/virtualbox/6.1.30/VirtualBox-6.1.30-148432-Win.exe
            wget "https://download.virtualbox.org/virtualbox/6.1.30/VirtualBox-6.1.30-148432-Win.exe" -OutFile c:\Temp\virtualbox6.1.30.exe
            cmd /c 'c:\temp\virtualbox6.1.30.exe'
            $QIDsVirtualBox = 1
        } else { $QIDsVirtualBox = 1 } 
      }
      { $QIDsAdobeReader -contains $_ } {
        $yesno = Read-Host "[ ] Install newest Adobe Reader DC? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
            #  Adobe Reader DC - https://get.adobe.com/reader/download/?installer=Reader_DC_2021.007.20099_English_Windows(64Bit)&os=Windows%2010&browser_type=KHTML&browser_dist=Chrome&dualoffer=false&mdualoffer=true&cr=false&stype=7442&d=McAfee_Security_Scan_Plus&d=McAfee_Safe_Connect
            wget "https://get.adobe.com/reader/download/?installer=Reader_DC_2021.007.20099_English_Windows(64Bit)&os=Windows%2010&browser_type=KHTML&browser_dist=Chrome&dualoffer=false&mdualoffer=true&cr=false&stype=7442&d=McAfee_Security_Scan_Plus&d=McAfee_Safe_Connect" -OutFile c:\Temp\readerdc.exe
            cmd /c 'c:\temp\readerdc.exe'
            $QIDsAdobeReader = 1
        } else { $QIDsAdobeReader = 1 }
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
      { $QIDNVIDIAPrivEsc -contains $_ } {
        $yesno = Read-Host "[ ] Install newest Adobe Reader DC? [n] "
        if ($yesno.ToUpper()[0] -eq 'Y') { 
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
              $yesno = Read-Host "[ ] Remove NVIDIA PrivEsc exe c:\windows\system32\nvvsvc.exe ? [n] "
              if ($yesno.ToUpper()[0] -eq 'Y') { 
                cmd.exe /c "taskkill /f /im nvvsvc.exe"
                cmd.exe /c "del %windir%\System32\nvvsvc.exe"
              }
            }
        } else { $QIDNVIDIAPrivEsc = 1 }
      }

      Default {
        Write-Host "[X] Skipping QID $_ : " -ForegroundColor Red -NoNewline
        Write-Host "$ThisTitle" -ForegroundColor White
      }
    }
}

Write-Host "[o] Done! Stopping transcript" -ForegroundColor Green
Stop-Transcript
$null = Read-Host "--- Press enter to exit ---"

