[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Automated = $false,    # this allows us to run without supervision and apply all changes (could be dangerous!)
  [switch] $Update = $false,       # This allows us to run through the GPOs that are NOT installed and install them. Any older versions would need to be removed manually.
  [switch] $Help                   # Allow -Help to display help for parameters
)

#$Verbose = $true 
Write-Verbose "[!] Running as Verbose: $Verbose"

<#
 #    ░██████╗░██████╗░░█████╗░░░░░░░████████╗░█████╗░░█████╗░██╗░░░░░░██████╗
 #    ██╔════╝░██╔══██╗██╔══██╗░░░░░░╚══██╔══╝██╔══██╗██╔══██╗██║░░░░░██╔════╝
 #    ██║░░██╗░██████╔╝██║░░██║█████╗░░░██║░░░██║░░██║██║░░██║██║░░░░░╚█████╗░
 #    ██║░░╚██╗██╔═══╝░██║░░██║╚════╝░░░██║░░░██║░░██║██║░░██║██║░░░░░░╚═══██╗
 #    ╚██████╔╝██║░░░░░╚█████╔╝░░░░░░░░░██║░░░╚█████╔╝╚█████╔╝███████╗██████╔╝
 #    ░╚═════╝░╚═╝░░░░░░╚════╝░░░░░░░░░░╚═╝░░░░╚════╝░░╚════╝░╚══════╝╚═════╝░
 #                 Alex Datsko - alexd@mmeconsulting.com - 2023
 #>

# Security GPO Installer - aka 'GPO Tools'
# Alex Datsko - MME Consulting Inc. - alex.datsko@mmeconsulting.com

$VersionMajor = "0.43"
$VersionMinor = "b23-08-25"
$Version = "$VersionLong $VersionShort"

<#
##########
# History
##########
 0.43 - Removed Security Group creation and modified script to not use them, they will not be maintained well over time and will cause confusion.
        Added Get-Yesno to main loop stuff for testing purposes etc.
        Added more Verbose text for bug fixing/reporting
 0.42 - ..Continued
 0.41 - Modified to become Create-MasteringGPOs.ps1
 0.40 - Few fixes, more on Root Org OU Picker
 0.39 - Worked on Root Org OU picker
 0.38 - Fixed DNS MaxUDPPacketSize bad permissions, 
 0.37 - Added option to Install WMI filters, set WMI filter for Windows update policy
 0.36 - Added Backup-ExistingGPOs before any changes are made, to new folder $GPOPath\Backup
 0.35 - Fixed the import of comments from CSV, via 3rd param of Create-SecurityGPO.  Fixed a reference to Autoplay security group that was hardcoded still, and had a space in it causing an error
 0.34 - Added CSV import ability, reimplemented skip import on same name, moved around GPO import logic a little in Create-SecurityPolicy
 0.33 - Installed STIG PolicyDefinitions into c:\Windows\PolicyDefinitions (or central policy store) - fixed some policy names to add 'CC' also
 0.32 - fixing all of the bugs.. a few like 
 0.31 - Turned off  name checking again, it will need a re-write.. Added ability to try to enable 2016 domain and forest functional level when turning on AD recycle bin
 0.30 - Large update - standardizing to MME Techdays 2022 standards - Renaming of many GPOs
          Removed auto-creation of OUs, fixed auto-creation of groups (location), added Pick-SecurityGroup, etc
 0.25 - Few fixes- Stopped creating Server OU in root, this is not going to be our standard, if any it should be in the OrgName OU which is technically not created in the script either.
        Updated Dell Workstation BIOS fix for TPM enable, script updated and it should only run the exe once now.
 0.24 - Refactored some code - created Check-OrgName, etc
 0.23 - Fixed a few more small issues, added major/minor version, added show-logo
 0.22 - Renamed all GPOs adding prefixes, Refactored adding of OUs, Added ability to link to Autoplay group with permissions
 0.21 - Fixed creation of OU's for Computers, Workstations, Laptops, and Security groups
 0.20 - Added creation of OU's for Workstations, Laptops, and security group for Autoplay Enabled
 0.10-0.19 - Basic script creation and adding of GUI features and extensibility for linking GPOs to correct OUs, etc.
#>

 # Known issues: 
#
#   Autoplay Enabled- New-GPLink giving exception 0x80072030
#   Get AD sec grp members of Autoplay group for list of computers (won't be listed when first checking, if already created and group members are added, but who cares I guess)

# CSV File to import GPOs from
$CSVFile = "GPOList.csv"
# Set default location to install Policy definitions - Central policy store would be "c:\windows\Sysvol\domain\policies\policydefinitions"
$PolicyDefFolder = "C:\Windows\PolicyDefinitions"
# Path to directory where backed up GPO's are stored. Default = Current location
$GPOPath = "$(Get-Location)\"
# Words to ignore... can be lower case, compared in 
$ignorelist = ("enable disable yes no set the last fix retry retries setting settings account guest administrator admin dc dns dhcp windows 7 8 8.1 10 2012 r2 2016 2019 office 2011 2013 explorer rce cve information disclosure vulnerability vuln - .").ToUpper()
# Global var of matched words when comparing strings
$matchedwords = ""
$OrgNamePicked = $false
$OrgNamePath = ""
$Date = Get-Date -Format "yyyy-MM-dd"
$Time = Get-Date -Format "HH:mm"
$DateTime = "$Date $Time"
Add-Type -AssemblyName PresentationFramework  # For MessageBox 
$AutoplayGroup="SEC - CC - Autoplay Enabled"
$AutoplayGroupSAM="SEC-CC-AutoplayEnabled"
$ServerGroup="SEC - CC - Servers"
$ServerGroupSAM="SEC-CC-Servers"
$CachedCredentialsGroup="SEC - CC - Cached Credentials Enabled"
$CachedCredentialsGroupSAM="SEC-CC-CachedCredentialsEnabled"

###################################################
function Show-Logo {
  param (
    $Version
  )
    Write-Host @"

    ░██████╗░██████╗░░█████╗░░░░░░░████████╗░█████╗░░█████╗░██╗░░░░░░██████╗
    ██╔════╝░██╔══██╗██╔══██╗░░░░░░╚══██╔══╝██╔══██╗██╔══██╗██║░░░░░██╔════╝
    ██║░░██╗░██████╔╝██║░░██║█████╗░░░██║░░░██║░░██║██║░░██║██║░░░░░╚█████╗░
    ██║░░╚██╗██╔═══╝░██║░░██║╚════╝░░░██║░░░██║░░██║██║░░██║██║░░░░░░╚═══██╗
    ╚██████╔╝██║░░░░░╚█████╔╝░░░░░░░░░██║░░░╚█████╔╝╚█████╔╝███████╗██████╔╝
    ░╚═════╝░╚═╝░░░░░░╚════╝░░░░░░░░░░╚═╝░░░░╚════╝░░╚════╝░╚══════╝╚═════╝░
"@
For ($i=0; $i -le 39-([math]::round($Version.length / 2)); $i++) { Write-Host " " -NoNewLine }
Write-Host $Version"
                Alex Datsko - alexd@mmeconsulting.com - 2023

"

}

###################################################
function Get-YesNo {
  param ([string]$prompt)

  $yesno = (Read-Host "[?] $prompt [Y]").toUpper()
  if (($yesno -eq "Y") -or ($yesno -eq "")) {
    return $true
  } 
  return $false
}

###################################################
function Get-YesNoOther {
  param ([string]$prompt)

  $yesno=" "
  While ("YNO?" -notcontains $yesno) {
    $yesno = (Read-Host "[?] $prompt [Y/n/o/?=help]").toUpper()
    if (($yesno -eq "Y") -or ($yesno -eq "")) {
      return "Y"
    } 
    if ($yesno -eq "N") {
      return "N"
    } 
    if ($yesno -eq "O") {
      return "O"
    } 
    if ($yesno -eq "?") {
      Write-Host "[!] Help: `n  Y=Yes, N=No, O=Link to other OU, ?=This text"
      return "?"
    } 
  }
}

##################################################
function Compare-Strings {

    param (
        $string1,
        $string2
    )

  $result = $false
  if ($string2.Length -gt 1) { # If comparing GPO has no name, do not compare..
    #Write-Host "String1:  [$string1] Length in words: [$($string1.split(' ').length)] Split: $($string1.split(' '))"
    #Write-Host "String2:  [$string2] Length in words: [$($string2.split(' ').length)] Split: $($string2.split(' '))"

    for ($j = 0; $j -le ($string2.split(' ').Count); $j++) {     # iterate through existing gpo name 
      for ($i = 0; $i -le ($string1.split(' ').Count); $i++) {   # iterate through import gpo name..
        #  current word number is $i , current word is  $string1.split(' ')[$i]
        $current = ($string1.split(' ')[$i])
        $existing = ($string2.split(' ')[$j])
        if (($current.length -gt 1) -and ($existing.length -gt 1)) {
          $current = $current.ToUpper()
          $existing = $existing.ToUpper()
          #Write-Host " Ignorelist: $Ignorelist `r`n Current: $Current"
          if ($ignorelist -like "*$($current)*") {
            #Write-Host "Ignoring word $current"
          } else {
            if ($existing -like "*$($current)*") {   
              # don't match 0 or 1 length words
              # even if the word exists inside another word in the existing GPO.. return true
             $matchedwords += $current
             $result = $true
              #Write-Host "Hit: $current -like *$($existing)*"
            }
          } 
        }
      }
    }
  }
  return $result
}

###################################################
function Get-CSVFile {
  param ([string]$CSVFile)
  
  $CSVWorking = $false

  if (!($CSVFile)) {
    $CSVFile = "GPOList.csv"
  }
  while (!$CSVWorking) {
    if (!(Test-Path $CSVFile)) {
      Write-Host "[!] CSV File not found : $($Pwd)\$($CSVFile)"
      $CSVFile = Read-Host "[?] Please enter the path to the list of GPOs to import ?"
    }
    $GPOs = Import-Csv -Path $CSVFile
    if ($GPOs) { $CSVWorking = $true } else {
      Write-Host "[!] Not able to read GPOs from $CSVFile !"
      Exit
    }
  }
  return $CSVFile
}


###################################################
function Pick-OU {
  param(
     $OUList )

  $done=0
  while (!($done)) {
    try { # Have user pick from a list of OU's
      if (!($OUList)) { 
        #Write-Verbose "[x] No OU list supplied, Choosing from all OUs.." 
        $OUList = (Get-ADOrganizationalUnit -filter *)    
      }
    } catch { 
      Write-Error "`r`n(Get-ADOrganizationalUnit -filter *) error listing domains!`r`n"
      Exit
    } 

    #Write-Verbose "(List of OUs)" 
    $i = 0
    foreach ($OU in $OUList) {
    Write-Host "$i : [$($OU.Name)] - $($OU.DistinguishedName)"
    $i += 1
    }
    $maxopt = $i
    Write-Host "$maxopt : <Done>"
    $input = Read-Host "Please pick the OU to apply to [$maxopt] "
    $choice = [int]$input
    Write-Verbose "Choice: $choice"
    if ($input -eq "") { $choice = [int]$i }  #If no input, do nothing.
    #Write-Host "Input : $input `r`nChoice : $choice" 
    if (!($choice -eq $maxopt) -and !($choice -eq "")) {  # make sure we have picked something, ignore if its DO NOT IMPORT or somehow blank string
      $DomainOUName = $OUList[$choice].Name
      $DomainString = $OUList[$choice].DistinguishedName
      #Write-Verbose "You have picked: $DomainOUName - $DomainString"
    } else {
      Write-Host "[!] WILL NOT IMPORT THIS POLICY. (or, nothing chosen)"
      Return $DomainString
    }
    
    # Validate choice:
    $choices = @()
    for ($j=0 ; $j -le $maxopt ; $j++) { $choices += [int]$j }  #Ugly.. Further validation that choice is an actual choice..
    #Write-Verbose "Choice : $choice `r`nChoices : $choices`r`nChoices contains choice : $($choices.Contains($choice))"
    if ($choices.Contains($choice)) {
      Write-Verbose "(Good choice made)" 
      $Done=1
    } else {
      Write-Host "[X] Error in selection." 
      # Instead, have them type the LDAP string??? 
      # Or, just pick from whats there.. duh
      #$IncorrectOU = 0
      #while ($IncorrectOU) {
      #  $DomainString = Read-Host "Please type domain LDAP path to use instead of $($DomainString)?  "
      #  if ([adsi]::Exists("LDAP://$($DomainString)")) { $IncorrectOU = 1 } else { Write-Host "LDAP://$($DomainString) not found!! Try again.." }
      #}
    }
  }   
  Write-Verbose "(Returning $DomainString)" 
  return $DomainString
}

###################################################
function Pick-Computer {
  param(
    $ADComputers )  # We can try to pass a smaller group of computers, just need Name, (DistinguishedName ?)
    
    # Have user pick from a list of Computers
    try { 
      if (!($ADComputers)) {    Write-host "[x] (No computers passed to Pick-Computer, selecting from all!)"; $ADComputers = (Get-ADComputer -filter *)    }
      # Add property to array to show if the Computer is selected
      $ADComputers | Add-Member -MemberType NoteProperty -Name "IsSelected" -Value $false -Force      

      $done = 0
      while (!($done)) {
          Write-Host "`r`n[ ] List of computers:"
          $i = 0
          foreach ($ADComputer in $ADComputers) {
            Write-Host "$i : [$($ADComputer.Name.PadLeft(20))] - $(if ($ADComputer.IsSelected -eq $true) { "[SELECTED]" } else { "[--------]" } ) - $($ADComputer.DistinguishedName)"
            $i += 1
          }
          $maxopt = $i
          Write-Host "$maxopt : DONE"
          $input = Read-Host "Add or remove computers to the list [$($maxopt)=Done] "
          $choice = [int]$input
          #Write-Host "Input : $input `r`nChoice : $choice" 
          if (!($input -eq "")) {  # make sure we have picked something, ignore if its the DONE (last) option or a blank string
            if ((!($choice -is [int])) -or (($choice -is [int]) -and ($choice -gt $maxopt))) {
              Write-Host "`r`n[X] Invalid option!"
            }
            if (($choice -is [int]) -and ($choice -lt $maxopt)) {
              if ($ADComputers[$choice].IsSelected) { 
                #Write-Host "Currently selected. " 
                $ADComputers[$choice].IsSelected = $false
              } else {   
                if (!($ADComputers[$choice].IsSelected)) { 
                  #Write-Host "Currently de-selected. " 
                  $ADComputers[$choice].IsSelected = $true 
                }
              }
              Write-Host "[o] You have picked the computer: $($ADComputers[$choice].Name). $(If ($ADComputers[$choice].IsSelected -eq $true) { "Added" } else { "Removed" })"
            }
          } else {
            Write-Host "[ ] No options selected"
            #Return
          }
          if ($choice -eq $maxopt) { $done = 1 }
      }
    } catch { 
      Write-Error "`r`n(Get-ADComputer -filter *) error listing computers!`r`n"
      #Exit
    } 
    # Turn list of computers into array of computer names, (also DNs as this is more helpful)
    $ComputerNames = @()
    $DNs = @()
    foreach ($ADComputer in $ADComputers) {
      if ($ADComputer.IsSelected) {
        #Write-Host "Found $ADComputer.Name selected"
        $ComputerNames += $ADComputer.Name
        $DNs += $ADComputer.DistinguishedName
      }
    }
    Write-Verbose "Returning: $DNs"
    return $DNs
}


###################################################
function Pick-Group {
# Have user pick from a list of Security Groups, or a passed list of security groups
  param(
    $ADGroups )  # We can try to pass a smaller group of computers, just need Name, (DistinguishedName ?)
    
    if ($ADGroups.count() -lt 1) {
      $ADGroups = Get-ADGroup -filter * 
    } else {
      # Already passed some groups.. Do nothing
    }
    try { 
      $ADGroups = Get-ADGroup -filter * 

      $ADGroups | Add-Member -MemberType NoteProperty -Name "IsSelected" -Value $false -Force      

      $done = 0
      while (!($done)) {
          Write-Host "`r`n[ ] List of groups:"
          $i = 0
          foreach ($ADgroup in $ADgroups) {
            Write-Host "$i : [$($ADgroup.Name.PadLeft(20))] - $(if ($ADgroup.IsSelected -eq $true) { "[SELECTED]" } else { "[--------]" } ) - $($ADgroup.DistinguishedName)"
            $i += 1
          }
          $maxopt = $i
          Write-Host "$maxopt : DONE"
          $input = Read-Host "Add or remove groups to the list [$($maxopt)=Done] "
          $choice = [int]$input
          #Write-Host "Input : $input `r`nChoice : $choice" 
          if (!($input -eq "")) {  # make sure we have picked something, ignore if its the DONE (last) option or a blank string
            if ((!($choice -is [int])) -or (($choice -is [int]) -and ($choice -gt $maxopt))) {
              Write-Host "`r`n[X] Invalid option!"
            }
            if (($choice -is [int]) -and ($choice -lt $maxopt)) {
              if ($ADgroups[$choice].IsSelected) { 
                #Write-Host "Currently selected. " 
                $ADgroups[$choice].IsSelected = $false
              } else {   
                if (!($ADgroups[$choice].IsSelected)) { 
                  #Write-Host "Currently de-selected. " 
                  $ADgroups[$choice].IsSelected = $true 
                }
              }
              Write-Host "[o] You have picked the group: $($ADgroups[$choice].Name). $(If ($ADgroups[$choice].IsSelected -eq $true) { "Added" } else { "Removed" })"
            }
          } else {
            Write-Host "[ ] No options selected"
            $choice = $maxopt
            #Return
          }
          if ($choice -eq $maxopt) { $done = 1 }
      }


    } catch { 
      Write-Error "`r`n(Get-ADGroup -filter *) error listing groups!`r`n"
      #Exit
    } 
    # Turn list of computers into array of computer names, (also DNs as this is more helpful)
    $GroupNames = @()
    $DNs = @()
    foreach ($ADGroup in $ADGroups) {
      if ($ADGroup.IsSelected) {
        #Write-Host "Found $ADComputer.Name selected"
        $GroupNames += $ADGroup.Name
        $DNs += $ADGroup.DistinguishedName
      }
    }
    Write-Verbose "Returning: $DNs"
    return $DNs
}


###################################################
Function Add-GPO {
  param(
     $GPO,
     $Domainstring,
     $GUID,
     $TargetName )
       
  Write-Verbose "GPO: $GPO"
  Write-Verbose "DomainString: $DomainString"
  Write-Verbose "GUID: $GUID"
  Write-Verbose "TargetName: $TargetName"

  $yesno = Get-YesNoOther "Link `r`n  Policy: [$($TargetName)] `r`n  OU: [$($DomainString)] "
  if (($yesno -eq "Y") -or ($yesno -eq "")) {
    #Write-Host "--GPO: $GPO"
    #Write-Host "--Using $DomainString "
    try { 
      $GPO | New-GPLink -Target "$DomainString" -LinkEnabled Yes -ErrorAction SilentlyContinue
      Write-Host "[+] Linked ""$TargetName"" to $DomainString" -ForegroundColor Green
    } catch {
      Write-Host "[!] ERROR: Couldn't linked ""$TargetName"" to $DomainString !" -ForegroundColor Red
    }
    return $true
  }
  if ($yesno -eq "O") {
    ### Pick an OU to link to...
    $Choice = Pick-OU (Get-ADOrganizationalUnit -filter *)
    # Validate choice:
    $choices = @()
    for ($j=0 ; $j -le $maxopt ; $j++) { $choices += [int]$j }  #Ugly.. Further validation that choice is an actual choice..
    #Write-Host "Choice : $choice `r`nChoices : $choices`r`nChoices contains choice : $($choices.Contains($choice))"
    if ($choices.Contains($choice)) {
      $yesno = (Read-Host "Link: Apply ( $TargetName ) to OU $DomainOUName [ $($DomainString) ]? [Y] ").toUpper()
      if (($yesno -eq "Y") -or ($yesno -eq "")) {
        Write-Host "Using $DomainString "
      } else {
        $IncorrectOU = 0
        while ($IncorrectOU) {
          $DomainString = Read-Host "Please type domain LDAP path to use instead of $($DomainString)?  "
          if ([adsi]::Exists("LDAP://$($DomainString)")) { $IncorrectOU = 1 } else { Write-Host "LDAP://$($DomainString) not found!! Try again.." }
        }
      }
      try {
        $GPO = Import-GPO -BackupId $GUID -TargetName $TargetName -path $GPOPath -CreateIfNeeded -ErrorAction SilentlyContinue #Already imported, but import again just in case, and to get output variable
        Write-Verbose "Imported policy: $TargetName [$GUID]"
      } catch {
        Write-Host "[!] ERROR: Couldn't import policy: $TargetName [$GUID]" -ForegroundColor Red
        exit
      }
      try { 
        ####### LINK TO OU #######
        Write-Host "Trying to Link : ( $TargetName ) to $DomainOUName [ $DomainString ]" -ForegroundColor Yellow
        $GPO | New-GPLink -Target $DomainString -LinkEnabled Yes
        Write-Host "[o] Linked $GPO to $DomainString !" -ForegroundColor Green
      } catch {
        Write-Host "[!] Error: could not link $($GPO.DisplayName) to $DomainString .. Passing" -ForegroundColor Red
        #exit
      }
    } else { # Should be doing somethign here... current bug..
    } 
  } else {
    Write-Host "[.] Skipping.."
  }
}

###################################################
Function Create-OU {   # Create an OU (refactored)
  param (
    $OUName,
    $NewOUString
  )
     try {
        Write-Host "[*] Creating new OU - [$($OUName)] in $NewOUString" -ForegroundColor Yellow
        New-ADOrganizationalUnit -Name "$($OUName)" -Path $NewOUString
      } catch {
        Write-Host "[!] Couldn't create new OU - [$($OUName)] in $NewOUString !! Exiting.." -ForegroundColor Red
        exit
      }
}

###################################################
Function Choose-OU {
  param(
     $GPO,
     $Domainstring,
     $GUID,
     $TargetName )
       
  $DomainString = Pick-OU (Get-ADOrganizationalUnit -filter *)

  Write-Verbose "(Returning DomainString $DomainString)" 
  return $DomainString 
}

###################################################
function Add-ComputersToAutoplayGroup {
  param (
    [string]$DomainString
  )

  <#  NO LONGER USING AFTER 08-25-23
    Write-Host "[ ] OU for computers: $DomainString .. Checking for security group for Autoplay .."
    
    # See if AD Security Group exists
    $ADSecGroups = Get-ADGroup -filter {groupCategory -eq 'Security'} | Select Name | Sort
    if (!($ADSecGroups -match $AutoplayGroup)) {
    # Create the SecurityGroup if needed
      $AutoplayGroup = New-ADGroup -Name $AutoplayGroup -SamAccountName $AutoplayGroupSAM -GroupCategory Security -GroupScope Global -Path $DomainString
    } else {
      $AutoplayGroup = Get-ADGroup -filter {groupCategory -eq 'Security'} | Where {$_.Name -eq $AutoplayGroup}
      Write-Host "[o] Autoplay Enabled group already exists."
    }

    # Determine workstations to add to group (Print out a list of all workstations, have user check them off)
    $ComputersToAdd = Pick-Computer   # Returns list of DNs
    # Add Workstations to SecurityGroup
    $ComputersToAdd | ForEach-Object { $AutoplayGroup | Add-ADGroupMember -members $_ }
    
    # Verify they were added:
    Write-Host "[ ] Autoplay Enabled group members (please verify): "
    $(($AutoplayGroup | Get-ADGroupMember).Name)
    #>
}

###################################################
function Check-OrgName {
  #Pick Orgname for OU
  Write-Host "[?] Please pick an OU to use as the Organization Root OU (if it exists, or pick the last option to create a new one.) "
  $OrgNameOU = $null
  while ($null -eq $OrgNameOU) {    # Repeat until valid OrgName is determined
    $OrgnameOU = Pick-OU
    if ($null -eq $OrgNameOU) { # if null after picking: 
      Write-Host "[.] This will be the OrgName OU.  All other sub-OU's should be office names."
      $inp = Read-Host "[?] Please type the name of the Organization.  (Or hit enter to skip..) "
      if (!($inp -eq "")) {
        if (Get-YesNo "You have picked [$($inp)] ? Are you sure") {
          New-ADOrganizationalUnit -Name "$($inp)" -Path "$((Get-ADDomain).DistinguishedName)" 
          $OrgnameOU = Get-ADOrganizationalUnit -Filter * | Where-Object { $_.Name -like "*$($inp)*" }
          $OrgnamePath = (Get-ADOrganizationalUnit -Filter * | Where-Object { $_.Name -like "*$($inp)*" }).DistinguishedName
          Write-Verbose "Created OrgName OU $OrgnameOU"
          return $OrgNamePath
        } else {
          Write-Host "[.] Okay, lets try again."
          $OrgNameOU = $null
        }
      } else {
        Write-Host "[!] Skipped.. Pick again or hit the last number to exit."
      }
    } else {
      if (Get-YesNo "You have picked [$($OrgNameOU)] ? Are you sure") {
        $OrgnameOU = Get-ADOrganizationalUnit -Filter * | Where-Object { $_.DistinguishedName -like "*$($OrgNameOU)*" }
        $OrgnamePath = (Get-ADOrganizationalUnit -Filter * | Where-Object { $_.DistinguishedName -like "*$($OrgNameOU)*" }).DistinguishedName
        return $OrgNamePath
      } else {
        Write-Host "[.] Okay, lets try again."
        $OrgNameOU = $null
      }
    }
  }
}

###################################################
function Create-PhysicalServerGroup {   # Create Server group, if it doesn't exist
    $OrgName = Check-OrgName

    $Servers = (Get-ADOrganizationalUnit -Filter {Name -like $OrgName}).DistinguishedName
    return $Servers
}

###################################################
function Create-ComputerOU {   # Create all computer OUs, if they doesn't exist
    Write-Host "[ ] Scanning for a Computer OU .." -ForegroundColor Yellow
    
    $OrgName = Check-OrgName
    $OUfound = $false
    $OUList = (Get-ADOrganizationalUnit -Filter *)
    $OUList | foreach-Object {   # See if Computer OU exists
        if ($_.Name -like "*Computers") { 
            $OUfound = $true
            Write-Host "[i] Computers OU found .. $_.Name " -ForegroundColor Green
            $DomainString = $_.DistinguishedName
        } 
    }
    if (!($OUfound)) {      # If not found, create new OU for computers
      try {
        $DomainString = (Get-ADDomainController | Select-Object  -ExpandProperty DefaultPartition)
      } catch {
        Write-Host "[X] Couldn't get Domain LDAP string : (Get-ADDomainController | Select-Object -ExpandProperty DefaultPartition)" -ForegroundColor Red
      }
      $done = $false
      while (!($OrgName)) {
        $OrgName = Read-Host "[?] What is the organization name (append this before 'Computers' for the computers OU "
        if ($OrgName) { $done = $true } else {
          Write-Host "[x] Please enter an organization name." -ForegroundColor Red
        }
      }
      Create-OU "$($OrgName) Computers" $DomainString
      $NewOUString = (Get-ADOrganizationalUnit -Filter {Name -like "*Computers"}).DistinguishedName
      Create-OU "Workstations" $NewOUString
      Create-OU "Laptops and Tablets" $NewOUString

    } else {               # Found Computers  OU, but lets make sure Workstations / Laptops is there also?

      $NewOUStrings = (Get-ADOrganizationalUnit -Filter {Name -like "*Computers"}).DistinguishedName
      
      # Need to check if one OU is root of others, i.e Practice Computers -> Office1 Computers , we don't want to make the 2 OUs in Practice Computers..
      # To be added....
    }
    
    Write-Verbose "  Domainstring: $DomainString"
    return $DomainString    # Return the LDAP path where we can create the Computers OUs, groups etc
}

###################################################
Function Create-SecurityGroup {
    param (
            [string] $Name,
            [string] $SAMAccountName,
            # Displayname will be the same as $SecGrp
            [string] $Path,
            [string] $Description
          )

    if (!($Name)) {
          Write-Host "[X] Can't create a securityGroup without at least a name." -ForegroundColor Red
          return $false
    }
    # Duplicated code...
    #$DomainString = Check-OrgName
    #Write-Host "Create-SecurityGroup - Check-Orgname returned $DomainString"
    #if (!($DomainString)) {
    #  Write-Host "[X] Couldn't find OrgName - please pick it from a list" -ForegroundColor Red
    #  $DomainString = Pick-OU
    #  Write-Host "Create-SecurityGroup - Pick-OU returned $DomainString"
    #}
    $DomainString = $Path

    if (!($Description)) { 
        $Description = $Name
    }

    if (!($SAMAccountName)) { 
        $SAMAccountName = $Name.replace(' ','').replace('_','').replace('(','').replace(')','') # Get rid of spaces, _, (, ) .. (- is okay)
    }

    # See if Security group exists already?
    $GroupExists = Get-ADGroup -Filter {Name -eq $Name } 
    if ($GroupExists) {
        Write-Host "[i] Security Group $(($GroupExists).Name) already exists" -ForegroundColor Green
        return $GroupExists.DistinguishedName
    } else {
        # Create Security group
        Write-Host "[!] Trying to create security group $Name" -ForegroundColor Yellow
        try {
          if ($Verbose) {
            Write-Host "  Name: `t`t`t`t$Name"
            Write-Host "  SAMAccountName: `t`t$SAMAccountName"
            Write-Host "  Description: `t`t`t$Description"
            Write-Host "  DomainString: `t`t$DomainString"
          }
            New-ADGroup -Name "$Name" -SamAccountName $SAMAccountName -GroupCategory Security -GroupScope Global -DisplayName "$Name" -Path "$DomainString" 
            Write-Host "[!] Created Security Group $Name - $SAMAccountName - $Description"  -ForegroundColor Yellow
        } catch {
            Write-Host "[X] Couldn't create Security Group $Name - $SAMAccountName - $Description"  -ForegroundColor Red
        }
    }
    $ReturnSecGrp = Get-ADGroup -Filter {Name -eq $Name }     # Should be able to find this now..
    return $ReturnSecGrp
}

###################################################
function Create-MasteredGPO {       # Mega loop for installing each GPO, per GPO logic starts here   ##############################################################
  param(
     [string] $GUID,
     [string] $TargetName,
     [string] $Comment)

  Write-Host "`r`n`r`n---------------------------------`r`n[.] Processing : $GUID - $TargetName"
  $Domainstrings = ""
  $DomainString = (Get-ADDomain | Select -expandproperty DistinguishedName)

  $GUID = $GUID.ToUpper()

  $GuidFolderNotFound=$false
  $GPOFolder="{$($GUID)}"
  if (test-path($GPOFolder)) { # Folder found, we are in correct directory
    #Write-Host "[o] $GPOFolder Folder found."
  } else {
    # Lets give the ability to have my powershell exported/renamed policies to be imported, in the format:
    #   SEC - CC - Auditing MegaGPO__{efdd58ef-2975-4f83-a411-29c21e7b0deb}
    $Results = gci . -filter "*$GUID*"
    if ($Results.Count -eq 1) { 
      $GPOFolder=$Results.Name
      # Have to rename them back, can't specify the location manually with Import-GPO ..
      Rename-Item "$($GPOPath)\$($GPOFolder)" "$($GPOPath)\{$($GUID.ToUpper())}" -Force
    } else {
      $GuidFolderNotFound=$true
    }
  } 
  if ($GuidFolderNotFound) { # GUID Folder not found
    Write-Host "`r`nERROR: Please run this in the BackupsGPOs folder where $GUID or $($TargetName)__$($GUID) can be found!`r`n"
    Write-Error "Exiting - $GUID - folder not found."
    exit
  }
  
  # Check if GPO exists, by name.. Not the best comparison obviously!!!  Future: Check by value set
  $ExistingGPOList = (Get-GPO -All)
  $poss = 1
  $skipchecking = $false
  foreach ($ExistingGPO in $ExistingGPOList) {
#    if ((Compare-Strings ($ExistingGPO.DisplayName) ($GPO.DisplayName)) -and !($skipchecking)) {   
    if (($($ExistingGPO.DisplayName) -eq $($GPO.DisplayName)) -and !($skipchecking)) {
      Write-Host "Duplicate Found.  NEW GPO: "  -NoNewLine
      Write-Host "[$($GPO.DisplayName)]" -ForegroundColor Gray -NoNewLine
      Write-Host " - EXISTING GPO: "  -NoNewLine
      Write-Host "[$($ExistingGPO.DisplayName)]" -ForegroundColor Gray
      #$yesno = (Read-Host "This GPO might already be loaded.  Skip [$($GPO.DisplayName)]? [Y,n,s=skip checking] ").toUpper()
      #if ($yesno -eq "S") { $skipchecking = $true ; Write-Host "Skipping All!!" }
      #if (($yesno -eq "Y") -or ($yesno -eq "")) {
      Write-Host "Skipping!"
      Return
      #}
      $poss += 1 
    }
  }

  Write-Verbose "Create-MasteredGPO right before Import-GPO: "
  Write-Verbose "GUID: $GUID"
  Write-Verbose "TargetName: $TargetName"
  Write-Verbose "GPOPath: $GPOPath"
  Write-Verbose "DomainString: $DomainString"
  Write-Verbose "Comment: $Comment"

  # Import GPO before special cases
  $GPO = Import-GPO -BackupId $GUID -TargetName $TargetName -path $GPOPath -CreateIfNeeded # -WhatIf 

  ##### Start of Special cases : Check for common possibilities of targeting another OU #####
  if ($TargetName -like "*DC/DNS*") {
    Write-Host "[!] Detected DC/DNS GPO, adding OU=Domain Controllers to LDAP string" -ForegroundColor White
    $DomainString = "OU=Domain Controllers,"+(Get-ADDomain | Select -expandproperty DistinguishedName)
  }

  if (($TargetName -like "*HVH*") -or ($TargetName -like "*Server*")) {
    Write-Host "[!] Detected Server GPO. Pick the OU to apply it to:" -ForegroundColor White
    $DomainString = Pick-OU
    <#
    # For the application to a specific security group only such as 'SEC - Servers'
    # No longer doing this, 08/25/23
    if ($DomainString) {
        #$LinkResults = $GPO | New-GPLink -Target $DomainString -LinkEnabled Yes
        # Can't link here or it will error out down below...
        $GPO | Set-GPPermission -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoRead -Replace
        $GPO | Set-GPPermission -TargetName $ServerGroupSAM -TargetType Group  -PermissionLevel GpoRead,GpoApply -Replace
    }
    #>
  }

  if ($TargetName -like "*Autoplay - Enable*") {
    if (Get-YesNo "Add the Autoplay - Enabled GPO? ") {
      Write-Host "[!] Detected Autoplay - Enable GPO.  Please pick the OU to apply this to." -ForegroundColor White
      #Add-ComputersToAutoPlayGroup
      $DomainString = Pick-OU

      <# Code removed 08-25-23 - For Security Group permissions. Now applying to OU
      # Need to have AT LEAST GpoRead permissions for Authenticated users to not get errors in Group Policy event log
      #$GPO = Import-GPO -BackupId $GUID -TargetName $TargetName -path $GPOPath 
      $GPO | Set-GPPermission -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoRead -Replace
      $GPO | Set-GPPermission -TargetName $AutoplayGroupSAM -TargetType Group -PermissionLevel GpoRead
      $GPO | Set-GPPermission -TargetName $AutoplayGroupSAM -TargetType Group -PermissionLevel GpoApply
      #>
    } else {
      Write-Host "[!] Note : will need to mention No again below" -ForegroundColor Yellow
    }
  }
  if ($TargetName -like "*Autoplay - Disable*") {
    if (Get-YesNo "Add the Autoplay - Disabled GPO? ") {
      #$Domainstring = Get-ADOrganizationalUnit -Filter 'Name -like "*Computers*"'  # Put this in the root, it will be overridden by the above one in Computers
      Write-Host "[!] Using default domain $DomainString for Autoplay - Disable .. " -ForegroundColor White
    } else {
      Write-Host "[!] Note : will need to mention No again below" -ForegroundColor Yellow
    }
  }

  if ($TargetName -like "*Credential Caching - Disable*") {
    if (Get-YesNo "Add the Credential Cachine - Disabled GPO? ") {
      Write-Host "[!] Detected Credential Caching GPO, Lets pick the OU it applies to.." -ForegroundColor White
      $WorkstationOU = Pick-OU
      if ($WorkstationOU) {
        if ($WorkstationOU -is [array]) {
          $DomainStrings = [System.Collections.Generic.List[string]]::new()
          $DomainStrings.Add($WorkstationOU)
        } else { 
          $DomainString = $WorkstationOU
        }
      }
    } else {
      Write-Host "[!] Note : will need to mention No again below" -ForegroundColor Yellow
    }
  }

  if ($TargetName -like "SEC - CC - Credential Caching - Enable*") {
    if (Get-YesNo "Add the Credential Cachine - Enabled GPO? ") {
      Write-Host "[!] Detected Credential Caching GPO, searching for Security Group 'Cached Credentials Enabled' .." -ForegroundColor White
      if ($OrgNamePath) {
          $DomainString = $OrgNamePath
      } else {
        $OrgNamePath = Pick-OU
      }
      $GPO | Set-GPPermission -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoRead -Replace
      $GPO | Set-GPPermission -TargetName $CachedCredentialsGroupSAM -TargetType Group  -PermissionLevel GpoRead
      $GPO | Set-GPPermission -TargetName $CachedCredentialsGroupSAM -TargetType Group  -PermissionLevel GpoApply
    } else {
      Write-Host "[!] Note : will need to mention No again below" -ForegroundColor Yellow
    }
  }
  
  ## Link to multiple OUs ##
  if ($Domainstrings) { 
    Write-Host "[ ] Multiple OUs targeted: $DomainStrings" -ForegroundColor Gray
    foreach ($domainstring in $Domainstrings) {
      Add-GPO -GPO $GPO -DomainString $Domainstring -GUID $GUID -TargetName $TargetName 
    }
  } else {
    Add-GPO -GPO $GPO -DomainString $Domainstring -GUID $GUID -TargetName $TargetName 
  }
  Write-Verbose "GPO.DisplayName: $($GPO.DisplayName)"
  (Get-GPO -Name ($GPO.DisplayName)).Description = $Comment      # Add comment to GPO

}

###################################################
function Replicate-AD {
  $yesno = (Read-Host "Run repadmin /syncall /APeD to replicate to all DCs? [Y] ").toUpper()
  if (($yesno -eq "Y") -or ($yesno -eq "")) {
    Write-Host "Running Repadmin:"
    $output = repadmin /syncall /APeD
    $yesno = (Read-Host "Display output? [Y] ").toUpper()
    if (($yesno -eq "Y") -or ($yesno -eq "")) {
      $output
    }
  } 
}

###################################################
function Backup-ExistingGPOs
{
  $BackupGPOPath="$($GPOPath)\Backup"
  Write-Output "[.] Checking for Backup folder in $GPOPath .."
  if (!(Test-Path "$BackupGPOPath")) {
    Write-Output "[.] Not found. Creating $($BackupGPOPath) .."
    New-Item -Type Directory "$BackupGPOPath"
  } else {
    Write-Output "[.] $BackupGPOPath exists."
  }
  $GPOs = Get-GPO -All
  $GPOs | ForEach {
    $_.DisplayName
    $Id = (Backup-GPO -Guid $_.Id -Path $BackupGPOPath).Id | Select -ExpandProperty Guid
    $_ | Add-Member -NotePropertyName "BackupId" -NotePropertyValue $Id
  }
  $GPOs | ForEach {
    Get-GPOReport -Guid $_.Id -ReportType Html -Path "$($BackupGPOPath)\{$($_.BackupId)}\$($_.DisplayName.replace('/',' '))).html"
    Rename-Item "$($BackupGPOPath)\{$($_.BackupId)}" "$($BackupGPOPath)\$($_.DisplayName.replace('/',' '))__{$($_.BackupId)}" -Force
  }
  Write-Output "[.] Current GPO Backup completed! Wrote to: $($BackupGPOPath)"
  #Write-Output "[.] Current GPO Backup completed! Opening in explorer, please make sure backups exist."
  #explorer.exe "$BackupGPOPath"
}

###################################################
function Check-DomainFunctionalLevel {
    Write-Host "Checking Domain functional level..."
    $Domain = Get-ADDomain | Select -expandproperty DistinguishedName
    $Func = (get-ADDomain | select -ExpandProperty DomainMode)
    $FunctionalLevelMatch =  $func -match "\d+"
    $FunctionalLevel = $matches[0]
    If ($FunctionalLevel -lt 2012) {
      # It seems like these are all okay on 2008 r2 functional level, so far..
      Write-Error "[X] NOTE: The functional level is $func .. Should be 2012 R2 or higher.. Proceed with caution."
      #exit
    } else {
      Write-Host "[o] Domain Functional level $func is >= 2012 R2 .. Good."
    }
    return $FunctionalLevel
}

###################################################
function Test-ADRecycleBin
{
    $enabledScopes = (Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes

    if ($enabledScopes) {
        Return $true
    }
    else {
        Return $false
    }
}

###################################################
function Enable-ADRecycleBin { 
  param (
         $FunctionalLevel
         )
 $Domain=$(Get-ADDomainController | select-Object -expand Domain)

  if ($FunctionalLevel -gt 2008) {
    if (!(Test-ADRecycleBin)) {
        $yesno = (Read-Host "Do you want to enable the AD Recycle bin on $($Domain) [Y]").toUpper()
        if (($yesno -eq "Y") -or ($yesno -eq "")) {
          Write-Verbose "[o] Enabling AD Recycle Bin Feature on $($Domain) .."
          try {
            Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADDomainController | select-Object -expand Domain) 
          } catch {
            Write-Host -Foreground Red -Background Black ($formatstring -f $fields)
            Write-Error "[!] Could not enable AD Recycle Bin Feature!!"
          }
        } else {
          Write-Verbose "[.] Skipping AD Recycle Bin Feature"
        }
    } else {
        Write-Host "[x] Skipping AD Recycle Bin Feature, already enabled!" -ForegroundColor Green
    }
  } else {
      Write-Host "[x] AD Recycle Bin Feature could not be turned on, functional level 2008 r2 or lower.  " -ForegroundColor Red
      $yesno = (Read-Host "[?] Would you like to try to raise the Forest functional level? [Y] ").toUpper()
      if (($yesno -eq "Y") -or ($yesno -eq "")) {
        Write-Host "[.] Setting Domain Functional Level to 2016.." -ForegroundColor Green
        Set-ADDomainMode -Identity $domain -DomainMode Windows2016Domain
        Write-Host "[.] Setting Forest Functional Level to 2016.." -ForegroundColor Green
        Set-ADForestMode -Identity $domain -ForestMode Windows2016Forest
        Write-Host "[.] Turning on AD Recycle Bin.." -ForegroundColor Green
        Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADDomainController | select-Object -expand Domain) 
        if (!(Test-ADRecycleBin)) {
          Write-Host "[x] AD Recycle Bin Feature could not be turned on, Some error occured!! Skipping...  " -ForegroundColor Red
        }
      }
  }
}

function Check-CentralPolicyStore {
  $TryPath = "$($env:windir)\SYSVOL\domain\Policies\PolicyDefinitions"
  if (test-path $TryPath) {
    Write-Host "`n[!] $TryPath found - Central Policy store in effect." -ForegroundColor Green
    return $TryPath
  }
  $TryPath = "$($env:windir)\PolicyDefinitions"
  if (test-path $TryPath) {
    Write-Host "`n[!] $TryPath found - No Central Policy store in effect." -ForegroundColor Yellow
    return $TryPath
  } else {
    Write-Host "`n[X] Is this machine a domain controller?  No $TryPath found!"
    Exit
  }
}

function Install-PolicyDefinitions {
  param (
    [string]$PolicyDefFolder
  )

  $Done = $false
  if (!($PolicyDefFolder)) {
    # Pick whether or not to do Central policy store?
    while (!($Done)) {
      $choice = (Read-Host "`n[?] Enter (1) to use C:\Windows\PolicyDefinitions, or (2) for Central Policy store location ($($env:systemroot)\SYSVOL\domain\policies\PolicyDefinitions) ").toUpper()
      if ($choice -eq '1') {
        $PolicyDefFolder = "$($env:systemroot)\PolicyDefinitions" 
        $Done = $true
      } else {
        if ($choice -eq '2') {
          $PolicyDefFolder = "C:\Windows\SYSVOL\domain\policies\PolicyDefinitions" 
          if (!(Test-Path -Path $PolicyDefFolder)) {
            Write-Host "[.] Creating $($PolicyDefFolder) .."
            New-Item -ItemType Directory $PolicyDefFolder -Force | Out-Null
          }
          $Done = $true
        } else {
          # If neither 1 or 2, pick the default policy store b
          Write-Host "`n[!] Please pick 1 or 2."
        }
      }
    }
    Write-Host "[.] Using $PolicyDefFolder"
  }
  
  $yesno = ""
  while (($yesno -ne "Y") -and ($yesno -ne "N")) {
      $yesno = (Read-Host "`n[?] Would you like to install the latest PolicyDefinitions to $($PolicyDefFolder) ? [y=yes,n=No,L=List] ").toUpper()
      if (($yesno -eq "L") -or ($yesno -eq "")) {
        if (!(Test-Path ".\PolicyDefinitions")) {  # If it was not backed up to folder but to zip file..
          Write-Host "[.] Checking for PolicyDefinitions backup file..."
          $PolicyStoreZip = (Get-ChildItem -Path "$($GPOPath)" -Filter *.zip) | where {$_.Name -like 'PolicyStore*'}
          if ($PolicyStoreZip -like "PolicyStore-*.zip") {
              Write-Verbose "PolicyStore Zip backup found: $PolicyStoreZip"
              # Test and see if Central PoliciesStore already exists?
              $PolicyStoreParent = "$($env:systemroot)\SYSVOL\domain\policies" # Since the archive was created with the PolicyDefinitions folder inside
              $PolicyStoreLocation = "$($PolicyStoreParent)\PolicyDefinitions"  # PolicyDefinitions will not exist, but policies will.
              $SkipPolicyStore = $false
              if (Test-Path "$($PolicyStoreLocation)\AcrobatReaderDC.admx") {  # Check the Central policy store
                $SkipPolicyStore = "$($PolicyStoreLocation)"
              }
              if (Test-Path "$($env:systemroot)\PolicyDefinitions\AcrobatReaderDC.admx") {  # Check the default policy store
                $SkipPolicyStore = "$($env:systemroot)\PolicyDefinitions"
              }
              if (!($SkipPolicyStore)) {
                  $inp = Read-Host "Create and restore to new Central policy store? [Y/n] "
                  if ($inp.ToUpper() -eq 'Y' -or $inp -eq "") { 
                    if (!(Test-Path -Path $PolicyStoreLocation)) {
                      Write-Host "[.] Creating Policy Store location.. $PolicyStoreLocation"
                      New-Item -ItemType Directory -Path $PolicyStoreLocation  -Force
                      if (!(Test-Path -Path $PolicyStoreLocation)) {
                        Write-Host "[!] Error, couldn't create $PolicyStoreLocation !! Exiting.."
                        Exit
                      }
                    }
                    Expand-Archive -Path "$($GPOPath)\$($PolicyStoreZip)" -DestinationPath "$PolicyStoreParent" -Force # -Verbose
                  } else {
                    $inp = Read-Host "Restore to default policy store $($env:systemroot)\PolicyDefinitions? [Y/n] "
                    if ($inp.ToUpper() -eq 'Y' -or $inp -eq "") {
                      $ADDomain = (Get-ADDomain).DNSRoot
                      $PolicyStoreLocation = "$($env:systemroot)\PolicyDefinitions"
                      Expand-Archive -Path "$($GPOPath)\$($PolicyStoreZip)" -DestinationPath "$PolicyStoreLocation" -Force # -Verbose
                    }
                  }
                  Write-Host "[+] PolicyStore backup extracted to $PolicyStoreLocation"
              } else {
                Write-Host "[!] Skipping Policy store backup extraction, Policy store items such as Adobe AcrobatReaderDC.admx found in $($SkipPolicyStore) !"
              }
          } else {
            Write-Host "[-] PolicyStore backup not found."
          }

        }
        if (Test-Path ".\PolicyDefinitions") {
          GCI ".\PolicyDefinitions"
        }
      }
      if ($yesno -eq "Y") {
        $pwd = Get-Location
        Write-Host "[.] Making backup of current policy definitions in $($PolicyDefFolder), saving as $($pwd)\PolicyDef-$($date).zip ..."
        Compress-Archive -Path "c:\Windows\PolicyDefinitions" -DestinationPath "$($pwd)\PolicyDef-$($date).zip" -Force
        Write-Host "[!] Installing policy definitions, overwriting any which may be there!!"
        Write-Host "[.] Copying ADMX files from $($pwd)\PolicyDefinitions to $PolicyDefFolder .."
        Copy-Item -Recurse -Force -Verbose ".\PolicyDefinitions\*.*" "$PolicyDefFolder"
        # 
        $PolicyLangFolder = "$($PolicyDefFolder)\$((Get-WinSystemLocale).Name)"
        if (!(test-path "$($PolicyLangFolder)")) { 
          Write-Host "[.] $($PolicyLangFolder) not found, creating.." -ForegroundColor Yellow
          New-Item -ItemType Directory -Path "$($PolicyLangFolder)\"
        }
        Write-Host "[.] Copying ADML files from $($pwd)\PolicyDefinitions\en-US to $($PolicyLangFolder) .."
        Copy-Item -Recurse -Force -Verbose ".\PolicyDefinitions\en-US\*.*" "$($PolicyLangFolder)"
        Write-Host "[!] Complete!`n"
      } 
      if ($yesno -eq "N") {
        Write-Host "[!] Skipping PolicyDefinitions installation.  NOTE: Some policies will not show properly if the policy definitions are not installed properly!"
        Write-Host "    To install, the raw admx file(s) must be installed in $($PolicyDefFolder), and the ADML files must be in $($PoliceDefFolder)\en-US. No other folders are necessary!`n"
      }
  }
}

function Install-WMIFilters {
  param (
    [string]$WMIFilterFolder
  )
  $yesno=""
  $MofFiles = GCI $WMIFilterFolder
  while (($yesno -ne "Y") -and ($yesno -ne "N")) {
      $yesno = (Read-Host "`n[?] Would you like to install the latest WMI Filters ? [y=yes,n=No,L=List] ").toUpper()
      if (($yesno -eq "L") -or ($yesno -eq "")) {
        $MofFiles
      }
      if ($yesno -eq "Y") {
        foreach ($MofFile in $MofFiles) {
          Write-Output "[.] Installing $($WMIFilterFolder)\$($MofFile.Name) .."
          mofcomp.exe -N:root\Policy $($WMIFilterFolder)\$($MofFile.Name)
        }
      } 
      if ($yesno -eq "N") {
        Write-Host "[!] Skipping WMI Filter MOF file installation.  NOTE: Some policies will not be filtered properly if these do not exist already!"
        Write-Host "    To install, you can use: mofcomp.exe -N:root\Policy <filename.mof>`n"
      }
  }
}
Function Test-PreviousGPOBackup {
  # Check for Previously extracted backup, i.e {1B71417C-EC55-4B1B-9AC0-84771062B24F}
  if (Test-Path $GPOPath) { 
    $CheckFolders = (gci -Path "$GPOPath" -Directory)
    ForEach ($F in $CheckFolders) {
      if ($F.Name -like "{*}") {
        $RemoveOldBackup=$true
        $OldBackupExample = ($F.Name)
      }
    }
    if ($RemoveOldBackup) {
        Write-Host "[!] Old backup folders found in $GPOPath : for example: $OldBackupExample"
        $inp = Read-Host "[?] Remove everything in $($GPOPath)? [Y/n] "
        if ($inp.ToUpper() -eq 'Y' -or $inp -eq "") {
          Remove-Item -Force -Recurse $GPOPath
        }
    }
  }
}

Function Test-GPOBackup {
  # Check for Backup Files
  $BackupFiles = Get-ChildItem -Path "$($pwd)" -Filter *.zip | where { $_.Name -like "backup*.zip" }
  if ($BackupFiles.Count -gt 1) {
    $BackupFile = $BackupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1  # Select newest backup*.zip
    return $BackupFile
  } else { 
    if ($BackupFiles.Count -eq 1) {
      $BackupFile = $BackupFiles 
      return $BackupFile
    } else { # 0 backup files found
      return $null
    }
  }
}

function Compare-BackupToPath {
  # Path to the folder to compare
  param ([string]$folderPath,
         [string]$zipPath)
<#
  # Compare the contents of the folder and the zip file
  $compareResult = Compare-Object $(Get-ChildItem $folderPath -Recurse | Select-Object FullName) $(Expand-Archive $zipPath -PassThru | Select-Object FullName) -Property FullName -IncludeEqual
  if ($CompareResult.Count -ne 0) { 
    return $True  # need to extract, there are differences
  } else {
    return $False
  }
#>
  return $true   # For now, this will take too long and code above doesn't work. Need to extract to temporary folder etc, more like:

  <#
  
  Import-Module Microsoft.PowerShell.Archive
  $tempFolderPath = "$env:temp"
  Expand-Archive -Path $zipFilePath -DestinationPath $tempFolderPath
  $diff = Compare-Object (Get-ChildItem $tempFolderPath -Recurse) (Get-ChildItem $folderPath -Recurse) -Property Name, Length -PassThru

  if ($diff) {
      Remove-Item -Path $folderPath -Recurse -Force
      Move-Item -Path $tempFolderPath\* -Destination $folderPath
  }

  Remove-Item -Path $tempFolderPath -Recurse -Force
 
  #>
}

Function Extract-GPOBackup {
  param ($BackupFile)
  if (Compare-BackupToPath $GPOPath $BackupFile) {
    Write-Host "[.] Found newest backup file $($BackupFile), extracting ..."
    Expand-Archive -Path $BackupFile -DestinationPath $pwd -Force # -Verbose
    if (!(Test-Path -Path "$GPOPath")) { 
      Write-Host "[!] Failed! $GPOPath not found.. Some error happened extracting $BackupFile to $GPOPath " 
      Exit 
    }     
  }
}

Function Check-GPOExists {
  param ([string]$gpoName)

  if (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue) {
    Write-Verbose "The GPO '$gpoName' exists."
    return $true
  } else {
    Write-Verbose "The GPO '$gpoName' does not exist."
    return $false
  }
}

Function Update-NewGPOsOnly {

  Write-Host "`n[!] Parameter -Update detected. Updating newest GPOs only." -ForegroundColor Green
  Write-Host "[!] Importing GPO List from CSV .."
  $CSVFile = Get-CSVFile
  $GPOs = Import-Csv -Path $CSVFile
  Write-Host "[!] Importing New GPOs only.."
  ForEach ($GPO in $GPOs) {
    if (!(Check-GPOExists $GPO.DisplayName)) {  # I guess we are back to checking by exact GPO DisplayName after all, and we can prune duplicates after by hand..
      Create-MasteredGPO $GPO.BackupId $GPO.DisplayName $GPO.Description
    }
  }
  exit
}


#########################################################################################################################################################
# MAIN 

Show-Logo $Version

if ($Update) {
  Update-NewGPOsOnly
}
<#
Test-PreviousGPOBackup
$BackupFile = Test-GPOBackup
if ($BackupFile) {
  Extract-GPOBackup $BackupFile
  $GPOPath = "$($pwd)\BackupGPO"  # Set new 'root' path as needed
  if (Test-Path "$($GPOPath)\GPOList.csv") {
    Write-Host "[!] Found $($GPOPath)\GPOList.csv, changing location to $GPOPath"
    Set-Location $GPOPath
  }
} else {
  Write-Host "[!] No Backup files found! Exiting."
  Exit
}
#>

$FunctionalLevel = Check-DomainFunctionalLevel
Enable-ADRecycleBin $FunctionalLevel

if (Get-YesNo "Backup Existing GPOs?") {
  Backup-ExistingGPOs
}

if (Get-YesNo "Install PolicyDefinitions?") {
  $PolicyStore = Check-CentralPolicyStore 
  Install-PolicyDefinitions $PolicyStore
}

Write-Host "`r`n[!] Creating necessary OU's and groups as needed: "
$OrgNamePath = Check-OrgName 

<# # Create MME Standard Security Groups - Disabled as of 08-25-2023
$AutoplaySecGrp = Create-SecurityGroup -Name $AutoplayGroup -SAMAccountName $AutoplayGroupSAM -Path $OrgNamePath
$ServerSecGrp = Create-SecurityGroup -Name $ServerGroup -SAMAccountName $ServerGroupSAM -Path $OrgNamePath
$CachedCredentialsEnabledSecGrp = Create-SecurityGroup -Name $CachedCredentialsGroup -SAMAccountName $CachedCredentialsGroupSAM -Path $OrgNamePath
#>

Write-Host "[!] Importing GPO List from CSV .."
$CSVFile = Get-CSVFile
$GPOs = Import-Csv -Path $CSVFile
Write-Host "[!] Importing GPOs .."
ForEach ($GPO in $GPOs) {
  Create-MasteredGPO $GPO.BackupId $GPO.DisplayName $GPO.Description
}

Write-Host "[!] Finished adding all policies." -ForegroundColor Yellow

Replicate-AD
Invoke-GPUpdate -Force
