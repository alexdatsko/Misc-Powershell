#####################################
#
# Check-BackupSizes.ps1 - v1.90
#
# 5/22/2020 Alex Datsko 
#
# Gets a list of the size of the backup TIB files and compares it to the size of the drives being backed up to make sure backups completed successfully
# Currently we have the ability to check 2 different backups which can span 3 different physical drives, but this could easily be modified 
# Leave any of the locations/paths blank below to ignore this job, they can be added safely in the future if needed


### CHANGE THESE TO MATCH THE ENVIRONMENT
$PortablePath="E:\Daily Server Backup.TIB"                             # Onsite backup job TIB location, or Veeam backup folder
$PortableLocation1="C:"                                                # Locations of data backed up in Portable job
$PortableLocation2="D:"
$PortableLocation3=""

$OnsitePath="F:\Daily Server Backup.TIB"                               # Onsite backup job TIB location, or Veeam backup folder
$OnsiteLocation1="C:"                                                  # Locations of data backed up in Onsite job
$OnsiteLocation2="D:"
$OnsiteLocation3=""

$AdditionalPath=""                                                     # Additional backup job Backup location (i.e iSCSI, NAS, NVR, Bulk storage for other purposes)
$AdditionalLocation1=""                                                # Locations of data backed up in additional jobs
$AdditionalLocation2=""
$AdditionalLocation3=""

$ReportPath="C:\Backups (Do Not Delete)\Reports\BackupSize\"           # This is where the monthly reports will be saved
$SizeDiffThreshold=.05                                                 # This is the percentage difference in size that is allowable, i.e .10 = 10%, .03 = 3%
###

function Init-BackupSize 
{
    if ([System.Diagnostics.EventLog]::Exists('Veeam Agent')) {  # just because the log is there doesn't mean it's installed
      if (test-path($env:ProgramFiles+"\Veeam\Endpoint Backup\Veeam.EndPoint.Backup.exe")) {  # more likely actually in use
        $Using_Veeam=1
        Write-Host "Veeam in use here!"
      } else { Write-Host "No veeam!" }
    } else { Write-Host "No veeam!" }

    Write-EventLog -LogName "MME" -Source "Backup Sizes" -EventId 10700  -EntryType Information -Message "Backup Sizes script started"

    if (![System.Diagnostics.EventLog]::Exists('MME')) {
        New-EventLog -LogName "MME" -Source "Backup Sizes"    # Create MME log / Source "Backup Sizes" if it doesn't exist
    }

    $Year = Get-Date -format "yyyy" 
    $YearMonth = Get-Date -format "yyyy-MM"
    $LastMonth = (Get-Date).AddMonths(-1) -f "yyyy-MM"
    $DateTime = Get-Date -format "yyyy-MM-dd hh:mm"
    # Create year folder if it doesn't exist
    try {
      $FullReportPath = $ReportPath + $Year
      New-Item -ItemType Directory -Force -Path $FullReportPath | Out-Null
    } catch {
      write-host "Error creating folder $FullReportPath !!"
      Write-EventLog -LogName "MME" -Source "Backup Sizes" -EventId 703  -EntryType Information -Message "Couldn't create folder $FullReportPath"
      exit
    }
}

function Check-VeeamLogs() {
  if ($Using_Veeam) {
    write-host "Veeam detected, checking for last backups through Windows Event logs.."
    $Yesterday = (Get-Date) - (New-TimeSpan -Day 1)

    #Log Name:      Veeam Agent
    #Source:        Veeam Agent
    #Date:          6/19/2020 11:49:40 PM
    #Event ID:      190
    #Task Category: None
    #Level:         Information
    #Keywords:      Classic
    #User:          N/A
    #Computer:      Server
    #Description:
    #Veeam Agent 'PSMA2HVH' finished with Success.
    #Job details: Computer has been backed up successfully.
    
    # THIS IS BROKEN AND IM TOO FRUSTRATED TO CONTINUE.....
    $Results = (Get-WinEvent -LogName 'Veeam Agent' | Where-Object { $_.TimeCreated -ge $Yesterday -and $_.Id -eq 190 }) | fl TimeCreated,Id,Message
    # THIS WORKS
    $TimeCreated = (Get-WinEvent -LogName 'Veeam Agent' | Where-Object { $_.TimeCreated -ge $Yesterday -and $_.Id -eq 190 }) | select-object -expand TimeCreated
    $Id = (Get-WinEvent -LogName 'Veeam Agent' | Where-Object { $_.TimeCreated -ge $Yesterday -and $_.Id -eq 190 }) | select-object -expand Id
    $Message = (Get-WinEvent -LogName 'Veeam Agent' | Where-Object { $_.TimeCreated -ge $Yesterday -and $_.Id -eq 190 }) | select-object -expand Message
    # THIS DOESN'T
    #Out-Host "Event ID: $Results.Id"
    #Out-Host "Message: $Results.Message"
    foreach ($r in $Results) {
      foreach-object ($r) {
        Out-Host "$_.Id-$_.TimeCreated-$_.Message"
      }
    }
    #Search out the actual files.  Let's check the backup folder for newest Folders.

    Write-EventLog -LogName "MME" -Source "Backup Sizes" -EventId 10700  -EntryType Information -Message "Result: "
  }
}

function Get-FreeSpace()   #DONE
{  
 param (
   [Parameter(Mandatory=$true, Position=0)]
   [string] $DiskLocation     # Should be 'C:' , 'D:' etc:
  )

  if ($DiskLocation -ne "") {
    $d = $Disklocation[0]
    if (($Disklocation[1] -ne ":") -or (($d -ne "A") -and ($d -ne "B") -and ($d -ne "C") -and ($d -ne "D") -and ($d -ne "E") -and ($d -ne "F") -and ($d -ne "G") -and ($d -ne "H"))) {
      #something wrong if none of these conditions match..
      return -1
    }
    $size = (get-wmiobject win32_logicaldisk -computername localhost -filter "deviceID='$DiskLocation'" | select-object -expand size) / 1gb
    $free = (get-wmiobject win32_logicaldisk -computername localhost -filter "deviceID='$DiskLocation'" | select-object -expand freespace) / 1gb
    [Math]::floor($size - $free)
  } else {
    -2     # return -2 if disklocation is blank.. shouldn't get her ebecause parameter is mandatory.
  }
  return
}

function Create-BackupSizeReport()
{
 param (
   [Parameter(Mandatory=$true, Position=0)]
   [system.Object] $BackupName, 
   [Parameter(Mandatory=$true, Position=1)]
   [string] $BackupFilePath, 
   [Parameter(Mandatory=$true, Position=2)]
   [string] $Location1, 
   [Parameter(Mandatory=$false, Position=3)]
   [string] $Location2, 
   [Parameter(Mandatory=$false, Position=4)]
   [string] $Location3
 )  
  if ($BackupFilePath[-1] -eq '\') { 
    # if trailing character is a backslash, this is a folder.  We want to examine individual files in it
    # get a list of newest files by date
    # get newest filename
    # check if incremental file or full backup

    
  }

  write-Host "[1] Getting file/disk sizes for $BackupName .."
  
  if (!(test-path($BackupFilePath))) { 
    $message = "$BackupFilePath not found, or permission issue!!"
    $message
    Write-EventLog -LogName "MME" -Source "Backup Sizes" -EventId 704  -EntryType Error -Message $message
    exit
  }
  $BackupSize = (get-item $BackupFilePath).Length / 1gb

  if ($Location1 -ne "") { $Loc1Size = Get-FreeSpace($Location1) }
  if ($Location2 -ne "") { $Loc2Size = Get-FreeSpace($Location2) }
  if ($Location3 -ne "") { $Loc3Size = Get-FreeSpace($Location3) }
  $LocationSizes = $Loc1Size+$Loc2Size+$Loc3Size
  
  write-Host "[2] Calculating backup report for $BackupJob .."
  
  # Check if the TIB is much smaller or bigger than it should be calculated by drive sizes
  $SizeDiff = $LocationSizes - $BackupSize
  if ($SizeDiff -lt 0) { write-host "Backup size smaller than drive size by $SizeDiff" } #smaller 
  if ($SizeDiff -gt 0) { write-host "Backup size larger than drive size by $SizeDiff" } #larger
  if ($SizeDiff -eq 0) { write-host "Backup size equal to drive size" } #equal
  
  # Check if the Backup File is much smaller or bigger than it was during last backup
  if (Test-Path $ReportFullPath) {
    $ThisMonth = Import-CSV -path $ReportFullPath
    # Compare the last backup size
  } else {
    # Look at last months backup sizes
	$ReportFullPath = $ReportPath + $Year + "\Portable"+$ReportFile
	$LastMonth = Import-CSV -path $ReportFullPath
  }
  
  if ($PastSizes -gt 0) {
      if ($BackupSize / ($PastSizes+0.1) -gt $SizeDiffThreshold) {   # +0.1 to not divide by 0
        $message = "The Backup file appears to be smaller than usual. Please troubleshoot. Disk sizes are:`r`n"
	    if ($Location1 -ne "") { $message += " Location1 ($Location1) - $Loc1Size`r`n " }
	    if ($Location2 -ne "") { $message += " Location2 ($Location2) - $Loc2Size`r`n " }
	    if ($Location3 -ne "") { $message += " Location3 ($Location3) - $Loc3Size`r`n " }
	    $message += " Total - $LocationSizes GB `r`n "
	    $message += " Backup size = $BackupSize GB "
        write-eventlog -logname MME -Source "Backup Sizes" -EntryType Error -EventID 170 -Message $message
      }
  } else {
    # what to do if past backups show as 0..
  }

  Write-Host "[3] Writing file to $ReportFullPath .."
  
  $ReportFile=$YearMonth+"_BackupSizes.csv"
  $ReportFullPath = $ReportPath + $Year + "\" + $BackupName + $ReportFile
  $ReportFullPath
  # Check if file exists, if not we will want to write headers:
  if (!(Test-Path $ReportFullPath)) {
    "DateTime, BackupName, BackupSize, Location1, Location2, Location3, LocationSizes, SizeDiff" | out-file $ReportFullPath -Encoding ASCII
  }
  try {
  "$DateTime, $BackupName, $BackupSize, $Location1, $Location2, $Location3, $LocationSizes, $SizeDiff" | out-file -Append $ReportFullPath -Encoding ASCII
  } catch {
    Write-host "[X] Error: Couldn't write to $ReportFullPath !"
  }
}

# CSV Files:
# D:\Backups (Do Not Delete)\Reports\BackupSize\2020\Portable YYYY-MM BackupSizes.csv
# D:\Backups (Do Not Delete)\Reports\BackupSize\2020\Onsite YYYY-MM BackupSizes.csv
# D:\Backups (Do Not Delete)\Reports\BackupSize\2020\Additional YYYY-MM BackupSizes.csv

# CSV File format:
# DateTime, BackupName, BackupSize, Location1, Location2, Location3, LocationSizes, SizeDiff

# Example:
# 2020/05/22 8:00pm, "Portable", BackupSize="300g", Location1="C:", Location2="D:", Location3="", LocationSizes="303g", SizeDiff=false
# 2020/05/22 11:00pm, "Onsite", BackupSize="300g", Location1="C:", Location2="D:", Location3="", LocationSizes="380g", SizeDiff=true
# 2020/05/22 2:00am, "NVR", BackupSize="1000g", Location1="V:", Location2="", Location3="", LocationSizes="980g", SizeDiff=true

# actual data: 
# 2020/05/22 8:00pm, "Portable", 300, "C:", "D:", "", 303, false
# 2020/05/22 11:00pm, "Onsite", 300, "C:", "D:", "", 380, true
# 2020/05/22 2:00am, "NVR", 1800, V:", "", "", 980, true

Init-BackupSize

if ($PortablePath -ne "") { 
  Create-BackupSizeReport -BackupName 'Portable' -BackupFilePath $PortablePath -Location1 $PortableLocation1 -Location2 $PortableLocation2 -Location3 $PortableLocation3
}

if ($OnsitePath -ne "") {
  Create-BackupSizeReport -BackupName 'Onsite' -BackupFilePath $OnsitePath -Location1 $PortableLocation1 -Location2 $PortableLocation2 -Location3 $PortableLocation3
}

if ($AdditionalPath -ne "") { 
  Create-BackupSizeReport -BackupName 'Additional' -BackupFilePath $AdditionalPath -Location1 $PortableLocation1 -Location2 $PortableLocation2 -Location3 $PortableLocation3
}

Write-Host "[.] Backup sizes script completed."
Write-EventLog -LogName "MME" -Source "Backup Sizes" -EventId 10701  -EntryType Information -Message "Backup Sizes script finished"

