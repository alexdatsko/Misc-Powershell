# Installs the PSMA DSU Check script to be run on a certain date.

$date = Get-Date -Format "yyyy-MM-dd" 
$datetime = Get-Date -Format "yyyy-MM-dd hh:mm"
$DateChecked = "" # When to run the check DSU script
$StandardLocation="D:\Backups (Do Not Delete)\Scripts\"     # trailing backslash necessary!
$ServerAdminUser = ''
$ServerAdminPassword = ''
$Task_Path = '.\PSMA 2.0 - Get-DellServerUpdates.xml'
$DSU_Installer = "Systems-Management_Application_55R7T_WN64_1.9.1.0_A00.EXE"

# Create MME Event Log if it doesn't exist

if (![System.Diagnostics.EventLog]::Exists('MME')) {
    New-EventLog -LogName "MME" -Source "Dell Server Updates" 
}
$msg = "INSTALLER: Starting Install-DSUScript.ps1 ..."
Write-Host $msg
Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 10550  -EntryType Information -Message $msg 

# Check for the DSU installation, (eventually) 

Write-Host "Checking if DSU is installed here ..."
$DSU_Installed = 0
$DSUPath = "C:\Dell\DELL EMC System Update\"
if (!(test-path($DSUPATH+"dsu.exe"))) {   
  $DSUPath = "C:\Program Files\Dell\DELL EMC System Update\"  # I don't believe this will ever be Program Files (x86)..
  if (!(test-path($DSUPATH+"dsu.exe"))) {     # Check for new install path as of DSU 1.8.0
    $msg = "INSTALLER: Could not DSU.exe in either path: C:\Dell\DELL EMC System Update\ or C:\Program Files\Dell\DELL EMC System Update\ .. Exiting"
    Write-Host $msg
    Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 502  -EntryType Error -Message $msg
    exit
  } else {  # working with 1.8.0+
    $DSUExe = $DSUPath+"DSU.exe"
  }
} else { # working with 1.7.0 or <
  $DSUExe = $DSUPath+"DSU.exe"
}

# install DSU if it doesn't exist

if (!($DSU_Installed)) {
  $msg = "INSTALLER: DSU Not installed, running installer $DSU_Installer ... "
  Write-Host $msg
  Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 10551  -EntryType Information -Message $msg    
  try {
  . .\$DSU_Installer
  } catch {
    $msg = "INSTALLER: DSU installer needs to be run as administrator, error running $DSU_Installer !!!"
    Write-Host $msg
    Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 551  -EntryType Error -Message $msg    
  }
} else { 
  $msg = "INSTALLER: DSU Found "
  Write-Host $msg
}

# Create folder in $standardLocation

Write-Host "Creating folder in StandardLocation ..."
if (!(test-path($StandardLocation))) {  
  New-Item -Folder $StandardLocation
  if (!(test-path($StandardLocation))) {  
    $msg = "INSTALLER: Could not create $StandardLocation - Please run as admin, or make sure the parent path $StandardLocation exists!!!"
    Write-Host $msg
    Write-EventLog -LogName "MME" -Source "Dell Server Updates" -EventId 550  -EntryType Error -Message $msg    
  }
}

# Prompt for Standard location of powershell scripts file, Server Admin account, server Admin password

$StandardLocation = Get-Host "Where should the scripts be installed, i.e [D:\Backups (Do Not Delete)\Scripts] ? "
if ($StandardLocation -eq '') { $StandardLocation = $DefaultLocation }
$ServerAdminUser = Get-Host "Server Administrator account i.e [Administrator] ? "
if ($ServerAdminUser -eq '') { $ServerAdminUser = 'Administrator' }
while ($ServerAdminPassword -eq '') {
  $ServerAdminPassword = Get-Host "Server Administrator password? "
  if ($ServerAdminPassword -eq '') { Write-host "Server Admin password can't be blank!!" } 
}
$DateChecked = Get-Host "Date to check DSU i.e [Current Date] ?  "
if ($DateChecked -eq '') { $DateChecked=$Date } 


# Modify script to change standard Location

Write-Host "Modifying script to replace StandardLocation ..."
$file = '.\Get-DellServerUpdates.ps1'
$FindStr = '$StandardLocation'
(Get-Content $file) -replace $FindStr, $StandardLocation+'\' | Set-Content $file    # We want the trailing backslash until I add logic code to check for it

# Make quick backup of XML

#      <Arguments>-ExecutionPolicy Bypass -File "D:\Backups (Do Not Delete)\Scripts\Get-DellServerUpdates.ps1"</Arguments>
#      <WorkingDirectory>D:\Backups (Do Not Delete)\Scripts</WorkingDirectory>
#      <UserId>Administrator</UserId>

Write-Host "Backing up current task XML file..."
Copy-Item -Path "PSMA 2.0 - Get-DellServerUpdates.xml" -Destination "PSMA 2.0 - Get-DellServerUpdates.xml.backup" 

# Modify Task XML to change standard Location, ServerAdminAccount, etc

Write-Host "Modifying XML..."
(Get-Content $Task_Path) -replace 'D:\Backups (Do Not Delete)\Scripts', $StandardLocation | Set-Content $Task_Path     # This should catch both paths
(Get-Content $Task_Path) -replace 'Administrator', $ServerAdminUser | Set-Content $Task_Path 
# !!!! FINISH REPLACING STUFF FOR DATE CHECKED... UGH this will suck

# Copy scripts from current location to StandardLocation

Copy-Item -Path ".\Get-DellServerUpdates.ps1" -Destination $StandardLocation

# Install Scheduled Task

# -Create a new task action
$taskAction = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument '-File $StandardLocation\Get-DellServerUpdates.ps1'
$taskAction
$taskTrigger = New-ScheduledTaskTrigger -At 5AM #-Monthly Doesn't exist!! NEed to do specific months and day of the month here and this is going to be a pain...
# The name of your scheduled task.
$taskName = "PSMA 2.0: Check for Dell Server Updates "


# -Register the scheduled task
Register-ScheduledTask `
    -TaskName $taskName `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Xml (Get-Content $Task_Path -Raw)

# Verify scheduled task creation

Get-ScheduledTaskInfo -TaskName Check

# Run scheduled task

Start-ScheduledTask -TaskName ExportAppLog

# Verify results

Get-ChildItem $