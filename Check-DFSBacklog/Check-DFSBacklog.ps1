$DFSBacklogVersion = "1.0"

# DFS backlog variables
$DFSthreshold = 25
$ScriptDriveLetter = "D" # This is usually C or D, it is the Drive letter holds the Backups DND folder
$ScriptPath = ":\Backups (Do Not Delete)\Scripts\"  

$ScriptFullPath = $ScriptDriveLetter+$ScriptPath
# Location of PSMA 2.0 Reports
$ReportDriveLetter = $ScriptDriveLetter
$ReportPath = ":\Backups (Do Not Delete)\Reports\"
$ReportFullPath = $ReportDriveLetter+$ReportPath

################ _framework.psm1 ###################

function get-DateTimeFormatted {
    Param
    (	
	    [string] $message
    )

    $message = (Get-Date).ToString('MM/dd/yyyy hh:mm:ss tt')
    return $message
}

############################# FILE RELATED STUFF ##############################

function Unzip($zipfile, $outdir)
{   # This function will OVERWRITE any existing files by default.   Works on anything from Powershell 2.0+ (7,8,10, etc)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zipfile)
    foreach ($entry in $archive.Entries)
    {
        $entryTargetFilePath = [System.IO.Path]::Combine($outdir, $entry.FullName)
        $entryDir = [System.IO.Path]::GetDirectoryName($entryTargetFilePath)

        #Ensure the directory of the archive entry exists
        if(!(Test-Path $entryDir )){
            New-Item -ItemType Directory -Path $entryDir | Out-Null 
        }

        #If the entry is not a directory entry, then extract entry
        if(!$entryTargetFilePath.EndsWith("\")){
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entryTargetFilePath, $true);  # the $True overwrites
        }
    }
}

############################# I/O STUFF ##############################

function Test-Internet ($IPAddress) { 
  $test = (Test-Connection -ComputerName $IPAddress -Count 4 | measure-Object -Property ResponseTime -Average).average 
  $replyinMS= ($test -as [int] ) 
  return $replyinMS
}

function Write-Text ($symbol, $color, $msg)
{
	if ($symbol -ne $null)
	{
		Write-Host "[$symbol]" -ForegroundColor $color -NoNewLine
		Write-Host " - $msg"
	}
	else 
	{
		Write-Host $msg
	}
}

function Write-Message {
	Param
	(	
		[string] $message,
		[string] $type,
		[bool] $prependNewLine
	)
	$msg = ""
	if ($prependNewline) { Write-Host "`n" }
	switch ($type) {
		"error" { 
			$symbol = "!"
			$color = [System.ConsoleColor]::Red
			}
		"warning" {
			$symbol = "!"
			$color = [System.ConsoleColor]::Yellow
			}
		"debug" {
			$symbol = "DBG"
			$color = [System.ConsoleColor]::Magenta
			}
		"success" {
			$symbol = "+"
			$color = [System.ConsoleColor]::Green
			}
		"prereq" {
			$symbol = "PREREQ"
			$color = [System.ConsoleColor]::Cyan
			}
		"status" {
			$symbol = "*"
			$color = [System.ConsoleColor]::White
			}
		default { 
			$color = [System.ConsoleColor]::White
			#$symbol = "*" Don't do this. Looks bad.
			}
		}

		# I know, I know. This code is truly horrible. Judge not, lest I find your github repos...
		if ($PSCmdlet.MyInvocation.BoundParameters -ne $null -and $PSCmdlet.MyInvocation.BoundParameters['Debug'].IsPresent)
		{
			Add-Content $debuglog $message
			Write-Text $symbol $color $message
		}
		elseif ($type -ne "debug") 
		{
			Write-Text $symbol $color $message
		}

}

############################# RANDOM STUFF ##############################

function Get-RandomAlphaNum($len)
{
	$r = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	$tmp = foreach ($i in 1..[int]$len) { $r[(Get-Random -Minimum 1 -Maximum $r.Length)] }
	return [string]::Join('', $tmp)
}

function Get-RandomAlpha($len)
{
	$r = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	$tmp = foreach ($i in 1..[int]$len) { $r[(Get-Random -Minimum 1 -Maximum $r.Length)] }
	return [string]::Join('', $tmp)
}

############################# EVENT LOG STUFF ##############################

function Add-MMEEventLog($LogName) 
{
    if ($debug) { 
      write-message "Log: MME"
      write-message "Source: DFSBacklog"
	}
    
  if (!(get-EventLog -Logname "MME" -Source "DFSBacklog"))
  {
	try 
    {
      
      New-EventLog -LogName "MME" -Source "DFSBacklog" 
      start-sleep -seconds 5 #wait 5s in case the script is being created, noticed I was having some trouble here.
      Limit-EventLog -LogName "MME" -RetentionDays $RetentionDays -OverflowAction OverwriteOlder -MaximumSize $EventLogMaxSize   # set the limitation parameters	  
      # write success msg to PSMAScripts that a log was created
      Write-Eventlog -LogName "MME" -Source "DFSBacklog" -EntryType Information -EventId 10099 -Message "Create MME event log successfully."	  
	}
	catch
	{
	  Write-Error "Failed to create MME event log, $_"
	}
  }
}

function Add-MMEEventLogSource($LogName, $LogSource)
{

  if (!([System.Diagnostics.EventLog]::SourceExists($LogSource)))
  {
	try
	{
	  New-EventLog -LogName "MME" -Source $LogSource -ErrorAction SilentlyContinue -Verbose 
	  Write-Eventlog -LogName "MME" -Source $LogSource -EntryType Information -EventId 900 -Message "Create source [$LogName] $LogSource event log successfully."
	  # Limit-EventLog -LogName $LogName -RetentionDays $RetentionDays -OverflowAction OverwriteOlder -MaximumSize $EventLogMaxSize   # set the limit parameters again?  Probably not..
	}
	catch
	{
	  Write-Error "Failed to create $LogName event log, $_.Message $_.Details"
	}
  } else {
    
  }
}

function Write-MMEErrorEvent($LogSource, $EventID, $LogMessage)
{

    try {
      Write-Eventlog -LogName MME -Source $LogSource -EntryType Error -EventId $EventID -Message ($LogMessage)
	}
	catch
	{ # could log this to System Critical 9999 or something
      # or could put this in a report that gets emailed separately. 
	  Write-Message "Failed to write ERROR LogMessage to: `r`n  Event log: MME`r`n  Source: $LogSource`r`n  Event ID: $EventID`r`n  Message: $LogMessage`r`nMessage details: $_.Message $_.Details"
	}
}

function Write-MMEWarningEvent($LogSource, $EventID, $LogMessage)
{

    try {
      Write-Eventlog -LogName MME -Source $LogSource -EntryType Warning -EventId $EventID -Message ($LogMessage)
	}
	Catch
	{
	  Write-Message "Failed to write WARNING LogMessage to: `r`n  Event log: $Logname`r`n  Source: $LogSource`r`n  Event ID: $EventID`r`n  Message: $LogMessage`r`nMessage details: $_.Message $_.Details"
	}
}

function Write-MMEInformationEvent($LogSource, $EventID, $LogMessage) 
{

    try
    {
      Write-Eventlog -LogName MME -Source $LogSource -EntryType Information -EventId $EventID -Message ($LogMessage)
	}
	Catch
	{
	  Write-Message  "Failed to write INFORMATION LogMessage to: `r`n  Event log: $Logname`r`n  Source: $LogSource`r`n  Event ID: $EventID`r`n  Message: $LogMessage`r`nMessage details: $_.Message $_.Details"
	}
}

function Search-MMEEventLog($LogSource, $daystocheck, $msg) 
{
	if ([System.Diagnostics.EventLog]::Exists($LogName)) {
	  if ([System.Diagnostics.EventLog]::SourceExists($LogSource)) {
	
        #Add-EventLog($LogName)
	    #Add-EventLogSource($LogName, $LogSource)   # Try to create event log / source if it doesn't exist
	    $date = (Get-Date).AddDays(0-$daystocheck) 
	    $Results = get-winevent -filterhashtable @{ logname=$logname; StartTime = $date }|where-object {$_.message -match "$msg" } | fl -property Message
        # $Results should be returned to the parent script
      }
    }
}


############################# SCRIPT INTERNAL STUFF ##############################


function IsAdmin {
    # Determine if admin powershell process
    $wid=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp=new-object System.Security.Principal.WindowsPrincipal($wid)
    $adm=[System.Security.Principal.WindowsBuiltInRole]::Administrator
    return $prp.IsInRole($adm)
}

##############################################################################################################

if (!(IsAdmin)) {
  if ($debug) { write-message "Could not process updates, Check-DFSBacklog.ps1 not running as Administrator!" "error" }
  Write-MMEErrorEvent("DFS Backlog", 100, "Check-DFSBacklog.ps1 not running as Administrator!")
}

# start MME Event log and create DFSBacklog source if it doesn't exist
if (!(get-EventLog -Logname "MME" -Source "DFSBacklog" -ErrorAction SilentlyContinue))
{
	try 
    {
      New-EventLog -LogName "MME" -Source "DFSBacklog" -ErrorAction SilentlyContinue
    } catch {
      #error
      write-host "Critical error: Couldn't create DFSBacklog source in MME event log!!"
      #exit # still need 
    }
}

$RGroups = Get-WmiObject  -Namespace "root\MicrosoftDFS" -Query "SELECT * FROM DfsrReplicationGroupConfig"
$ComputerName=$env:ComputerName
$Succ=0
$Warn=0
$Err=0
$Date=Get-Date -Format g
$DateFileFriendly=Get-Date -format "yyyyMMdd"

$DFSBacklogReportFolder=$ReportFullPath+"DFSBacklog\"
if (!(test-path($ReportFullPath))) {
  try {
    mkdir $ReportFullPath
  } catch {
    write-Host "Couldn't create $ReportFullPath !!"
    exit
  }
}
if (!(test-path($DFSBacklogReportFolder))) {
  cd $ReportFullPath
  try {
    mkdir $DFSBacklogReportFolder
  } catch {
    write-Host "Couldn't create $DFSBacklogReportFolder !!"
    exit
  }
}



$DFSlogfile = $ReportFullPath+"\DFSBacklog\DFSBacklog-$DateFileFriendly.txt"
if ($debug) { write-host "DFSlogfile = $DFSlogfile" } 

Out-File -FilePath $DFSlogfile -Encoding ASCII -InputObject $Date
foreach ($Group in $RGroups)
{
    $RGFoldersWMIQ = "SELECT * FROM DfsrReplicatedFolderConfig WHERE ReplicationGroupGUID='" + $Group.ReplicationGroupGUID + "'"

    #Test if the WMI object "root\MicrosoftDFS" exists, if not, this script should not be running.
    if (get-wmiobject -namespace root -class __NAMESPACE -filter "name='MicrosoftDFS'") {
      # found
    } else {
      # not found, error
      write-host "No DFS found on this machine!"
      Write-MMEErrorEvent("DFS Backlog", 101, "DFS was not found on this machine.")
      exit
    }

    $RGFolders = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query  $RGFoldersWMIQ
    $RGConnectionsWMIQ = "SELECT * FROM DfsrConnectionConfig WHERE ReplicationGroupGUID='"+ $Group.ReplicationGroupGUID + "'"
    $RGConnections = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query  $RGConnectionsWMIQ
    foreach ($Connection in $RGConnections)
    {
        $ConnectionName = $Connection.PartnerName#.Trim()
        if ($Connection.Enabled -eq $True)
        {

                foreach ($Folder in $RGFolders)
                {
                    $RGName = $Group.ReplicationGroupName
                    $RFName = $Folder.ReplicatedFolderName
 
                    if ($Connection.Inbound -eq $True)
                    {
                        $SendingMember = $ConnectionName
                        $ReceivingMember = $ComputerName
                        $Direction="inbound"
                    }
                    else
                    {
                        $SendingMember = $ComputerName
                        $ReceivingMember = $ConnectionName
                        $Direction="outbound"
                    }
 
                    $BLCommand = "dfsrdiag backlog /RGName:'" + $RGName + "' /RFName:'" + $RFName + "' /smem:" + $SendingMember + " /rmem:" + $ReceivingMember
                    $Backlog = Invoke-Expression -Command $BLCommand
 
                    $BackLogFilecount = 0
                    foreach ($item in $Backlog)
                    {
                        if ($item -ilike "*Backlog File count*")
                        {
                            $BacklogFileCount = [int]$Item.Split(":")[1].Trim()
                        }
                    }
 
                    if ($BacklogFileCount -eq 0)
                    {
                        $Color="white"
                        $Succ=$Succ+1
                        # Don't really need to clutter up the event log with success no backlogs..  There is a report at the end of the script reporting success status to this event source anyway.
                        #write-eventlog -logname MME -Source "DFSBacklog" -EntryType Information -EventID 10000 -Message "No DFS Backlog to Report"
                    }
                    elseif ($BacklogFilecount -lt $DFSthreshold)
                    {
                        $Color="yellow"
                        $Warn=$Warn+1
                        write-eventlog -logname MME -Source "DFSBacklog" -EntryType Warning -EventID 1000 -Message "$BacklogFileCount files in backlog $SendingMember->$ReceivingMember for $RGName"
                        write-eventlog -logname MME -Source "DFSBacklog" -EntryType Warning -EventID 1001 -Message "$Backlog"
                                                   
                    }
                    else
                    {
                        $Color="red"
                        $Err=$Err+1
                        write-eventlog -logname MME -Source "DFSBacklog" -EntryType Error -EventID 103 -Message "$BacklogFileCount files in backlog $SendingMember->$ReceivingMember for $RGName"
                        write-eventlog -logname MME -Source "DFSBacklog" -EntryType Error -EventID 104 -Message "$Backlog"
                    }
                    Write-Host "$BacklogFileCount files in backlog $SendingMember->$ReceivingMember for $RGName" -fore $Color
                    
                    $DFSOutput = "$BacklogFileCount files in backlog $SendingMember->$ReceivingMember for $RGName`r`n"
                    Out-File -FilePath $DFSlogfile -Encoding ASCII -InputObject $DFSOutput -Append

                } # Closing iterate through all folders
            
        } # Closing  If Connection enabled
    } # Closing iteration through all connections
} # Closing iteration through all groups
Write-Host "Successful: $Succ"
Write-Host "Warnings: $Warn"
Write-Host "Errors: $Err"


$DFSOutput2 = "$Succ successful, $Warn warnings and $Err errors from $($Succ+$Warn+$Err) replications."

Out-File -FilePath $DFSlogfile -Encoding UTF8 -InputObject "%nSuccessful: $Succ" -Append
Out-File -FilePath $DFSlogfile -Encoding UTF8 -InputObject "%nWarnings: $Warn" -Append
Out-File -FilePath $DFSlogfile -Encoding UTF8 -InputObject "%nErrors: $Err" -Append

$FullEventLog = (Get-Content -Path $dfslogfile)

New-EventLog -LogName "MME" -Source "DFSBacklog" -ErrorAction SilentlyContinue

# Write to actual Event log if this is not a debug run
if (!($DebugDFSBacklog)) 
{ 
  write-eventlog -logname MME -Source "DFSBacklog" -EntryType Information -EventID 10001 -Message "$FullEventLog" 
} else {
  # write to screen otherwise
  write-host ""
  write-host $FullEventLog
  write-host ""
}
