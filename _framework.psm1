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
      write-message "Source: Updater"
	}
    
  if (!(get-EventLog -Logname "MME" -Source "Updater"))
  {
	try 
    {
      New-EventLog -LogName "MME" -Source "Updater" -ErrorAction SilentlyContinue
      start-sleep -seconds 5 #wait 5s in case the script is being created, noticed I was having some trouble here.
      Limit-EventLog -LogName "MME" -RetentionDays $RetentionDays -OverflowAction OverwriteOlder -MaximumSize $EventLogMaxSize   # set the limitation parameters	  
      # write success msg to PSMAScripts that a log was created
      Write-Eventlog -LogName "MME" -Source "PSMAScripts" -EntryType Information -EventId 10099 -Message "Create MME event log successfully."	  
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