function Add-MMEEventLogSource($LogName, $LogSource)
{

  if (!([System.Diagnostics.EventLog]::SourceExists($LogSource))) {
	try {
	New-EventLog -LogName "MME" -Source $LogSource -ErrorAction SilentlyContinue -Verbose 
	Write-Eventlog -LogName "MME" -Source $LogSource -EntryType Information -EventId 900 -Message "Create source [$LogName] $LogSource event log successfully."
	# Limit-EventLog -LogName $LogName -RetentionDays $RetentionDays -OverflowAction OverwriteOlder -MaximumSize $EventLogMaxSize   # set the limit parameters again?  Probably not..
	} 	catch 	{
	  Write-Error "Failed to create $LogName event log, $_.Message $_.Details"
	}
  } else {
    
  }
}

function Write-MMEEvent($LogSource, $EventID, $LogMessage)
{
  try {
    Write-Eventlog -LogName MME -Source $LogSource -EntryType Error -EventId $EventID -Message ($LogMessage)
	} 	catch 	{ 
	  Write-Message "Failed to write INFO LogMessage to: `r`n  Event log: MME`r`n  Source: $LogSource`r`n  Event ID: $EventID`r`n  Message: $LogMessage`r`nMessage details: $_.Message $_.Details"
	}
}

Function Remove-InstalledSoftwarebyUninstallReg {
  param ($SoftwareName)
  Write-Host "[.] Searching Uninstaller registry for $SoftwareName.."
  if (Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
      Where-Object DisplayName -eq $SoftwareName -OutVariable Results) {
    Write-Host "[.] Removing $(($Results).DisplayName) .."
    & "$($Results.InstallLocation)\uninst.exe" /S
    Write-MMEEvent("RemoveSoftware", 1000, "Removed $(($Results).DisplayName) by calling '$($Results.InstallLocation)\uninst.exe /S'")
  }
}

Add-MMEEventLogSource("MME", "RemoveSoftware")
$Input = Read-Host "[?] What is the software name to remove? "
Remove-InstalledSoftwarebyUninstallReg $Input
