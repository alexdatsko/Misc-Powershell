[cmdletbinding()]  # For verbose, debug etc
param (
  [string]$LogPath = 'c:\temp\HV-RemotePages.log'   # Default log to write to
)

$info = '''###############################################################
# Poll-RemotePagesTotal.ps1
#   This script takes an average of $pollCount polls, across $pollinterval seconds, for the perfmon counter "\Hyper-V VM Vid Partition($($hostname))\Remote Physical Pages"
#     v0.2 - Alex Datsko (alexd@mmeconsulting.com) 8/19/24'''
$info

#$counterPath = "\Hyper-V VM Vid Partition(*)\Remote Physical Pages"
#$hostname = (hostname)
$counterPath = "\Hyper-V VM Vid Partition(_total)\Remote Physical Pages"

# Define the interval between each poll in seconds
$pollInterval = 5

# Define how many times to poll (set to 0 for infinite polling)
$pollCount = 20
$script:IntsanceName = '.'

function Write-Log {
  param(
    [string]$message
  )

  try {
    $message | Out-File $LogPath -Append
  } catch {
    Write-Error "[!] Unable to append to $LogPath !!"
  }
}

function Poll-RemotePages {
    param(
        [string]$counter,
        [int]$interval,
        [int]$count
    )
    $values = @()

    # Loop to poll the counter
    for ($i = 0; $i -lt $count -or $count -eq 0; $i++) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        $counterValue = Get-Counter -Counter $counter       
        $counterValue.CounterSamples | ForEach-Object {
            $message = "$timestamp - Instance: $($_.InstanceName), Remote Pages: Total: $($_.CookedValue)"
            Write-Verbose $message
            Write-Log $message
            $script:InstanceName = $_.InstanceName
            $values += $_.CookedValue
        }
        
        Start-Sleep -Seconds $interval
    }
    foreach ($value in $values) {
       $RemotePagesAverage += $value
    }
    return [int]($RemotePagesAverage / $pollCount)

}

$LogDir = Split-Path -Path $LogPath
if (-not (Test-Path $LogDir)) {
  try {
    New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction SilentlyContinue
  } catch {
    write-error "[!] Couldn't create $LogDir !"
  }
}

if (-not (Get-EventLog -LogName Application -Source "HyperV PerfAlerts" -ErrorAction SilentlyContinue)) {
  New-EventLog -LogName Application -Source "HyperV PerfAlerts" -ErrorAction SilentlyContinue
}

Write-Output "[+] Polling $counterpath : $pollcount times, interval: $pollinterval"

$RemotePagesTotal = Poll-RemotePages -counter $counterPath -interval $pollInterval -count $pollCount
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$message = "$timestamp - counterpath: $counterpath - Instance: $($script:InstanceName)`nRemote Pages: Total (average of last 15 seconds): $($RemotePagesTotal)"
Write-Output $message

if ([int]$RemotePagesTotal -gt 0) { 
  Write-EventLog -LogName Application -Source "HyperV PerfAlerts" -EntryType Information -EventID 450 -Message $message
}
