if (!([System.Diagnostics.EventLog]::Exists('MME'))) {
  # Create the MME event log if it does not exist.
  New-EventLog -LogName "MME" -Source "PSMA 2.0" -ErrorAction SilentlyContinue
  Start-Sleep -seconds 5 
  Limit-EventLog -LogName "MME" -RetentionDays 365 -OverflowAction OverwriteOlder -MaximumSize 2G   
}

$date = (Get-Date).ToString('yyyy-MM-dd')
$msg = "PSMA 2.0 Consistency Check : "

$loc_64bit = "C:\Program Files\dell\SysMgt\oma\bin\"
$loc_32bit = "C:\Program Files (x86)\dell\SysMgt\oma\bin\"

function set-exepath($exename) {
  if (test-path($loc_32bit)) {
    return $loc_32bit+$exename
  } else {
    if (test-path($loc_64bit)) {
      return $loc_64bit+$exename
    }
  }
}

$loc = set-exepath("omreport.exe")
$param = "storage vdisk"

$cmd = '& "'+$loc+'"'+$param

try { 
  $result = Invoke-Expression $cmd
} catch {
  write-host "Failure! Couldn't run omreport.exe storage vdisk:  $result "
  write-eventlog -Logname "MME" -Source "PSMA 2.0" -EventID 10052 -Entrytype Error -Message "Couldn't run omreport.exe storage vdisk: $result"
}

$IDlast = $result | select-string -Pattern "ID                                : " -Allmatches | Select-Object -Last 1
$junk,$ID = $IDlast -split(": ")
$VDCount = $ID -as [int]
$VDCount += 1       # Virtual Disk ID starts at 0

$msg = $msg+"Virtual Disks found: $VDCount `r`n"
Write-host $msg 

# Now we have the last Vdisk ID, run the consistency checks

$loc = set-exepath("omconfig.exe")
$param = " storage vdisk action=checkconsistency controller=0 vdisk="

for ($p=0; $p -le $($VDCount); $p++) { 
  $result = ""
  $fullparam = $($param+$p)
  $cmd = '& "'+$loc+'"'+$fullparam

  write-host "$cmd"

  try { 
    $result = Invoke-Expression $cmd
  } catch {
    write-host "Failure! Couldn't start consistency check on $p :  $result "
    write-eventlog -Logname "MME" -Source "PSMA 2.0" -EventID 10051 -Entrytype Error -Message "Couldn't start consistency check on $p :  $result "
  }

  $result
  $msg = $msg+"Started consistency check on VD $p :  `r`n  $result `r`n"
}

# Write a single event with all task completion status to MME Event log if success
write-eventlog -Logname "MME" -Source "PSMA 2.0" -EventID 10050 -Entrytype Information -Message $msg


