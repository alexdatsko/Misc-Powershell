[cmdletbinding()]  # For verbose, debug etc
param (
  $FromPath = "C:\Windows\twain_32 - TSSCAN.dll",    # File to copy from
  $ToPath = "C:\Windows\twain_32.dll",               # File to copy to (or folder name, file is more specific..)
  $LogFile = "c:\Scripts\Logs\Copy-FileToFolder.log"
)

$info = ''###################################################################################################################################
# Copy-FileToFolder.ps1 
#   If the file hash has changed, this script will copy a single file from $FromPath to $ToPath
#   Checks Hash of Twain_32.dll file against TSscan's modified version.
#   MOST LIKELY WILL NEED TO BE RUN WITH ADMINISTRATOR PERMISSIONS!
#
#   Will try $trytimes tries, every $tryseconds seconds, in case file is locked, will report an error after giving up.
#   (Created to replace c:\windows\Twain_32.dll with the TSScan one, due to SFC replacing the file weekly)
#   Alex Datsko @ MME Consulting Inc 
#   Version history: v0.1 - 8/27/24 - initial
#                    v0.2 - 9/5/24 - kill process if dll in use by an app, try for 3 hours
#                    v0.3 - 9/12/24 - logging to c:\Scripts\Logs
#                    v0.4 - 9/23/24 - Logging fixes, testing if files exist, etc''
#                    v0.5 - 10/7/24 - Added Fix-FilePermissions to try to take ownership from TrustedInstaller and fix permissions so we can revert the file.
#		     v0.6 - 10/21/24 - RobR-Changed take-ownership to takeown and hard coded filename after testing. It had been failing.
#        v0.7 - 05/07/25 - AlexD - Came back to this for McMurphy,Austin, trying a couple different things

$info

$trytimes = 36          # This will try 36 times, which for 5m intervals, is 3 hours.
$tryseconds = 300       # Amount of time to sleep between tries, defaults to 300 = 5 minutes.

$DateTime = Get-Date -Format "yyyy-MM-dd hh:mm"
"`n$DateTime ------------------------------" | tee -append $LogFile


function Restore-Twain32 {
  [CmdletBinding()]
  param($FromPath, $ToPath, $LogFile) 
  $Source = $FromPath
  $Destination = $ToPath
  
  if (-not (Test-Path $Source)) {
      Throw "Source file not found: $Source"
  }

  # Step 1: robocopy in Backup mode to overwrite the protected file
  $rcArgs = @(
      (Split-Path $Source -Parent),
      (Split-Path $Destination -Parent),
      (Split-Path $Source -Leaf),
      '/B',       # backup mode
      '/R:2',     # retry twice on failure
      '/W:5',     # wait 5s between retries
      '/NFL','/NDL','/NJH','/NJS'  # suppress extra logging
  )
  $exit = Start-Process -FilePath robocopy -ArgumentList $rcArgs -NoNewWindow -Wait -PassThru
  if ($exit.ExitCode -ge 8) {
      "robocopy failed with code $($exit.ExitCode)" | Tee -Append $LogFile
  }

  # Step 2: (Optional) revert owner to TrustedInstaller
  try {
      $ti = New-Object System.Security.Principal.NTAccount('NT SERVICE\TrustedInstaller')
      $acl = Get-Acl $Destination
      $acl.SetOwner($ti)
      Set-Acl -Path $Destination -AclObject $acl
  } catch {
      "Could not reset owner to TrustedInstaller: $_"  | Tee -Append $LogFile
  }
}

function Fix-FilePermissions {
  param (
    [string] $ToPath
  )

  if (Test-Path $ToPath) { # Take ownership and set Administrators to full control:
    $currentOwner = Get-Acl $ToPath | Select-Object -ExpandProperty Owner

    if ($currentOwner -ne "Administrator" -and $currentOwner -ne "BUILTIN\Administrators") {
      try {
        Takeown /f $ToPath /A
      } catch {
        "[!] Issue changing ownership of '$dllPath' from $($currentOwner)! Error: $_" | Tee -Append $LogFile
      }
    }

    try {
      $user = "BUILTIN\Administrators"
      $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, "FullControl", "Allow")
      $acl = Get-Acl $ToPath
      $acl.AddAccessRule($accessRule)
      Set-Acl $ToPath $acl
 
    } catch {
      "[!] Issue changing permissions on '$ToPath' from $($currentOwner)! Error: $_"  | Tee -Append $LogFile
    }
  } else {
    "[!] The file '$ToPath' does not exist."  | Tee -Append $LogFile
  }
}


function Copy-FileToLocation {
  param($FromPath, $ToPath, $LogFile) 
  "[.] Copying : $FromPath to $ToPath"  | Tee -Append $LogFile
  $exmsg = $null
  $done = 0
  while (!$done) {
    if (Test-Path "$FromPath" -ErrorAction Continue) {
      "[+] Copying $FromPath to $ToPath" | tee -append $LogFile
      try {
        Copy-Item -Path "$FromPath" -Destination "$ToPath" -Force -Recurse -ErrorAction Continue | tee -append $Logfile
      } catch {
        $exmsg = "[-] An error occurred during the copy operation: $_"
        $exmsg | Tee -Append $LogFile
        "[.] Trying to fix file permissions on $ToPath in case there are issues here:" | tee -append $LogFile 
        Fix-FilePermissions $ToPath
        "[.] Scanning for PIDs that are using $ToPath ...`n" | Tee -Append $LogFile
        Find-ProcessUsingDLL $ToPath -Kill
      }
      if ($exmsg -eq $null) { 
        "[+] Completed!" | tee -append $LogFile 
        $done = 1
        exit
      } else { 
        "[-] ERROR. Not copied. Trying again in $tryseconds" | tee -append $LogFile 
        Start-Sleep $tryseconds
      }
    } else {
      "[-] $FromPath not found, or Access Denied reading folder.." | tee -append $LogFile
    }
    $tries += 1
    if ($trytimes -gt $tries) {
      "[-] Failed to copy $trytimes times, with $tryseconds delay.  Aborting..." | tee -append $LogFile
      $done = 1
      exit
    }
  }
}

if (Test-Path $ToPath) {
  if (Test-Path $FromPath) { 
    $ToPathhash = $(Get-FileHash "$ToPath").Hash 
    $FromPathhash = $(Get-FileHash "$FromPath").Hash
    if ($ToPathhash -ne $FromPathhash) {
        "[-] Orig file $FromPath hash: $FromPathhash does not match $ToPath hash: $ToPathhash" | tee -append $LogFile
        Restore-Twain32 $FromPath $ToPath $LogFile
        #Copy-FileToLocation $FromPath $ToPath $LogFile
    } else {
        "[+] Hashes match: no actions taken."  | Tee -Append $LogFile
        Write-Verbose "    Orig file $FromPath SHA256 hash: $FromPathhash == $ToPath SHA256 hash: $ToPathhash" | tee -append $LogFile
    }
  } else {
    "[-] Can't find file $FromPath !!! Exiting" | tee -append $LogFile
    Exit
  }
} else {
  "[-] Can't find file $ToPath !!! Exiting" | tee -append $LogFile
  Exit
}


