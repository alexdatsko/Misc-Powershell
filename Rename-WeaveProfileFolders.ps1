# This is to be run on a Termserver, it will rename all the Weave user profile folders to weave.old in case this is causing memory leaks and high CPU usage.

# import-module activedirector
# $users = get-ADUser -filter *    # Only works on a DC
$users = dir c:\users | select Name 
foreach ($user in $users.Name) { 
  write-host "$user" 
  if (test-path("c:\users\$user\AppData\local\weave")) { 
    Write-Host "  Moving C:\Users\$User\Appdata\local\weave c:\users\$user\appdata\local\weave.old .."
    move "C:\Users\$User\Appdata\local\weave" "c:\users\$user\appdata\local\weave.old" 
  } 
}
