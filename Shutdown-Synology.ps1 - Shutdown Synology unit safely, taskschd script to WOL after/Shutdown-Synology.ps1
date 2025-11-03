# Script to shut down the Synology during an APC Power event
# Alex Datsko @ . 09-28-2021

$nasHostname = '192.168.1.2'
$username = 'apc'
$sourcedir = "D:\Backups (Do Not Delete)\Scripts\"
$pwfile = "$($sourcedir)pw_securestring.dat"
$plinkPath = 'plink.exe'
if (!(test-path($plinkpath))) { 
  wget "https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe" -outfile $plinkPath
}
$password = '' # DO NOT save plaintext password here
$MaxMins = 5    # Check that machine is shut down for X minutes
$SecondsBetween = 10  # Check ever Y seconds

if (test-path($pwfile)) { $secpassword = Get-Content $pwfile | ConvertTo-SecureString; $password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecPassword)) }

if (!($password.length -gt 1)) {
  $passwordSec = Read-Host "Enter Synology $username password" -AsSecureString
  $passwordSec | ConvertFrom-SecureString | Out-File $pwfile
  $password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSec))
}

Write-Host "Trying to shutdown Synology with plink:"
Write-Host "$plinkPath -batch -ssh -pw $password $username@$nasHostname echo $password | sudo -i -S shutdown -h now; id"
. ".\$plinkPath" -batch -ssh -pw $password $username@$nasHostname "echo $password | sudo -i -S shutdown -h now; id"

$password='                                         '

Write-Host "`r`n`r`n[o] Checking that $IP is shut down for $MaxMins minutes..." -ForegroundColor Green
for ($num = 1 ; $num -le ($MaxMins*(60 / $SecondsBetween)) ; $num++) { 
    if (!(Test-NetConnection $IP)) {
      Write-Host "Got no reply: "  -ForegroundColor Gray
      Test-NetConnection $IP
      Write-Host "Machine down. Exiting!"  -ForegroundColor Green
      exit
    } else {
      Write-Host "Machine still up @ $(num*$SecondsBetween)m.. Continue sending WOL for $($MaxMins - ($num*$SecondsBetween)) minutes"  -ForegroundColor White
    }
}