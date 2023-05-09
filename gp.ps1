
param (
    [string]$msg = "default"
 )
 Write-Host "`n[[ Git Push script - gp.ps1 ]] Alex Datsko" 
if ("Default" -eq $msg) {
  write-host "`n Error: please give commit message, i.e :`n  gp.ps1 'added kittens'`n"
  exit
} else {
  sl "\\synologycms\dropbox\scripts\AlexD Powershell\Misc-Powershell"
  write-host "[.] Pulling"
  git pull
  write-host "[.] Adding *"
  git add *
  write-host "[.] Committing with msg: '$commitmsg'"
  git commit -m "$commitmsg"
  write-host "[.] Pushing.."
  git push
  Write-Host "[!] Done! Exiting.`n"
}