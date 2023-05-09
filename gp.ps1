
param (
  [string]$msg = "default"
)
Write-Host "`n[[ Git Push script - gp.ps1 ]] v0.2 Alex Datsko" 
if ($msg -eq "default") {
  write-host "`n Error: please give commit message, i.e :`n  gp.ps1 'added kittens'`n"
  exit
} else {
  write-host "[.] Commit msg: '$msg'"
  sl "\\synologycms\dropbox\scripts\AlexD Powershell\Misc-Powershell"
  write-host "[.] Pulling"
  git pull
  write-host "[.] Adding *"
  git add *
  write-host "[.] Committing with msg: '$msg'"
  git commit -m "$msg"
  write-host "[.] Pushing.."
  git push
  Write-Host "[!] Done! Exiting.`n"
}