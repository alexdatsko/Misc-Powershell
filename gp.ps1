
#######################################################
# gp.ps1 - Git Push my Install-SecurityFixes.ps1 script
# v0.2 - Can parse commit message from script before uploading, or optionally use a diff msg

param (
  [string]$msg = "default"
)

Write-Host "`n[[ Git Push script - gp.ps1 ]] v0.2 Alex Datsko" 
if ($msg -eq "default") {
  # Parse for something after this string:
  # New in this version:
  #write-host "`n Error: please give commit message, i.e :`n  gp.ps1 'added kittens'`n"
  #exit
  $SearchStr = '# New in this version:*'
  sl "\\synologycms\dropbox\scripts\AlexD Powershell\Misc-Powershell"
  $script = Get-Content Install-SecurityFixes.ps1
  foreach ($scriptline in $script) {
    if ($scriptline -like $SearchStr) {
      $msg = ($scriptline -split $SearchStr)[1]
      Write-Host "Using Commit msg: $msg"
    }
  }

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