Write-Host "`n[[ Git Push script - gp.ps1 ]] Alex Datsko" 
$COMMITMSG=$args[1]
if ($args[2]) {
  Write-Host "Please put the commit message in doublequotes, i.e:"
  oWrite-Host '  gp.ps1 "added kittens!!"'
}
sl "\\synologycms\dropbox\scripts\AlexD Powershell\Misc-Powershell"
write-host "[.] Pulling"
git pull
write-host "[.] Adding *"
git add *
write-host "[.] Committing with $commitmsg"
git commit -m $COMMITMSG
write-host "[.] Pushing.."
git push
Write-Host "[!] Done! Exiting.`n"
