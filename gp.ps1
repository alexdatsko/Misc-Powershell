write-host "`n[.] Git Push script (for Misc-Powershell)"
if ($null -ne $args[0]) {
  $commitmsg=$args[0]
} else {
  write-host "`n Error: please give commit message, i.e :`n  gp.ps1 'added kittens'`n"
  exit
}
sl "\\synologycms\dropbox\scripts\AlexD Powershell\Misc-Powershell"
write-host "[.] Adding *"
git add *
write-host "[.] Committing with $commitmsg"
git commit -m $commitmsg
write-host "[.] Pushing.."
git push
echo "[!] Done! Exiting.`n"
