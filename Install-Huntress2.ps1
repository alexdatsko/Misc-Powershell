$filecheck = "c:\ProgramData\huntress-do_not_remove.txt"
if (!(Test-Path $filecheck)) {
  wget 'https://huntress.io/download/2a4de25f7adf540d7dc61d6dbcb79db8' -OutFile "$env:temp/HuntressInstaller.exe"
  cmd.exe /c '%TEMP%\HuntressInstaller.exe /S /ACCT_KEY=2a4de25f7adf540d7dc61d6dbcb79db8 /ORG_KEY=\"gm\"'
  "Please do not remove this file, it is used in the GPO for the installation of the Huntress.io application. Thanks - Alex Datsko @ MME Consulting" | Out-File $filecheck
} else { 
  $msg = "$env:computername $filecheck file already found! Skipping install."
  Write-Output $msg
}