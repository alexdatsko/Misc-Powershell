$filecheck = "c:\ProgramData\huntress-do_not_remove.txt"
if (!(Test-Path $filecheck)) {
  wget 'https://huntress.io/download/<scrubbed>' -OutFile "$env:temp/HuntressInstaller.exe"
  cmd.exe /c '%TEMP%\HuntressInstaller.exe /S /ACCT_KEY=<scrubbed> /ORG_KEY=\"gm\"'
  "Please do not remove this file, it is used in the GPO for the installation of the Huntress.io application. Thanks" | Out-File $filecheck
} else { 
  $msg = "$env:computername $filecheck file already found! Skipping install."
  Write-Output $msg
}