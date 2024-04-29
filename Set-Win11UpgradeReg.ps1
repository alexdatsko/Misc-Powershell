$ServerSetupExePath = "\\SERVER\path\to\setup.exe"

Write-Host "[!] Preparing to upgrade Windows 11 to 23H2."

$SetupKey='HKLM:\SYSTEM\Setup';
$LabConfigKey=Join-Path -Path $SetupKey -ChildPath 'LabConfig';
Write-Host "[.] Setting up regsitry keys for $LabConfigKey"
if(-not(Test-Path $LabConfigKey)){New-Item -Path $LabConfigKey -Force};
try {
  @(@{Name='BypassTPMCheck';Value=1;PropertyType='DWord'},@{Name='BypassSecureBootCheck';Value=1;PropertyType='DWord'},@{Name='BypassRAMCheck';Value=1;PropertyType='DWord'}) | ForEach-Object {New-ItemProperty -Path $LabConfigKey -Name $_.Name -Value $_.Value -PropertyType $_.PropertyType -Force}
  Write-Host "[.] $LabConfigKey\BypassTPMChec=1, BypassSecureBootCheck=1, BypassRAMCheck=1, [Dword] all created!" -ForegroundColor Green
} catch {}

$MoSetupKey = 'HKLM:\SYSTEM\Setup\MoSetup'; 
Write-Host "[.] Setting up regsitry keys for $MoSetupKey" -ForegroundColor Yellow
if (-not (Test-Path $MoSetupKey)) { New-Item -Path $MoSetupKey -Force}; 
try {
  New-ItemProperty -Path $MoSetupKey -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -Value 1 -PropertyType 'DWord' -Force
  Write-Host "[.] $MoSetupKey\AllowUpgradesWithUnsupportedTPMOrCPU=1 [Dword] created!" -ForegroundColor Green
} catch {}

Write-Host "[!] Done!" -ForegroundColor Green
$inp = Read-Host "Would you like to run ""$ServerSetupExePath"" /auto upgrade /dynamicupdate disable /compat IgnoreWarning  ?"
if ($inp[0].ToUpper() -eq 'Y' -or $inp[0].ToUpper() -eq '') {
  $args = "/auto upgrade","/dynamicupdate disable","/compat IgnoreWarning"
  Start-Process -FilePath $ServerSetupExePath $ArgumentList -Wait -WindowStyle Maximized
}