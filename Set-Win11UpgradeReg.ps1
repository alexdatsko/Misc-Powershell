$SetupKey='HKLM:\SYSTEM\Setup';
$LabConfigKey=Join-Path -Path $SetupKey -ChildPath 'LabConfig';
if(-not(Test-Path $LabConfigKey)){New-Item -Path $LabConfigKey -Force};
@(@{Name='BypassTPMCheck';Value=1;PropertyType='DWord'},@{Name='BypassSecureBootCheck';Value=1;PropertyType='DWord'},@{Name='BypassRAMCheck';Value=1;PropertyType='DWord'}) | ForEach-Object {New-ItemProperty -Path $LabConfigKey -Name $_.Name -Value $_.Value -PropertyType $_.PropertyType -Force}

$MoSetupKey = 'HKLM:\SYSTEM\Setup\MoSetup'; 
if (-not (Test-Path $MoSetupKey)) { New-Item -Path $MoSetupKey -Force}; 
New-ItemProperty -Path $MoSetupKey -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -Value 1 -PropertyType 'DWord' -Force