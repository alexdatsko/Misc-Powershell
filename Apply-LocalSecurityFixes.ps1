# disable guest account and rename
Rename-LocalUser -Name "Guest" -NewName "GuestAcctNew" | Disable-LocalUser

# disable autoplay
$path ='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'
Set-ItemProperty $path -Name NoDriveTypeAutorun -Type DWord -Value 0xFF
Set-ItemProperty $path -Name NoAutorun -Type DWord -Value 0x1

# spectre/meltdown
cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 0 /f'
cmd /c 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f'

# ipv4 source routing bug
netsh int ipv4 set global sourceroutingbehavior=drop

