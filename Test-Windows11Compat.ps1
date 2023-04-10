Write-Host "`n`n
#########################################
# Test-Windows11Compat.ps1
# Test to make sure all features are enabled which are required for Windows 11 
#
"
function Display-PlusOrMinus {
  param ([boolean]$bool)

  if ($bool) {
    Write-Host "[+] " -NoNewLine
  } else {
    Write-Host "[-] " -NoNewLine
  }
}

write-host "[.] Checking features.." -NoNewLine
$namespace='root\cimv2\security\microsofttpm'
$TPMVersion = (Get-WmiObject -Namespace $namespace -Query 'select SpecVersion from win32_tpm').SpecVersion
Write-Host "." -NoNewLine
$TPMIsActivated=(Get-WmiObject -Namespace $namespace -Query 'select IsActivated_InitialValue from win32_tpm').IsActivated_InitialValue
Write-Host "." -NoNewLine
$TPMIsEnabled=(Get-WmiObject -Namespace $namespace -Query 'select IsEnabled_InitialValue from win32_tpm').IsEnabled_InitialValue
Write-Host "." -NoNewLine
$TPMIsOwned=(Get-WmiObject -Namespace $namespace -Query 'select IsOwned_InitialValue from win32_tpm').IsOwned_InitialValue
if (bcdedit /enum firmware | findstr /i EFI) { $UEFIEnabled = $true  } else { $UEFIEnabled = $false }
Write-Host "." -NoNewLine
$SecureBootEnabled=(Confirm-SecureBootUEFI)
Write-Host "." -NoNewLine
$MemoryInGB= (Get-WmiObject Win32_OperatingSystem | Select -ExpandProperty TotalVisibleMemorySize)/1024/1024
Write-Host "." -NoNewLine
$CPUGen=(Get-WmiObject Win32_Processor | Select -ExpandProperty Name)
Write-Host "." -NoNewLine
$systemDriveSize = Get-WmiObject Win32_LogicalDisk | ? {$_.DeviceID -eq "C:"} | Select -ExpandProperty Size
if ($systemDriveSize -gt 63.99GB) { $SysDriveOver64gb=$True } else { $SysDriveOver64gb=$False }
Write-Host "." -NoNewLine
$graphicsCardName = Get-WmiObject Win32_VideoController | Select -ExpandProperty Name
$graphicsCardDriverVersion = Get-WmiObject Win32_VideoController | Select -ExpandProperty DriverVersion
Write-Host "." -NoNewLine
$displayResolution = @(Get-WmiObject Win32_VideoController | Select -ExpandProperty CurrentVerticalResolution)
$displayResolutionMin = ($DisplayResolution | sort-object -Descending | Select -last 1)
#$displayDiagonalSize = Get-WmiObject Win32_VideoController | Select -ExpandProperty PhysicalMonitorSize
#Write-Host "." -NoNewLine
Add-Type -AssemblyName System.Windows.Forms
$monitor = [System.Windows.Forms.Screen]::PrimaryScreen
$displayBitsPerColorChannel = [math]::Round((($monitor.BitsPerPixel) / 3),1)
Write-Host "." -NoNewLine

write-host "`n`n"
write-host "[.] CPU Generation: $CPUGen (needs 1ghz, 2 cores, Intel 8th gen or higher, or compatible AMD/Qualcomm)"
Display-PlusOrMinus -Bool $SysDriveOver64gb
write-host "System Drive is over 64gb: $SysDriveOver64gb"
Display-PlusOrMinus -Bool ($MemoryInGB -gt 3.9)
write-host "Memory in GB: $MemoryInGB (4gb required)"
Display-PlusOrMinus -Bool $UEFIEnabled
write-host "UEFI is Enabled: $UEFIEnabled"
Display-PlusOrMinus -Bool $SecureBootEnabled
write-host "SecureBoot is Enabled: $SecureBootEnabled"
Display-PlusOrMinus -Bool ($TPMVersion -like '*2,*')
write-host "TPM Version: $TPMVersion"
Display-PlusOrMinus -Bool $TPMIsActivated
write-host "TPM is Activated: $TPMIsActivated"
Display-PlusOrMinus -Bool $TPMIsEnabled
write-host "TPM is Enabled: $TPMIsEnabled"
Display-PlusOrMinus -Bool $TPMIsOwned
write-host "TPM is Owned: $TPMIsOwned"
if ($graphicsCardName -and $graphicsCardDriverVersion -and $graphicsCardDriverVersion -ge "2.0") {
  Write-Host "[+] Your system is compatible with DirectX 12 or later with WDDM 2.0 driver."
} else {
  Write-Host "[-] Your system is not compatible with DirectX 12 or later with WDDM 2.0 driver."
}
if ($displayResolutionMin -and $displayResolutionMin -ge 720) {
    Write-Host "[+] Your system has a high definition (720p) display, smallest resolution found $displayResolutionMin lines."
} else {
    Write-Host "[-] Your system does not have a high definition (720p) display, smallest resolution found $displayResolutionMin lines."
}
#if ($displayDiagonalSize -and $displayDiagonalSize.Height -ge 9) {
#    Write-Host "[+] Your system has a display that is greater than 9"" diagonally."
#} else {
#    Write-Host "[-] Your system does not have a display that is greater than 9"" diagonally."
#}
if ($displayBitsPerColorChannel -and $displayBitsPerColorChannel -ge 8) {
    Write-Host "[+] Your system has a display that is 8 bits per color channel. Found: $displayBitsPerColorChannel"
} else {
    Write-Host "[-] Your system does not have a display that is 8 bits per color channel. Found: $displayBitsPerColorChannel"
}

write-host "[!] Done!`n"
