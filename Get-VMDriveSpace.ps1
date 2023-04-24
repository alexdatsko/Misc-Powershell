Write-Host "################################
# Get-VMDriveSpace.ps1
# Alex Datsko 04-11-23
# Gets a list of all VMs and their VHDXs, shows a quick report on the amount of free space on each VHDX
"

Get-VM | ForEach-Object {
  $vm = $_.VMID
  $vmname = $_.VMName
  $drives = Get-VHD $vm
  $drives | ForEach-Object {
    $vhdpath = $_.Path
    $vhdpathshort = ($vhdpath).split(' ')[-1]
    $size=[math]::round((Get-VHD -Path $vhdpath).size / 1GB,1)
    $filesize=[math]::round((Get-VHD -Path $vhdpath).filesize / 1GB,1)
    $freespace=$size - $filesize
    if (!($vhdpath.ToUpper() -like '*.AVHDX')) {
      Write-Host "$vmname $vhdpathshort Size $filesize GB Free $freespace GB"
    }
  }
}