# Get-VHDSizes - This should audit all VM's and also get the capacity and used space inside the VM, with one fell swoop.
# Started 8/3/20 - Alex Datsko

# Currently shows the VHD path, size, and filesize, the correllation with the VM name and getting the free space of the VM's internal file system is not working yet.
# This will show the vhds and their sizes:  
#             get-vm | select vmid | get-vhd | select path,vhdtype,size,filesize | fl
# This will show the vms internal disk space:
#             get-vm | select -expandproperty vmname | foreach { $_ ; gwmi win32_logicaldisk -computername $_ -Filter "DeviceID='C:'" | Select-object Name,Caption,Description,Size,Freespace | fl }

$vms = get-vm | select vmname,vmid
$vhds = get-vm | select vmname,vmid | get-vhd | select path,size,filesize
#$vhds
foreach ($vhd in $vhds) { 
  
  $vhdpath = $vhd | select-object -expandproperty Path
  $vhdvmid = $vhd | select-object -expandproperty Vmid
  $vmname = $vms | where { $_.vmid -eq $vhdvmid } | select-object -expandproperty VMName
  
  $cDisk = Get-WmiObject Win32_LogicalDisk -ComputerName $vmname -Filter "DeviceID='C:'" | Select-Object Size,FreeSpace
  $cCapacity = $([math]::Round($cDisk.Size/1GB))
  $cFreespace = $([math]::Round($cDisk.Freespace/1GB))
  $cUsed = $cCapacity - $cFreespace

  $dDisk = Get-WmiObject Win32_LogicalDisk -ComputerName $vmname -Filter "DeviceID='D:'" | Select-Object Size,FreeSpace
  $dCapacity = $([math]::Round($dDisk.Size/1GB))
  $dFreespace = $([math]::Round($dDisk.Freespace/1GB))
  $dUsed = $dCapacity - $dFreespace

  write-host "Name: $vmname"
  write-host "Path: $vhdpath"
  write-host "VMID: $vhdvmid"
  write-host "Size: $([math]::Round($vhd.size/1GB))g"
  write-host "Filesize: $([math]::Round($vhd.filesize/1GB))g"
  write-host "Drive C: Capacity: $cCapacity"
  write-host "Drive C: Used: $cUsed"
  write-host "Drive C: FreeSpace: $cFreeSpace"
  write-host "Drive D: Capacity: $dCapacity"
  write-host "Drive D: Used: $dUsed"
  write-host "Drive D: FreeSpace: $dFreeSpace"
  write-host "`r`n"
}
