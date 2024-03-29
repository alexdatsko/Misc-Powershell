#$path = "Serial Numbers.txt"
$path = "D:\Backups (Do Not Delete)\Serial Numbers.txt"
$data = ""

$date = Get-Date -format "yyyy-MM-dd HH:mm"
$day = (get-date).DayOfWeek
$datedata = "`r`n$date : $day : "
write-host $datedata
Add-Content $path $datedata

$driveobjs = Get-WmiObject win32_diskdrive | where { $_.model -inotmatch 'dell' -and $_.model -inotmatch 'DRAC' -and $_.model -inotmatch 'iSCSI' }
foreach ($driveobj in $driveobjs) {
  $drive =  ($driveobj | Format-List SerialNumber, model | out-string) -replace "`r`n",'' -replace "`n",'' -replace "`r",'' -replace "SerialN",' SerialN' -replace '`t',''
  $drive = ($drive -replace 'SerialNumber',"Serial Number" -replace 'model'," | Model" -replace '`t','' -replace '  ','')
  $drivevolume = " | Volumes: " 

  $partitions = get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($driveobj.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"
  if ($partitions -eq $null) { $drivevolume = " Volumes: None" }
  foreach($part in $partitions)
  {
      #Out-Host "`tPartition: $($part.name)"
      $vols = get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($part.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"
      foreach($vol in $vols)
      {
        $drivevolume = $drivevolume + "  $($vol.volumename)"
      }
  }
  $data = "$drive $drivevolume"
  write-host $data
  Add-Content $path $data

}
