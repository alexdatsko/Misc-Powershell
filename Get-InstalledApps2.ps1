$pclist = @(get-adcomputer -filter 'name -like "*"')
if (!($pclist)) {
  write-host "Couldn't get computer list from Get-ADComputer !!"
  [Environment]::Exit(1)
}

# Default to localhost
$pclist = @("localhost")

$list=@()

Foreach ($pcname in $pclist) {
  
  # Get the minimal list from WMIC win32_product in case there are things not found in the registry
  $win32_prod = Get-WmiObject Win32_Product -ComputerName $pcname | select Name,Version

  # Get a fuller list from the registry Uninstall keys
  $InstalledSoftwareKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
  $InstalledSoftware=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$pcname)
  $RegistryKey=$InstalledSoftware.OpenSubKey($InstalledSoftwareKey) 
  $SubKeys=$RegistryKey.GetSubKeyNames()
  Foreach ($key in $SubKeys){
    $thisKey=$InstalledSoftwareKey+"\\"+$key
    $thisSubKey=$InstalledSoftware.OpenSubKey($thisKey)
    $obj = New-Object PSObject
    $obj | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $pcname
    $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))
    $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"))
    $list += $obj
  }

  # Add minimal WMIC list to the fuller list above
  foreach ($prod in $win32_prod) {
    $obj = New-Object PSObject
    $obj | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $pcname
    $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($prod.Name)
    $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($prod.Version)
    $list += $obj
  }
}

# Display any products that exist, are unique, etc
$fulllist = $list | where { $_.DisplayName } | select ComputerName, DisplayName, DisplayVersion | sort ComputerName,DisplayName,@{Expression="DisplayVersion";Descending=$true} -Unique | FT
$fulllist | tee "InstalledApps.txt"

