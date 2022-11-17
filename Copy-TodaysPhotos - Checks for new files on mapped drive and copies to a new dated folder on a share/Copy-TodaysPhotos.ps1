<<<<<<< HEAD
﻿######################################################################################
#
# Copy-TodaysPhotos.ps1
#
# Copies all photos from F:\DCIM\<Todays date> to \\server\practice documents\Clinic Camera\<Todays date>
#
# Alex Datsko - MME Consulting Inc. Last modified 2022-03-24
#

Write-Host "`r`n`r`n# Copy-TodaysPhotos.ps1 #`r`n" -ForegroundColor Green

# Delay 5 seconds
Write-host "Delaying for 5 seconds.."
#start-sleep -seconds 5

$todaysdate = get-date -format "yyyy-MM-dd"
$datecomparetoday = get-date -format "MM/dd/yyyy"
$datecomparetomorrow = ((get-date).adddays(1)).tostring("MM/dd/yyyy")

$dcimfolder = "F:\DCIM"

# For testing..
#$copyto = "c:\temp"
#$copytoday = "c:\temp\$todaysdate"

$copyto = "\\server\practice documents\Clinic Camera"
$copytoday = "\\server\practice documents\Clinic Camera\$todaysdate"

# Find last date of folder in $copyto in case days were skipped.
$i=1
$allfolders = (Get-ChildItem -Path $copyto -Directory -Recurse) 
$lastdayfolder = $null
while (!($lastdayfolder)) {  # There should only be one folder here for each day.. Can try taking the first one.
  #Write-Host "Trying to add days : -$i"
  $lastdayfolders = ($allfolders | Where { ($_.LastWriteTime -ge (Get-Date).AddDays(-$i)) -and ($_.LastWriteTime -le (Get-Date).AddDays(-($i-1))) })   
                                                                     # ^^ Start with between -1 and 0, then -2 and -1, then -3 and -2, etc.
  if ($lastdayfolders) {  
    $lastdayfolder = ($lastdayfolders | Select-Object -First 1)
    $lastdayfolderdate = (($lastdayfolder | Select -ExpandProperty LastWriteTime).ToString("yyyy-MM-dd") | Out-String).Replace("`n","")
  }
  $i+=1; 
}

Write-Host "  Last folder found : $($lastdayfolder.FullName) `r`n  Dated : $lastdayfolderdate"

# Create folder $copytoday if it doesnt exist
If(!(test-path $copytoday))
{
  Write-host "$copytoday not found, creating folder for $todaysdate .. "
  New-Item -ItemType Directory -Force -Path $copytoday
}

# searches thru complete folder for array of files dated today
if (!(test-path $dcimfolder)) {
  write-host "$dcimfolder not found, card is not connected."
  #[Environment]::Exit(1)
  exit
}

Write-Host "[.] Copying files since $lastdayfolderdate to $datecomparetomorrow .."
$filestocopy = Get-ChildItem -Path $dcimfolder -File -Recurse | 
    Where-Object { $_.LastWriteTime -ge $lastdayfolderdate -and $_.LastWriteTime -le $datecomparetomorrow } | 
    select-Object -expand FullName 

write-host "New files found:"
$filestocopy

foreach ($file in $filestocopy) {
  $fileonly = Split-Path $file -Leaf
  Write-host "Copying $fileonly to $copytoday "
  Move-Item -Path $file -Destination $copytoday 
}

write-host "Done! Note: Files were not deleted, they will need to be removed manually."

=======
﻿######################################################################################
#
# Copy-TodaysPhotos.ps1
#
# Copies all photos from F:\DCIM\<Todays date> to \\server\practice documents\Clinic Camera\<Todays date>
#
# Alex Datsko - MME Consulting Inc. 2021-05-26
#

$todaysdate = get-date -format "yyyy-MM-dd"
$datecomparetoday = get-date -format "MM/dd/yyyy"
$datecomparetomorrow = ((get-date).adddays(1)).tostring("MM/dd/yyyy")

clear

# Delay 5 seconds
#Write-host "Delaying for 5 seconds.."
#start-sleep -seconds 5

$copyto = "\\server\practice documents\Clinic Camera\$todaysdate"

If(!(test-path $copyto))
{
      write-host "$copyto not found, creating folder for $todaysdate .. "
      New-Item -ItemType Directory -Force -Path $copyto
}

$dcimfolder = "F:\DCIM"

# searches thru complete folder for array of files dated today
if (!(test-path $dcimfolder)) {
  write-host "$dcimfolder not found, card is not connected."
  #[Environment]::Exit(1)
  exit
}

$filestocopy = Get-ChildItem -Path $dcimfolder -File -Recurse | 
    Where-Object { $_.LastWriteTime -ge $datecomparetoday -and $_.LastWriteTime -le $datecomparetomorrow } | 
    select-Object -expand FullName 

write-host "New files found:"
$filestocopy

foreach ($file in $filestocopy) {
  $fileonly = Split-Path $file -Leaf
  #$fileonly
  #$pathonly =  $file.replace($fileonly,'')
  #$pathonly
  #$filepath = split-path $pathonly
  #$filepath
  Write-host "Copying $fileonly to $copyto "
  Move-Item -Path $file -Destination $copyto 
}

write-host "Done! Note: Files were not deleted, they will need to be removed manually."

>>>>>>> 789b4d5dde1cb51e650d191400987b7331e1195e
