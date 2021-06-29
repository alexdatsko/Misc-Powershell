######################################################################################
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

