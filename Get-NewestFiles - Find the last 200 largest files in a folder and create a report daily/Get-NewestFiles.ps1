# Get-NewestFiles.ps1
# Grab list of X newest files in d:\data\dolphin\working for review, showing largest files first
# Alex D @  916-550-5514

$date = Get-Date -format "yyyy-MM-dd"

$numfiles = 200

$folder = "D:\data\dolphin\working\"

$reportpath = "D:\Backups (DO NOT DELETE)\Reports\"
$reportpathfull = $reportpath + "DolphinWorking\"
$reportfile = $reportpathfull + "DolphinWorking-" + $date + ".txt"

# Make sure report path(s) are created so they can be written
if (test-path $reportpath) {
  write-host "Report folder $reportpath found."
} else {
  write-host "Creating "+$reportpath+" .."
  New-Item -Path $reportpath -ItemType "directory"
}
if (test-path $reportpathfull) {
  write-host "Report folder "+$reportpathfull+" found."
} else {
  write-host "Creating "+$reportpathfull+" .."
  New-Item -Path $reportpathfull -ItemType "directory"
}
if (test-path $reportpathfull) {
  write-host "Report folder "+$reportpathfull+" found (again)."
} else {
  write-host "Could not create report folder, exiting!!!"
  exit 1
}

# Get large list of files in folder
$working = gci $folder -recurse 
# Get smaller list of X last written files
$workinglast = $working | sort-object -property LastWriteTime | select -last $numfiles 

# Find total folder size
$workingsize = "{0} MB" -f ([Math]::Floor(($working | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB))

# Create report of largest X files
$sizeoutput = $folder + " size on disk: "+$workingsize+"`r`n" | out-file -encoding ascii $reportfile -NoNewline
$report = $workinglast | Sort-Object Length -Descending | out-string | out-file -encoding ascii $reportfile -Append -NoNewline
