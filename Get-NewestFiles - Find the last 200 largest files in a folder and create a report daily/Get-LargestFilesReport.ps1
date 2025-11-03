# Get-LargestFiles.ps1 - 01-06-2021
# Grab list of X largest files in a Drive or Folder for review, showing largest files first
# Alex D @  916-550-5514

$date = Get-Date -format "yyyy-MM-dd HH:mm"


$numfiles = 50

$folder = "D:\"
$reportpath = "D:\Backups (DO NOT DELETE)\Reports"
$reportname = "LargestFiles"


function Get-LargeFileReport {
  param (
    [string[]]$Folder,
    [string[]]$ReportPath,
    [string[]]$ReportName
 )
  
  write-host "Folder: ${Folder}"
  write-host "ReportPath: ${ReportPath}"
  write-host "ReportName: ${ReportName}"

  $reportpathfull = "${reportpath}\${reportname}"
  $reportfile = "${reportpathfull}\${reportname}-${date}.txt"

  write-host "ReportPathFull: " $ReportPathFull
  write-host "ReportFile: " $ReportFile

  write-host "`r`nMake sure report path(s) are created so they can be written..."
  if (test-path $reportpath) {
    write-host "Report folder $reportpath found."
  } else {
    write-host "Creating " $reportpath " .."
    New-Item -Path $reportpath -ItemType "directory" | out-null
  }
  if (test-path $reportpathfull) {
    write-host "Report folder " $reportpathfull " found."
  } else {
    write-host "Creating " $reportpathfull " .."
    New-Item -Path $reportpathfull -ItemType "directory" | out-null
  }
  if (test-path $reportpathfull) {
    write-host "Report folder " $reportpathfull " found (again)."
  } else {
    write-host "Could not create report folder, exiting!!!"
    exit 1
  }

  write-host "Getting large list of files in folder ${folder} .."
  $working = gci $folder -recurse 
  write-host "Getting smaller list of ${numfiles} last written files.."
  $workinglast = $working | sort-object Length -Descending | select -first $numfiles 

  write-host "Finding total folder size.."
  $workingsize = "{0} MB" -f ([Math]::Floor(($working | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB))

  write-host "Creating report of largest ${numfiles} files..."
  $sizeoutput = $folder + " size on disk: ${workingsize}`r`n" | out-file -encoding ascii $reportfile
  $report = $workinglast | out-string | out-file -encoding ascii $reportfile -Append 

}





Get-LargeFileReport -Folder $folder -ReportPath $reportpath -ReportName $reportname

