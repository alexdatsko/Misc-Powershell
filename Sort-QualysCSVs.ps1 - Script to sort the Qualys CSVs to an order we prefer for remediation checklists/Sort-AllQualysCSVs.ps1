[cmdletbinding()]  # For verbose, debug etc
param(
  [string]$CSVType,
  [string]$InFile,
  [string]$OutFile = "REMEDIATION-$($InFile)"
)

Write-Host "`n`n##########################################################################"
Write-Host "# Sort-AllQualysCSVs.ps1  --  Sorts Qualys reports into preferred format"
Write-Host "# Alex Datkso  "
Write-Host "#   v0.1 - 10-10-2025 - Initial working script"
Write-Host "# "
Write-Host "#        Picks most recent Internal CSV files (for all clients) in the folder the script is run from, arranges them, and opens as their XLSX form."
Write-Host "#        NOTE: This process takes about 30 seconds per file!"

function Select-BothFiles {
  param (
    $ScriptRoot
  )
  $date = get-date -format "yyyy-MM-dd"
  # Get the newest Internal and External file in the current folder.
  $internalFile = Get-ChildItem -Path $ScriptRoot -Filter "*Internal*.csv" | 
    Sort-Object -Property LastWriteTime -Descending | 
    Select-Object -First 1 |
    Select-Object -ExpandProperty FullName
  $internalFileNew = $internalFile.replace("Internal_","Internal_$date")
  Rename-Item -Path $internalFile -NewName $internalFilenew
  
  #$externalFile = Get-ChildItem -Path $ScriptRoot -Filter "*External*.csv" |
  #  Sort-Object -Property LastWriteTime -Descending |
  #  Select-Object -First 1 |
  #  Select-Object -ExpandProperty FullName
  #$externalFileNew = $externalFile.replace("External_","External_$date")
  #Rename-Item -Path $externalFile -NewName $externalFilenew
    
  return $internalFileNew #, $externalFileNew
}

function Convert-CSVtoXLSX {
  param (
      [Parameter(Mandatory=$true)]
      [string]$CSVFilePath,
      [string]$XLSXFilePath,
      [string]$FilteredQIDs

  )

  Write-Verbose "CSVFilePath: $CSVFilePath"
  Write-Verbose "XLSXFilePath: $XLSXFilePath"

  # Get the directory and base name of the CSV file
  $Directory = [System.IO.Path]::GetDirectoryName($CSVFilePath)
  $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($CSVFilePath)
  Write-Verbose "Directory $Directory"
  Write-Verbose "Basename $Basename"
  if ($XLSXFilePath -eq "") {
    $XLSXFilePath = ("$($BaseName).xlsx").replace(".csv","")
  }
  Write-Verbose "XLSXFilePath: $XLSXFilePath"

#####

  $Data = Import-Csv -Path $CSVFilePath
  $Excel = New-Object -ComObject Excel.Application
  $Workbook = $Excel.Workbooks.Add()
  $Worksheet = $Workbook.Worksheets.Item(1)

  # Populate headers
  $colIndex = 1
  foreach ($prop in $Data[0].PSObject.Properties) {
      $Worksheet.Cells.Item(1, $colIndex) = $prop.Name
      $colIndex++
  }

  # Populate data
  $highlightQIDsInt = '90006','90007','91564','91565','92175','105170','105171'      # Internal QIDs to ignore every time
  $highlightQIDsExt = '82003','38169','38170','38173','38863'                # External QIDs to ignore every time

  $rowIndex = 2
  foreach ($row in $Data) {
    $colIndex  = 1
    $QIDValue  = $null
    foreach ($prop in $row.PSObject.Properties) {
      $Worksheet.Cells.Item($rowIndex, $colIndex) = $prop.Value
      if ($prop.Name -eq 'QID') { $QIDValue = $prop.Value }
      if ($prop.Name -eq 'Severity') { $Severity = $prop.Value }
      $colIndex++
    }
    if ($highlightQIDsInt -contains $QIDValue) {
      $Worksheet.Rows.Item($rowIndex).Interior.ColorIndex = 6
      $Worksheet.Cells.Item($rowIndex, 8) = 'AlexD'
      $Worksheet.Cells.Item($rowIndex, 9) = 'Ignored, low risk'
    }
    if ($highlightQIDsExt -contains $QIDValue) {
      $Worksheet.Rows.Item($rowIndex).Interior.ColorIndex = 6
      $Worksheet.Cells.Item($rowIndex, 11) = 'AlexD'
      $Worksheet.Cells.Item($rowIndex, 12) = 'Ignored, low risk'
    }
    if ($Severity -eq '0') {  # Catch external IPs that are clean, mark it!
      $Worksheet.Rows.Item($rowIndex).Interior.ColorIndex = 4
      $Worksheet.Cells.Item($rowIndex, 11) = 'AlexD'
      $Worksheet.Cells.Item($rowIndex, 12) = 'Clean!'
    }
    $rowIndex++
  }

  # ADD TABLE
  $lastRow    = $Data.Count + 1
  #$lastColumn = $Data[0].PSObject.Properties.Count
  $lastColumn = $worksheet.UsedRange.Columns.Count
  Write-Host "Setting range for table from A1 to: $lastRow , $lastColumn"
  $range      = $Worksheet.Range("A1", $Worksheet.Cells.Item($lastRow, $lastColumn))
  $table      = $Worksheet.ListObjects.Add(1, $range, "importedCSV", 1)


##

  if ($Basename -like "*INTERNAL*") {
    # Column widths for Internal report
    $Worksheet.Columns.Item(1).ColumnWidth  = 18
    $Worksheet.Columns.Item(2).ColumnWidth  = 18
    $Worksheet.Columns.Item(3).ColumnWidth  = 18
    $Worksheet.Columns.Item(4).ColumnWidth  = 8
    $Worksheet.Columns.Item(5).ColumnWidth  = 55
    $Worksheet.Columns.Item(7).ColumnWidth  = 14
    $Worksheet.Columns.Item(8).ColumnWidth  = 14
    $Worksheet.Columns.Item(9).ColumnWidth  = 28
    $Worksheet.Columns.Item(10).ColumnWidth = 70
    $Worksheet.Columns.Item(11).ColumnWidth = 70
    $Worksheet.Columns.Item(12).ColumnWidth = 70
    $Worksheet.Columns.Item(13).ColumnWidth = 70
    $Worksheet.Columns.Item(14).ColumnWidth = 22
    $Worksheet.Columns.Item(15).ColumnWidth = 22
    $Worksheet.Columns.Item(16).ColumnWidth = 22
  }

  if ($Basename -like "*EXTERNAL*") {
    # Column widths for External report
    $Worksheet.Columns.Item(1).ColumnWidth  = 14
    $Worksheet.Columns.Item(2).ColumnWidth  = 24
    $Worksheet.Columns.Item(3).ColumnWidth  = 36
    $Worksheet.Columns.Item(4).ColumnWidth  = 9
    $Worksheet.Columns.Item(5).ColumnWidth  = 9
    $Worksheet.Columns.Item(9).ColumnWidth  = 9
    $Worksheet.Columns.Item(10).ColumnWidth = 9
    $Worksheet.Columns.Item(11).ColumnWidth = 9
    $Worksheet.Columns.Item(12).ColumnWidth = 24
    $Worksheet.Columns.Item(13).ColumnWidth = 67
    $Worksheet.Columns.Item(14).ColumnWidth = 67
    $Worksheet.Columns.Item(15).ColumnWidth = 67
    $Worksheet.Columns.Item(16).ColumnWidth = 67
  }

  $Worksheet.Activate()
  $Worksheet.Range("B1").Select() 
  $Excel.ActiveWindow.FreezePanes = $true

  # Save the workbook to the XLSX file path
  $Workbook.SaveAs($XLSXFilePath)
  $Workbook.Close()
  $Excel.Quit()
  [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Excel) | Out-Null
}

function Convert-CSVFile {
  param(
    [string]$InFile,
    [string]$OutFile
  )

  # If not set, set Outfile name based on Internal
  if (-not $OutFile) {
    $OutFile = "$($runpath)\REMEDIATION-$(Split-Path $InFile -Leaf)"
    if ($Infile -like "*External*") {
      $OutFile = "$($OutFile -replace "REMEDIATION","EXTREMEDIATION")" 
    }
  }  
  Write-Verbose "[.] Converting to CSV: $InFile"
  # Display parameters for the conversion
  #Write-Verbose "[.] Reading from file: $InFile"
  Write-Verbose "[.] Writing to file: $OutFile  `n"

  # Test that files exist or can be written to etc
  if (-not (Test-Path $InFile)) {
    Write-Host "[!] Error, can't access $InFile"
    exit
  }

  Write-Host "[.] Populating new CSV file.. "
  if ($InFile -like "*Internal*") {  
    # Column order I want: "NetBIOS","IP","QID","Vulnerability Description","Severity","Fixed Date","Fixed Name","Fixed Note","Results","Solution","Threat","Impact","CVE ID","Last Detected"
    Import-CSV $InFile | Select-Object "NetBIOS","Computer Name (DNS)","IP","QID","Vulnerability Description","Severity","Fixed Date","Fixed Name","Fixed Note","Results","Solution","Threat","Impact","CVE ID","Last Detected","First Detected" | Sort-Object "NetBIOS","Vulnerability Description" | Export-CSV $OutFile
  }
  if ($InFile -like "*External*") {  
    # Column order I want: "IP","Computer Name (DNS)","Devices connected from IP addresses","IPs","Port","Protocol","QID","Vulnerability Description","Severity","Results","Solution","Threat","Impact"
    Import-CSV $InFile | Select-Object "IP","Computer Name (DNS)","Devices connected from IP addresses","IPs","Port","Protocol","QID","Vulnerability Description","Severity","Fixed Date","Fixed Name","Fixed Note","Results","Solution","Threat","Impact" | Sort-Object "IP","Port","Vulnerability Description"| Export-CSV $OutFile
  }

  if (Test-Path $Outfile) {
    Write-Host "[!] Success writing temp .CSV file." -ForegroundColor Green
  } else {
    Write-Host "[!] Error writing .CSV file $outfile !!!" -ForegroundColor Red
  }

  # Convert to XLSX and remove intermediary file
  $dateformat = get-date -format "yyyy-MM-dd"
  $datestring = "_$($dateformat)_"
  #$OutXLSXFile = ("$($OutFile).xlsx").replace('.csv','').replace('__',$datestring) # Added to change to todays date
  $OutXLSXFile = ("$($OutFile).xlsx").replace('.csv','') # Date is now renamed from the input file instead, not needed twice..
  Write-Host "[.] Converting $OutFile to XLSX : $OutXLSXFile"
  Convert-CSVtoXLSX -CSVFilePath $OutFile -XLSXFilePath $OutXLSXFile
  
  try {
    Write-Host "[.] Removing intermediatary file: $outfile"
    Remove-Item -Force "$($OutFile)" -ErrorAction SilentlyContinue
  } catch {
    Write-Host "[!] Error removing temporary file $OutFile, remove it manually." -ForegroundColor Red
  }

  Write-Host "[!] Done with $OutXLSXFile !"
  #Write-Host "[.] Opening XLSX file in excel!`n"
  #explorer $OutXLSXFile
}

################ MAIN ##################

# Scrub parameters
if ($Infile -like ".\*") {
  $InFile = $InFile.replace(".\","")    # Remove ./ from beginning of filename
  $OutFile = $OutFile.replace(".\","")    # Remove ./ from beginning of filename
}

$curPath = ($pwd) # for now, this seems to work..
if ($curPath -like "*Microsoft.Powershell.Core\FileSystem*") {
  $runPath = "\\$(($curPath -split "\\\\")[1])"   # Escaped \\\\ is \\
} else {
  $runPath = $curpath
}

Write-Verbose "runpath: $runpath"
$Filenames = (gci *.csv).FullName

Write-Verbose "Filenames: $Filenames"
#Write-Verbose "ExternalFile $ExternalFile"

foreach ($InternalFile in $Filenames) {
  Convert-CSVFile "$($InternalFile)"
#  Convert-CSVFile "$($ExternalFile)" 
}

#$input = Read-Host "[ press enter to exit, or close this window ]"
