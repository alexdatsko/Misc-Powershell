[cmdletbinding()]  # For verbose, debug etc
param(
  [string]$CSVType,
  [string]$InFile,
  [string]$OutFile = "REMEDIATION-$($InFile)"
)

Write-Host "`n`n##########################################################################"
Write-Host "# Sort-BothQualysCSVs.ps1  --  Sorts Qualys reports into preferred format"
Write-Host "# v0.2 - 5-9-2024 - Alex Datkso MME Consulting Inc "
Write-Host "# "
Write-Host "#        Picks most recent Internal and External CSV file in the folder the script is run from, arranges them, and opens them both as their XLSX form."
Write-Host "#        NOTE: This process takes about 30 seconds per file!"

function Select-BothFiles {
  param (
    $ScriptRoot
  )
  # Get the newest Internal and External file in the current folder.
  $internalFile = Get-ChildItem -Path $ScriptRoot -Filter "*Internal*.csv" | 
    Sort-Object -Property LastWriteTime -Descending | 
    Select-Object -First 1 |
    Select-Object -ExpandProperty FullName
  
  $externalFile = Get-ChildItem -Path $ScriptRoot -Filter "*External*.csv" |
    Sort-Object -Property LastWriteTime -Descending |
    Select-Object -First 1 |
    Select-Object -ExpandProperty FullName
  
  return $internalFile, $externalFile
}

function Convert-CSVtoXLSX {
    param (
        [Parameter(Mandatory=$true)]
        [string]$CSVFilePath,
        [string]$XLSXFilePath

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

    $Data = Import-Csv -Path $CSVFilePath
    $Excel = New-Object -ComObject Excel.Application
    $Workbook = $Excel.Workbooks.Add()
    $Worksheet = $Workbook.Worksheets.Item(1)
    $colIndex = 1
    foreach ($prop in $Data[0].PSObject.Properties) {
        $Worksheet.Cells.Item(1, $colIndex) = $prop.Name
        $colIndex++
    }
    $rowIndex = 2
    foreach ($row in $Data) {
        $colIndex = 1
        foreach ($prop in $row.PSObject.Properties) {
            $Worksheet.Cells.Item($rowIndex, $colIndex) = $prop.Value
            $colIndex++
        }
        $rowIndex++
    }

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
    Import-CSV $InFile | Select-Object "NetBIOS","IP","QID","Vulnerability Description","Severity","Fixed Date","Fixed Name","Fixed Note","Results","Solution","Threat","Impact","CVE ID","Last Detected","First Detected" | Sort-Object "NetBIOS","Vulnerability Description" | Export-CSV $OutFile
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
  $OutXLSXFile = ("$($OutFile).xlsx").replace('.csv','')
  Write-Host "[.] Converting $OutFile to XLSX : $OutXLSXFile"
  Convert-CSVtoXLSX -CSVFilePath $OutFile -XLSXFilePath $OutXLSXFile
  
  try {
    Write-Host "[.] Removing intermediatary file: $outfile"
    Remove-Item -Force "$($OutFile)" -ErrorAction SilentlyContinue
  } catch {
    Write-Host "[!] Error removing temporary file $OutFile, remove it manually." -ForegroundColor Red
  }

  Write-Host "[!] Done!"
  Write-Host "[.] Opening XLSX file in excel!`n"
  explorer $OutXLSXFile
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
}

Write-Verbose "runpath: $runpath"
$InternalFile,$ExternalFile = Select-BothFiles -ScriptRoot $runPath

Write-Verbose "InternalFile $InternalFile"
Write-Verbose "ExternalFile $ExternalFile"

if ($InternalFile) {
  Convert-CSVFile "$($InternalFile)"
  Convert-CSVFile "$($ExternalFile)" 
}

#$input = Read-Host "[ press enter to exit, or close this window ]"
