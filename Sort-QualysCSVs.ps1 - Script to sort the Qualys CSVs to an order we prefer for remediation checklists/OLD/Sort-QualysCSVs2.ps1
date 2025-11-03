[cmdletbinding()]  # For verbose, debug etc
param(
  [string]$CSVType,
  [string]$InFile,
  [string]$OutFile
)

# Scrub parameters
if ($Infile -like ".\*") {
  $InFile = $InFile.replace(".\","")    # Remove ./ from beginning of filename
  $OutFile = $OutFile.replace(".\","")    # Remove ./ from beginning of filename
}

Write-Host "`n`n##########################################################################"
Write-Host "# Sort-QualysCSVs.ps1  --  Sorts Qualys reports into preferred format"
Write-Host "# v0.2 Alex Datkso "
Write-Host "# 4-12-2024"
Write-Host "#   Usage:"
Write-Host "#     Sort-QualysCSVs.ps1 -CSVType [Internal/External] -InFile 'Ortho DDS PLLC_Internal_2024-04-09.csv' -OutFile 'REMEDIATION-Ortho DDS PLLC_Internal_2024-04-09.csv'"
Write-Host "#                         ^^ -Parameter names are unnecessary, when in this order ^^"
Write-Host "#       -CSVType - You can use the first letter only, i.e: I for Internal, E for External, or B for Both (Both will pick the newest files)"
Write-Host "#       -InFile - Either input file name, or full path.  Can use first few letters[tab] to auto-complete."
Write-Host "#       -OutFile - will default to REMEDIATION-[infile name.csv] if omitted"
Write-Host "#       -Verbose - Display verbose output`n`n"
Write-Host "#   For example:"
Write-Host "#     Sort-QualysCSVs.ps1 I 'Ortho DDS PLLC_Internal_2024-04-09.csv' 'REMEDIATION-Ortho DDS PLLC_Internal_2024-04-09.csv'"
Write-Host "#       Picks Internal scan and arranges and outputs as a CSV file with the above filename"
Write-Host "#     Sort-QualysCSVs.ps1 B"
Write-Host "#       Picks most recent Internal and External CSV file, and arranges them and opens them both!"


function Select-BothFiles {
  # Get the newest Internal and External file in the current folder.
  $internalFile = Get-ChildItem -Path $PSScriptRoot -Filter "*Internal*.csv" | 
    Sort-Object -Property LastWriteTime -Descending | 
    Select-Object -First 1 |
    Select-Object -ExpandProperty FullName
  
  $externalFile = Get-ChildItem -Path $PSScriptRoot -Filter "*External*.csv" |
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

    # Get the directory and base name of the CSV file
    $Directory = [System.IO.Path]::GetDirectoryName($CSVFilePath)
    $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($CSVFilePath)
    if ($XLSXFilePath -eq "") {
      $XLSXFilePath = ("$($BaseName).xlsx").replace(".csv","")
    }

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
    [string]$inputfile,
    [string]$outputfile
  )

  # Scrub path from filename, working in pwd only here
  $InFile = (Split-Path $inputfile -Leaf)
  if ($outputfile -ne "") {
    try {
      $OutFile = (Split-Path $outputfile -Leaf)
    } catch {
      Write-Host "[!] ERROR Splitting path for outputfile: [ $outputfile ]"
    }
  }

  if ($Outfile -eq $Infile -or $OutFile -eq "") {
    Write-Host "[.] Output file cannot be the same as input file.."
    $OutFile = "REMEDIATION-$($InFile)"
    if ($InFile -like "*External*") {
      $OutFile = "EXT$($OutFile)"    # I like EXTREMEDIATION- instead of REMEDIATION- to make these more obvious.
    }
  }

  # Display parameters for the conversion
  Write-Host "[.] Reading fro m file: $InFile"
  Write-Host "[.] Writing to file: $OutFile  `n"

<# this broke for some reason, on some folders/files???? 4-19-24
  # Test that files exist or can be written to etc
  if (-not (Test-Path $InFile)) {
    Write-Host "[!] Error, can't access $InFile" -ForegroundColor Red
    exit
  }
  #>

  <# # Lets automatically overwrite for now, who cares 
  if (Test-Path $OutFile) {
    $input = (Read-Host "[!] $OutFile exists, overwrite? [Y/n] ").ToUpper()
    if ($input[0] -eq "" -or $input[0] -eq "N") {
      exit
    } else {
      Write-Verbose "[.] Overwriting $OutFile"
    }
  }
  #>

  Write-Host "[.] Converting file.. "
  if ($CSVTypeDetection -eq "Internal" -or ($CSVTypeDetection -eq "Both" -and $Infile -like "*internal*")) {  
    # Column order I want: "NetBIOS","IP","QID","Vulnerability Description","Severity","Fixed Date","Fixed Name","Fixed Note","Results","Solution","Threat","Impact","CVE ID","Last Detected"
    Import-CSV $InFile | Select-Object "NetBIOS","IP","QID","Vulnerability Description","Severity","Results","Solution","Threat","Impact","CVE ID","Last Detected" | Export-CSV $OutFile
  }
  if ($CSVTypeDetection -eq "External" -or  ($CSVTypeDetection -eq "Both" -and $Infile -like "*external*")) {  
    # Column order I want: "IP","Computer Name (DNS)","Devices connected from IP addresses","IPs","Port","Protocol","QID","Vulnerability Description","Severity","Results","Solution","Threat","Impact"
    Import-CSV $InFile | Select-Object "IP","Computer Name (DNS)","Devices connected from IP addresses","IPs","Port","Protocol","QID","Vulnerability Description","Severity","Results","Solution","Threat","Impact" | Export-CSV $OutFile
  }

  #Convert to XLSX and remove intermediary file
  $OutXLSXFile = ("$($OutFile).xlsx").replace('.csv','')
  Write-Host "[.] Converting $OutFile to XLSX : $OutXLSXFile"
  Convert-CSVtoXLSX $OutFile $OutXLSXFile
  try {
    Remove-Item -Force $OutFile -ErrorAction SilentlyContinue
  } catch {
    Write-Host "[!] Error removing temporary file $OutFile, remove it manually." -ForegroundColor Red
  }

  Write-Host "[!] Done, opening XLSX file in excel!`n"
  explorer $OutXLSXFile
}

$CSVTypeDetection = if ($CSVType.ToUpper()[0] -eq "I") { "Internal" } elseif ($CSVType.ToUpper()[0] -eq "E") { "External" } elseif ($CSVType.ToUpper()[0] -eq "B") { "Both" } else { "Unknown" }
if ($CSVTypeDetection -eq "Unknown")  {  # Lets pick from Internal/External using the GUI if not specified.
  Add-Type -AssemblyName System.Windows.Forms

  # Create the form
  $form = New-Object System.Windows.Forms.Form
  $form.Text = "Choose CSV Type"
  $form.Size = New-Object System.Drawing.Size(300, 210)
  $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

  # Create the radio buttons
  $radioButtonInternal = New-Object System.Windows.Forms.RadioButton
  $radioButtonInternal.Location = New-Object System.Drawing.Point(20, 20)
  $radioButtonInternal.Size = New-Object System.Drawing.Size(100, 20)
  $radioButtonInternal.Text = "Internal"

  $radioButtonExternal = New-Object System.Windows.Forms.RadioButton
  $radioButtonExternal.Location = New-Object System.Drawing.Point(20, 50)
  $radioButtonExternal.Size = New-Object System.Drawing.Size(100, 20)
  $radioButtonExternal.Text = "External"

  $radioButtonBoth = New-Object System.Windows.Forms.RadioButton
  $radioButtonBoth.Location = New-Object System.Drawing.Point(20, 80)
  $radioButtonBoth.Size = New-Object System.Drawing.Size(100, 20)
  $radioButtonBoth.Text = "Both"
  $radioButtonBoth.Checked = $true

  # Create the OK button
  $buttonOK = New-Object System.Windows.Forms.Button
  $buttonOK.Location = New-Object System.Drawing.Point(100, 130)
  $buttonOK.Size = New-Object System.Drawing.Size(75, 23)
  $buttonOK.Text = "OK"
  $buttonOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $form.AcceptButton = $buttonOK

  # Add the controls to the form
  $form.Controls.Add($radioButtonInternal)
  $form.Controls.Add($radioButtonExternal)
  $form.Controls.Add($radioButtonBoth)
  $form.Controls.Add($buttonOK)

  # Show the form and get the result
  $result = $form.ShowDialog()

  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    if ($radioButtonInternal.Checked) {
      $csvType = "Internal"
    } else { 
      if ($radioButtonExternal.Checked) {
        $csvType = "External"
      } else {
        if ($radioButtonBoth.Checked) {
          $csvType = "Both"
        } else {
          $csvType = "Unknown"
        }
      }
    }
    Write-Verbose "Selected CSV type: $csvType"
    $CSVTypeDetection = $csvType
  }
}

# Error out if we don't know what type of file we want to open at this point..
if ($CSVTypeDetection -eq "Unknown")  { Write-Host "[!] ERROR: Unknown if Internal/External/Both CSV Type, please pick an option again.." -ForegroundColor Red ; exit }
Write-Host "`n[.] File Type: $CSVType - ($CSVTypeDetection)"
if ($CSVTypeDetection -eq "Both") {
  $InternalFile, $ExternalFile = Select-BothFiles
} 

if ($Infile -eq "" -and $CSVTypeDetection -ne "Both") {  # Lets open a file picker if no filename is provided and we are not auto-running on both.
  if ($CSVTypeDetection -eq "Internal") {
    $mask = "*Internal*"
  } else {
    if ($CSVTypeDetection -eq "External") {
      $mask = "*External*"
    } else {
      $mask = "*"
    }
  }
  Write-Host "mask: $mask"
  Add-Type -AssemblyName System.Windows.Forms
  # Open file picker dialog GUI if we haven't picked Both
  $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
  $openFileDialog.InitialDirectory = $pwd
  $openFileDialog.Filter = "CSV files (*.csv)|$($mask).csv|All files (*.*)|$($mask).*"
  $openFileDialog.Title = "Select a file"

  if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $selectedFile = $openFileDialog.FileName
    Write-Verbose "[+] Selected file: $selectedFile"
    if ($selectedFile -eq "") {
      Write-Verbose "Error, no file selected.."
    } else {
      $InFile = (Split-Path $selectedFile -Leaf)
    }
  }
}

if ($InternalFile) {
  Convert-CSVFile $InternalFile
  Convert-CSVFile $ExternalFile 
} else {
  Convert-CSVFile $InFile
}

$input = Read-Host "[ press enter to exit, or close this window ]"
