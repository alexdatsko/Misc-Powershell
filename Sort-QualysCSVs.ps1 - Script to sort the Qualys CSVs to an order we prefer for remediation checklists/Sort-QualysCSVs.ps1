param(
  [string]$CSVType,
  [string]$InFile,
  [string]$OutFile = "REMEDIATION-$($InFile)",
  $Verbose = $false
)

Write-Host "`n`n##########################################################################"
Write-Host "# Sort-QualysCSVs.ps1  --  Sorts Qualys reports into preferred format"
Write-Host "# v0.1 Alex Datkso MME Consulting Inc"
Write-Host "# 4-10-2024"
Write-Host "#   Usage:"
Write-Host "#   Sort-QualysCSVs.ps1 -CSVType [Internal/External] -InFile 'Ortho DDS PLLC_Internal_2024-04-09.csv' -OutFile 'REMEDIATION-Ortho DDS PLLC_Internal_2024-04-09.csv'"
Write-Host "#     CSVType - You can use the first letter only, i.e: I for Internal or E for External"
Write-Host "#     InFile - Either input file name, or full path.  Can use first few letters[tab] to auto-complete."
Write-Host "#     OutFile - will default to REMEDIATION-[infile name.csv] if omitted`n`n"

# Scrub parameters
if ($Infile -like ".\*") {
  $InFile = $InFile.replace(".\","")    # Remove ./ from beginning of filename
  $OutFile = $OutFile.replace(".\","")    # Remove ./ from beginning of filename
}

$CSVTypeDetection = if ($CSVType.ToUpper()[0] -eq "I") { "Internal" } elseif ($CSVType.ToUpper()[0] -eq "E") { "External" } else { "Unknown" }
if ($CSVTypeDetection -eq "Unknown")  {  # Lets pick from Internal/External using the GUI if not specified.
  Add-Type -AssemblyName System.Windows.Forms

  # Create the form
  $form = New-Object System.Windows.Forms.Form
  $form.Text = "Choose CSV Type"
  $form.Size = New-Object System.Drawing.Size(300, 150)
  $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

  # Create the radio buttons
  $radioButtonInternal = New-Object System.Windows.Forms.RadioButton
  $radioButtonInternal.Location = New-Object System.Drawing.Point(20, 20)
  $radioButtonInternal.Size = New-Object System.Drawing.Size(100, 20)
  $radioButtonInternal.Text = "Internal"
  $radioButtonInternal.Checked = $true

  $radioButtonExternal = New-Object System.Windows.Forms.RadioButton
  $radioButtonExternal.Location = New-Object System.Drawing.Point(20, 50)
  $radioButtonExternal.Size = New-Object System.Drawing.Size(100, 20)
  $radioButtonExternal.Text = "External"

  # Create the OK button
  $buttonOK = New-Object System.Windows.Forms.Button
  $buttonOK.Location = New-Object System.Drawing.Point(100, 80)
  $buttonOK.Size = New-Object System.Drawing.Size(75, 23)
  $buttonOK.Text = "OK"
  $buttonOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $form.AcceptButton = $buttonOK

  # Add the controls to the form
  $form.Controls.Add($radioButtonInternal)
  $form.Controls.Add($radioButtonExternal)
  $form.Controls.Add($buttonOK)

  # Show the form and get the result
  $result = $form.ShowDialog()

  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
      if ($radioButtonInternal.Checked) {
          $csvType = "Internal"
      } else {
          $csvType = "External"
      }
      Write-Output "Selected CSV type: $csvType"
      $CSVTypeDetection = $csvType
  }
}

# Error out if we don't know what type of file we want to open at this point..
if ($CSVTypeDetection -eq "Unknown")  { Write-Host "[!] ERROR: Unknown if Internal/External CSV Type, please pick an option again.." -ForegroundColor Red ; exit }

if ($Infile -eq "") {  # Lets open a file picker if no filename is provided.
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

  $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
  $openFileDialog.InitialDirectory = $pwd
  $openFileDialog.Filter = "CSV files (*.csv)|$($mask).csv|All files (*.*)|$($mask).*"
  $openFileDialog.Title = "Select a file"

  if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
      $selectedFile = $openFileDialog.FileName
      Write-Output "[] Selected file: $selectedFile"
      if ($selectedFile -eq "") {
        $
      } else {
        $InFile = (Split-Path $selectedFile -Leaf)
      }
  }
}

# Set Outfile name based on Internal
$OutFile = "REMEDIATION-$($InFile)"
if ($CSVTypeDetection -eq "External") {
  $OutFile = "EXT$($OutFile)"    # I like EXTREMEDIATION- instead of REMEDIATION- to make these more obvious.
}

# Display parameters
Write-Host "`n[.] File Type: $CSVType - ($CSVTypeDetection)"
Write-Host "[.] Reading from file: $InFile"
Write-Host "[.] Writing to file: $OutFile  `n"

# Test that files exist or can be written to etc
if (-not (Test-Path $InFile)) {
  Write-Host "[!] Error, can't access $InFile"
  exit
}

if (Test-Path $OutFile) {
  $input = (Read-Host "[!] $OutFile exists, overwrite? [Y/n] ").ToUpper()
  if ($input[0] -eq "" -or $input[0] -eq "N") {
    exit
  } else {
    Write-Host "[.] Overwriting $OutFile"
  }
}

Write-Host "[.] Converting file.. "
if ($CSVType.ToUpper()[0] -eq "I") {  # First character is 'I' or 'I'
  # Column order I want: "NetBIOS","IP","QID","Vulnerability Description","Severity","Fixed Date","Fixed Name","Fixed Note","Results","Solution","Threat","Impact","CVE ID","Last Detected"
  Import-CSV $InFile | Select-Object "NetBIOS","IP","QID","Vulnerability Description","Severity","Results","Solution","Threat","Impact","CVE ID","Last Detected" | Export-CSV $OutFile
}
if ($CSVType.ToUpper()[0] -eq "E") {  # First character is 'e' or 'E'
  # Column order I want: "IP","Computer Name (DNS)","Devices connected from IP addresses","IPs","Port","Protocol","QID","Vulnerability Description","Severity","Results","Solution","Threat","Impact"
  Import-CSV $InFile | Select-Object "IP","Computer Name (DNS)","Devices connected from IP addresses","IPs","Port","Protocol","QID","Vulnerability Description","Severity","Results","Solution","Threat","Impact" | Export-CSV $OutFile
}

Write-Host "[!] Done, opening file in excel!`n"
explorer $OutFile

$input = Read-Host "[ press enter to exit, or close this window ]"