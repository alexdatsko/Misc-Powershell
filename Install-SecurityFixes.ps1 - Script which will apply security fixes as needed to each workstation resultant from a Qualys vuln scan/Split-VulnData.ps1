[cmdletbinding()]  # For verbose, debug etc

######################################################################
# Split-VulnData.ps1
# Alex Datsko - .
#
#   This will take a bulk import file of Qualys data, produced by Josh @ Black Talon, and will split it into 
#   client-specific CSV files that will work with MME's Install-SecurityFixes.ps1 script.
#
# v0.1 - 07-03-2025 - Initial
#


param (
    [string]$inputCsv = "input.csv",       # Define input batch CSV file to break up
    [string]$outputFolder = "output",      # Define Output folder to use for client-specific scans
    [switch]$last = $true,                 # Scans for the last date in dated files such as MME_Internal_2025-06-29.csv
    [string]$date = ""                     # Set the filename date by known scan date instead of whats in filename.
)

Write-Output "[.] Sorting thru $inputCsv, creating multiple CSV output.."

# Ensure output directory exists
if (-not (Test-Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder -ErrorAction SilentlyContinue | Out-Null
    if (-not (Test-Path $outputFolder)) {
        Write-Output "[-] Couldn't create new folder $($pwd)/$($outputFolder)  -- exiting!"
        exit
    }
} else {  
    $oldfiles = GCI "$($outputFolder)\*.csv"
    if ($oldfiles) {
        Write-Output "[.] Cleaning output folder $outputFolder for *.csv .. "
        Remove-Item "$($outputFolder)\*.csv" -Force
    }
}

if ($last) {
    $files = Get-ChildItem -File -Filter 'MME-internal-*.csv'
        $filelist = $files | Where-Object { $_.Name -match '\d{4}-\d{2}-\d{2}' } | Sort-Object -Descending 
        $latestFile = $filelist | Select-Object -First 1

    $inputCsv = $latestFile.FullName
    if ($inputCsv) {
      Write-Output "[+] Using input file: $inputCsv"
    }
}

if (!(Test-Path $inputCsv)) {
    Write-Output "[-] Input CSV file $inputCsv doesn't exist!"
}

if (!($date)) {
if ($inputCsv -match '\d{4}-\d{2}-\d{2}') {
    $datetime = $matches[0]
}
} else {
    $datetime = $date
}
Write-Output "[+] Using date: $datetime"

# Import CSV
$data = Import-Csv $inputCsv

# Group by 'Account Name' and export each group
$data | Group-Object 'Account Name' | ForEach-Object {
    $groupName = ($_.Name).replace('[\\/:*?"<>|] ', '_')
    $groupname = ($groupName -replace " ","_")
    Write-Output "[.] Creating $($groupName)_Internal_$($datetime).csv .."    # _Internal_ needs to be in the filename!
    $outputPath = Join-Path $outputFolder "$($groupName)_Internal_$($datetime).csv"   
    $_.Group | Export-Csv -Path $outputPath -NoTypeInformation
}

Write-Output "[!] Done!" 