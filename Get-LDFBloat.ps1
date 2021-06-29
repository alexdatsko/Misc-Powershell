# Checks for LDF file size and alerts if over threshold
# Saves output as a CSV file for importing to a dashboard

$path="C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\DolphinPlatform.ldf"

$ldfthreshold = 5GB

function Get-LDFBloat {
  param (
    [string[]]$path
  )

  $a = (get-item $path).Length -gt $ldfthreshold
  if ($a) {write-eventlog -logname Application -Source "LDF Bloat" -EntryType Error -EventID 1 -Message "The LDF file '${path}' appears to be bloated. Please troubleshoot $path."}

  $reportfolder = "d:\Backups (DO NOT DELETE)\Reports\LDFBloat"
  $date = get-Date -format "yyyy-MM-dd"
  $time = get-Date -format "HHmm"
  $reportfile = "${reportfolder}\${date}-LDFBloat.csv"
  $LDFSize = [math]::Round(((get-item $path).Length / 1GB),3)
  "${date},${time},${path},${LDFSize}" | out-file -FilePath $reportfile -Append
}

Get-LDFBloat -Path $path
