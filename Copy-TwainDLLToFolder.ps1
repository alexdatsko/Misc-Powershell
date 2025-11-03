param (
  $filepath = "\\dc-server\Installation Software\TSScan\twain32.dll for server for ScanX\Twain_32.dll"      # File to copy from
  $folderpath = "C:\Windows\Twain_32.dll"                                                                   # File to copy to (or folder name, file is more specific..)
)

$info = '''###################################################################################################################################
# Copy-FileToFolder.ps1 
#   Script to Copy a single file to $folderpath, for example to overwrite a windows DLL file 
#   (Created to replace c:\windows\Twain_32.dll due to automated SFC scans "fixing" the file weekly)
#   Alex Datsko @  8-27-24'''

$info

$LogFile = "c:\Temp\Copy-FileToFolder.log"

$DateTime = Get-Date -Format "yyyy-MM-dd"
"`n$DateTime ------------------------------" | tee -append $LogFile

Write-Output "[.] Copying : $filepath to $folderpath"
if (Test-Path "$filepath" -ErrorAction Continue) {
  Write-Output "[+] Copying $filepath to $folderpath" | tee -append $LogFile
  $ex = $null
  try {
    Copy-Item -Path "$filepath" -Destination "$folderpath" -Force -Recurse -ErrorAction Continue | tee -append $Logfile
  } catch [System.Exception] as $ex {
    Write-Error "[-] An error occurred during the copy operation: $ex.Message" | Tee -Append $LogFile
  }
  if ($ex -eq $null) { Write-Output "[+] Completed!" | tee -append $LogFile } else { Write-Output "[-] ERROR. Not copied." | tee -append $LogFile }
} else {
  Write-Output "[-] $filepath not found, or Access Denied reading folder.." | tee -append $LogFile
}
