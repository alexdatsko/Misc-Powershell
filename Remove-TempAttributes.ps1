########################################################
# Remove-TempAttributes.ps1
# Alex Datsko - .
#
#   This script should remove Temporary Attributes from any file in a folder.
#
# v0.1 - 04-22-2025 - Initial 

$Folder = "C:\Temp\temp"


Get-childitem $Folder -recurse | foreach { Write-Host "Filename: $_  " -NoNewLine ; fsutil usn readdata c:"$_" |findstr -i attributes } 

Get-ChildItem $Folder -recurse | ForEach-Object {
    if (($_.attributes -band 0x100) -eq 0x100) {
        $_.attributes = ($_.attributes -band 0xFEFF)
    }
}

Get-childitem $Folder -recurse | foreach { Write-Host "Filename: $_  " -NoNewLine ; fsutil usn readdata c:"$_" |findstr -i attributes } 
