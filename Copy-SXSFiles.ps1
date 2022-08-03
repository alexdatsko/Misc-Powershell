$SXSfolder = "c:\temp\SXSfiles"
Write-host "SXS Cleanup - 2021-08-11 Alex Datsko @ MME Consulting Inc"
write-host "Creating folder $SXSFolder .. "
new-item -type directory $SXSfolder

$notfoundlist=@()
Get-Content $SXSfolder\sxsfiles.txt | Foreach-Object {
  $path=($_ -split "\\")[0]
  $filename=($_ -split "\\")[1]
  #Write-host "`r`nPath: $path`r`nFilename: $filename"
  if (!(test-path("$env:windir\winsxs\$_"))) {
    Write-host ".. Skipping (File not found) : $env:windir\WinSXS\$_ "
    $notfoundlist += $_
  } else {
    if (!(test-path("$SXSfolder\$path"))) {
      new-item -type directory $SXSfolder\$path
    }
    Write-host "Copying item : `r`n`t$env:windir\WinSXS\$_  `r`nTo Destination:`r`n`t$SXSfolder\$path"
    copy-item -Path $env:windir\WinSXS\$_ -Destination $SXSfolder\$path
  }
}
$notfoundlist | out-file $SXSfolder\Notfoundlist.txt
Write-Host "Not found list : $SXSFolder\Notfoundlist.txt"
