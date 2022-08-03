# Get-BitlockerKeys.ps1 - Pastes all Bitlocker recovery keys to txt files on Desktop
# 2022-02-24 - Alex Datsko @ MME Consulting Inc.

$hostname = hostname
$OldLoc = Get-Location
$alph=@()
65..90|foreach-object{$alph+=[char]$_}      #  $alph = @('A','B','C','D',..,'Z')
$FinalResults = @("")
#$alph = @("E") # For testing

foreach ($DriveLetter in $alph) {
  Write-Verbose "[ ] Trying $($DriveLetter):\ .."
    $Loc=(Set-Location "$($DriveLetter):\" -PassThru -ErrorAction SilentlyContinue) | Select -ExpandProperty Path
    if ((Get-Location).Path -eq $Loc) {       
      $result = Invoke-Expression "manage-bde.exe -protectors -get $($DriveLetter):"
      if (!($result -like "*ERROR*")) {
        Set-Location $OldLoc
        $result | Out-File "$($Env:UserProfile)\Desktop\_$($hostname) - $($DriveLetter) Drive - BitLocker Recovery Key.txt"
        Write-Host "[!] Wrote $($Env:UserProfile)\Desktop\_$($hostname) - $($DriveLetter) Drive - BitLocker Recovery Key.txt" -ForegroundColor Green
        $FinalResults += "[!] Wrote $($Env:UserProfile)\Desktop\_$($hostname) - $($DriveLetter) Drive - BitLocker Recovery Key.txt"
      }
    } else {
      Write-Host "[x] No drive letter $DriveLetter found." -ForegroundColor Gray
    }
}
Write-Host "[!] Final results: " -ForegroundColor Yellow
foreach ($f in $FinalResults) {
  Write-Host "$f" -ForegroundColor Green
}
