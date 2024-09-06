[cmdletbinding()]  # For verbose, debug etc
function Find-ProcessUsingDLL {
  param($DLLFullPath,
        $Kill = $false)
  
  $returnPids = @()
  foreach ($p in Get-Process -IncludeUserName) {
    foreach ($m in $p.modules) {
      if ($m.FileName -like $DLLFullPath) {
        $returnPids += $p.id
        if ($Kill) {
          Write-Output "Found: $($p.UserName) using $($m.FileName) in $($p.Path) PID: $($p.id) - In 'Kill' mode. Terminating!"
          Stop-Process -Id $p.id -Force
        } else {
          Write-Output "Found: $($p.UserName) using $($m.FileName) in $($p.Path) PID: $($p.id) - Not in 'Kill' mode. Use -Kill to kill the process."
        }
      }
    }
  }
  if ($returnPids) {
   # return $returnPids # Probably unnecessary..
  }
}