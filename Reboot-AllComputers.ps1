Start-Transcript

$ADComputers = (Get-ADComputer -filter *).Name

foreach ($computer in $ADComputers) {
  Write-Host "Rebooting $computer .."
  Restart-Computer -ComputerName $computer -Force 
}

