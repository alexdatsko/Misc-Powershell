# Get all active computers, logged into within last 3 months

$Computers = $(Get-ADComputer -Filter {Enabled -eq $true} -Properties LastLogon,LastLogonDate |
  Where-Object { $_.Name -notlike '*SERVER' -and ($_.LastLogonDate -ge $threeMonthsAgo) } | select -ExpandProperty Name
  Sort-Object)
$Computers