# Test-Network.ps1

$folder = "D:\Backups (Do Not Delete)\Reports\Test-Network"
$date = Get-Date -format "yyyy-MM-dd"
$datetime = Get-Date -format "yyyy-MM-dd HH:mm"
$out = "$($folder)\testnetwork-$($date).txt"
"`r`n---------------------------------------`r`n$datetime" | Out-File -FilePath $out -Append

mkdir $folder
ping dxserver | Out-File -FilePath $out -Append
ping frontdesk1 | Out-File -FilePath $out -Append
ping op6 | Out-File -FilePath $out -Append
ping sbnas | Out-File -FilePath $out -Append

. .\Test-NetworkSpeed.ps1 -Path \\dxserver\DTXCommon -Size 200 -Verbose | Out-File -FilePath $out -Append
. .\Test-NetworkSpeed.ps1 -Path \\frontdesk1\c$ -Size 200 -Verbose | Out-File -FilePath $out -Append
. .\Test-NetworkSpeed.ps1 -Path \\op6\c$ -Size 200 -Verbose | Out-File -FilePath $out -Append
. .\Test-NetworkSpeed.ps1 -Path \\sbnas\Software -Size 200 -Verbose | Out-File -FilePath $out -Append
