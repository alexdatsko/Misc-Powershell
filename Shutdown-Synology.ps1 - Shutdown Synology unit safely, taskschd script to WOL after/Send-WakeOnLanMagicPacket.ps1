# Sends a WOL magic packet to wake up a device, twice a minute for $MaxMins minutes

$IP = "192.168.1.2"  # Also 10.0.1.3 
$MaxMins = 20
$SecondsBetween = 10

#$Mac = "00-11-32-2a-aa-d0"   # MAC Address of 192.168.1.2 interface on Synology
# ^^ Lets not set this, but figure it out based on an Arp request after pinging..
$null = Test-NetConnection $IP
$AllMacs = (arp -a) # Base on arp output after ping, should exist.
foreach ($ThisMac in $AllMacs) {
  $MacSplit = $ThisMac -split '\s+'
  #Write-Host "0 $($MacSplit[0]) 1 $($MacSplit[1]) 2 $($MacSplit[2]) 3 $($MacSplit[3]) 4 $($MacSplit[4])" # figure out the whitespace splitting..
  if ($MacSplit[1] -eq $IP) {
    Write-Host "Found $IP using $($MacSplit[2])"
    $Mac = $MacSplit[2]
  }
}

Write-Host "`r`n`r`n[o] Trying to wake up $IP / $Mac for $MaxMins minutes..." -ForegroundColor Green
for ($num = 1 ; $num -le ($MaxMins*(60 / $SecondsBetween)) ; $num++) {   
    Write-Host "Sending Magic packet to $Mac .."  -ForegroundColor White
    $MacByteArray = $Mac -split "[:-]" | ForEach-Object { [Byte] "0x$_" }
    [Byte[]] $MagicPacket = (,0xFF * 6) + ($MacByteArray  * 16)
    $UdpClient = New-Object System.Net.Sockets.UdpClient
    $UdpClient.Connect(([System.Net.IPAddress]::Broadcast),7)
    $UdpClient.Send($MagicPacket,$MagicPacket.Length)
    $UdpClient.Close() 
    Write-Host "Waiting $SecondsBetween seconds.." -ForegroundColor Gray
    Start-Sleep $SecondsBetween
    Write-Host "Pinging $IP .." -ForegroundColor Gray
    if (Test-NetConnection $IP) {
      Write-Host "Got reply: "  -ForegroundColor Green 
      Test-NetConnection $IP
      Write-Host "Machine up. Exiting!"  -ForegroundColor Green
      exit
    } else {
      Write-Host "Machine still down @ $($num*$SecondsBetween)m.. Continue sending WOL for $($MaxMins - ($num*$SecondsBetween)) minutes"  -ForegroundColor White
    }
}
