#######################################
# Ping-Network.ps1
# Alex Datsko -  2020
#
# Scans the whole network range of the (first and assumed only) current IP address of the machine
# Or, takes an argument of an IP to convert to IP range, i.e 10.1.10.100 or 10.1.10.0 will scan the full 10.1.10.0/24
#
if ($Args[0]) { 
  $ipv4 = $Args[0]
} else {
  $hostname = hostname
  $ipV4 = Test-Connection -ComputerName $hostname -Count 1  | Select -ExpandProperty IPV4Address | Select -ExpandProperty IPAddressToString
}
$ipfirst3 = $ipv4.split(".")[0]+"."+$ipv4.split(".")[1]+"."+$ipv4.split(".")[2]+"."
# ASSUMES a /24 subnet!!!
write-host "[!] Trying IP Address: $ipv4 (assuming /24)"

1..254 | ForEach-Object {
  $ipaddress = $ipfirst3+$_
  try {
    $reply = Test-Connection -ComputerName $ipaddress -Count 1 -Delay 1 -ErrorAction SilentlyContinue
  } catch {  # do nothing if no response..
  }
  if ($reply) {
    Write-Host "[ ] Response found: $ipaddress"
    $ipaddress | out-file "Ping-Response.txt" -append
    try {  
      $OS = Get-WmiObject -Computer $ipaddress -Class Win32_OperatingSystem
      if ($OS) { 
        write-host "[o] Windows PC found @ $ipaddress - $OS "
      }
    } catch {   # no response to WMI gives error, do nothing
    }
    if ($OS) {
      $dnsname = ([System.Net.Dns]::GetHostByAddress($ipaddress).HostName)
      $dnsname| out-file "Ping-WindowsComputers.txt" -append
      write-host "[o] Windows PC found @ $ipaddress - $OS - $dnsname"
    }
  } else {
    write-host "[x] No reply @ $ipaddress"
  }
}