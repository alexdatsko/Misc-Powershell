$hostname = hostname
$ipV4 = Test-Connection -ComputerName $hostname -Count 1  | Select -ExpandProperty IPV4Address | Select -ExpandProperty IPAddressToString
$ipfirst3 = $ipv4.split(".")[0]+"."+$ipv4.split(".")[1]+"."+$ipv4.split(".")[2]+"."
# ASSUMES a /24 subnet!!!
write-host "IP Address: $ipv4"
write-host "IP Subnet: "$($ipfirst3+"0")

1..254 | ForEach-Object {
  $ipaddress = $ipfirst3+$_
  try {
    $reply = Test-Connection -ComputerName $ipaddress -Count 1 -Delay 1 -ErrorAction SilentlyContinue
  } catch {  # do nothing if no response..
  }
  if ($reply) {
    try {
      $OS = Get-WmiObject -Computer $ipaddress -Class Win32_OperatingSystem
      if ($OS) { 
        write-host "Windows PC found @ $ipaddress"
      }
    } catch {   # no response to WMI gives error, do nothing
    }
    if ($OS) {
      $dnsname = ([System.Net.Dns]::GetHostByAddress($ipaddress).HostName)
      $dnsname| out-file "WindowsComputers.txt" -append
    }
  } else {
    write-host "No reply @ $ipaddress"
  }
}