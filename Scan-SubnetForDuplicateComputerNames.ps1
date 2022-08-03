$Subnets  = @(
"192.168.105","192.168.106","192.168.115","192.168.101"
)
$ResFile = "Results.csv"
$TmpFolder = "c:\Temp"

Function Scan-Subnet {
    param (
        $Subnet
    )

    # Continue to run script when an error occurs
    $ErrorActionPreference = "SilentlyContinue"
    Write-Host "------------------------------------------------------`r`n[o] Scanning $($Subnet).0/24 .."  -ForegroundColor Green

    # Process through the loop of IP addresses 1-254
    1..254 | foreach -Process `
    {
        # We're combining the contents of different objects, so create our own
        $obj = New-Object PSObject;
    
        # Perform the Ping using WMI
        $ping = get-WmiObject -Class Win32_PingStatus -Filter ("Address='$Subnet." + $_ + "'");
    
        
   
        # Take the Ping Status Code that is returned (0 = pingable)
        #$obj | Add-Member NoteProperty StatusCode($ping.StatusCode);  #Don't care about this right now
      
        # If we can ping the address, let's try to resolve the hostname
        if($ping.StatusCode -eq 0)
        {

              # Put the IP Address into our object
              $obj | Add-Member NoteProperty IPAddress($ping.Address);

              # Record that the ping was successful
              #$obj | Add-Member NoteProperty Status("Online");
              #$DateTime = (Get-Date -Format "MM-dd-yy hh:mm")

          
              # Try to resolve the IP address to a hostname in DNS
              $dns = [System.Net.Dns]::GetHostByAddress($ping.Address);
        
               if($dns -ne $null)
               {
                 # Add the resolved hostname to our collection
                 $obj | Add-Member NoteProperty ResolvedHostName($dns.HostName);
                 Write-Host "  [o] $($Ping.Address) - $($dns.HostName)";
               }                else                {
                 # Couldn't resolve the IP address to a hostname
                 $obj | Add-Member NoteProperty ResolvedHostName("");
                 Write-Host "  [ ] $($Ping.Address) - [Can't resolve]";
               }
        }
        else
        {
            # Can't ping IP address, so mark host as offline
               
               # DONT ADD AT ALL.. Only care about online hosts
               #$obj | Add-Member NoteProperty ResolvedHostName("");
               #$obj | Add-Member NoteProperty Status("Offline");
               Write-Debug "  [x] $($Ping.Address) Offline";
        }
        #$obj | Add-Member NoteProperty DateTime($DateTime);   # Don't care about this right now..
        # Write the collection out
        Write-Output $obj;
    
        # Cleanup DNS object
        $dns = $null;
    }
    
}

Set-Location $TmpFolder
#Start-Transcript

Foreach ($subnet in $subnets) {
  $Res = Scan-Subnet $Subnet 
  #Write-Host "`r`nResults: "
  #Write-Host $Res
  #Write-Host "----"
  if (Test-Path("$($TmpFolder)\$($ResFile)" )) {
    $SavedCSV = Import-Csv "$($TmpFolder)\$($ResFile)" 
    foreach ($Result in $Res) {  # Determine if result is in CSV file already
      if ($SavedCSV.ResolvedHostName) {
        $Hostnames = $SavedCSV.ResolvedHostName    
        if ($Result.ResolvedHostName) { # Make sure it resolved to something to be added to CSV..
          if ($Hostnames.Contains($Result.ResolvedHostName)) {
            $HostName = ($SavedCSV | ? { $_.ResolvedHostName -eq $Result.ResolvedHostName}).ResolvedHostName
            $HostIP =   ($SavedCSV | ? { $_.ResolvedHostName -eq $Result.ResolvedHostName}).IpAddress
            if ($HostIP -eq $Result.IpAddress) {
              Write-Host "[x] Already found in $($TmpFolder)\$($ResFile)!"
            } else { # Hostname found but IP doesn't match!!
              $CSV = "{0},{1},DUPLICATE HOSTNAME AS,{2},{3}" -f $Result.IpAddress,$Result.ResolvedHostName,$HostName,$HostIP
              $CSV | Add-Content "$($TmpFolder)\$($ResFile)"          
            }
   
          } else { #Write to CSV if there is a new ResolvedHostName     
            $CSV = "{0},{1}" -f $Result.IpAddress,$Result.ResolvedHostName
            $CSV | Add-Content "$($TmpFolder)\$($ResFile)"
          }
        } # end if ResolvedHostName -ne ""
      }
    }
  } else {
    foreach ($Result in $Res) {  # Add to CSV file if it doesn't exist         
      if ($Result.ResolvedHostName) {  # Only add IPs with hostnames that resolve
        $CSV = $NewLine = "{0},{1}" -f $Result.IpAddress,$Result.ResolvedHostName
        $CSV | Add-Content "$($TmpFolder)\$($ResFile)"
      }
    }
  }
}

#Stop-Transcript