Function Scan-Subnet {
    param (
        $Subnet
    )

    # Continue to run script when an error occurs
    $ErrorActionPreference = "SilentlyContinue"
 
    # Process through the loop of IP addresses 1-254
    1..254 | foreach -Process `
    {
        # We're combining the contents of different objects, so create our own
        $obj = New-Object PSObject;
    
        # Perform the Ping using WMI
        $ping = get-WmiObject -Class Win32_PingStatus -Filter ("Address='$Subnet" + $_ + "'");
    
        # Put the IP Address into our object
        $obj | Add-Member NoteProperty IPAddress($ping.Address);
    
        # Take the Ping Status Code that is returned (0 = pingable)
        $obj | Add-Member NoteProperty StatusCode($ping.StatusCode);
      
        # If we can ping the address, let's try to resolve the hostname
        if($ping.StatusCode -eq 0)
        {
              # Record that the ping was successful
               $obj | Add-Member NoteProperty Status("Online");
        
            # Try to resolve the IP address to a hostname in DNS
            $dns = [System.Net.Dns]::GetHostByAddress($ping.Address);
        
               if($dns -ne $null)
               {
                # Add the resolved hostname to our collection
                 $obj | Add-Member NoteProperty ResolvedHostName($dns.HostName);
               }
               else
               {
                # Couldn't resolve the IP address to a hostname
                   $obj | Add-Member NoteProperty ResolvedHostName("");
               }
        }
        else
        {
            # Can't ping IP address, so mark host as offline
               $obj | Add-Member NoteProperty ResolvedHostName("");
               $obj | Add-Member NoteProperty Status("Offline");
        }
      
        # Write the collection out
        Write-Output $obj;
    
        # Cleanup DNS object
        $dns = $null;
    }
}

Scan-Subnet "192.168.105"  # Prescott
Scan-Subnet "192.168.106"  # PV
Scan-Subnet "192.168.101"  # TX
Scan-Subnet "192.168.115"  # Chino

