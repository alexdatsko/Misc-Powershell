# Find GUID with:
# Get-WmiObject -ComputerName $PC -Class Win32_Product | ?{$_.Name -like 'Qualys Cloud Security Agent'} | select IdentifyingNumber

$Guid = '{E225050F-3598-4094-A945-1AD47DB8ACE0}'
$ADComputers = (Get-ADComputer -filter *).Name
#$List = 'dc-server'#,'as-server'
$Outfile = "c:\Temp\BTS-software-installed.txt"
$OutfileMissing= "c:\Temp\BTS-software-missing.txt"

if (test-path($Outfile)) { 
  Remove-Item $Outfile -Force
}
if (test-path($OutfileMissing)) { 
  Remove-Item $OutfileMissing -Force
}

foreach($PC in $ADComputers){
    $guidfound = ""
    Write-Host "`r`n----------------------------------`r`n[ ] Checking $PC .."
    $data = Get-WmiObject -ComputerName $PC -Class Win32_Product 
    foreach ($d in $data) {
      #Write-Host "  $d"  # Print out all the software on each machine if-Verbose.
    }
    $guidfound = $data | ?{ $_.IdentifyingNumber -eq $Guid}
    $guidfound
    if($guidfound){
        Write-Host "Found on: $PC"
        "$PC has $($guidfound.name) installed" | Out-file $Outfile -Append

    } else {
      Write-Host "[X] Not found on $PC .. Pinging"
      $result = tnc $PC
      if ($result.PingSucceeded) {    # Only add to list if its a machine that is online..
        $PC | Out-File $OutfileMissing -Append
      } else {
        "$PC - (NOT PINGING)" | Out-File $OutfileMissing -Append
      }
    }
}
