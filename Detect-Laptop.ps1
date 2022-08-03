$filename = "laptops.txt"

Function Detect-Laptop {
    Param( 
      [string]$computer = “localhost” 
      )

    $isLaptop = $false
    
    #The chassis is the physical container that houses the components of a computer. Check if the machine’s chasis type is 9.Laptop 10.Notebook 14.Sub-Notebook
    try {
        if(Get-WmiObject -Class win32_systemenclosure -ComputerName $computer | Where-Object { $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 -or $_.chassistypes -eq 14}) { 
          $isLaptop = $true 
        }
    } catch {
      $islaptop = "Unknown: $($PSItem.Exception.Message)"
    }
    #Shows battery status , if true then the machine is a laptop.
    try { 
        if(Get-WmiObject -Class win32_battery -ComputerName $computer) { 
          $isLaptop = $true 
        }
    } catch {
      $isLaptop = "Unknown: $($PSItem.Exception.Message)"
    }
    $isLaptop
}

$laptops = 0
$Computers = Get-ADComputer -Filter *
Foreach ($Computer in $Computers.Name) {
  Write-Host "Testing $Computer .."
  if ((Detect-Laptop $Computer) -eq $true) {
    "$Computer is a laptop: $(Detect-Laptop $Computer)" | Out-File $filename 
    $laptops += 1
  }
}
Write-Host "Done! $laptops found"
