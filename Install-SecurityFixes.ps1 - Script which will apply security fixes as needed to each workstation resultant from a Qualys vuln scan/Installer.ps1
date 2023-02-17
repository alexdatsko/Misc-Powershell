Write-Host "[.] Installing Install-SecurityFixes.ps1 - MME Qualys Vulnerability Remediation script"
Write-Host "[.] Alex Datsko @ MME Consulting Inc. alex.datsko@mmeconsulting.com"

if (!(Test-Path C:\Temp)) { mkdir c:\Temp }
Set-Location c:\Temp;
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest 'https://raw.githubusercontent.com/alexdatsko/Misc-Powershell/main/Install-SecurityFixes.ps1%20-%20Script%20which%20will%20apply%20security%20fixes%20as%20needed%20to%20each%20workstation%20resultant%20from%20a%20Qualys%20vuln%20scan/Install-SecurityFixes.ps1' -OutFile 'c:\Temp\Install-SecurityFixes.ps1'
Invoke-WebRequest 'https://raw.githubusercontent.com/alexdatsko/Misc-Powershell/main/Install-SecurityFixes.ps1%20-%20Script%20which%20will%20apply%20security%20fixes%20as%20needed%20to%20each%20workstation%20resultant%20from%20a%20Qualys%20vuln%20scan/_config.ps1' -Outfile 'c:\Temp\_config.ps1'
$path=""
while (!($path)) {
  $path = Read-Host "Would you like to install this in a certain location? If so, type the path, such as ""\\server\data\secaud"", otherwise, hit Enter to run from here. >" 
  if ($path) { 
    Move-Item -Path "C:\Temp\Install-SecurityFixes.ps1" -Destination "$($path)"
    Move-Item -Path "C:\Temp\_config.ps1" -Destination "$($path)" 
  } else { 
    $path=Get-Location 
  } 
  if (!(Test-Path $path)) { # Make sure path is valid or can be created
    try { 
      mkdir $path 
    } catch {
      Write-Host "[!] Couldn't create path $($path) !! Not able to move to this location, please try again.."   
      $path="" 
    }
  }
  if ($path) {
    Write-Host "[.] Editing config file, please make any changes necessary.
    notepad.exe "$($path)\_config.ps1"
    Write-Host "[!] Done! Running script..
    . '$($path)\Install-SecurityFixes.ps1'
  }
}
