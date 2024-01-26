# Enables Powershell Remoting
# From <https://community.spiceworks.com/topic/2008490-remote-access-in-powershell> 

$folder = "C:\temp"  # <--- Put Sysinternals PSExec.exe in here
$sec = 20            # <--- How many seconds to wait after quickconfig
$AddServer = "*.domain.local"   # <----- added to trustedhosts

Write-Host "[ ] Enter credentials to run as across the network (i.e MME or Administrator domain user)"
$cred = Get-Credential

Function Enable-WinRmPsExec {
    Param ([Parameter(Mandatory=$true)]
    [System.String[]]$Computer)

    ForEach ($comp in $computer ) {
        # Preliminary checks
        Write-Host "[$comp] Setting up Windows Firewall as Domain.." -ForegroundColor Green
        Start-Process -Filepath "$folder\psexec.exe" -Argumentlist "\\$comp -h -d powershell.exe -ex bypass Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Domain"  -Credential $cred
        Write-Host "[$comp] Update Windows Firewall to allow remote WMI Access" -ForegroundColor Green
        Start-Process -Filepath "$folder\psexec.exe" -Argumentlist "\\$comp -h -d netsh advfirewall firewall set rule group='Windows Management Instrumentation (WMI)' new enable=yes" -Credential $cred
        Write-Host "[$comp] Add to the TrustedHosts list .." -ForegroundColor Green
        Start-Process -Filepath "$folder\psexec.exe" -Argumentlist "\\$comp -h -d powershell.exe -ex bypass Set-Item wsman:\localhost\Client\TrustedHosts -Value $AddServer -Force" -Credential $cred
        Write-Host "[$comp] Update Windows Firewall to allow RDP .." -ForegroundColor Green
        Start-Process -Filepath "$folder\psexec.exe" -Argumentlist "\\$comp -h -d powershell.exe -ex bypass Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'"  -Credential $cred
        Write-Host "[$comp] Enable RDP .." -ForegroundColor Green
        Start-Process -Filepath "$folder\psexec.exe" -Argumentlist "\\$comp -h -d powershell.exe -ex bypass Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0" -Credential $cred

        # Enable WinRm Quickconfig
	    Write-Host "[$comp] Enabling WINRM Quickconfig" -ForegroundColor Green
        Start-Process -Filepath "$folder\psexec.exe" -Argumentlist "\\$comp -h -d winrm.cmd quickconfig -q" -Credential $cred
	    Write-Host "[$comp] Waiting for $sec Seconds......." -ForegroundColor Yellow
	    Start-Sleep -Seconds $sec -Verbose	
        Start-Process -Filepath "$folder\psexec.exe" -Argumentlist "\\$comp -h -d powershell.exe -ex bypass enable-psremoting -force" -Credential $cred
	    Write-Host "[$comp] Enabling PSRemoting" -ForegroundColor Green
        Start-Process -Filepath "$folder\psexec.exe" -Argumentlist "\\$comp -h -d powershell.exe -ex bypass -force" -Credential $cred
        
	    Write-Host "[$comp] Testing Wsman .." -ForegroundColor Green	
        Test-Wsman -ComputerName $comp
    }      
}

Write-Host "[O] Starting WinRm installation via PSExec.exe " -ForegroundColor Green	
$computers =  (Get-ADComputer -Filter {(Enabled -eq $True)}).Name
Write-Host "[O] Starting PsExec processes on the following computers:" -ForegroundColor Green	
$computers | ForEach { $_ }
Enable-WinRmPsExec -Computer $computers
Write-Host "[O] Done.." -ForegroundColor Green	
