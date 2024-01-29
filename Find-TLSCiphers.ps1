# Get all computers logged into within last 3 months, find the TLS ciphers on each machine with WinRM, and log to filename tls.log


$threeMonthsAgo = (Get-Date).AddMonths(-3)

$Computers = Get-ADComputer -Filter {Enabled -eq $true} -Properties LastLogon,LastLogonDate |
    Where-Object { $_.Name -notlike '*SERVER' -and ($_.LastLogonDate -ge $threeMonthsAgo) } | 
    Select-Object -ExpandProperty Name | 
    Sort-Object

$ScriptBlock = {
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
    $RegistryValue = (Get-ItemProperty -Path $RegistryPath -Name "Functions").Functions
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        RegistryValue = $RegistryValue
    }
}

$Results = Invoke-Command -ComputerName $Computers -ScriptBlock $ScriptBlock

#$Results

foreach ($Result in $Results){ "`n----- $($Result.ComputerName) -----" | tee -append "tls.log" ; $Result.RegistryValue | tee -append "tls.log" }


