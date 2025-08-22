$start = (Get-Date).AddDays(-31)

$events = @(
    @{Type="Boot"; ID=12; Source="Microsoft-Windows-Kernel-General"},
    @{Type="Boot"; ID=6005; Source="EventLog"},
    @{Type="Shutdown"; ID=13; Source="Microsoft-Windows-Kernel-General"},
    @{Type="Shutdown"; ID=6006; Source="EventLog"},
    @{Type="UnexpectedShutdown"; ID=41; Source="Microsoft-Windows-Kernel-Power"},
    @{Type="Reboot"; ID=1074; Source="User32"},
    @{Type="Sleep"; ID=42; Source="Microsoft-Windows-Kernel-Power"},
    @{Type="Resume"; ID=1; Source="Microsoft-Windows-Power-Troubleshooter"}
)

$allEvents = @()

foreach ($ev in $events) {
    $matches = Get-WinEvent -FilterHashtable @{LogName='System'; ID=$ev.ID; StartTime=$start} -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -eq $ev.Source }

    foreach ($match in $matches) {
        $allEvents += [PSCustomObject]@{
            Type      = $ev.Type
            Time      = $match.TimeCreated.ToString("s")
            EventID   = $ev.ID
            Provider  = $ev.Source
            Message   = ($match.Message -replace "`r?`n", ' ') -replace '\s+', ' '
        }
    }
}

$sorted = $allEvents | Sort-Object Time
$sorted_output = $sorted | Format-Table -AutoSize | out-string

Ninja-Property-Set "lastPowerEvents" $sorted_output