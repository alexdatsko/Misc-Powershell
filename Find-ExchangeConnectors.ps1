$DaysToCheck = 365  # Check for new connectors within the last year

# Set the time range
$StartDate = (Get-Date).AddDays(0-$DaysToCheck).ToUniversalTime()
$EndDate = (Get-Date).ToUniversalTime()

Install-Module ExchangeOnlineManagement -Force -AllowClobber
Import-Module ExchangeOnlineManagement
Connect-IPPSSession

# Validate cmdlet is available
if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
    Write-Error "Search-UnifiedAuditLog is still not available. You are NOT connected to Microsoft Purview."
    return
}

# Search Unified Audit Log for relevant operations
$AuditResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate `
    -Operations "New-InboundConnector", "Set-InboundConnector" -ResultSize 5000

# Parse and display useful details
$ConnectorEvents = foreach ($record in $AuditResults) {
    $AuditData = $record.AuditData | ConvertFrom-Json

    [PSCustomObject]@{
        CreationDate = $record.CreationDate
        Operation    = $record.Operation
        UserId       = $AuditData.UserId
        Cmdlet       = $AuditData.CmdletName
        Parameters   = ($AuditData.Parameters | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
    }
}

# Output or export
$ConnectorEvents | Format-Table -AutoSize
# Optional: export to CSV
# $ConnectorEvents | Export-Csv -Path "InboundConnectorChanges.csv" -NoTypeInformation

