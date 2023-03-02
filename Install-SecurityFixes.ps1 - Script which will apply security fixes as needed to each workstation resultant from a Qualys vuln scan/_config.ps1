Write-Output "[.] Loading Configuration items.."

# Configuration file in v0.31+ should have the following information:
$ServerName = "SERVER"                       # Change as needed, this is the server name to check for the Qualys CSV file.
$CSVLocation = "Data\SecAud"                 # Location to check for the Qualys results CSV file.
$tmp = "$($env:temp)\SecAud"                 # Temporary folder to save downloaded files to
$IgnoreDaysOld = 30                          # X number of days to warn if the machine has been reimaged or replaced since: (last scan may be a different host with more active vulns!)
$QIDsIgnored = @()                           # List of Qualys vulnerabilities to ignore
$QIDsIgnored += @(105170,105171)             # This will ignore Cached Credentials
$QIDsIgnored += @(90007)                     # This will ignore Autoplay
$InstallDellBIOSProvider = $true             # This will install the DellBIOSProvider.ps1 powershell module if not found
$SetWOL = $true                              # This will use the DellBIOSProvider module to turn on WakeOnLan
$BackupBitlocker = $true                     # This will backup Bitlocker Keys to AD

Write-Output "[+] Done Loading Configuration items."
