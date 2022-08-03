$date = Get-Date -Format "yyyy-MM-dd"
$EventIDs = 4624,4625

# Find DC list from Active Directory
#$DCs = Get-ADDomainController -Filter *
 
# Define time for report (default is 1 day)
#$StartDate = (get-date).AddDays(-1)
$StartDate = (Get-Date).AddDays(-14)
 
$filename = "$env:computername-logon-$date.csv"
$failfilename = "$env:computername-logfails-$date.csv"
Write-Host "Writing to filename $filename ... "
#"Type,Date,Status,User,Workstation,IP Address" | out-file $filename
#"TimeCreated,SecurityId,AccountName,AccountDomain,LogonId,LogonType,Workstation,LogonGuid" | out-file $filename   # probably shouldn't need this either with Export-CSV

# Store successful logon events from security logs with the specified dates and workstation/IP in an array

$event4624 = Get-WinEvent -FilterHashtable @{
    LogName="Security";
    ID=4624;
    StartTime=$StartDate
  } 
$event4624 | Select-Object -Property TimeCreated, `
@{Name='SecurityId';Expression={$_.Properties[4].Value}}, `
@{Name='AccountName';Expression={$_.Properties[5].Value}}, `
@{Name='AccountDomain';Expression={$_.Properties[6].Value}}, `
@{Name='LogonId';Expression={$_.Properties[7].Value}}, `
@{Name='LogonType';Expression={$_.Properties[8].Value}}, `
@{Name='Workstation';Expression={$_.Properties[11].Value}}, `
@{Name='LogonGuid';Expression={$_.Properties[12].Value}} |
    Export-CSV -Path $filename

$event4625 = Get-WinEvent -FilterHashtable @{
    LogName="Security";
    ID=4625;
    StartTime=$StartDate
}
#$c=0
#foreach ($e in $Event4625) { 
#  foreach ($line in $e.Properties) {
#    write-host "$c $($line.Value)"
#    $c += 1 
#  }
#  $c = 0
#}
Write-Host "Writing Event 4625 Fails to filename $failfilename ... "
$event4625 | Select-Object -Property TimeCreated, `
@{Name='SecurityId';Expression={$_.Properties[0].Value}}, `
@{Name='AccountName';Expression={$_.Properties[1].Value}}, `
@{Name='AccountDomain';Expression={$_.Properties[2].Value}}, `
@{Name='LogonId';Expression={$_.Properties[3].Value}}, `
@{Name='LogonType';Expression={$_.Properties[4].Value}}, `
@{Name='LogonAccount';Expression={$_.Properties[6].Value}}, `
@{Name='FailReason';Expression={$_.Properties[8].Value}}, `
@{Name='FailType';Expression={$_.Properties[9].Value}}, `
@{Name='ProcessName';Expression={$_.Properties[12].Value}}, `
@{Name='Workstation';Expression={$_.Properties[13].Value}}, `
@{Name='WorkstationIP';Expression={$_.Properties[14].Value}}, `
@{Name='LogonProcess';Expression={$_.Properties[16].Value}} |
    Export-CSV -Path $failfilename