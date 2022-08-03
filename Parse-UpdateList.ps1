# Will parse Windows update list from SystemInfo to see if any of the following list is applied:
# Can convert list with Ctrl-H, replace , with ", "   and add first and last quotes

$UpdateList = @(
 "KB4018294", "KB4018300", "KB4018313", "KB4092465", "KB4461597", "KB4461607", "KB4461608", "KB4461630", "KB4462115", "KB4462138", "KB4462139", "KB4462143", "KB4462146", "KB4462154", "KB4462155", "KB4462171", "KB4462174", "KB4462177", "KB4462186", "KB4462211", "KB4462202", "KB4462184", "KB4462199")


Function Get-MSHotfix  
{  
    $outputs = Invoke-Expression "wmic qfe list"  
    $outputs = $outputs[1..($outputs.length)]  
      
      
    foreach ($output in $Outputs) {  
        if ($output) {  
            $output = $output -replace 'Security Update','Security-Update'  
            $output = $output -replace 'NT AUTHORITY','NT-AUTHORITY'  
            $output = $output -replace '\s+',' '  
            $parts = $output -split ' ' 
            if ($parts[5] -like "*/*/*") {  
                $Dateis = [datetime]::ParseExact($parts[5], '%M/%d/yyyy',[Globalization.cultureinfo]::GetCultureInfo("en-US").DateTimeFormat)  
            } else {  
                $Dateis = get-date([DateTime][Convert]::ToInt64("$parts[5]", 16)) -Format '%M/%d/yyyy'  
            }  
            New-Object -Type PSObject -Property @{  
                KBArticle = [string]$parts[0]  
                Computername = [string]$parts[1]  
                Description = [string]$parts[2]  
                FixComments = [string]$parts[6]  
                HotFixID = [string]$parts[3]  
                InstalledOn = Get-Date($Dateis)-format "dddd d MMMM yyyy"  
                InstalledBy = [string]$parts[4]  
                InstallDate = [string]$parts[7]  
                Name = [string]$parts[8]  
                ServicePackInEffect = [string]$parts[9]  
                Status = [string]$parts[10]  
            }  
        }  
    }  
} 
Write-Host "[ ] All Updates found:" -ForegroundColor Green
#Get-WmiObject -class win32_quickfixengineering
Get-MSHotfix | ft

Write-Host "[ ] Checking through updates.. " -ForegroundColor Green
foreach ($Update in $UpdateList) {
  $ListFound = Get-MSHotfix | ? { $_.HotFixID -eq $Update } 
}
if ($ListFound) { 
  Write-Host "[o] Updates found: " -ForegroundColor Green
  $ListFound
} else {
  Write-Host "[X] None found!!" -ForegroundColor Red
}
