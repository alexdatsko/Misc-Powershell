$path = "c:\temp"
$numdays = 7
write-host "`r`n--------------------[ Files written within last $numdays days ]----------------------"
$directories = Get-ChildItem -Recurse -Path $path | Where-Object { $_.psIsContainer -eq $true }

ForEach ( $d in $directories ) { 
    # Any children written in the past week?
    $recentWrites = Get-ChildItem $d.FullName | Where-Object { $_.LastWriteTime -gt $(Get-Date).AddDays(0-$numdays) } 
    If ($recentWrites) {
        #Write-Host "Found Folder: $($d.FullName) modified in last 7 days"
            $files = Get-ChildItem -Recurse -Path $d.FullName | Where-Object { $_.psIsContainer -eq $false }

            ForEach ( $f in $files ) { 
                # Any files written in the past week?
                $recentfWrites = Get-ChildItem $f.FullName | Where-Object { $_.LastWriteTime -gt $(Get-Date).AddDays(0-$numdays) } 
                If ($recentfWrites) {
                    Write-Host "$($f.FullName)"
                }
        }
    }
}