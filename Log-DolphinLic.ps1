$OneHourAgo = (Get-Date).AddHours(-1)
get-winevent -FilterHashtable @{LogName="Security"} | ?{$_.message -match "4B90443F-7293-49BE-8A60-7B66700B900A.LIC" -and $_.TimeCreated -gt $OneHourAgo} | fl | tee c:\temp\licfile-new.txt -append
