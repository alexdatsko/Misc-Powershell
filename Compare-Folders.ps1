Write-host "Getting file list from I:\Patients.."
$SourceObjects = Get-ChildItem -Recurse "I:\Patients" | Where-Object { $_.CreationTime -ge "01/01/2016" -and $_.CreationTime -le "01/01/2021" }
Write-host "Exporting to C:\temp\brown-dmi-patientfiles_2016-2021.csv"
$SourceObjects | Export-CSV -Path "C:\temp\brown-dmi-patientfiles_2016-2021.csv"
Write-host "Getting file list from D:\Data\Dentimax Imaging\Patients"
$TargetObjects = Get-ChildItem -Recurse "D:\Data\Dentimax Imaging\Patients"
Write-host "Comparing file lists.."
$ObjectResults = Compare-Object -ReferenceObject $SourceObjects -DifferenceObject $TargetObjects 
Write-host "Writing comparison to C:\temp\_brown-dmi-patientfiles-comparison.txt"
$ObjectResults | out-file -Path "C:\temp\_brown-dmi-patientfiles-comparison.txt"
Write-host "Done!"