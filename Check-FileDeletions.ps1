
Unregister-Event FileDeleted -ErrorAction SilentlyContinue
Unregister-Event FileRenamed -ErrorAction SilentlyContinue

$folder = "C:\Dolphin"
$filter = "*.exe"
$global:output = "c:\temp\dol-deletion.log"
Write-Host "Monitoring $folder\$filter, output to $output"

$fsw = New-Object IO.FileSystemWatcher $folder, $filter -Property @{
 IncludeSubdirectories = $true;
 NotifyFilter = "FileName,DirectoryName"
}

Register-ObjectEvent $fsw Deleted -SourceIdentifier FileDeleted -Action {
 if ($Event.SourceEventArgs.FullPath -ine $output) {
  $name = $Event.SourceEventArgs.Name
  $change = $Event.SourceEventArgs.ChangeType
  $time = $Event.TimeGenerated
  Write-Host "$time  $change ""$name""" -fore red
  Out-File $output -Encoding ASCII -Append -InputObject "$time - $change = ""$name"""
 }
}

Register-ObjectEvent $fsw Renamed -SourceIdentifier FileRenamed -Action {
 if ($Event.SourceEventArgs.OldFullPath -ine $output) {
  $oldname = $Event.SourceEventArgs.OldName
  $name = $Event.SourceEventArgs.Name
  $time = $Event.TimeGenerated
  Write-Host "$time  Renamed ""$oldname"" to ""$name""" -fore white
  Out-File $output -Encoding ASCII -Append -InputObject "$time - $change = ren ""$oldname"" ""$name"""
 }
}

