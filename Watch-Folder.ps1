###############################
# Watch-Folder.ps1
# This will watch a folder for newly created files in a folder

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.IncludeSubdirectories = $true
$watcher.Path = 'C:\users\reception1\Appdata\Local\Temp'
$watcher.EnableRaisingEvents = $true
$action =
{
    $path = $event.SourceEventArgs.FullPath
    $changetype = $event.SourceEventArgs.ChangeType
    Write-Host "$path was $changetype at $(get-date -format "MM/dd/yyyy HH:mm")"
}
Register-ObjectEvent $watcher 'Created' -Action $action


# To remove: 
# Get-EventSubscriber | Unregister-Event