$A = Get-ChildItem -Path HKLM:\SYSTEM\Software\Microsoft\TIP\TestResults -Recurse -ErrorAction SilentlyContinue
$A | remove-item -Force -Recurse -ErrorAction SilentlyContinue