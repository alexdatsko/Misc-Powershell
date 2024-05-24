Write-Host "`n[[ Fix for Profile issues from WebCache Containers - v0.1 ]]`n"
Write-Host "[!] This should be run from the affected profile (as admin) having the ESNT 490 issue!"
Write-Host "[.] Removing files from profile $env:LocalAppData .."
try {
  Remove-Item -Path "$env:LocalAppData\Microsoft\Windows\WebCacheLock.dat" -Force -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:LocalAppData\Microsoft\Windows\WebCache"  -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:LocalAppData\Microsoft\Windows\INetCache"  -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:LocalAppData\Microsoft\Windows\INetCookies"  -Force -Recurse -ErrorAction SilentlyContinue
} catch {
  Write-Warning "[!] Warning, something failed: $($_.Exception.Message)"
} 
Write-Host "[.] Removing files from Default profile .."
try {
  Remove-Item -Path "$env:SystemDrive\Users\default\AppData\Local\Microsoft\Windows\WebCacheLock.dat" -Force -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:SystemDrive\Users\default\AppData\Local\Microsoft\Windows\WebCache" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:SystemDrive\Users\default\AppData\Local\Microsoft\Windows\INetCache" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:SystemDrive\Users\default\AppData\Local\Microsoft\Windows\INetCookies" -Force -Recurse -ErrorAction SilentlyContinue
} catch {
  Write-Warning "[!] Warning, something failed: $($_.Exception.Message)"
} 
Write-Host "[!] Done!"

