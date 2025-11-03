# Update-Firefox.ps1
# Alex Datsko  10-9-2023
#   This script should download Firefox (via Ninite) to the users %temp% folder, kill all chrome browser windows at once, and update Firefox
#   Meant to be run on Sundays and Wednesdays at 11pm

$tmp = "$env:temp"
Invoke-WebRequest "https://ninite.com/firefox/ninite.exe" -OutFile "$($tmp)\ninitefirefox.exe"
taskkill.exe /f /im firefox.exe
Start-Sleep 5 # Wait 5 seconds to make sure this is completed
Start-Process -FilePath "$($tmp)\ninitefirefox.exe" -NoNewWindow
Start-Sleep 25 # Wait 25 seconds to make sure the app has updated
taskkill.exe /f /im ninite.exe
taskkill.exe /f /im ninitefirefox.exe
