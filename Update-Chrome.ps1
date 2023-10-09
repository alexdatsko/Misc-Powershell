# Update-Chrome.ps1
# Alex Datsko MME Consulting Inc 10-9-2023
#   This script should download Chrome (via Ninite) to the users %temp% folder, kill all chrome browser windows at once, and update Chrome 
#   Meant to be run on Sundays and Wednesdays at 11pm

$tmp = "$env:temp"
Invoke-WebRequest "https://ninite.com/chrome/ninite.exe" -OutFile "$($tmp)\ninitechrome.exe"
taskkill.exe /f /im chrome.exe
Start-Sleep 5 # Wait 5 seconds to make sure this is completed
Start-Process -FilePath "$($tmp)\ninitechrome.exe" -NoNewWindow
Start-Sleep 25 # Wait 25 seconds to make sure the app has updated
taskkill.exe /f /im ninite.exe
taskkill.exe /f /im ninitechrome.exe
