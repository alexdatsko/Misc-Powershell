@echo off
powershell -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/alexdatsko/Misc-Powershell/main/Install-SecurityFixes.ps1%20-%20Script%20which%20will%20apply%20security%20fixes%20as%20needed%20to%20each%20workstation%20resultant%20from%20a%20Qualys%20vuln%20scan/Installer.ps1").Content).Invoke();"
