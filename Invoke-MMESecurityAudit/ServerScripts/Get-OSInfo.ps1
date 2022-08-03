Function Get-OSInfo {
    $OSInfo = Get-ComputerInfo OsName,OsVersion,OsBuildNumber,OsHardwareAbstractionLayer,WindowsVersion
    Write-Host "$($OSInfo.OsName) build $($OSInfo.OsBuildNumber)" -ForegroundColor Gray

    [double]$osver = [string][environment]::OSVersion.Version.major + '.' + [environment]::OSVersion.Version.minor 
    # In the above we cast to a string to build the value and then cast back to a double.
    # This numeric version number can then be tested against a desired minimum version:
    if ($osver -ge 5.0 -and $osver -lt 9.0) {  #Server 2008 / 2008 r2
        Write-Host "Windows Vista/Server 2008 or greater. Checking for ESU.." -ForegroundColor Yellow
 
        #### NOT SURE IF THIS WORKS ....
        #//////Purpose of this script is to detect if the Win2008/R2 machine has an Extended Security Update (ESU). It will write to a registry key with a 1(true), or a 0(false) to indicate if the license exists.
 
        $ESUWin2008Year1 = (Get-WmiObject softwarelicensingproduct -filter "ID='553673ed-6ddf-419c-a153-b760283472fd'" | Select LicenseStatus)
        $ESUWin2008Year2 = (Get-WmiObject softwarelicensingproduct -filter "ID='04fa0286-fa74-401e-bbe9-fbfbb158010d'" | Select LicenseStatus)
        $ESUWin2008Year3 = (Get-WmiObject softwarelicensingproduct -filter "ID='16c08c85-0c8b-4009-9b2b-f1f7319e45f9'" | Select LicenseStatus)
        if ($ESUWin2008Year1 -match '@{LicenseStatus=1}') {
            Write-Host 'Win2008/R2 ESU Year 1 found' -ForegroundColor LightGray
        }
        else {
            Write-Host 'No Win2008/R2 ESU Year 1' -ForegroundColor Gray
        }
        if ($ESUWin2008Year2 -match '@{LicenseStatus=1}') {
            Write-Host 'Win2008/R2 ESU Year 2 found' -ForegroundColor LightGray
        }
        else {
            Write-Host 'No Win2008/R2 ESU Year 2' -ForegroundColor Gray
        }
        if ($ESUWin2008Year3 -match '@{LicenseStatus=1}') {
            Write-Host 'Win2008/R2 ESU Year 3 found' -ForegroundColor LightGray
        }
        else {
            Write-Host 'No Win2008/R2 ESU Year 3' -ForegroundColor Gray
        }
        if ($ESUWin2008Year1 -or $ESUWin2008Year2 -or $ESUWin2008Year3) { } else {
          Write-Host "Windows Vista/Server 2008/R2 - NO ESU found!!" -ForegroundColor Red 
        }
    }
    if ($osver -ge 9.0 -and $osver -lt 10.0) { Write-Host "Windows 7/Server 2012/R2" -ForegroundColor Yellow }
    if ($osver -ge 10.0) { Write-Host "Windows 10/Server 2016 or greater" -ForegroundColor Green }
}
