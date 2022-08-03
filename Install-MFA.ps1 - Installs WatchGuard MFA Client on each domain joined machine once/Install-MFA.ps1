# Install Watchguard AuthPoint MFA client 

$PathFrom = "\\Server\Data\MFA"
$PathTo = "C:\Temp"
$Files = @("AuthPoint_Agent_for_Windows_x64-2.7.1.371.msi","wlconfig.cfg")

$datetime = Get-Date -Format "yyyy-MM-dd hh:mm"
Write-Host "Running @ $datetime .."

If (!(Test-Path($PathTo))) {
  New-Item -ItemType Directory $PathTo
}


$Name = "*AuthPoint*"
Write-Host "Searching Win32_Product for $Name .."
$GUID = (get-wmiobject -class Win32_Product | ?{ $_.Name -like "$Name"}).IdentifyingNumber


#if (!(Test-Path("$($PathTo)\$($Files[1])"))) {  # Check if wlconfig.cfg already exists in c:\Temp
if (!($GUID)) {
    Write-Host "$Name found, installed as $GUID"

    ForEach ($file in $Files) {
      Copy-Item "$($PathFrom)\$file" $PathTo
    }
    Set-Location $PathTo
    "-----Installed Authpoint @: $datetime" | out-file "AuthPointInstall.log" -Append

    msiexec /i $Files[0] /quiet /qn /L*V "$($PathTo)\AuthpointInstall.log"
    # NOTE: THIS WILL REBOOT THE CLIENT IMMEDIATELY!!

} else {
  "-----Already found Autopoint $GUID installed: $datetime" | out-file "AuthPointInstall.log" -Append
}
