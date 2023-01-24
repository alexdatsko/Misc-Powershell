[cmdletbinding()]  # For verbose, debug etc
param (
  [string] $FilePath = 'C:\Windows\Logs\CBS\CBS.log'   # Default value of CBS.log file to read
)

$date = Get-Date -format "yyyy-MM-dd_hh-mm"
$active = 0     # Set this to 0 to NOT remove the registry entries but run in Test mode to see what would be deleted

"#############################################################"
"# Fix-ERROR_SXS_ASSEMBLY_MISSING.PS1"
"# Fixes the problem with SFC/DISM resulting in 0x80073701 = ERROR_SXS_ASSEMBLY_MISSING"
"# Found at https://social.technet.microsoft.com/Forums/ie/en-US/c1d825aa-f946-427c-bd81-cf3a18908651/server-2016-unable-to-add-rsat-role-the-referenced-assembly-could-not-be-found-error?forum=winservermanager"
"# Modified 12-30-22 Alex Datsko alex.datsko@mmeconsulting.com"
"# It may be that language packs need to be removed with lpksetup.exe as well."

#Read CBS log file contents into memory
$Contents = ""
while ("" -eq $Contents) {
  try {
    "[.] Trying to read in $filepath .."
    $Contents = Get-Content -Path $filepath
  } catch {
    "[!] File is currently in use.  Re-running script in 10 seconds ... [Paused]"
    Start-Sleep 10
  }
}

"[.] Parse log file for missing assemblies .."
$InterestingLines = $Contents | Select-String -SimpleMatch '(ERROR_SXS_ASSEMBLY_MISSING)'
if ($InterestingLines) {
  "[!] Interesting lines found:"
  $InterestingLines
} else {
  "[!] Nothing of interest found! Exiting .."
  exit
}

"[.] Creating backup of ALL registry entries in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing .."
reg save "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" "c:\temp\ComponentBasedServicing-$($date).reg"
"[+] Done. Saved to c:\temp\ComponentBasedServicing-$($date).reg"

# Example:
<#
2022-12-28 07:15:27, Error                 CSI    0000000a (F) HRESULT_FROM_WIN32(ERROR_SXS_ASSEMBLY_MISSING) #8110# from Windows::ServicingAPI::CCSITransaction::ICSITransaction_PinDeployment(Flags = 0, a = Microsoft-Windows-SNMP-SC-Deployment-LanguagePack, version 10.0.14393.0, arch amd64, culture [l:5]'nl-NL', nonSxS, pkt {l:8 b:31bf3856ad364e35}, cb = (null), s = (null), rid = 'Microsoft-Windows-SNMP-SC-Package~31bf3856ad364e35~amd64~nl-NL~10.0.14393.0.SNMP', rah = (null), manpath = (null), catpath = (null), ed = 0, disp = 0)[gle=0x80073701]
#>

"[.] Retrieve unique Package names from error messages .."
$Packages = @()
foreach ($Line in $InterestingLines) {
    #$Package  = $(($Line -split("'") )[1]).Substring(0,$Line.Length - ($Line.split(".")[4]).Length - 1)
    $L = $Line | Out-String

    <#
    # Looks like there is a 'nl-NL' before the package name that matches the registry entry in PackageDetect.
    # If i use [1] it will get the language, but [3] gets the actual full package which I think was intended, by the $Package variable
#    $Rest = $(($L -split("'") )[1])    
    $Rest = $(($L -split("'") )[3])
    #>

    # HOWEVER, 12-30-22 update - this has not been working to actively solve any of these issues
    # I think the nuclear option might be better, to remove ANY package using the languagepack that is not installed
    # Make sure you have a full registry backup of Component Based Servicing before you continue.. Let's remove entries of ALL the offending packages using this language..
    $Rest = $(($L -split("'") )[1])    

    $Package = $Rest.Substring(0,$Rest.Length - ($Rest.split(".")[4]).Length - 1)
    if ($Packages -notcontains $Package) { $Packages += $Package }
}

$AllKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackageDetect', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages')

"[.] Processing registry entries .."
foreach ($RegRoot in $AllKeys) {
    $Keys = Get-ChildItem $RegRoot | where {$_.PSIsContainer}
    foreach ($Key in $Keys) {
    write-Verbose "Checking $($Key.name)"
        foreach ($Package in $Packages) {
            foreach ($Property in $Key.Property) {
                write-Verbose "$Property ? $Package"
                if ($Property -match $Package) {
                    $ShortTarget = $($Key.Name).Substring(87) 
                    write-host "Found $Package in $ShortTarget...  " -ForegroundColor Yellow -NoNewline
                    $Target = $($Key.Name).TrimStart("HKEY_LOCAL_MACHINE\\")
                    try {
                        # Attempt to give Admins full control of key and delete key.
                        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Target,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
                        $acl = $key.GetAccessControl()
                        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("BUILTIN\Administrators","FullControl","Allow")
                        $acl.SetAccessRule($rule)
                        $key.SetAccessControl($acl)
                        if ($active) {
                          Remove-ItemProperty -Path "HKLM:\$Target" -Name $Package -Force
                        } else {
                          Write-Verbose "Would have deleted: Remove-ItemProperty -Path "HKLM:\$Target" -Name $Package -Force"
                        }
                        Write-Host "delete successful." -ForegroundColor Green
                    } catch {
                        Write-Host "delete failed.  Delete manually." -ForegroundColor Red
                    }
                }
            }
        }
    }
}