[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Automated = $false,    # this allows us to run without supervision and apply all changes necessary
  [switch] $NoInstall = $false,    # this allows us to run without installing the SSO Agent (Auth Gateway), just download the files and set up GPO for SSO Client, and Wgauth user
  [switch] $Test = $false          # for testing purposes only
)



$info = '''
###############################################################
# Filename:    Install-WatchguardSSO.ps1
# Author:      Alex Datsko - MME Consulting Inc.
# Description: This will download and install the Watchguard SSO Agent (Auth Gateway) from the Watchguard site and install it.
#              It will create a standardized domain user, Watchguard (username: wgauth), with a password specified, and add 
#              them to the Administrators group as needed by the SSO Agent. This user will be used in setting up the application.
#              It will also download the Watchguard SSO Client, move it to C:\Windows\Sysvol\domain\Software and set up a GPO to
#              install it on each client machine.  The GPO must be restored from a backup residing in .\BackupGPO.  The path will
#              be modified to have the correct AD domain in the UNC share to Sysvol\Software\filename
# Version: v0.1 - 10/1/2024 - orig
# Version: v0.2 - 10/2/2024 - GPO restore
# Version: v0.3 - 10/10/2024 - disabled GPO restore for now, but user account creation and addition to administrators group is done
#
'''

# Download location for SSO Client (to be installed on workstations)
$WG_SSO_Client_URL = "https://cdn.watchguard.com/SoftwareCenter/Files/SSO_AGENT_CLIENT/12_7/WG-Authentication-Client_12_7.msi"
$WG_SSO_Client_Filename = (Split-Path $WG_SSO_Client_URL -Leaf)

# Download location for SSO Agent / 'Auth Gateway' (to be installed on server only)
$WG_SSO_Agent_URL = "https://cdn.watchguard.com/SoftwareCenter/Files/SSO_AGENT_CLIENT/12_10_2/WG-Authentication-Gateway_12_10_2.exe"
$WG_SSO_Agent_Filename = (Split-Path $WG_SSO_Agent_URL -Leaf)

$AgentString = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  # Hack for SSL error downloading files.

$ADDomain = (Get-ADDomain).DNSRoot
$SysvolSoftwareLocal = "C:\Windows\Sysvol\domain\Software" # Location where the file will be moved to, \\<domain>\Sysvol\<domain>\Software location which is centralized
$SysvolSoftwareDomain = "\\$($ADDomain)\Sysvol\$($ADDomain)\Software" # Location where the GPO will install the file from
$SysvolSoftwareFile = "$($SysvolSoftwareDomain)\$($WG_SSO_Client_Filename)"

$date = Get-Date -Format "MM-dd-yyyy"
$time = Get-Date -Format "hh:mm:ss"
$datetime = "$date $time"
#$tmp = $env:temp
$tmp = $pwd  # Lets work out of local folder..

################################################################### FUNCTIONS

function Check-UserGroup {
  param (
    [string]$user,
    [string]$group
  )
  try {
    $members = Get-ADGroupMember -Identity $group -Recursive | Select -ExpandProperty Name
  } catch {
    Write-Error "[-] Error checking Get-ADGroupMember : $_"
  }

  If ($members -contains $user) {
    Write-Verbose "$user exists in the group $group"
    return $true
  } Else {
    Write-Verbose "$user does not exist in the group $group"
    return $false
  }
}

function Create-WatchguardUser {
  param (
    [string] $wgusername = "wgauth",
    [string] $wgfullname = "Watchguard",
    [Parameter(Mandatory)] [string] $wgpw = "",
    [string]$ADDomain = "$((Get-ADDomain).DNSRoot)"
  )
  Import-Module ActiveDirectory
  if (-not (get-aduser -filter * | where {$_.SAMAccountName -eq "wgauth"})) {
    Write-Host "[+] Wgauth user not found, creating.. " -ForegroundColor yellow
    $wgpassword = ($wgpw | ConvertTo-SecureString -AsPlainText -Force)
    New-ADUser -SamAccountName $wgusername -Name $wgfullname -PasswordNeverExpires $true -AccountPassword $wgpassword -UserPrincipalName "$($wgusername)@$($ADDomain)"
    Enable-ADAccount -Identity $wgusername
    # User is disabled
    # No UPN Set
  } else {
    Write-Host "[+] Wgauth user exists." -ForegroundColor green
  }
  if (!(Check-UserGroup -user $wgusername -group "Administrators")) {
    Write-Host "[.] Adding to administrators group.." -ForegroundColor yellow
    # Add to Administrators group
    $member = get-aduser -filter * | where {$_.SAMAccountName -eq "wgauth"}
    try {
      Add-ADGroupMember -Identity "Administrators" -Members $member
    } catch { 
      Write-Error "`n[-] wgauth user couldn't be added to Administrators group, permissions possibly?" 
      exit
    }
    Write-Host "[+] wgauth user added to Administrators group! Good to go." -ForegroundColor green
  } else {
    Write-Host "[+] wgauth user already in administrators group.. Good to go." -ForegroundColor green
  }
}

function Download-WatchguardSoftware {
  param (
    [string]$tmp = ".",
    [string]$SysvolSoftwareLocal,
    [string]$WG_SSO_Client_Filename,
    [string]$WG_SSO_Client_URL,
    [string]$WG_SSO_Agent_Filename,
    [string]$WG_SSO_Agent_URL
  )
  $outfile = "$($tmp)\$($WG_SSO_Client_Filename)"
  Write-Host "[.] Downloading WG SSO Client from $WG_SSO_Client_URL to $outfile ..."
  Invoke-WebRequest -Uri "$WG_SSO_Client_URL" -UserAgent "$UserAgent" -outfile "$outfile"
  try {
    Write-Host "[.] Creating Sysvol location: $SysvolSoftwareLocal ..."
    $null = New-Item -Itemtype Directory $SysvolSoftwareLocal -Force | Out-Null
  } catch { Write-Error "[!] Error creating folder $SysvolSoftwareLocal : $_ " ; exit }
  try {
    if (!(test-path "$($SysvolSoftwareLocal)\$(Split-Path $outfile -leaf)")) {
      Write-Host "[.] Moving WG SSO Client to: $($SysvolSoftwareLocal)\$(Split-Path $outfile -leaf) ..."
      Move-Item -Path "$outfile" -Destination "$SysvolSoftwareLocal"
    } else {
      Write-Host "[+] SSO Client installer already exists at: '$($SysvolSoftwareLocal)\$($outfile)'" -ForegroundColor Green
    }
  } catch { Write-Error "[!] Error moving file: $_ " ; exit }
  $outfile = "$($tmp)\$($WG_SSO_Agent_Filename)"
  if (!(test-path "$($tmp)\$($outfile)")) {
    Write-Host "[.] Downloading WG SSO Agent from $WG_SSO_Agent_URL to $outfile ..."
    Invoke-WebRequest -Uri "$WG_SSO_Agent_URL" -UserAgent "$UserAgent" -outfile $outfile
    if (-not (Test-Path "$outfile")) {
      Write-Host "[.] Error downloading WG SSO Agent `n  From $WG_SSO_Agent_URL `n  To: ""$outfile"" ... `n  $_" 
      return $false
    } else { return $true }
  } else {
    Write-Host "[+] SSO Auth Gateway installer already exists at: '$($tmp)\$($outfile)'" -ForegroundColor Green
  }
}

function Install-WatchguardSSOAgent {
  param (
    [string] $tmp = ".",
    [string] $wgusername = "$((Get-ADDomain).DNSRoot)\wgauth",
    [Parameter(Mandatory)] [string] $wgpw,
    [string]$ADDomain = "$((Get-ADDomain).DNSRoot)",
    [string]$ADDomainNetBios = "$((Get-ADDomain).NetBiosName)",   
    [string]$ADDomainDN = "$((Get-ADDomain).DistinguishedName)"
  )

#  Write-Host "`n[.] Extracting WG SSO Agent MSI from $WG_SSO_Agent_Filename_New ..."  -ForegroundColor Yellow
#  Expand-Archive -Path "$WG_SSO_Agent_Filename_New" -Destination ".\WG_SSO_Agent" -Force
#  $WG_SSO_Agent_MSI = ""
#  Write-Host "`n[.] Installing WG SSO Agent from MSI $WG_SSO_Agent_MSI ..."  -ForegroundColor Yellow
#  $Arguments = "/i ""$($WG_SSO_Agent_MSI)cd \"" /qn /quiet"    # /qb can perform a UAC elevation prompt, but /qn cannot, it will just silent fail.

  # No MSI here, we might be able to make one with https://exemsi.com, but likely it can't be automated anyway.. so lets just install and configure it manually I guess.
  Write-Host "`n[.] Installing Watchguard Auth Gateway (SSO Agent) from "$($tmp)\$($WG_SSO_Agent_Filename)" .."  -ForegroundColor White
  Write-Host "`n[!] Please step through the installation of the Watchguard Auth Gateway application, we will wait until this is completed."  -ForegroundColor Yellow
  Write-Host "[!] NOTE: Use this for user information:"
  Write-Host "> Domain User Name: $wgusername"
  Write-Host "> Password: $wgpw"
  Write-Host "Don't forget to check off the option for Event Log Monitor!!" -ForegroundColor Red
#  Write-Host "> AD Domain Name: $ADDomain"
#  Write-Host "> AD NetBIOS Name: $ADDomainNetBios"
#  Write-Host "> AD Distinguished Name: $ADDomainDN"
  $Arguments = @()
  Start-Process "$($tmp)\$($WG_SSO_Agent_Filename)" -Wait # -ArgumentList $Arguments
  Write-Host "[+] Done with SSO Auth Gateway install."  -ForegroundColor Green
}

function Encrypt-ADInfoXML {
    param (
        [string]$PlainText,
        [string]$Key, # DES key
        [string]$thisIV # Default IV if not passed, 8 bytes for DES
    )

    # Ensure key is 8 bytes for DES
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $IVBytes = [System.Text.Encoding]::UTF8.GetBytes($thisIV)

    # Convert plain text to bytes
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)

    # Create the DES provider
    $des = New-Object System.Security.Cryptography.DESCryptoServiceProvider
    $des.Mode = [System.Security.Cryptography.CipherMode]::CBC
    #$des.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $des.Padding = [System.Security.Cryptography.PaddingMode]::None

    # Create an encryptor
    $encryptor = $des.CreateEncryptor($keyBytes, $IVbytes)

    # Perform encryption
    $memoryStream = New-Object System.IO.MemoryStream
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cryptoStream.Write($plainBytes, 0, $plainBytes.Length)
    $cryptoStream.FlushFinalBlock()
    $cryptoStream.Close()

    # Get the encrypted bytes and convert them to base64
    $encryptedBytes = $memoryStream.ToArray()
    $cipherValue = [Convert]::ToBase64String($encryptedBytes)

    # Return the Base64-encoded CipherValue
    return $cipherValue
}


function Decrypt-ADInfoXML {
    param (
        [string]$CipherValue,
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] [string]$thisIV
    )

    $encryptedBytes = [Convert]::FromBase64String($CipherValue)
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $IVbytes = [System.Text.Encoding]::UTF8.GetBytes($thisIV)

    $des = New-Object System.Security.Cryptography.DESCryptoServiceProvider
    $des.Mode = [System.Security.Cryptography.CipherMode]::CBC
    #$des.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $des.Padding = [System.Security.Cryptography.PaddingMode]::None

    $decryptor = $des.CreateDecryptor($keyBytes, $IVbytes)
    $memoryStream = New-Object System.IO.MemoryStream
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cryptoStream.Write($encryptedBytes, 0, $encryptedBytes.Length)
    $cryptoStream.FlushFinalBlock()
    $cryptoStream.Close()

    $decryptedBytes = $memoryStream.ToArray()
    $decryptedText = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

    return $decryptedText
}

function Reconfigure-WatchguardSSOAgent {
  param(
    [string] $tmp = ".",
    [Parameter(Mandatory)] [string] $wgpw,
    [string] $ADInfos = "C:\Program Files (x86)\WatchGuard\WatchGuard Authentication Gateway\AdInfos.xml",
    [string]$ADDomain = "$((Get-ADDomain).DNSRoot)",   # mme-demo.local 
    [string]$ADDomainDN = "$((Get-ADDomain).DistinguishedName)"   # MMEDEMO
  )
  
  Write-Host "`n[.] Reconfigure Watchguard Auth Gateway (SSO Agent) manually..`n"  -ForegroundColor Yellow

  Write-Host "> Login with : admin / readwrite"
  Write-Host "> Domain User Name: $wgusername"
  Write-Host "> Password: $wgpw"
  Write-Host "> AD Domain Name: $ADDomain"
  Write-Host "> AD NetBIOS Name: $ADDomainNetBios"
  Write-Host "> AD Distinguished Name: $ADDomainDN"

  Start-Process "c:\Program Files (X86)\Watchguard\\Watchguard Authentication Gateway\SSOGUITool.exe" -Wait
  Return $true

  Write-Host "`n[.] Reconfiguring Watchguard Auth Gateway (SSO Agent) config file.."  -ForegroundColor Yellow
  $xmlContent = Get-Content $AdInfos
  [xml]$xml = $xmlContentping 
  $cipherValue = $xml.EncryptedData.CipherData.CipherValue
  $key = "DD822F06" 
  $ThisIV = "29884f25"
  $decryptedText = Decrypt-ADInfoXML -cipherValue $xml.EncryptedData.CipherData.CipherValue -key $key -ThisIV $thisIV
  $decryptedText | Set-Content "AdInfos.xml.tmp"
  
  
# FIX decryptedText
  Write-Host "Fix the file.."
  Pause

  $decryptedText = get-Content "AdInfos.xml.tmp" 

  $encryptedCipherValue = Encrypt-ADInfoXML -PlainText $decryptedText -Key $key -thisIV $thisIV
  $encryptedCipherValue | Set-Content $AdInfos

  Write-Host "[.] Restarting Auth gateway service.."  -ForegroundColor Yellow 
  Get-Service "wagsrvc" | Restart-Service -Force -Wait
  if ((Get-Service "wagsrvc").Status -eq "Running")  {
    Write-Host "[+] Watchguard Auth Gateway service restarted. Good to go."
  } else {
    Write-Host "[!] Watchguard Auth Gateway service not running!! Start manually with:  `nnet start wagsrvc"
  }
  Write-Host "[+] Done with SSO Auth Gateway reconfigure."  -ForegroundColor Green
  
}

########### GPO 

function Restore-WatchguardClientGPO {
  param (
    [string]$GPOPath = "c:\temp\BackupGPO", # Directory for the Watchguard GPO backup
    [string]$GPOBackupFile = "$(gci BackupGPO*.zip)",
    [string]$ADDomain = "$((Get-ADDomain).DNSRoot)",
    [string]$ADDomainDN = "$((Get-ADDomain).DistinguishedName)"
  )
  if (Test-Path $GPOPath) { Remove-Item "$($GPOPath)" -Force -Recurse -ErrorAction SilentlyContinue }  # Remove this folder if it exists.. re-extract.
  try {
    Expand-Archive -Path $GPOBackupFile -Destination $GPOPath -Force -ErrorAction Continue
  } catch { 
    Write-Host "[!] There was a problem extracting '$GPOBackupFile' to '$GPOPath' !!! - `n  Error: $_" -ForegroundColor Red
    return $false
  }
  Import-Module GroupPolicy
  $GPOFolders = (gci "$($GPOPath)" -Directory).Name
  Write-Host "[.] Searching $GPOPath for folders like '*Watchguard - SSO Client*' .."
  Write-Verbose "$GPOFolders"
  ForEach ($GPOFolder in $GPOFolders) {
    if ($GPOFolder -like "*Watchguard - SSO Client*") {
      $GPOName = ("$($GPOFolder.Split('{')[0])").Split('__')[0]
      $GPOBackupId = ("{$($GPOFolder.Split('{')[-1])").ToUpper()
      Write-Host "[.] Processing '$GPOName' .. `n[.] Renaming folder '$($GPOFolder)' to '$($GPOBackupId)'"
      $NewGPOPath = "$($GPOPath)\$($GPOBackupId)"
      Write-Host "[+] New GPO Path: $NewGPOPath" -ForegroundColor Yellow
      Rename-Item -Path "$($GPOPath)\$($GPOFolder)" "$GPOBackupId" -Force
      # Re-Path the software installation policy
      
      $BackupFile = "$($NewGPOPath)\Backup.xml"
      if (Test-Path $BackupFile) {
        Write-Host "[.] Modifying $($BackupFile) .."
        # <DSAttributeMultiString bkp:DSAttrName="msiFileList"><DSValue><![CDATA[0:\\mme-demo.local\SYSVOL\MME-DEMO.local\Software\WG-Authentication-Client_12_7.msi]]>
        $SysvolGenericFile = "mme-demo.local"
<#
        $lines = Get-Content $($BackupFile) -Encoding unicode 
        Write-Host "[.] Renaming to $(Split-Path $BackupFile -Leaf).old .."
        Rename-Item $BackupFile "$(Split-Path $BackupFile -Leaf).old"
        Write-Host "[.] Reconfiguring $($BackupFile) .."
        "" | Set-Content $BackupFile  # overwrite file since its loaded into $lines
        foreach ($line in $lines) {
          if ($line -like "*mme-demo.local*") {
            Write-Verbose "linebefore: $line"
            $newline = (($line -replace "mme-demo.local",$ADDomain) -replace "MME-DEMO.local",$ADDomain) 
            $newline | out-file $BackupFile -Append
            Write-Verbose "lineafter: $line"
          } else {
            if ($line -like "*dc=mme-demo,dc=local*") {
              Write-Verbose "linebefore: $line"
              $newline = (($line -replace "dc=mme-demo,dc=local",$ADDomainDN) -replace "dc=MME=DEMO,dc=local",$ADDomainDN) 
              $newline | out-file $BackupFile -Append
              Write-Verbose "lineafter: $line"
            } else {           
              $line | out-file $BackupFile -Append
              Write-Verbose "lineunchanged: $line"
            }
            # Server.MME-DEMO.local could exist but I think this is  fine to leave currently. 
          }
        }
#>
        $xmlDoc = New-Object System.Xml.XmlDocument
        $xmlDoc.Load($BackupFile)
        $nodes = $xmlDoc.SelectNodes("//text()[contains(., 'mme-demo.local')]")
        foreach ($node in $nodes) {
          $node.Value = $node.Value.Replace("mme-demo.local", $ADDomain)
        }
        $nodes = $xmlDoc.SelectNodes("//text()[contains(., 'dc=mme-demo,dc=local')]")
        foreach ($node in $nodes) {
          $node.Value = $node.Value.Replace("dc=mme-demo,dc=local", $ADDomainDN)
        }
        $xmlDoc.Save($BackupFile)

        if (!(Test-Path $BackupFile)) {
          Write-Host "[!] Error - $BackupFile not found!" -ForegroundColor Red
        } else {
          Write-Host "[+] Reconfigured $($BackupFile)." -ForegroundColor Green
        }

        Write-Host "[.] Adding $($GPOName) to GPOs"
        Write-Verbose "GPOPath: $GPOPath `nGPOBackupId\GPOPath: $($GPOBackupDest)\$($GPOPath)\ `nGPOName: $GPOName"
        $GPO = Import-GPO -Path "$($GPOPath)\" -BackupId "$GPOBackupId" -TargetName "$GPOName" -CreateIfNeeded
        Write-Host "[+] Added $($GPOName)"

        $gpoLink = "$($ADDomainDN)"
        Write-Host "[.] Linking GPO to domain- '$gpoLink'"
        New-GPLink -Name "$GPOName" -Target $gpoLink
        Write-Host "[+] Software installation policy added to GPO '$gpoName' Completed." -ForegroundColor Green
      }  else  { 
        Write-Host "[-] Script error importing GPO '$gpoName'" -ForegroundColor Red
        return $false
      }

    }
  }
  return $true

}


#####################################################################  MAIN 


Write-Host $info -Foregroundcolor White
Write-Host $datetime -ForegroundColor White

if ($Test) {
  if (Restore-WatchguardClientGPO -GPOBackupDest "C:\temp" -GPOPath "BackupGPO") {
    Write-Host "[+] WG SSO Client GPO Installation complete, please reboot all hosts to complete process." -ForegroundColor Green
  } else {
    Write-Host "[!] Error installing GPO, please do this manually:" -ForegroundColor Red
    gpmc.msc
  }
  exit
}

if (!(Test-Path $tmp)) { 
  Write-Host "[.] Creating temp folder $tmp ..."  
  $null = (New-Item $tmp -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null)
}

$wgpw = Read-Host '[?] Enter the WGauth domain user password: '

Create-WatchguardUser -wgpw $wgpw

Download-WatchguardSoftware -tmp $tmp `
  -SysvolSoftwareLocal $SysvolSoftwareLocal `
  -WG_SSO_Client_Filename $WG_SSO_Client_Filename `
  -WG_SSO_Client_URL $WG_SSO_Client_URL `
  -WG_SSO_Agent_Filename $WG_SSO_Agent_Filename `
  -WG_SSO_Agent_Url $WG_SSO_Agent_URL `

<#
if (Restore-WatchguardClientGPO -GPOBackupDest "C:\temp" -GPOPath "BackupGPO") {
  Write-Host "[+] WG SSO Client GPO Installation complete, please reboot all hosts to complete process." -ForegroundColor Green
} else {
  Write-Host "[!] Error installing GPO, please do this manually:" -ForegroundColor Red
  gpmc.msc
}
#>

if (!($NoInstall)) {
  Install-WatchguardSSOAgent -tmp $tmp -wgpw $wgpw
}

#Reconfigure-WatchguardSSOAgent -wgpw $wgpw -tmp $tmp  # Not working...
Write-Host "[!] Reconfigure Watchguard SSO Auth Gateway manually."

$ADDomain = "$((Get-ADDomain).DNSRoot)"
$ADDomainDN = "$((Get-ADDomain).DistinguishedName)" 
$ips = (ipconfig /all | findstr /i "IPv4")
  
Write-Host "`n[.] Reconfigure Watchguard Auth Gateway (SSO Agent) manually..`n"  -ForegroundColor Yellow

Write-Host "> Login with : admin / readwrite"
Write-Host "> Domain User Name: $wgusername"
Write-Host "> Password: $wgpw"
Write-Host "> AD Domain Name: $ADDomain"
Write-Host "> AD NetBIOS Name: $ADDomainNetBios"
Write-Host "> AD Distinguished Name: $ADDomainDN"
Write-Host "> Server IPv4 addresses (one of these will be correct, please confirm its within the normal LAN subnet): "
$ips
$wgpw = ""

Write-Host "[!] Done! Exiting." 
Clear-History
