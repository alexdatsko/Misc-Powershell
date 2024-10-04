[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Automated = $false,    # this allows us to run without supervision and apply all changes necessary
  [switch] $NoInstall = $false     # this allows us to run without installing the SSO Agent (Auth Gateway), just download the files and set up GPO for SSO Client, and Wgauth user
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

function Create-WatchguardUser {
  param (
    [string] $wgusername = "wgauth",
    [string] $wgfullname = "Watchguard",
    [Parameter(Mandatory)] [string] $wgpw = ""
  )
  Import-Module ActiveDirectory
  if (-not (get-aduser -filter * | where {$_.SAMAccountName -eq "wgauth"})) {
    Write-Host "[+] Wgauth user not found, asking for password: " -ForegroundColor yellow
    $wgpassword = ($wgpw | ConvertTo-SecureString -AsPlainText -Force)
    New-ADUser -SamAccountName $wgusername -Name $wgfullname -AccountNeverExpires -PasswordNeverExpires -AccountPassword $wgpassword 
  } else {
    Write-Host "[+] Wgauth user exists." -ForegroundColor green
  }
}

function Download-WatchguardSoftware {
  param (
    [string]$tmp = "."
  )
  $outfile = "$($tmp)\$($WG_SSO_Client_Filename)"
  Write-Host "[.] Downloading WG SSO Client from $WG_SSO_Client_URL to $outfile ..."
  Invoke-WebRequest -Uri "$WG_SSO_Client_URL" -UserAgent "$UserAgent" -outfile "$outfile"
  try {
    Write-Host "[.] Creating Sysvol location: $SysvolSoftwareLocal ..."
    $null = New-Item -Itemtype Directory $SysvolSoftwareLocal -Force | Out-Null
  } catch { Write-Error "[!] Error creating folder $SysvolSoftwareLocal : $_ " ; exit }
  try {
    Write-Host "[.] Moving WG SSO Client to: $SysvolSoftwareLocal ..."
    Move-Item -Path "$outfile" -Destination "$SysvolSoftwareLocal"
  } catch { Write-Error "[!] Error moving file: $_ " ; exit }
  $outfile = "$($tmp)\$($WG_SSO_Agent_Filename)"
  Write-Host "[.] Downloading WG SSO Agent from $WG_SSO_Agent_URL to $outfile ..."
  Invoke-WebRequest -Uri "$WG_SSO_Agent_URL" -UserAgent "$UserAgent" -outfile $outfile
  if (-not (Test-Path "$outfile")) {
    Write-Host "[.] Error downloading WG SSO Agent `n  From $WG_SSO_Agent_URL `n  To: ""$outfile"" ... `n  $_" 
    return $false
  } else { return $true }
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
    [string]$ADDomain = "$((Get-ADDomain).DNSRoot)",
    [string]$ADDomainDN = "$((Get-ADDomain).DistinguishedName)"
  )
  Write-Host "`n[.] Reconfiguring Watchguard Auth Gateway (SSO Agent) config file.."  -ForegroundColor Yellow
#  Write-Host "> Domain User Name: $wgusername"
#  Write-Host "> Password: $wgpw"
#  Write-Host "> AD Domain Name: $ADDomain"
#  Write-Host "> AD NetBIOS Name: $ADDomainNetBios"
#  Write-Host "> AD Distinguished Name: $ADDomainDN"

  $xmlContent = Get-Content $AdInfos
  [xml]$xml = $xmlContent
  $cipherValue = $xml.EncryptedData.CipherData.CipherValue
  $key = "DD822F06" 
  $ThisIV = "29884f25"
  $decryptedText = Decrypt-ADInfoXML -cipherValue $xml.EncryptedData.CipherData.CipherValue -key $key -ThisIV $thisIV
  $decryptedText | Set-Content "AdInfos.xml.tmp"
  
  
# FIX decryptedText
  Write-Host "Fix the file.."
  Pause

  $decryptedText | get-Content "AdInfos.xml.tmp"

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
    [string]$GPOPath = "BackupGPO",
    [string]$ADDomain = "$((Get-ADDomain).DNSRoot)",
    [string]$ADDomainDN = "$((Get-ADDomain).DistinguishedName)"
  )
  Import-Module GroupPolicy
  $GPOFolders = (gci $GPOPath -Directory).Name
  Write-Host "[.] Searching $GPOPath for folders like __Watchguard .."
  Write-Verbose "$GPOFolders"
  ForEach ($GPOFolder in $GPOFolders) {
    if ($GPOFolder -like "*Watchguard - SSO Client*") {
      $GPOName = ("$($GPOFolder.Split('{')[0])").Split('__')[0]
      $GPOBackupId = ("{$($GPOFolder.Split('{')[-1])").ToUpper()
      Write-Host "[.] Processing '$GPOName' .. `n[.] Renaming folder '$($GPOFolder)' to '$($GPOBackupId)'"
      Rename-Item "$($GPOPath)\$($GPOFolder)" "$($GPOPath)\$($GPOBackupId)" -Force
      # Re-Path the software installation policy
      $BackupFile = "$($GPOFolder)\Backup.xml"
      Write-Host "[.] Modifying $BackupFile .."
      # <DSAttributeMultiString bkp:DSAttrName="msiFileList"><DSValue><![CDATA[0:\\mme-demo.local\SYSVOL\MME-DEMO.local\Software\WG-Authentication-Client_12_7.msi]]>
      $SysvolGenericFile = "mme-demo.local"
      $lines = Get-Content $BackupFile
      Write-Host "[.] Renaming to $($BackupFile).old .."
      Rename-Item $BackupFile "$($BackupFile).old"
      "" | Set-Content $BackupFile
      foreach ($line in $lines) {
        if ($line -like "*mme-demo.local*") {
          (($line -replace "mme-demo.local",$ADDomain) -replace "MME-DEMO.local",$ADDomain) | out-file $BackupFile
        } else {
          if ($line -like "*dc=mme-demo,dc=local*") {
            (($line -replace "dc=mme-demo,dc=local",$ADDomainDN) -replace "dc=MME=DEMO,dc=local",$ADDomainDN) | out-file $BackupFile
          } else {           
            $line | out-file $BackupFile
          }
          # Server.MME-DEMO.local could exist but I think this is  fine to leave currently.
        }
      }
      $GPO = Import-GPO -Path "$GPOPath" -BackupId "$GPOBackupId" -TargetName "$GPOName" -CreateIfNeeded
      Write-Host "[+] Added $($GPO.DisplayName)"

      $gpoLink = "$($ADDomainDN)"
      Write-Host "[.] Linking GPO to domain '$gpoLink'."
      New-GPLink -Name $GPOName -Target $gpoLink -Enforced $false
      Write-Host "[+] Software installation policy added to GPO '$gpoName' Completed." -ForegroundColor Green
    }
  }


}

function Create-WatchguardClientGPO {
  param (
    [string]$ADDomain = "$((Get-ADDomain).DNSRoot)",
    [string]$ADDomainDN = "$((Get-ADDomain).DistinguishedName)"
  )
  Import-Module GroupPolicy
  $gpoName = "Watchguard - SSO Client - Install"
  $gpoComment = "Installs Watchguard SSO Client software on each computer. To be applied to the root of the domain."
  $gpo = Get-GPO -Name $gpoName -Comment $gpoComment -ErrorAction SilentlyContinue
  if (-not $gpo) {
      $gpo = New-GPO -Name $gpoName
      Write-Host "GPO '$gpoName' created."
  } else {
      Write-Host "GPO '$gpoName' already exists."
  }

  # Define path to the installer
  $installerPath = "\\$($ADDomain)\sysvol\$($ADDomain)\Software\installer.msi"

  # Define the GPO target (for computers)
  $gpoTarget = "Computer"
  $gpoExtensionPath = "Software Settings\Software installation"
  $policyName = "Watchguard - SSO Client- Install"
  $gpoLink = "$($ADDomainDN)"

  # Add software installation policy
  #Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\Installer" -ValueName "Install MSI Software" -Type String -Value $installerPath
  # not sure what this should be

  Write-Host "[+] Linking GPO to domain '$gpoLink'."
  New-GPLink -Name $gpoName -Target $gpoLink -Enforced $false
  Write-Host "[+] Software installation policy added to GPO '$gpoName'."

  
}



#####################################################################  MAIN 


Write-Host $info -Foregroundcolor White
Write-Host $datetime -ForegroundColor White

if (!(Test-Path $tmp)) { 
  Write-Host "[.] Creating temp folder $tmp ..."  
  $null = (New-Item $tmp -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null)
}

$wgpw = Read-Host '[?] Enter the WGauth domain user password: '

Create-WatchguardUser -wgpw $wgpw

Download-WatchguardSoftware -tmp $tmp

Restore-WatchguardClientGPO -tmp $tmp -GPOPath $pwd

if (!($NoInstall)) {
  Install-WatchguardSSOAgent -tmp $tmp -wgpw $wgpw
}

Reconfigure-WatchguardSSOAgent -wgpw $wgpw -tmp $tmp  # Not working...

$wgpw = ""

Write-Host "[!] Done! Exiting." 
Clear-History
