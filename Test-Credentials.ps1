#################################################
#
# Test-Credentials.ps1
#
#   You can pass a username via argument, or the script will ask for password of current user (can be modified on-screen)
#   If a valid password is supplied, the script mentions this, otherwise shows insuccessful.
#

function Test-Cred {
           
    [CmdletBinding()]
    [OutputType([String])] 
       
    Param ( 
        [Parameter( 
            Mandatory = $false, 
            ValueFromPipeLine = $true, 
            ValueFromPipelineByPropertyName = $true
        )] 
        [Alias( 
            'PSCredential'
        )] 
        [ValidateNotNull()] 
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()] 
        $Credentials
    )
    $Domain = $null
    $Root = $null
    $Username = $null
    $Password = $null
      
    If($Credentials -eq $null)
    {
        Try
        {
          $domain = (Get-ADDomain -Current LoggedOnUser).Name
          if ($domain) {
            $credentials = get-credential $domain\$env:username  -ErrorAction Stop
          } else {          
            $credentials = get-credential $env:username  -ErrorAction Stop
          }
          
        }
        Catch
        {
            $ErrorMsg = $_.Exception.Message
            Write-Warning "Failed to validate credentials: $ErrorMsg "
            Pause
            Break
        }
    }
      
    # Checking module
    Try
    {
        # Split username and password
        $Username = $credentials.username
        $Password = $credentials.GetNetworkCredential().password
  
        # Get Domain
        $Root = "LDAP://" + ([ADSI]'').distinguishedName
        $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$UserName,$Password)
    }
    Catch
    {
        $_.Exception.Message
        Continue
    }
  
    If(!$domain)
    {
        Write-Warning "Something went wrong"
    }
    Else
    {
        If ($domain.name -ne $null)
        {
            return "Authenticated"
        }
        Else
        {
            return "Not authenticated"
        }
    }
}


$username=$args[0]
if ($username -eq "") {
  #get domain name
  $domain = (Get-ADDomain -Current LoggedOnUser).Name
  if ($domain) {
    $credentials = get-credential $domain\$env:username
  } else {
    $credentials = get-credential $env:username
  }
} else {
  #get domain name
  $domain = (Get-ADDomain -Current LoggedOnUser).Name
  if ($domain) {
    $credentials = get-credential $domain\$username
  } else {
    $credentials = get-credential $username
  }
}
$CredCheck = $Credentials  | Test-Cred
If($CredCheck -ne "Authenticated")
{
    Write-Warning "[X] Credential validation failed.."
    Break
} else {
    Write-Warning "[O] Credential validation successful!"
    Break
}
