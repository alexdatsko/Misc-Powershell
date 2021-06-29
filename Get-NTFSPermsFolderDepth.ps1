#$shares = get-smbshare | select -expandproperty 'path' | where {$_ -ne ''} 

$result = ''

Class ListClass {
    [String]$sharename
    [String]$acllist
    [String]$humanreadableACLlist
}

$listfull = @()

$shares = gci F:\Shares\*,F:\Shares\*\*,F:\Shares\*\*\* -Directory | select -ExpandProperty Fullname | sort 



foreach ($share in $shares) {
  $list = New-Object ListClass
  $result += "`r`n" + $share + "`r`n------------------------`r`n"
  $list.sharename = $share

  $GetACL = Get-Acl -Path $share 
  $result += $GetACL | fl | out-string
  $list.acllist = ($GetACL | fl | out-string).replace("`r`n`r`n","")
  
  $SDDLString = $GetACL.Sddl 
  foreach ($SDDL in $SDDLString) {
    $ACLObject = New-Object -TypeName System.Security.AccessControl.DirectorySecurity
    $ACLObject.SetSecurityDescriptorSddlForm($SDDL)
    $humanreadableACL = ($ACLObject.Access | fl | out-string).replace("`r`n`r`n","")
  }
  $result += "Human readable security SDDL (ACL) output:`r`n"
  $result += $humanreadableACL
  $list.humanreadableACLlist = $humanreadableACL
  $listfull += $list
}
$result | out-file "C:\temp\FShares-ACL-3deep.txt"
$listfull | Export-CSV "c:\temp\FShares-ACL-3deep.csv"
$listfull
