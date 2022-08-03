$shares = get-smbshare | select -expandproperty 'path' | where {$_ -ne ''} 

$result = ''


foreach ($share in $shares) {
  $result += "`r`n" + $share + "`r`n------------------------`r`n"
  $GetACL = Get-Acl -Path $share 
  $result += $GetACL | fl | out-string
  $SDDLString = $GetACL.Sddl 
  foreach ($SDDL in $SDDLString) {
    $ACLObject = New-Object -TypeName System.Security.AccessControl.DirectorySecurity
    $ACLObject.SetSecurityDescriptorSddlForm($SDDL)
    $humanreadableACL = $ACLObject.Access | fl | out-string
  }
  $result += "Human readable security SDDL (ACL) output:`r`n"
  $result += $humanreadableACL
}
$result | out-file -filepath "$($env:computername)-perms.txt"
$result
