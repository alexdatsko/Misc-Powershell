# Fix security permissions on service files found in Qualys scans

$files = @("c:\users\datskoa\file2.txt")

foreach ($file in $files) {
  Write-Output "[.] Removing Everyone permissions on $file .."
  $Right = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
  $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None 
  $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly  
  $objType = [System.Security.AccessControl.AccessControlType]::Allow 
  $objUser = New-Object System.Security.Principal.NTAccount("Everyone") 
  $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
      ($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
  $objACL = Get-ACL $file 
  $objACL.RemoveAccessRuleAll($objACE) 
  Set-ACL $file -AclObject $objACL  

  Write-Output "[.] Removing Users-Write/Modify/Append permissions on $file .."
  # .. Remove write/append/etc from 'Users'. First remove Users rule completely.
  $objUser = New-Object System.Security.Principal.NTAccount("Users") 
  $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
      ($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
  $objACL = Get-ACL $file 
  $objACL.RemoveAccessRuleAll($objACE) 
  # Then add ReadAndExecute only for Users
  $Right = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
  $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
      ($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
  $objACL.AddAccessRule($objACE) 
  Set-ACL $file -AclObject $objACL  
}

