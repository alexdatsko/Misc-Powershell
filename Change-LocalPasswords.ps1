$NewAdminPassword = ""
$NewMMEPassword = ""
$DontChangeList = "SERVER"

$Computers = Get-ADComputer -filter * | select-object -ExpandProperty name
foreach ($computer in $computers) {
  if (!($computer -in $DontChangeList)) {
    write-host "`r`nTrying to change passwords for $Computer ..."
    try {   
      .\pspasswd.exe \\$computer -nobanner Administrator $NewAdminPassword 
      .\pspasswd.exe \\$computer -nobanner MME $NewMMEPassword 
    } catch {  # failed changing passwords
      write-host "`r`n[$computer] Failed to set passwords"
    }
  }
}