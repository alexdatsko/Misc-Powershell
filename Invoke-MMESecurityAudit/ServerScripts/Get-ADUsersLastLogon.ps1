$users = get-aduser -Filter *
foreach ($user in $users) { 
  $Thisuser = get-aduser $user -properties lastlogontimestamp,pwdLastSet | select samaccountname,       @{Name="LastLogonTimeStamp";Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}},      @{Name="pwdLastSet";Expression={([datetime]::FromFileTime($_.pwdLastSet))}} 
  $Thisuser | export-csv ADUserLastLogon.csv -Append
}