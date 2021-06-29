function Get-dotNETVersion {
  $releasekey = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release 
  if ($releaseKey -ge 528040) {return "4.8 or later"; }
  if ($releaseKey -ge 461808) {return "4.7.2"; }
  if ($releaseKey -ge 461308) {return "4.7.1";}
  if ($releaseKey -ge 460798) {return "4.7";}
  if ($releaseKey -ge 394802) {return "4.6.2";}
  if ($releaseKey -ge 394254) {return "4.6.1";}
  if ($releaseKey -ge 393295) {return "4.6";}
  if ($releaseKey -ge 379893) {return "4.5.2";}
  if ($releaseKey -ge 378675) {return "4.5.1";}
  if ($releaseKey -ge 378389) {return "4.5";}
}

Get-dotNETVersion
