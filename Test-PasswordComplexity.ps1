
$hasbeenfound = $false

Function Test-Passwords {
  param(
    $let,
    [boolean]$upper,
    [boolean]$number,
    [boolean]$symbol
  )

  $ul = "";   $num = "";   $sym = ""
  if ($upper) {
    $ul = "A"
  }
  if ($number) {
    $num = "1"
  }
  if ($symbol) {
    $sym = "!"
  }
  
  $thistest = "$let$ul$num$sym"
  Write-Verbose "$($x): $thistest"
  $Result = (. ./Test-Credentials.ps1 $thistest)
  if ($Result) {
    if ($Result -like "*successful*") {    
        Write-Host "$thistest worked. "
        if ($hasbeenfound -eq $false) {
          $minlength=($thistest.length)
          Write-Host "Min length: $minlength" 
          $hasbeenfound=$true
        }
    }
  }
}

$let = "a"
for ($x=1;$x -lt 40; $x+=1) {
    Test-Passwords -let $let 
    Test-Passwords -let $let -ul $true 
    Test-Passwords -let $let -ul $true -num $true 
    Test-Passwords -let $let           -num $true -sym $true
    Test-Passwords -let $let -ul $true            -sym $true
    Test-Passwords -let $let -ul $true -num $true -sym $true
    $let+="a"
}
