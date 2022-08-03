function Compare-Strings {

    param (
        $string1,
        $string2
    )

  #Write-Host "String1:  [$string1] Length in words: [$($string1.split(' ').length)] Split: $($string1.split(' '))"
  #Write-Host "String2:  [$string2] Length in words: [$($string2.split(' ').length)] Split: $($string2.split(' '))"

  $result = $false
  for ($j = 0; $j -le ($string2.split(' ').Count); $j++) {     # iterate through existing gpo name 
    for ($i = 0; $i -le ($string1.split(' ').Count); $i++) {   # iterate through import gpo name..
      #  current word number is $i , current word is  $string1.split(' ')[$i]
      $current = ($string1.split(' ')[$i])
      $existing = ($string2.split(' ')[$j])
      if (($current.length -gt 1) -and ($existing.length -gt 1)) {
        $current = $current.ToUpper()
        $existing = $existing.ToUpper()
        if ($existing -like "*$($current)*") {   
          # don't match 0 or 1 length words
          # even if the word exists inside another word in the existing GPO.. return true
          $result = $true
          #Write-Host "Hit: $current -like *$($existing)*"
        } 
      }
    }
  }
  return $result
}

Compare-Strings "awesome test" "This is a quick re-test !!"
