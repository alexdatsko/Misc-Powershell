$folders=@("10220324",
"10020323",
"101__TSB")


foreach ($folder in $folders) { 
  new-item -ItemType Directory $folder
  for ($i=0; $i -lt 600; $i++) {  
    $s = '{0:d4}' -f [int]$i
    wget "http://192.168.0.1/DCIM/$($folder)/PICT0$($s).JPG" -outfile "$($folder)\PICT0$($s).JPG" 
    if (("$($folder)\PICT0$($s).JPG").length -lt 25kb) {
      ("$($folder)\PICT0$($s).JPG") | Remove-Item -Force   # delete it right after if its an empty file
    }
  }
}