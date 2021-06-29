################################################################################
#
#
# Get-BadBlockList.ps1 - Alex Datsko @ MME Consulting 01-17-2020
#
#
#   Get list of bad blocks from Dell PERC TSR Raid log file, and correllate to 
#   bad Logical Cluster Number and then lists files on disk that are affected 
#   and should be restored from backup.
#
#

$RAIDlog = $false
$LSIlog = $false

write-host "Showing files matching RAID* and lsi_* in current directory"
$RAIDfile = gci "." | where { $_.name -like "RAID*" }
if ($RAIDfile) {
  $RAIDfile
  $TSRRAIDfilename = $RAIDfile.Name
  $RAIDlog = $true
} else {
  $RAIDfile = gci "." | where { $_.name -like "lsi_*" }
  $RAIDfile
  $TSRRAIDfilename = $RAIDfile.Name
  $LSIlog = $true
}

if ($RAIDfile -eq "") {
  write-host
  write-host "Neither a RAIDxxxx nor lsi_xxxx.log not found.  Have you exported a log file yet?"
  exit
}

if (Test-Path "badblocklist.txt") {
  $clearlogs = Read-host -prompt "Old logs found, clear? [y/N] : "
  if ($clearlogs.ToUpper() -eq "Y") {
    Write-host "Clearing logs.."
    write-host
    try {
      Remove-Item �path "badblocklist.txt"
      Remove-Item �path "badblockinfo.txt"
      Remove-Item �path "nfi.log" 
      Remove-Item �path "affectedfiles.txt" 
    } catch {
      write-host "ERROR: Couldn't delete logs, are you running this as admin? "
      write-host 
      Break
    }
  }
}

while ($TSRRAIDfilename -eq "") {
  write-host "Enter filename of RAID controller logs from TSR, with full path if not in current folder. (i.e RAID.Slot.6-1.134283266, or lsi_0128.log)  "
  write-host "Hit [Enter] to open [$TSRRAIDfilename].  Filename: "
  $input = read-host 

  if ($input -ne "") {
    $TSRRAIDfilename = $input
  } else {
    if ($TSRRAIDfilename -eq "") {
      write-host "Nothing entered!"
      exit
    }
  }
}

$badlist = ""
if ($RAIDlog -eq $true) {
  #For iDRAC TSR RAIDLOG
  $badlist = get-content -Path $TSRRAIDfilename | select-string "BadListAdd" 
} 
if ($LSIlog -eq $true) {
  #For LSI RAID LOG Export from OMSA
  $badlist = get-content -Path $TSRRAIDfilename | select-string "BadLba" 
}
write-host "Found " $badlist.Length " entries"
$badlist | out-file -filepath badlist.txt

if ($false -eq $true) {
write-host "I am guessing that we are usign 512 byte sectors, 8 sectors per cluster.  Verify with :"
write-host ""
write-host "fsutil fsinfo ntfsinfo [drive:]"
write-host ""
write-host "Here is the info for C:"
$NTFSinfo_c = fsutil fsinfo ntfsinfo c:
$NTFSinfo_c 
write-host ""
write-host ""
write-host "Here is the info for D:"
$NTFSinfo_d = fsutil fsinfo ntfsinfo d:
$NTFSinfo_d
write-host ""
}

$sect_NTFSinfo_c = $NTFSinfo_c | Select-String("Bytes Per Sector  :               ")
$clus_NTFSinfo_c = $NTFSinfo_c | Select-String("Bytes Per Cluster :               ")
$junk,$byte_sect_c = $sect_NTFSinfo_c -split("Bytes Per Sector  :               ")
$junk,$byte_clus_c = $clus_NTFSinfo_c -split("Bytes Per Cluster :               ")

$sect_NTFSinfo_d = $NTFSinfo_d | Select-String("Bytes Per Sector  :               ")
$clus_NTFSinfo_d = $NTFSinfo_d | Select-String("Bytes Per Cluster :               ")
$junk,$byte_sect_d = $sect_NTFSinfo_d -split("Bytes Per Sector  :               ")
$junk,$byte_clus_d = $clus_NTFSinfo_d -split("Bytes Per Cluster :               ")

write-host""
write-host "Bytes per sector on C: $byte_sect_c"
write-host "Bytes per cluster on C: $byte_clus_c"
write-host "Bytes per sector on D: $byte_sect_d"
write-host "Bytes per cluster on D: $byte_clus_d"
write-host ""

pause

#$badlist = get-content -path badlist.txt

$blocklist = @()

write-host ""
write-host ""
write-host ""
write-host "LBA addresses with bad blocks:"


#LSI
#01/21/20 18:15:12: ErrLBAOffset (2) LBA(187ff1) BadLba=187ff3


#RAID
#01/16/20 11:10:13: ErrLBAOffset (17) LBA(bc8e00a) BadLba=bc8e021
if ($RAIDlog) {
  $splitstring = "pdLBA="
}
if ($LSIlog) {
  $splitstring = "BadLba="
}
foreach ($blockt in $badlist) {
  $junk,$thisblock=$blockt -split($splitstring)
  $thisblock | out-file -filepath badblocklist.txt  -append
  $blocklist += ($thisblock)
  $thisblock
}

write-host ""
write-host ""
write-host ""
write-host "Files impacted:"

$driveletter = read-host -prompt "Drive letter to analyze, i.e (C: or [D:]) ? "
if ($driveletter -eq "")  { $driveletter = "D:" }

foreach ($single_block in $blocklist) {
  $block = "0x" + $single_block
  
  # FSinfo is expecting a LCN address.
  # PERC RAID report is giving us a Hex LBA

  # We need to convert HEX LBA (Large Block Address) to LCN (Logical Cluster Number)
  # LBA = LCN * Cluster_Size
  # LCN = LBA / Cluster_Size

  $decimal_block = [Convert]::ToInt64($block,16)
 
  switch ($driveletter.ToUpper()) {
     "C:" {    $decblock = [math]::Round($decimal_block / ($byte_clus_c / $byte_sect_c))   }
     "D:" {    $decblock = [math]::Round($decimal_block / ($byte_clus_d / $byte_sect_d))   }
   }
 
  $lcn = $decblock

  $out = "LBA block (hex)= $block LBA block (decimal)= $decimal_block LCN= $lcn" 
  $out | out-file -filepath "badblockinfo.txt" -append
  write-host $out

  if ($true -eq $false) {   # don't run any of this, faster than commenting out =]
  $lcn1 = $lcn - 1
  $lcn2 = $lcn
  $lcn3 = $lcn + 1

  $fileimpacted1 = fsutil volume querycluster $driveletter $lcn1
  $fileimpacted2 = fsutil volume querycluster $driveletter $lcn2
  $fileimpacted3 = fsutil volume querycluster $driveletter $lcn3
  $fileimpacted1
  $fileimpacted2
  $fileimpacted3
  }
  
  $fileimpacted = ""
  $nfistring = .\nfi.exe $driveletter $decimal_block
  $nfistring | out-file -filepath "nfi.log" -append
  foreach ($string in $nfistring) {   # convert array of strings into one long string
    $fileimpacted = $fileimpacted + $string
  }
  
  $option = [System.StringSplitOptions]::RemoveEmptyEntries
  if ($fileimpacted -like "*is in file number*") {   #if it returns valid info
    $step1 = $fileimpacted -split "is in " | select -skip 1
    $step2 = $step1 -split "    $STANDARD_INFORMATION" | select -first 1
    $step3 = $step2.split('.',2)[1]
    $step4 = $driveletter+$step3

    $out_to_file = $step4
    $out_to_file | out-file -filepath affectedfiles.txt -append
    $out_to_file
  } else {   #didnt return good info
    "Bad address Cluster: $decblock LBA Addr: $decimal_block " | out-file -filepath affectedfiles.txt -append 
    "Bad address Cluster: $decblock LBA Addr: $decimal_block " 
  }
}

