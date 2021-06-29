################################# 
# Count emails in PST file      # 
# MK 11/2016                    # 
# Rev1.0                        # 
################################# 
 
#Check if Outlook is installed 
Get-ItemProperty HKLM:\SOFTWARE\Classes\Outlook.Application | Select-Object PSPath -OutVariable outlook 
if (!$outlook -match "Outlook.Application"){  
Write-Host "Outlook is not installed on this machine, Press any key to continue ..." 
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); 
} 
 
#Path to PST File 
$strPSTPath = "C:\Users\Ryan\Documents\Outlook Files\drbrown mykidsdentist.pst"
 
#Create Outlook COM Object 
$objOutlook = New-Object -com Outlook.Application 
$objNameSpace = $objOutlook.GetNamespace("MAPI") 
 
#Try to load the PST into Outlook 
try { 
$objNameSpace.AddStore($strPSTPath) 
} 
catch 
{ 
Write-Host "Could not load pst - usually this is because the file is locked by another process or is too big (try opening in outlook to see the full error) Press any key to continue ..." 
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); 
} 
 
#Try to load the Outlook Folders 
try { 
$PST = $objnamespace.stores | ? { $_.FilePath -eq $strPSTPath } 
} 
catch 
{ 
Write-Host "You have another PST added to outlook that cannot be accessed or found, please remove then re-run this script. Press any key to continue ..." 
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); 
} 
 
#Browse to PST Root 
$root = $PST.GetRootFolder() 
 
#Get top level folders 
$subfolders = $root.Folders 
 
#count items in PST Root 
$rootcount = $root.items.count 
 
#Write root count (usually zero) 
Write-Host "PST Root Folder Contains" $rootcount "Items" 
 
#Start Counter 
$counter = $rootcount 
 
#Iterate all folders (sub folders, ONLY 3 layers deep) 
foreach ($Folder in $SubFolders) 
{ 
  $count = $folder.items.count 
  Write-Host "Folder" $folder.FolderPath "Contains" $count "Items" 
  $counter += $count 
 
  foreach ($SubSubFolder in $Folder.Folders) 
  { 
    $count = $subsubfolder.items.count 
    Write-Host "Folder" $subsubfolder.FolderPath "Contains" $count "Items" 
    $counter += $count 
 
    foreach ($SubSubsubFolder in $subsubFolder.Folders) 
    { 
      $count = $subsubsubfolder.items.count 
      Write-Host "Folder" $subsubsubfolder.FolderPath "Contains" $count "Items" 
      $counter += $count 
 
    } 
 
  } 
} 
 
#Write total count 
Write-Host "Total Items" $counter -ForegroundColor Red 