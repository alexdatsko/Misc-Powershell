# Force Install Qualys - 10/27/22 Alex Datsko MME Consulting Inc

$app="\\server\sysvol\smo.local\Software\Mohr Orthodontics(2592).msi"
$CredUser = "smo.local\Administrator"
$namesToRemove = "CLINICPC","CONSULTPC","DRLT","EAST-CHECKOUTPC","EAST-CONSULT2PC ","EAST-LABPC","EAST-RECEPT2PC","FINANCEPC","HYPERV","IIS","RECEPTION1PC","SERVER","SQL","TERMSERVER"

[System.Collections.ArrayList]$computerNames = (Get-ADComputer -filter *).Name
Foreach ($name in $namesToRemove) {
    while ($computerNames -contains $name) {
        $computerNames.Remove($name)
    }
}
$computerNames

$creds=Get-Credential -UserName $CredUser -Message 'Enter $CredUser password: '
Foreach ($computer in $computerNames) { 
  Invoke-Command -ComputerName $computer -Credential $creds -ScriptBlock {
    New-Item -ItemType Directory "c:\Temp" -ErrorAction SilentlyContinue
    msiexec.exe /i $app /qn  | Tee "c:\temp\QualysInstall.log" -Append 
    Copy-Item "c:\temp\QualysInstall.log" "\\server\data\logs\QualysInstall" -Force -ErrorAction SilentlyContinue
  }
}
