#Requires -Version 3.0
#Requires -Modules ActiveDirectory, GroupPolicy

$computer = "TRAINING2"

##if ((([xml](Get-GPOReport -Name "Default Domain Policy" -ReportType Xml)).GPO.Computer.ExtensionData.Extension.Account |
            #Where-Object name -eq LockoutBadCount).SettingNumber) {

    $Password = ConvertTo-SecureString 'NotMyPassword' -AsPlainText -Force

    Get-ADUser -Filter * -SearchBase "OU=Sacramento Users,OU=MME Consulting,DC=assessment,DC=local" -Properties SamAccountName, UserPrincipalName, LockedOut |
        ForEach-Object {

            Do {

                Invoke-Command -ComputerName $computer {Get-Process
                } -Credential (New-Object System.Management.Automation.PSCredential ($($_.UserPrincipalName), $Password)) -ErrorAction SilentlyContinue

            }
            Until ((Get-ADUser -Identity $_.SamAccountName -Properties LockedOut).LockedOut)

            Write-Output "$($_.SamAccountName) has been locked out"
        }
##}
