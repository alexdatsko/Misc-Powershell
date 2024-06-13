auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
#auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
#auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:disable
# Filtering Platform (Firewall) too noisy for the gain?
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
#auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
#auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable
# Process creation not needed - Set by Sysmon 
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
wevtutil sl Security /ms:2147483648
wevtutil sl System /ms:536870912
wevtutil sl Application /ms:536870912
wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true /ms:65536500 
wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true /ms:65536500 
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:134217728
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:134217728

