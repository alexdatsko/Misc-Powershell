$date = Get-Date -format "yyyy-MM-dd"
$filename = "c:\temp\$date-ADSuccessLogons.csv"
Write-Host "Writing to $filename .. "
"computer,subjectusername,tarusername,logontype,ip" | out-file $filename 

#Get events in security log with id 4624
$items = Get-WinEvent -FilterHashtable @{logname="Security"; id=4624;}
#Get first item as xml
$xmlitems = [xml]$items.ToXml()

foreach ($xmlitem in $xmlitems) { 
  #Get EventID
  $eventid = $xmlitem.Event.System.EventID
  #Get logging computer
  $computer = $xmlitem.Event.System.Computer
  #Get computer
  $subjectusername = $xmlitem.Event.EventData.Data | where-object {$_.Name -eq "SubjectUserName"}
  #Get account
  $tarusername = $xmlitem.Event.EventData.Data | where-object {$_.Name -eq "TargetUserName"}
  #Get logon type
  $logontype = $xmlitem.Event.EventData.Data | where-object {$_.Name -eq "LogonType"}
  #Get ip address
  $ip = $xmlitem.Event.EventData.Data | where-object {$_.Name -eq "IpAddress"}
  #Get all data
  #$xmlitem.Event.EventData.Data 
  "$computer,$subjectusername,$tarusername,$logontype,$ip" | out-file $filename -append
}
