#USE DolphinPlatform;
#ALTER DATABASE DolphinPlatform SET RECOVERY SIMPLE;
#DBCC SHRINKFILE (N'DolphinPlatform.ldf', EMPTYFILE);
#ALTER DATABASE DolphinPlatform SET RECOVERY FULL;


[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlEnum") | out-null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | out-null
$s = New-Object ("Microsoft.SqlServer.Management.SMO.Server") 'SERVER'

#Current Transaction Log Size in MB
$s.databases["DolphinPlatform"].Logfiles[0].Size/1KB
$s.databases["DolphinPlatform"].LogFiles[0].Shrink(2, [Microsoft.SqlServer.Management.Smo.ShrinkMethod]::Default)
$s.databases["DolphinPlatform"].Logfiles.refresh($true)
$s.databases["DolphinPlatform"].Logfiles[0].Size/1KB
