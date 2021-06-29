$driveLetter = "X:"

$driveEject = New-Object -comObject Shell.Application
$driveEject.Namespace(17).ParseName($driveLetter).InvokeVerb("Eject")

