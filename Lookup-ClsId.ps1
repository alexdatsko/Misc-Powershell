function Lookup-Clsid {
	Param([string]$clsid)
	$CLSID_KEY = 'HKLM:\SOFTWARE\Classes\CLSID'
	  If ( Test-Path $CLSID_KEY\$clsid) {
  	  $name = (Get-ItemProperty -Path $CLSID_KEY\$clsid).'(default)'
      if (Get-ItemProperty -Path $CLSID_KEY\$clsid\InProcServer32 -ErrorAction SilentlyContinue) {
        $dll = (Get-ItemProperty -Path $CLSID_KEY\$clsid\InProcServer32).'(default)'
      }
	}
	$name, $dll
}

Lookup-Clsid "{D63B10C5-BB46-4990-A94F-E40B9D520160}"