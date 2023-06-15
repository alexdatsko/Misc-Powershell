function Convert-OpenSSLPrivateKey {
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$InputPath,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$OutputPath
    )
    $File = Get-Item $InputPath -Force -ErrorAction Stop
    if ($PSBoundParameters.Debug) {$DebugPreference = "continue"}
    function Get-ASNLength ($RawData, $offset) {
        $return = "" | Select FullLength, Padding, LengthBytes, PayLoadLength
        if ($RawData[$offset + 1] -lt 128) {
            $return.lengthbytes = 1
            $return.Padding = 0
            $return.PayLoadLength = $RawData[$offset + 1]
            $return.FullLength = $return.Padding + $return.lengthbytes + $return.PayLoadLength + 1
        } else {
            $return.lengthbytes = $RawData[$offset + 1] - 128
            $return.Padding = 1
            $lengthstring = -join ($RawData[($offset + 2)..($offset + 1 + $return.lengthbytes)] | %{"{0:x2}" -f $_})
            $return.PayLoadLength = Invoke-Expression 0x$($lengthstring)
            $return.FullLength = $return.Padding + $return.lengthbytes + $return.PayLoadLength + 1
        }
        $return
    }

    function Get-NormalizedArray ($array) {
        $Powers = 1..12 | %{[Math]::Pow(2,$_)}
        if ($Powers -notcontains $array.Length) {
            $MatchPower = $Powers -lt $array.Length | select -Last 1
            $array = $array[($array.Length - $MatchPower)..($array.Length - 1)]
        }
        [array]::Reverse($array)
        [Byte[]]$array
    }
    # parse content
    $Text = [IO.File]::ReadAllText($File)
    Write-Debug "Extracting certificate information..."
    if ($Text -match "(?msx).*-{5}BEGIN\sCERTIFICATE-{5}(.+)-{5}END\sCERTIFICATE-{5}") {
        $RawData = [Convert]::FromBase64String($Matches[1])
        try {$Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$RawData)}
        catch {Write-Warning "The data is invalid."; return}
        Write-Debug "X.509 certificate is correct."
    } else {Write-Warning "Missing certificate file."; return}
    if ($Text -match "(?msx).*-{5}BEGIN\sPRIVATE\sKEY-{5}(.+)-{5}END\sPRIVATE\sKEY-{5}") {
        Write-Debug "Processing Private Key module."
        $Bytes = [Convert]::FromBase64String($matches[1])
        if ($Bytes[0] -eq 48) {Write-Debug "Starting asn.1 decoding."}
        else {Write-Warning "The data is invalid."; return}
        $offset = 0
        # main sequence
        Write-Debug "Process outer Sequence tag."
        $return = Get-ASNLength $Bytes $offset
        Write-Debug "outer Sequence length is $($return.PayloadLength) bytes."
        $offset += $return.FullLength - $return.PayloadLength
        Write-Debug "New offset is: $offset"
        # zero integer
        Write-Debug "Process zero byte"
        $return = Get-ASNLength $Bytes $offset
        Write-Debug "outer zero byte length is $($return.PayloadLength) bytes."
        $offset += $return.FullLength
        Write-Debug "New offset is: $offset"
        # algorithm identifier
        Write-Debug "Proess algorithm identifier"
        $return = Get-ASNLength $Bytes $offset
        Write-Debug "Algorithm identifier length is $($return.PayloadLength) bytes."
        $offset += $return.FullLength
        Write-Debug "New offset is: $offset"
        # octet string
        $return = Get-ASNLength $Bytes $offset
        Write-Debug "Private key octet string length is $($return.PayloadLength) bytes."
        $offset += $return.FullLength - $return.PayLoadLength
        Write-Debug "New offset is: $offset"
    } elseif ($Text -match "(?msx).*-{5}BEGIN\sRSA\sPRIVATE\sKEY-{5}(.+)-{5}END\sRSA\sPRIVATE\sKEY-{5}") {
        Write-Debug "Processing RSA KEY module."
        $Bytes = [Convert]::FromBase64String($matches[1])
        if ($Bytes[0] -eq 48) {Write-Debug "Starting asn.1 decoding"}
        else {Write-Warning "The data is invalid"; return}
        $offset = 0
        Write-Debug "New offset is: $offset"
    }  else {Write-Warning "The data is invalid"; return}
    # private key sequence
    Write-Debug "Process private key sequence."
    $return = Get-ASNLength $Bytes $offset
    Write-Debug "Private key length (including inner ASN.1 tags) is $($return.PayloadLength) bytes."
    $offset += $return.FullLength - $return.PayLoadLength
    Write-Debug "New offset is: $offset"
    # zero integer
    Write-Debug "Process zero byte"
    $return = Get-ASNLength $Bytes $offset
    Write-Debug "Zero byte length is $($return.PayloadLength) bytes."
    $offset += $return.FullLength
    Write-Debug "New offset is: $offset"
    # modulus
    Write-Debug "Processing private key modulus."
    $return = Get-ASNLength $Bytes $offset
    Write-Debug "Private key modulus length is $($return.PayloadLength) bytes."
    $modulus = $Bytes[($offset + $return.FullLength - $return.PayLoadLength)..($offset + $return.FullLength - 1)]
    $modulus = Get-NormalizedArray $modulus
    $offset += $return.FullLength
    Write-Debug "New offset is: $offset"
    # public exponent
    Write-Debug "Process private key public exponent."
    $return = Get-ASNLength $Bytes $offset
    Write-Debug "Private key public exponent length is $($return.PayloadLength) bytes."
    Write-Debug "Private key public exponent padding is $(4 - $return.PayLoadLength) byte(s)."
    $padding = New-Object byte[] -ArgumentList (4 - $return.PayLoadLength)
    [Byte[]]$PublicExponent = $padding + $Bytes[($offset + $return.FullLength - $return.PayLoadLength)..($offset + $return.FullLength - 1)]
    $offset += $return.FullLength
    Write-Debug "New offset is: $offset"
    # private exponent
    Write-Debug "Process private key private exponent."
    $return = Get-ASNLength $Bytes $offset
    Write-Debug "Private key private exponent length is $($return.PayloadLength) bytes."
    $PrivateExponent = $Bytes[($offset + $return.FullLength - $return.PayLoadLength)..($offset + $return.FullLength - 1)]
    $PrivateExponent = Get-NormalizedArray $PrivateExponent
    $offset += $return.FullLength
    Write-Debug "New offset is: $offset"
    # prime1
    Write-Debug "Process Prime1."
    $return = Get-ASNLength $Bytes $offset
    Write-Debug "Prime1 length is $($return.PayloadLength) bytes."
    $Prime1 = $Bytes[($offset + $return.FullLength - $return.PayLoadLength)..($offset + $return.FullLength - 1)]
    $Prime1 = Get-NormalizedArray $Prime1
    $offset += $return.FullLength
    Write-Debug "New offset is: $offset"
    # prime2
    Write-Debug "Process Prime2."
    $return = Get-ASNLength $Bytes $offset
    Write-Debug "Prime2 length is $($return.PayloadLength) bytes."
    $Prime2 = $Bytes[($offset + $return.FullLength - $return.PayLoadLength)..($offset + $return.FullLength - 1)]
    $Prime2 = Get-NormalizedArray $Prime2
    $offset += $return.FullLength
    Write-Debug "New offset is: $offset"
    # exponent1
    Write-Debug "Process Exponent1."
    $return = Get-ASNLength $Bytes $offset
    Write-Debug "Exponent1 length is $($return.PayloadLength) bytes."
    $Exponent1 = $Bytes[($offset + $return.FullLength - $return.PayLoadLength)..($offset + $return.FullLength - 1)]
    $Exponent1 = Get-NormalizedArray $Exponent1
    $offset += $return.FullLength
    Write-Debug "New offset is: $offset"
    # exponent2
    Write-Debug "Process Exponent2."
    $return = Get-ASNLength $Bytes $offset
    Write-Debug "Exponent2 length is $($return.PayloadLength) bytes."
    $Exponent2 = $Bytes[($offset + $return.FullLength - $return.PayLoadLength)..($offset + $return.FullLength - 1)]
    $Exponent2 = Get-NormalizedArray $Exponent2
    $offset += $return.FullLength
    Write-Debug "New offset is: $offset"
    # coefficient
    Write-Debug "Process Coefficient."
    $return = Get-ASNLength $Bytes $offset
    Write-Debug "Coeicient length is $($return.PayloadLength) bytes."
    $Coefficient = $Bytes[($offset + $return.FullLength - $return.PayLoadLength)..($offset + $return.FullLength - 1)]
    $Coefficient = Get-NormalizedArray $Coefficient

    # creating Private Key BLOB structure
    Write-Debug "Calculating key length."
    $bitLen = "{0:X4}" -f $($modulus.Length * 8)
    Write-Debug "Key length is $($modulus.Length * 8) bits."
    [byte[]]$bitLen1 = iex 0x$([int]$bitLen.Substring(0,2))
    [byte[]]$bitLen2 = iex 0x$([int]$bitLen.Substring(2,2))
    [Byte[]]$PrivateKey = 0x07,0x02,0x00,0x00,0x00,0x24,0x00,0x00,0x52,0x53,0x41,0x32,0x00
    [Byte[]]$PrivateKey = $PrivateKey + $bitLen1 + $bitLen2 + $PublicExponent + ,0x00 + `
    $modulus + $Prime1 + $Prime2 + $Exponent1 + $Exponent2 + $Coefficient + $PrivateExponent
    $Base = [Convert]::ToBase64String($PrivateKey)
    $TempFile = [IO.Path]::GetTempFileName()
    $CertFileName = $TempFile + ".cer"
    $KeyFileName = $TempFile + ".key"
    [IO.File]::WriteAllBytes($CertFileName, $Cert.RawData)
    Set-Content -Path $KeyFileName -Value $Base -Encoding Ascii
    certutil -f -MergePFX $CertFileName $OutputPath
    $TempFile, $CertFileName, $KeyFileName | %{del $_ -Force}
}