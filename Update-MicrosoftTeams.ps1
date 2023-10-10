[cmdletbinding()]  # For verbose, debug etc

# Update-MicrosoftTeams.ps1
#   This script should download and install the newest version of Microsft Teams for Windows.
#   It programmatically depends on Whatpulse.org being up to date with the latest version numbers: https://whatpulse.org/app/microsoft-teams
#   It also assumes Microsoft will continue updating the links in the exact format: "https://statics.teams.cdn.office.net/production-windows-x64/VERSIONNUMBER/Teams_windows_x64.exe"
# 10-10-2023 Alex Datsko MME Consulting Inc

$VersionURL = "https://whatpulse.org/app/microsoft-teams"
$DownloadURL = "https://statics.teams.cdn.office.net/production-windows-x64/REPLACEME/Teams_windows_x64.exe"
$DownloadPath = "$($env:temp)"


Function Get-TeamsVersion {
  if (!($env:hostname -like "*TERMSERVER*")) {  # Can't use this to check for termservers..
    Write-Host "[.] Checking for Teams version using running process.." -ForegroundColor Yellow
    $teamsProcess = (Get-Process -Name Teams -ErrorAction SilentlyContinue) | Select -First 1  # This will not work for Termservers or computers where multiple users are logged in to Teams at the same time..
    if ($teamsProcess) {
        $teamsPath = $teamsProcess.Path
        $teamsVersion = (Get-Command $teamsPath).FileVersionInfo.ProductVersion
        Write-Host "[+] Teams is running from: $teamsPath" -ForegroundColor Green
        Write-Host "[+] Teams version: $teamsVersion" -ForegroundColor Green
        return [version]$teamsVersion
    } else {
        Write-Host "[-] Teams is not currently running."  -ForegroundColor Yellow
    }
  }
  #$teamsInfo = (Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE (Name LIKE 'Microsoft Teams%')" -ErrorAction SilentlyContinue) | Select -First 1   # This didn't work

  Write-Host "[.] Checking for Teams version using the registry.." -ForegroundColor Yellow
  $teamsPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams\Install" -Name "InstallDir" -ErrorAction SilentlyContinue  
  if ($teamsPath) {
      $teamsExePath = Join-Path $teamsPath "Teams.exe"
      $teamsVersion = (Get-ChildItem $teamsExePath).VersionInfo.FileVersion
      Write-Host "[+] Teams is installed at: $teamsExePath"  -ForegroundColor Green
      Write-Host "[+] Teams version: $teamsVersion" -ForegroundColor Green
      return [version]$teamsVersion      
  } else {
    Write-Host "[-] Teams is not installed machine-wide, or the registry key was not found."  -ForegroundColor Yellow
  }
  
  Write-Host "[.] Checking for Teams version using user profile LocalAppData path.." -ForegroundColor Yellow
  $teamsUserPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams', 'Current', 'Teams.exe')
  #$teamsUserUpdatePath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams', 'Update.exe')
  if (Test-Path $teamsUserPath) {
    $teamsVersion = (Get-ChildItem $teamsUserPath).VersionInfo.FileVersion
    Write-Host "[+] Teams is installed at: $teamsUserPath"  -ForegroundColor Green
    Write-Host "[+] Teams version: $teamsVersion" -ForegroundColor Green
    return [version]$teamsVersion  
  } else {
    Write-Host "[-] Teams is not installed machine-wide, or the executable was not found at $teamsUserPath .."  -ForegroundColor Red
  }
  


  return $null  # If not found, return null.
}

<#
https://whatpulse.org/app/microsoft-teams as of 10/10/2023: 

[..]
<div class="tab-content">
<div id="versions" class="tab-pane fade active in">
<table id="table_app_versions" class="table table-striped table-bordered" cellspacing="0" width="100%">
<thead>
<tr>
<th>Version</th>
<th width="75" class="text-center" nowrap="nowrap">OS</th>
<th width="175" class="text-center" nowrap="nowrap">Last Seen</th>
</tr>
</thead>
<tbody>
<tr>
<td>1.00.627655</td>
<td class="text-center"><span class="fab fa-apple fa-lg">&nbsp;</span></a></td>
<td class="text-center">2023-10-06</td>
</tr>
<tr>

[..]

<tr>
<td>1.00.624654</td>
<td class="text-center"><span class="fab fa-apple fa-lg">&nbsp;</span></a></td>
<td class="text-center">2023-09-15</td>
</tr>
<tr>
<td>1.6.00.24078</td>
<td class="text-center"><span class="fab fa-windows fa-lg">&nbsp;</span></a></td>
<td class="text-center">2023-09-14</td>
</tr>
<tr>
<td>1.00.624266</td>

#>


Function Get-TeamsNewestVersion {

  $response = Invoke-WebRequest -Uri $VersionURL
  $html = $response.ParsedHtml
  $tableRows = $html.getElementById('table_app_versions').getElementsByTagName('tr')

  foreach ($row in $tableRows) {
    $cells = $row.getElementsByTagName('td')
    if ($cells.length -gt 0) {
        $version = $cells[0].innerText

        # Get the span element within the second cell
        $span = $cells[1].getElementsByTagName('span')[0]

        # Check if the span element has the class "fa-windows"
        if ($span -and $span.className -match 'fa-windows') {
          Write-Verbose "$version - Contains fa-windows !"
          return $version
        }
    }
  }
  Write-Verbose "[!] Windows version not found, or can't read from $VersionURL."
  return $null
}

$CurrentVersion = Get-TeamsVersion
$TeamsNewestVersion = Get-TeamsNewestVersion

if (!($null -eq $TeamsNewestVersion)) {
  # Check if its been patched or not?
  if ([version]$TeamsNewestVersion -eq [version]$CurrentVersion) {
    Write-Host "[!] Looks like Teams is already up to date: Teams Newest Version $($TeamsNewestVersion) == Current installed version $($CurrentVersion)" -ForegroundColor Yellow
    exit
  }
  if ([version]$TeamsNewestVersion -lt [version]$CurrentVersion) {
    Write-Host "[!] Somehow you have a newer version than found on $VersionURL ?? Teams Newest Version shows as $($TeamsNewestVersion) < Current installed version $($CurrentVersion)" -ForegroundColor Yellow
    exit
  }

  if ([version]$TeamsNewestVersion -gt [version]$CurrentVersion) {
    Write-Host "[+] An update for Teams was found. New Version: $($TeamsNewestVersion) > Current Version: $($CurrentVersion)" -ForegroundColor Green
  }
  
  # Download and install newest version
  Write-Host "[.] Newest Teams version found: $($TeamsNewestVersion). Downloading to $DownloadPath.." -ForegroundColor Green
  $DownloadURL = $DownloadURL.replace("REPLACEME",$TeamsNewestVersion) # create complete URL for newest windows version
  Invoke-WebRequest -Uri $DownloadURL -OutFile "$($DownloadPath)\Teams_windows_x64.exe"  # download
  if (Test-Path "$DownloadPath\Teams_windows_x64.exe") {
    Write-Host "[+] Newest Teams version downloaded.  Running installer: $($DownloadPath)\Teams_windows_x64.exe with -s flag for silent install.." -ForegroundColor Green
    Start-Process -FilePath "$($DownloadPath)\Teams_windows_x64.exe" -ArgumentList "-s" -Wait  # execute and wait for completion
  } else {
    $Result = (Invoke-WebRequest -Uri $DownloadURL).ParsedHTML
    Write-Host "`n[!] Error downloading Teams Windows installer from $($DownloadURL). " -ForegroundColor Red  
    Write-Verbose "Returned: $Result"
  }

  # Another possibility for updating??
  #$teamsUserUpdatePath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams', 'Update.exe')
  #Start-Process -FilePath "$($TeamsUserUpdatePath)" -ArgumentList "--allusers" -Wait  # Not sure what the correct arguments will be here..

  # Check versions after update runs
  $NewVersion = Get-TeamsVersion
  if ([version]$NewVersion -gt [version]$CurrentVersion) {
    Write-Host "[+] Looks like Teams was updated. Currentversion $($NewVersion) > $($CurrentVersion)" -ForegroundColor Green
  } else {
    Write-Host "[-] Looks like Teams was NOT updated. Currentversion $($NewVersion) <= $($CurrentVersion)" -ForegroundColor Red
  }

} else {
  $Result = (Invoke-WebRequest -Uri $VersionURL).ParsedHTML
  Write-Host "`n[!] Error getting newest Teams Windows version from $($VersionURL). " -ForegroundColor Red
  Write-Verbose "Returned: $Result"
}

