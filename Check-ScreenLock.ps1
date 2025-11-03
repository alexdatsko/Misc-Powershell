#######################################################
# Check-ScreenLock.ps1
# Alex Datsko - .
#
#   Checks for screen lock registry settings and reports, for security audit purposes.
#
# v0.1 - 06-25-2025 - initial 

# Check GPO-based inactivity lock
$gpoLockKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
$gpoTimeout = Get-ItemProperty -Path $gpoLockKey -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue

if ($gpoTimeout) {
    "GPO-based screen lock timeout (HKLM): $([int]$gpoTimeout.ScreenSaveTimeOut / 60) minutes"
} else {
    "No GPO-based screen lock timeout set."
}

# Check user-based screensaver settings
$userKey = "HKCU:\Control Panel\Desktop"
$userSettings = Get-ItemProperty -Path $userKey -ErrorAction SilentlyContinue

if ($userSettings.ScreenSaveActive -eq "1") {
    "User screen saver is enabled. Timeout: $([int]$userSettings.ScreenSaveTimeOut / 60) minutes"
} else {
    "User screen saver is disabled or not configured."
}

# Check powercfg screen timeout for AC and DC
$acTimeout = powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE | Select-String "Current AC Power Setting Index"
$dcTimeout = powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE | Select-String "Current DC Power Setting Index"

function Convert-HexToTime {
    param($line)
    if ($line -match "0x([0-9a-fA-F]+)") {
        $hex = $matches[1]
        $seconds = [convert]::ToInt32($hex, 16)
        $minutes = [math]::Round($seconds / 60, 2)
        return "$seconds seconds ($minutes minutes)"
    } else {
        return "Unable to parse"
    }
}

"Power policy screen blanking (AC): " + (Convert-HexToTime $acTimeout)
"Power policy screen blanking (DC): " + (Convert-HexToTime $dcTimeout)
