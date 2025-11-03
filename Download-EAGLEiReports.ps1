[cmdletbinding()]  # For verbose, debug etc
param (
  [switch] $Automated = $false,    # this allows us to run without supervision and apply all changes necessary
  [switch] $NoInstall = $false     # this allows us to run without installing the SSO Agent (Auth Gateway), just download the files and set up GPO for SSO Client, and Wgauth user
)



$info = '''
###############################################################
# Filename:    Download-EAGLEiReports.ps1
# Author:      Alex Datsko - .
# Description: This will download the latest Qualys CSV reports from Black Talons EAGLEi
#              
#
# Version: v0.1 - 10/3/2024 - orig
#
#
'''

# Download location for SSO Client (to be installed on workstations)
$EAGLEi_Login_URL = "https://blacktalonsecurity.force.com/EAGLEi/s/login/?ec=302&startURL=%2FEAGLEi%2Fs%2F"

$AgentString = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  # Hack for SSL error downloading files.

$ADDomain = (Get-ADDomain).DNSRoot

$date = Get-Date -Format "MM-dd-yyyy"
$time = Get-Date -Format "hh:mm:ss"
$datetime = "$date $time"
$tmp = $env:temp

Start-Transcript


################################################################### FUNCTIONS

IWR $EAGLEi_Login_URL

################################################################### MAIN

Stop-Transcript
