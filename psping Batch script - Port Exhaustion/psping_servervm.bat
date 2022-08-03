@echo off
for /f "tokens=1-4 delims=/ " %%i in ("%date%") do (
     set dow=%%i
     set month=%%j
     set day=%%k
     set year=%%l
)

mkdir "D:\Backups (Do Not Delete)" > nul
mkdir "D:\Backups (Do Not Delete)\Reports" > nul
mkdir "D:\Backups (Do Not Delete)\Reports\psping" > nul

echo . >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
echo -----------------[START]---------------------------------------------- >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
echo Running... %year%-%month%-%day% %time%
echo Running... %year%-%month%-%day% %time% >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"

:: Processes
echo [PROCESSES]----- Checking local machine for running Processes >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
tasklist >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"

:: Perf mon
echo [TYPEPERF]----- Checking local machine for available mem, current TCP/UDP v4 and v6 availability >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
typeperf "\Memory\Available MBytes" -sc 3 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
typeperf "\TCPv4\*" -sc 1 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
typeperf "\UDPv4\*" -sc 1 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
typeperf "\TCPv6\*" -sc 1 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
typeperf "\UDPv6\*" -sc 1 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"

:: DNS
echo . >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
Echo [DNS]----- Checking that DNS is working, should show ping to 192.168.1.61.. >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
ping sbserver >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"

:: DOMAIN
echo . >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
Echo [DOMAIN]----- Checking that a query of the current DC is working, should show 0 0x0 NERR_Success.. >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
nltest /sc_query:springbrook.local >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"

:: ICMP pings
echo . >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
Echo [PING]----- Checking that Router is up.. >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
ping 192.168.1.1 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
Echo [PING]----- Checking that Server is up.. >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
ping 192.168.1.189 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"

:: PSPING port pings
echo . >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
Echo [PORT88]----- Checking that server Kerberos port 88 is available.. >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
"d:\Backups (Do Not Delete)\psping64 sbserver:88 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
Echo [PORT135]----- Checking that server RPC port 135 is available.. >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
"d:\Backups (Do Not Delete)\psping64 sbserver:135 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
Echo [PORT389]----- Checking that server LDAP port 389 is available.. >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
"d:\Backups (Do Not Delete)\psping64 sbserver:389 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
Echo [PORT389]----- Checking that server SMB port 445 is available.. >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
"d:\Backups (Do Not Delete)\psping64 sbserver:445 >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"

:: Netstat local and remote (if possible)
echo . >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
Echo [NETSTAT]----- Checking local netstat.. >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
netstat -anob >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
echo . >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
echo [NETSTAT]----- Checking server netstat:  >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
psexec64 \\sbserver -s "c:\windows\system32\netstat.exe" "-anob" >> "\\dxserver\d$\Backups (do not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
echo . >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
echo -----------------[DONE]---------------------------------------------- >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"
echo . >> "d:\Backups (Do Not Delete)\reports\psping\psping-%year%-%month%-%day%.log"

