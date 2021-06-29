@echo off
for /f "tokens=1-4 delims=/ " %%i in ("%date%") do (
     set dow=%%i
     set month=%%j
     set day=%%k
     set year=%%l
)
echo . >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
echo -----------------[START]---------------------------------------------- >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
echo Running... %year%-%month%-%day% %time%
echo Running... %year%-%month%-%day% %time% >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log

:: Processes
echo [PROCESSES]----- Checking local machine for running Processes >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
tasklist >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log

:: Perf mon
echo [TYPEPERF]----- Checking local machine for available mem, current TCP/UDP v4 and v6 availability >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
typeperf "\Memory\Available MBytes" -sc 3 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
typeperf "\TCPv4\*" -sc 1 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
typeperf "\UDPv4\*" -sc 1 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
typeperf "\TCPv6\*" -sc 1 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
typeperf "\UDPv6\*" -sc 1 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log

:: DNS
echo . >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
Echo [DNS]----- Checking that DNS is working, should show ping to 192.168.1.61.. >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
ping Server.ssa.local >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log

:: DOMAIN
echo . >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
Echo [DOMAIN]----- Checking that a query of the current DC is working, should show 0 0x0 NERR_Success.. >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
nltest /sc_query:ssa.local >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log

:: ICMP pings
echo . >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
Echo [PING]----- Checking that Truxel router is up.. >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
ping 192.168.1.1 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
Echo [PING]----- Checking that Server.ssa.local is up.. >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
ping 192.168.1.61 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log

:: PSPING port pings
echo . >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
Echo [PORT88]----- Checking that Server.ssa.local Kerberos port 88 is available.. >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
c:\sysinternals\psping64 server.ssa.local:88 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
Echo [PORT135]----- Checking that Server.ssa.local RPC port 135 is available.. >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
c:\sysinternals\psping64 server.ssa.local:135 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
Echo [PORT389]----- Checking that Server.ssa.local LDAP port 389 is available.. >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
c:\sysinternals\psping64 server.ssa.local:389 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
Echo [PORT389]----- Checking that Server.ssa.local SMB port 445 is available.. >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
c:\sysinternals\psping64 server.ssa.local:445 >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log

:: Netstat local and remote (if possible)
echo . >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
Echo [NETSTAT]----- Checking local netstat.. >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
netstat -anob >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
echo . >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
echo [NETSTAT]----- Checking Server.ssa.local netstat:  >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
psexec64 \\server.ssa.local -s "c:\windows\system32\netstat.exe" "-anob" >> \\termservera\c$\sysinternals\reports\psping-%year%-%month%-%day%.log
echo . >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
echo -----------------[DONE]---------------------------------------------- >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log
echo . >> c:\sysinternals\reports\psping-%year%-%month%-%day%.log

