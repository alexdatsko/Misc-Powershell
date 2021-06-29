@echo off
echo Starting TSR job:
racadm techsupreport collect -t sysinfo,ttylog
racadm jobqueue view
echo Waiting for TSR to complete..

:begin
echo Waiting for TSR to complete..
racadm jobqueue view | findstr "Job completed" 
if %ERRORLEVEL%==1 (
  echo TSR Completed.
  goto end
)
ping 1.2.4.5 -c 3 >nul
del nul /s /f /q 
goto begin

:end
racadm jobqueue view 
racadm techsupreport export -f TSR.zip
explorer .
echo Complete!