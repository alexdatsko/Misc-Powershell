@echo off
rem
rem   Maximize for best viewing
rem   This command file provides examples of proper command file syntax
rem
rem   Command Files run by PowerChute Business Edition must be placed in this directory.
rem
rem   Use the full path name of executable programs and external command files.
rem
rem   The @START command must be used to run executable programs (see example below).
rem   For the @START command, path names that include spaces must be enclosed in quotes; 
rem   arguments for the executable must be outside the quotes.  A double quote must
rem   precede the quoted path name.  For example, to execute a command file in 
rem   c:\Program Files\APC\PowerChute Business Edition\agent\cmdfiles called myShut.exe,
rem   the following line should be entered in the command file:
rem
rem   @START "" "c:\Program Files\APC\PowerChute Business Edition\agent\cmdfiles\myShut.exe"
rem
@echo on

powershell.exe -executionpolicy bypass -file "C:\Program Files (x86)\APC\PowerChute Business Edition\agent\cmdfiles\shutdown-hvh.ps1"