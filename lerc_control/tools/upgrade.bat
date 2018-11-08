@echo off

set company=%1
set reconnectdelay=%2
set chunksize=%3
set serverurls=%4
set host=%computername%

:: company=0 reconnectdelay=15 chunksize=2048 serverurls="https://your-server.you/"

:CHECK
SC QUERY lerc > NUL
IF ERRORLEVEL 1060 GOTO MISSING
ECHO EXISTS
:: ~5 second delay
PING localhost -n 5 >NUL
echo company=%company% reconnectdelay=%reconnectdelay% chunksize=%chunksize% serverurls=%serverurls%
GOTO CHECK

:MISSING
ECHO SERVICE MISSING
:: ~5 second delay
PING localhost -n 5 >NUL
msiexec /quiet /qn /l lerc_install.log /i lercSetup.msi company=%company% reconnectdelay=%reconnectdelay% chunksize=%chunksize% serverurls=%serverurls%

