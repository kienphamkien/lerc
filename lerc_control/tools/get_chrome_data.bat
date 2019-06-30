
@echo off

:: Attempt to get current user name
for /f "TOKENS=1,2,*" %%a in ('tasklist /FI "IMAGENAME eq explorer.exe" /FO LIST /V') do if /i "%%a %%b"=="User Name:" set _currdomain_user=%%c
for /f "TOKENS=1,2 DELIMS=\" %%a in ("%_currdomain_user%") do set _currdomain=%%a & set _curruser=%%b

::Get Chrome preferences
copy "C:\Users\%_curruser%\AppData\Local\Google\Chrome\User Data\Default\Preferences" "Chrome_Preferences" /Y

copy "C:\Users\%_curruser%\AppData\Local\Google\Chrome\User Data\Default\History" "Chrome_History" /Y

::copy "C:\Users\%_curruser%\AppData\Roaming\Mozilla\Firefox\Profiles" "Firefox_History" /Y
:: ^ Have to write some more batch to figure out whatever random folder name *.default-release
::   is in this Profiles dir.. then the places.sqlite file is inside of that folder