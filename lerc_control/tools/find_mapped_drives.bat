@echo off

set outputfile=%1

echo ***** mappeddrives *****>> %outputfile%
for /F "tokens=1-2 delims=\" %%a in ('reg query HKU') do (
	for /F %%a in ('reg query "HKU\%%b\Network" 2^> nul') do (
	echo %%a 
	reg query %%a | findstr RemotePath) >> %outputfile% 2>&1
)