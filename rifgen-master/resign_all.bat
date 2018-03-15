:: ------------------------------------------------------------------
:: Simple script to build a proper PKG using Python (by CaptainCPS-X)
:: ------------------------------------------------------------------
@echo off
cd "%~dp0"

:: Change this depending where you installed Python...
set PYTHON=c:\Python27

:: Don't change these...
set PATH=%PYTHON%;%PATH%
set PKG=.\bin\pkg_exdata.exe

:: Change these for your application / manual...
set CONTENTID=RIF000-INSTALLER_00-0000000000000000
set PKG_DIR=./exdata/
set PKG_NAME=./%CONTENTID%.pkg

:: Resign all rap files
for %%I in (./raps/*.rap) do (
	if exist "./raps/%%~nI.rif" (
		echo "File exist ./raps/%%~nI.rif"
	) else (
::		echo | ps3xploit_rifgen_edatresign_orig.exe "./raps/%%I"
		ps3xploit_rifgen_edatresign.exe "%cd%\raps\%%I"
	)
)

pause

if not exist "%cd%\exdata" mkdir "%cd%\exdata"
copy /Y "%cd%\raps\*.rif" "%cd%\exdata\"
copy /Y "%cd%\signed_act.dat" "%cd%\exdata\act.dat"
del "%cd%\raps\*rif"

%PKG% --contentid %CONTENTID% %PKG_DIR% %PKG_NAME%
ps3xploit_rifgen_edatresign %PKG_NAME% ps3
del "%PKG_NAME%"

pause