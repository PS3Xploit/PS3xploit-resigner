:: ------------------------------------------------------------------
:: Simple script to build a proper PKG using Python (by CaptainCPS-X)
:: Adapted to PS3xploit-ReSigner (by Caio99BR)
:: ------------------------------------------------------------------
:: Disable Debug output
@echo off

:: Save Current Working Dir
set CURRENT_DIR="%cd%"

:: Go to current dir
cd "%CURRENT_DIR%"

:: Main Tools
set TOOLS_PKG_EXDATA="%cd%\source\tools\ps3py_exe\pkg_exdata.exe"
set TOOLS_RESIGNER="%cd%\source\pre-compiled\windows\ps3xploit_rifgen_edatresign.exe"

:: Output variables
set OUTPUT_PKGS_DIR=output\pkgs
set OUPUT_RIF_PKG_FILES=output\temp
set OUPUT_RIF_PKG_NAME=output\rif_pkg\PKG_RIF-INSTALLER.pkg

:: Input Dirs
set INPUT_RAPS_DIR=input\raps
set INPUT_PKGS_DIR=input\pkgs

:: Input Files
set INPUT_ACT_DAT=input\act_dat\act.dat
set INPUT_IDPS_HEX=input\idps_hex\idps.hex

:: RIF Package ContentID
set RIF_PKG_CONTENTID=RIF000-INSTALLER_00-0000000000000000

:: Cleanup before everything
del %CURRENT_DIR%\%OUTPUT_PKGS_DIR%\*.pkg
del %CURRENT_DIR%\%OUPUT_RIF_PKG_NAME%_signed.pkg

:: Copy RAP files
if not exist %CURRENT_DIR%\%INPUT_RAPS_DIR%\*.rap (
	echo. 
	echo ps3xploit_resign: No '.rap' files found on '.\%INPUT_RAPS_DIR%\'
	echo. 
	if exist %CURRENT_DIR%\%INPUT_PKGS_DIR%\*.pkg (
		GOTO RESIGN_PKG_ONLY
	) else (
		echo. 
		echo ps3xploit_resign: No '.pkg' files found on '.\%INPUT_PKGS_DIR%\'
		echo. 
		pause
		exit /b
	)
)
copy /Y %CURRENT_DIR%\%INPUT_RAPS_DIR%\*.rap %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\

:: Copy act.dat files
if not exist %CURRENT_DIR%\%INPUT_ACT_DAT% (
	echo. 
	echo ps3xploit_resign: '.\%INPUT_ACT_DAT%' not found, exiting...
	echo. 
	pause
	exit /b
)
copy /Y %CURRENT_DIR%\%INPUT_ACT_DAT% %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\

:: Copy idps.hex files
if not exist %CURRENT_DIR%\%INPUT_IDPS_HEX% (
	echo. 
	echo ps3xploit_resign: '.\%INPUT_IDPS_HEX%' not found, exiting...
	echo. 
	pause
	exit /b
)
copy /Y %CURRENT_DIR%\%INPUT_IDPS_HEX% %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\

:: Resign all RAP files to RIF files
del %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\*.rif
for %%I in (%CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\*.rap) do (
	cd %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%
	%TOOLS_RESIGNER% %%I
	cd %CURRENT_DIR%\
)

:: Delete unneed files on pkg
del %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\*.rap
del %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\act.dat
del %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\idps.hex

:: Move 'signed_act.dat' to 'act.dat'
move %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\signed_act.dat %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\act.dat

:: Build PKG RIF
%TOOLS_PKG_EXDATA% --contentid %RIF_PKG_CONTENTID% %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\ %CURRENT_DIR%\%OUPUT_RIF_PKG_NAME%

:: Resign PKG RIF
if not exist %CURRENT_DIR%\%OUPUT_RIF_PKG_NAME% (
	echo. 
	echo ps3xploit_resign: '.\%OUPUT_RIF_PKG_NAME%' not found, exiting...
	echo. 
	pause
	exit /b
)
%TOOLS_RESIGNER% %CURRENT_DIR%\%OUPUT_RIF_PKG_NAME%

:: Cleanup
del %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\*.rif
del %CURRENT_DIR%\%OUPUT_RIF_PKG_FILES%\act.dat
del %CURRENT_DIR%\%OUPUT_RIF_PKG_NAME%

:: Resign PKG files
:RESIGN_PKG_ONLY
for %%I in (%CURRENT_DIR%\%INPUT_PKGS_DIR%\*.pkg) do (
	%TOOLS_RESIGNER% %%I
	move %%I_signed.pkg %CURRENT_DIR%\%OUTPUT_PKGS_DIR%\
)

:: Output header
echo. 
echo ps3xploit_resign: Output files:

:: See RIF PKG
if exist %CURRENT_DIR%\%OUPUT_RIF_PKG_NAME%_signed.pkg (
	echo. 
	echo.  RIF PKG:
	echo.    .\%OUPUT_RIF_PKG_NAME%_signed.pkg
	echo. 
)

:: See PKGS signed
if exist %CURRENT_DIR%\%OUTPUT_PKGS_DIR%\*.pkg (
	echo. 
	echo.  PKGS:
	for %%I in (%OUTPUT_PKGS_DIR%\*.pkg) do (
		echo.    .\%%I
	)
	echo. 
)

:: Let user see everything
pause
