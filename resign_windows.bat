:: ------------------------------------------------------------------
:: Simple script to build a proper PKG using Python (by CaptainCPS-X)
:: Adapted to PS3xploit-ReSigner (by Caio99BR)
:: ------------------------------------------------------------------
:: Disable Debug output
@echo off

:: Save Current Working Dir
set CURRENT_DIR=%cd%

:: Go to current dir
cd "%CURRENT_DIR%"

:: Main Tools
set TOOLS_PKG_EXDATA=source\tools\ps3py_exe\pkg_exdata.exe
set TOOLS_RESIGNER=source\pre-compiled\windows\ps3xploit_rifgen_edatresign.exe

:: Output Dirs
set OUTPUT_PKGS_DIR=output\pkgs
set OUTPUT_TEMP_DIR=output\temp

:: Input Dirs
set INPUT_PKGS_DIR=input\pkgs
set INPUT_RAPS_DIR=input\raps

:: Input Files
set INPUT_ACT_DAT=input\act_dat\act.dat
set INPUT_IDPS_HEX=input\idps_hex\idps.hex

:: RIF Package ContentID and Name
set RIF_PKG_CONTENTID=RIF000-INSTALLER_00-0000000000000000
set RIF_PKG_NAME=PKG_RIF-INSTALLER.pkg

:: Cleanup before everything
if exist "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\*.pkg" (
	echo.
	echo ps3xploit_resign: You have *.pkg files on output folder, keep in mind if you continue these files will be deleted.
	echo.
	echo ps3xploit_resign: Are you sure you want to continue?
	echo.
	pause
	del "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\*.pkg"

)
if exist "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\%RIF_PKG_NAME%_signed.pkg" del "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\%RIF_PKG_NAME%_signed.pkg"

:: Prevent missing dirs
if not exist "%CURRENT_DIR%\%INPUT_PKGS_DIR%\" mkdir "%CURRENT_DIR%\%INPUT_PKGS_DIR%\"
if not exist "%CURRENT_DIR%\%INPUT_RAPS_DIR%\" mkdir "%CURRENT_DIR%\%INPUT_RAPS_DIR%\"
if not exist "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\" mkdir "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\"
if not exist "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\" mkdir "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\"

:: Check for RAP or PKG files
if not exist "%CURRENT_DIR%\%INPUT_RAPS_DIR%\*.rap" (
	echo. 
	echo ps3xploit_resign: No '.rap' files found on '.\%INPUT_RAPS_DIR%\'
	echo. 
	if exist "%CURRENT_DIR%\%INPUT_PKGS_DIR%\*.pkg" (
		GOTO RESIGN_PKG_ONLY
	) else (
		echo. 
		echo ps3xploit_resign: No '.pkg' files found on '.\%INPUT_PKGS_DIR%\'
		echo. 
		pause
		exit /b
	)
)

:: Copy act.dat files
if not exist "%CURRENT_DIR%\%INPUT_ACT_DAT%" (
	echo. 
	echo ps3xploit_resign: '.\%INPUT_ACT_DAT%' not found, exiting...
	echo. 
	pause
	exit /b
)
copy /Y "%CURRENT_DIR%\%INPUT_ACT_DAT%" "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\"

:: Copy idps.hex files
if not exist "%CURRENT_DIR%\%INPUT_IDPS_HEX%" (
	echo. 
	echo ps3xploit_resign: '.\%INPUT_IDPS_HEX%' not found, exiting...
	echo. 
	pause
	exit /b
)
copy /Y "%CURRENT_DIR%\%INPUT_IDPS_HEX%" "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\"

:: Copy RAP files
copy /Y "%CURRENT_DIR%\%INPUT_RAPS_DIR%\*.rap" "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\"

:: Resign all RAP files to RIF files
if exist "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\*.rif" del "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\*.rif"
for %%I in ("%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\*.rap") do (
	cd "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\"
	echo y | "%CURRENT_DIR%\%TOOLS_RESIGNER%" "%%I"
	cd "%CURRENT_DIR%\"
)

:: Delete unneed files on PKG RIF
del "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\*.rap"
del "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\act.dat"
del "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\idps.hex"

:: Move 'signed_act.dat' to 'act.dat'
move "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\signed_act.dat" "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\act.dat"

:: Build PKG RIF
"%CURRENT_DIR%\%TOOLS_PKG_EXDATA%" --contentid %RIF_PKG_CONTENTID% %OUTPUT_TEMP_DIR%\ %OUTPUT_PKGS_DIR%\%RIF_PKG_NAME%

:: Resign PKG RIF
if not exist "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\%RIF_PKG_NAME%" (
	echo. 
	echo ps3xploit_resign: '.\%OUTPUT_PKGS_DIR%\%RIF_PKG_NAME%' not found, exiting...
	echo. 
	pause
	exit /b
)
echo y | "%CURRENT_DIR%\%TOOLS_RESIGNER%" "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\%RIF_PKG_NAME%"

:: Cleanup
del "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\*.rif"
del "%CURRENT_DIR%\%OUTPUT_TEMP_DIR%\act.dat"
del "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\%RIF_PKG_NAME%"

:: Resign PKG files
:RESIGN_PKG_ONLY
for %%I in ("%CURRENT_DIR%\%INPUT_PKGS_DIR%\*.pkg") do (
	echo y | "%CURRENT_DIR%\%TOOLS_RESIGNER%" "%%I"
	move "%%I_signed.pkg" "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\"
)

:: Output header
echo. 
echo ps3xploit_resign: Output files:

:: See PKGS signed
if exist "%CURRENT_DIR%\%OUTPUT_PKGS_DIR%\*.pkg" (
	echo. 
	echo.  PKGS:
	for %%I in (%OUTPUT_PKGS_DIR%\*.pkg) do (
		if "%%I" == "%OUTPUT_PKGS_DIR%\%RIF_PKG_NAME%_signed.pkg" (
			echo.    [RIF PKG] .\%%I
		) else (
			echo.    .\%%I
		)
	)
	echo. 
)

:: Let user see everything
pause
