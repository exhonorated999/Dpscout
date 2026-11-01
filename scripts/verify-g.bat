@echo off
rem Local verification sweep used during the macOS-portable groundwork.
rem Usage: scripts\verify-g.bat <test-filter>   (output: %TEMP%\vg.txt, marker VGEXIT)
setlocal
set FILTER=%1
cd /d "%~dp0..\src-tauri"
echo === portable tests (%FILTER%) === > "%TEMP%\vg.txt"
cargo test --features demo,portable --lib %FILTER% >> "%TEMP%\vg.txt" 2>&1
set P=%ERRORLEVEL%
echo === desktop tests (%FILTER%) === >> "%TEMP%\vg.txt"
cargo test --features demo --lib %FILTER% >> "%TEMP%\vg.txt" 2>&1
set D=%ERRORLEVEL%
echo === warrant baseline === >> "%TEMP%\vg.txt"
cargo test --features demo --lib warrant:: >> "%TEMP%\vg.txt" 2>&1
set W=%ERRORLEVEL%
echo VGEXIT portable=%P% desktop=%D% warrant=%W% >> "%TEMP%\vg.txt"
endlocal
