@echo off
rem Build BitLockerManager.exe (native C++ / Win32, with embedded icon)
rem Output: Build\BitLockerManager.exe
rem Usage: build_exe.bat [--no-pause]   (--no-pause for CI / scripted runs)
setlocal EnableDelayedExpansion
cd /d "%~dp0"
if not exist Build mkdir Build

set "NOPAUSE=0"
if /i "%~1"=="--no-pause" set "NOPAUSE=1"

rem ---- Locate vcvars64.bat: common paths first, then vswhere ----
set "VCVARS="
for %%P in (
  "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
) do (
  if not defined VCVARS if exist %%P set "VCVARS=%%~P"
)

rem Fallback: ask vswhere (ships with any VS / Build Tools install)
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do if exist "%%I\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%I\VC\Auxiliary\Build\vcvars64.bat"

if not defined VCVARS (
  echo [ERROR] vcvars64.bat not found.
  echo Please install Visual Studio 2022 or Build Tools with the "Desktop development with C++" workload.
  if "%NOPAUSE%"=="0" pause
  exit /b 1
)

call "%VCVARS%" >nul
if errorlevel 1 (
  echo [ERROR] Failed to load MSVC environment.
  if "%NOPAUSE%"=="0" pause
  exit /b 1
)

rem ---- Build icon + version resource ----
rc /nologo /fo app.res app.rc
if errorlevel 1 (
  echo [ERROR] rc.exe failed.
  if "%NOPAUSE%"=="0" pause
  exit /b 1
)

cl /nologo /W4 /O2 /MT /EHsc /utf-8 /DUNICODE /D_UNICODE /Fe:Build\BitLockerManager.exe BitLockerManager.cpp app.res /link /SUBSYSTEM:WINDOWS /MANIFEST:EMBED /MANIFESTUAC:NO /MANIFESTINPUT:app.manifest

if exist Build\BitLockerManager.exe (
  echo.
  echo [OK] Build success: Build\BitLockerManager.exe
) else (
  echo [ERROR] Build failed.
  if "%NOPAUSE%"=="0" pause
  exit /b 1
)
if "%NOPAUSE%"=="0" pause
exit /b 0
