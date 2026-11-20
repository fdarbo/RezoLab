@echo off
rem RezoLab - lanceur Windows (demande les droits administrateur)
set "APP="
set "ROOT="
rem Recherche de rezolab.py : a cote du script, dans \rezolab, puis dans le dossier parent
for %%B in ("%~dp0" "%~dp0..\") do for %%D in ("%%~fB" "%%~fB\rezolab") do if not defined APP if exist "%%~D\rezolab.py" (set "APP=%%~D" & set "ROOT=%%~fB")
if not defined APP (
  echo rezolab.py introuvable ^(cherche pres de %~dp0 et dans le dossier parent^)
  pause
  exit /b 1
)
cd /d "%ROOT%"
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Demande des droits administrateur...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
if not exist ".venv\Scripts\python.exe" (
  echo Environnement absent : lancez d'abord install_windows.bat
  pause
  exit /b 1
)
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:8420"
".venv\Scripts\python.exe" "%APP%\rezolab.py"
pause
