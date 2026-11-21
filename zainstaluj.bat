@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Instalacja Capsule: pakiety dla ikony w zasobniku (pystray, pillow)...
python -m pip install --upgrade pystray pillow
if errorlevel 1 (
  echo.
  echo Nie udalo sie zainstalowac pakietow. Capsule dziala, ale bez ikony w zasobniku.
  pause
)
start "" pythonw capsule.py --instaluj
