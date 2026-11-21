@echo off
cd /d "%~dp0"
start "" pythonw capsule.py %*
if errorlevel 1 python capsule.py %*
