@echo off
set "ROOT=%~dp0"
if "%ROOT:~0,4%"=="\\?\" set "ROOT=%ROOT:~4%"
cd /d "%ROOT%"
python "%ROOT%main.py" --train-from-source-plan %*
