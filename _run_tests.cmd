@echo off
.\venv\Scripts\python.exe -m pytest tests\ -x -q --no-header > _pytest_out.txt 2>&1
echo EXITCODE=%errorlevel% >> _pytest_out.txt
