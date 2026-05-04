@echo off
cd /d "c:\Users\haqua\Documents\GitHub\ransomware-detector-v2"
echo Starting MalwareBazaar Pipeline...
.venv\Scripts\python.exe scripts\pipeline_download_and_train.py --total-size-gb 5 --pe-ratio 0.7 --rate-limit 1.0
pause
