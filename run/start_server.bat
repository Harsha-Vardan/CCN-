@echo off
REM Activate venv (adjust path if needed)
if exist "..\venv\Scripts\activate.bat" (
  call ..\venv\Scripts\activate.bat
)
python ..\src\vpn_server.py --host 0.0.0.0 --port 9000
pause
