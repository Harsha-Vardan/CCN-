@echo off
if exist "..\venv\Scripts\activate.bat" (
  call ..\venv\Scripts\activate.bat
)
python ..\src\socks_local.py --server 127.0.0.1 --port 9000 --listen-port 1080
pause
