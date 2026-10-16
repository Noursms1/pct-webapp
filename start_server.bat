@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
  echo [!] No .venv found. Falling back to system pythonw.
  start "" pythonw.exe run_server.py --host 127.0.0.1 --port 8000
) else (
  start "" ".venv\Scripts\pythonw.exe" run_server.py --host 127.0.0.1 --port 8000
)
endlocal
