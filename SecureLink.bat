@echo off
rem Double-click launcher for the SecureLink dashboard.
rem Starts the GUI with pythonw (no console window) from the project folder.
cd /d "%~dp0"
where pythonw >nul 2>nul && ( start "" pythonw run_dashboard.pyw ) || ( start "" python run_dashboard.pyw )
