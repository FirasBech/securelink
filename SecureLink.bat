@echo off
rem One-click launcher for the SecureLink dashboard.
rem Just double-click this file. It starts the GUI with pythonw (no console
rem window) from the project folder; no terminal or commands needed.
cd /d "%~dp0"
where pythonw >nul 2>nul && ( start "" pythonw scripts\run_dashboard.pyw ) || ( start "" python scripts\run_dashboard.pyw )
