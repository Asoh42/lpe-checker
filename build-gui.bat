@echo off
setlocal
cd /d "%~dp0"

rem Requires MSYS2/MinGW-w64 gcc.exe in PATH.
where gcc >nul 2>nul || (
  echo Error: gcc was not found in PATH. Install MSYS2/MinGW-w64 first.
  exit /b 1
)

set CGO_ENABLED=1
go build -ldflags="-H windowsgui" -o lpe-checker-gui.exe ./cmd/lpe-checker-gui
if errorlevel 1 exit /b %errorlevel%
echo Built lpe-checker-gui.exe

