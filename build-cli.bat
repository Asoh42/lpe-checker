@echo off
setlocal
cd /d "%~dp0"

set CGO_ENABLED=0
go build -o lpe-checker-cli.exe ./cmd/lpe-checker-cli
if errorlevel 1 exit /b %errorlevel%
echo Built lpe-checker-cli.exe

