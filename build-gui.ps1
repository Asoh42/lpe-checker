$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

# Requires MSYS2/MinGW-w64 gcc.exe in PATH.
if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    throw "gcc was not found in PATH. Install MSYS2/MinGW-w64 first."
}

$env:CGO_ENABLED = "1"
go build '-ldflags=-H windowsgui' -o lpe-checker-gui.exe ./cmd/lpe-checker-gui
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Built lpe-checker-gui.exe"

