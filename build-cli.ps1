$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$env:CGO_ENABLED = "0"
go build -o lpe-checker-cli.exe ./cmd/lpe-checker-cli
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Built lpe-checker-cli.exe"

