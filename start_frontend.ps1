# Seva Cyber Sandbox — Start Vite React Frontend
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  SEVA CYBER SANDBOX — REACT 19 FRONTEND DEV SERVER" -ForegroundColor Cyan
Write-Host "  Target: http://localhost:5173" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$frontendDir = Join-Path $PSScriptRoot "frontend"
Set-Location -Path $frontendDir

npm run dev
