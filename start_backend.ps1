# Seva Cyber Sandbox — Start FastAPI Backend Server
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  SEVA CYBER SANDBOX — FASTAPI BACKEND SERVER" -ForegroundColor Cyan
Write-Host "  Target: http://127.0.0.1:8000 | Swagger Docs: http://127.0.0.1:8000/docs" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

Set-Location -Path $PSScriptRoot

if (Test-Path ".\venv\Scripts\python.exe") {
    & ".\venv\Scripts\python.exe" -m uvicorn api_server:app --host 127.0.0.1 --port 8000 --reload
} else {
    python -m uvicorn api_server:app --host 127.0.0.1 --port 8000 --reload
}
