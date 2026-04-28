@echo off
echo Starting API Graph Mapper...

echo [1/3] Starting Backend (FastAPI on port 8000)...
start "API Graph Mapper - Backend" cmd /k "cd backend && call .venv\Scripts\activate.bat && python -m uvicorn app.main:app --reload"

echo [2/3] Starting mitmproxy adapter (port 8080)...
start "API Graph Mapper - mitmproxy" cmd /k "mitmdump --listen-port 8080 -s mitm_addon.py"

echo [3/3] Starting Frontend (Vite on port 5173)...
start "API Graph Mapper - Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo All services launched in separate windows!
echo - Frontend: http://localhost:5173
echo - Backend:  http://localhost:8000
echo - Proxy:    127.0.0.1:8080
echo.
pause
