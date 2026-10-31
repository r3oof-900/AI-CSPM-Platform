@echo off
chcp 65001 > nul
title AI-CSPM FastAPI Backend Server
echo =====================================================================
echo  Launching AI-CSPM FastAPI Backend Server (Port 8000)
echo =====================================================================
cd /d F:\CSPM_Project\AI_CSPM_Engine
python -m uvicorn api_server:app --host 127.0.0.1 --port 8000 --reload
pause
