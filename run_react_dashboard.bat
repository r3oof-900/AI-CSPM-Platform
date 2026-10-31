@echo off
chcp 65001 > nul
title AI-CSPM React Web Dashboard
echo =====================================================================
echo  Launching AI-CSPM React Web Dashboard (Vite + React)
echo =====================================================================
cd /d F:\CSPM_Project\ai-cspm-dashboard
npm run dev -- --open
pause
