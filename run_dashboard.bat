@echo off
chcp 65001 > nul
title AI-CSPM Web Dashboard
echo =====================================================================
echo  Launching AI-CSPM Interactive Web Dashboard (Streamlit)
echo =====================================================================
streamlit run f:\CSPM_Project\AI_CSPM_Engine\app_dashboard.py
pause
