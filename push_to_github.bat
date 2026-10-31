@echo off
chcp 65001 > nul
title Push AI-CSPM to GitHub
echo =====================================================================
echo  Pushing AI-CSPM Platform to GitHub (r3oof-900/AI-CSPM-Platform)
echo =====================================================================
cd /d F:\CSPM_Project
git push -u origin main
echo =====================================================================
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Project uploaded successfully to GitHub!
) else (
    echo [ERROR] Push failed. If prompted, please sign in to GitHub in the browser.
)
echo =====================================================================
pause
