@echo off
:: ==============================
:: AUTO PUSH TO GITHUB - ClassConnect
:: By Bruno (mr.k4pel)
:: ==============================

:: Go to your project directory
cd /d "C:\Users\Bruno\Documents\PROJECT\classconnect"

:: Show the current Git status
echo Checking for changes...
git status

:: Stage all modified files
git add .

:: Automatically generate a commit message with date/time
setlocal enabledelayedexpansion
for /f "tokens=1-5 delims=/ " %%d in ("%date% %time%") do (
    set commit_msg=Auto commit on %%d %%e %%f %%g %%h
)
git commit -m "!commit_msg!"

:: Push to GitHub
echo Pushing to GitHub...
git push -u origin main

:: Done
echo ==================================
echo ✅ All changes pushed successfully to GitHub!
echo ==================================
pause
