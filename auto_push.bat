@echo off
cd /d "C:\Users\Bruno\Documents\PROJECT\classconnect"
git add .
git commit -m "Auto update %date% %time%"
git push origin main
