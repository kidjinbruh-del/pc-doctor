@echo off
REM Диагност ПК — запуск по двойному клику.
chcp 65001 >nul
title Диагност ПК
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Запустить-диагностику.ps1"
if errorlevel 1 (
  echo.
  echo Не удалось запустить. Проверьте, чтоDiagnose-PC.ps1 лежит рядом.
  pause
)