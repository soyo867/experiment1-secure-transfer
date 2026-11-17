@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist runtime\bob.json (
  echo 请先运行“准备演示环境.bat”。
  pause
  exit /b 1
)
python run.py gui --profile runtime\bob.json
if errorlevel 1 pause
