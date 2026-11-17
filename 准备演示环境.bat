@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -m pip install -r requirements.txt
if errorlevel 1 goto failed
python tools\setup_demo.py
if errorlevel 1 goto failed
echo 环境准备完成。先启动服务端，再启动客户端。
pause
exit /b 0
:failed
echo 环境准备失败，请检查上方错误信息。需要 Python 3.10 或更新版本。
pause
exit /b 1
