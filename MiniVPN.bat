@echo off
rem Запуск графического клиента MiniVPN в Windows (права администратора запросит само приложение)
cd /d "%~dp0"
python -c "import cryptography" 2>nul || python -m pip install -r requirements.txt
start "" pythonw -m minivpn.gui
