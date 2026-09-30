#!/bin/sh
# Запуск графического клиента MiniVPN в Linux
cd "$(dirname "$0")"
if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null && [ -t 0 ]; then
    exec sudo -E env PYTHONPATH="$PWD" python3 -m minivpn.gui "$@"
fi
PYTHONPATH="$PWD" exec python3 -m minivpn.gui "$@"
